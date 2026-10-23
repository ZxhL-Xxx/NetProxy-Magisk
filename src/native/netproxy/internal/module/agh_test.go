package module

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fanju6/NetProxy-Magisk/src/native/netproxy/internal/agh"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestDNSHandoffRequiresActualIdentityAndHoldsOnAPIFailure(t *testing.T) {
	started, mode, apiFail := int64(123456), "Rule", false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiFail {
			http.Error(w, "fixture unavailable", http.StatusServiceUnavailable)
			return
		}
		var payload []byte
		switch r.URL.Path {
		case "/daemon.StartedService/GetVersion":
			payload = protowire.AppendTag(payload, 2, protowire.VarintType)
			payload = protowire.AppendVarint(payload, 1)
		case "/daemon.StartedService/GetStartedAt":
			payload = protowire.AppendTag(payload, 1, protowire.VarintType)
			payload = protowire.AppendVarint(payload, uint64(started))
		case "/daemon.StartedService/GetClashModeStatus":
			payload = protowire.AppendTag(payload, 2, protowire.BytesType)
			payload = protowire.AppendString(payload, mode)
		default:
			http.NotFound(w, r)
			return
		}
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
		_, _ = w.Write(append(frame, payload...))
	}))
	defer server.Close()
	options := Options{ServiceAddress: server.URL}
	all := agh.Scope{IPv4: true, IPv6: true}
	state := ServiceState{State: "ready", PID: 42, CoreStartedAtMillis: started, DNSHandoff: &all}
	check := func(pid int, want agh.Scope, hold, failed bool) {
		t.Helper()
		got, held, err := resolveDNSHandoffState(t.Context(), options, state, pid)
		if got != want || held != hold || (err != nil) != failed {
			t.Fatalf("got %v hold=%v err=%v; want %v hold=%v failed=%v", got, held, err, want, hold, failed)
		}
	}
	check(42, all, false, false)
	mode = "Direct"
	check(42, agh.Scope{}, false, false)
	mode = ""
	check(42, agh.Scope{}, true, true)
	mode, apiFail = "Proxy", true
	check(42, agh.Scope{}, true, true)
	apiFail, started = false, started+1
	check(42, agh.Scope{}, true, true)
	check(0, agh.Scope{}, false, false)
	check(43, agh.Scope{}, false, false)
	state.State = "starting"
	check(42, agh.Scope{}, true, false)
	state.State = "stopping"
	check(42, agh.Scope{}, false, false)
}

func TestPreparedIdentityPersistsRuntimeDNSOnlyUntilReadyEnds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"type":"ebpf","tag":"netproxy-in","local":{"enabled":true,"dns_mode":"off"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := preparedServiceIdentity(PrepareResult{Inbound: path, Backend: "ebpf"}, 123456)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DNSHandoff == nil || *identity.DNSHandoff != (agh.Scope{}) {
		t.Fatal("used saved hijack instead of actual runtime")
	}
	statePath := filepath.Join(t.TempDir(), "service.json")
	if err := WriteServiceState(statePath, "ready", 42, 123, 123, "", identity); err != nil {
		t.Fatal(err)
	}
	state, err := ReadServiceState(statePath)
	if err != nil || state.DNSHandoff == nil {
		t.Fatalf("lost runtime DNS identity: %v", err)
	}
	if err := WriteServiceState(statePath, "starting", 42, 123, 0, ""); err != nil {
		t.Fatal(err)
	}
	state, err = ReadServiceState(statePath)
	if err != nil || state.DNSHandoff != nil {
		t.Fatalf("stale DNS identity survived transition: %v", err)
	}
}
