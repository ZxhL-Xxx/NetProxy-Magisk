package inbound

import "testing"

func TestRuntimeHandoffOnlyForGlobalLocalHijack(t *testing.T) {
	for _, tc := range []struct {
		entry string
		ipv4  bool
		ipv6  bool
	}{
		{`{"type":"ebpf","tag":"netproxy-in","local":{"enabled":true,"dns_mode":"hijack"},"shared":{"enabled":false}}`, true, true},
		{`{"type":"ebpf","tag":"netproxy-in","local":{"enabled":true,"dns_mode":"off"},"shared":{"enabled":true,"dns_mode":"hijack","interface":["wlan1"]}}`, false, false},
		{`{"type":"ebpf","tag":"netproxy-in","local":{"enabled":false},"shared":{"enabled":true,"dns_mode":"hijack","interface":["wlan1"]}}`, false, false},
		{`{"type":"ebpf","tag":"netproxy-in","local":{"enabled":true,"dns_mode":"respect_policy"}}`, false, false},
		{`{"type":"ebpf","tag":"netproxy-in","network":["tcp"],"local":{"enabled":true,"dns_mode":"hijack"}}`, false, false},
		{`{"type":"ebpf","tag":"netproxy-in","local":{"enabled":true,"dns_mode":"hijack","ipv6":false}}`, true, false},
		{`{"type":"tun","tag":"netproxy-in","dns_mode":"hijack","auto_route":true,"auto_redirect":true,"address":["172.19.0.1/30","fdfe::1/126"]}`, true, true},
		{`{"type":"tun","tag":"netproxy-in","dns_mode":"hijack","auto_route":true,"auto_redirect":true,"address":["172.19.0.1/30"]}`, true, false},
		{`{"type":"tun","tag":"netproxy-in","dns_mode":"hijack","auto_route":true,"auto_redirect":true,"address":["172.19.0.1/30"],"exclude_uid":[10001]}`, false, false},
		{`{"type":"tun","tag":"netproxy-in","dns_mode":"disabled"}`, false, false},
	} {
		ipv4, ipv6, err := RuntimeLocalDNSHijack([]byte(`{"inbounds":[` + tc.entry + `]}`))
		if err != nil || ipv4 != tc.ipv4 || ipv6 != tc.ipv6 {
			t.Fatalf("%s: got %v/%v, %v; want %v/%v", tc.entry, ipv4, ipv6, err, tc.ipv4, tc.ipv6)
		}
	}
	for _, malformed := range []string{`{`, `{"inbounds":[]}`, `{"inbounds":[{"type":"direct"}]}`} {
		if _, _, err := RuntimeLocalDNSHijack([]byte(malformed)); err == nil {
			t.Fatalf("accepted %s", malformed)
		}
	}
}
