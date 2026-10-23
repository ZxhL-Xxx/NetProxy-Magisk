package agh

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type firewallFixture struct {
	rules      map[string][]string
	calls      int
	failInsert bool
}

func newFirewall() *firewallFixture {
	f := &firewallFixture{rules: make(map[string][]string)}
	for _, c := range chains {
		f.rules[c.name] = []string{"-m owner --uid-owner 0 --gid-owner 3004 -j RETURN", "-p udp --dport 53 -j REDIRECT --to-ports 5591", "-p tcp --dport 53 -j REDIRECT --to-ports 5591"}
	}
	return f
}

func (f *firewallFixture) run(_ context.Context, binary string, args ...string) ([]byte, error) {
	f.calls++
	if !slices.Contains([]string{"iptables", "ip6tables"}, binary) || len(args) < 6 || args[0] != "-w" || args[2] != "-t" {
		return nil, fmt.Errorf("unsafe firewall operation: %s %v", binary, args)
	}
	action, name := args[4], args[5]
	rules, exists := f.rules[name]
	if !exists {
		return []byte("No chain/target/match by that name"), errors.New("exit 1")
	}
	switch action {
	case "-S":
		var output strings.Builder
		for _, entry := range rules {
			fmt.Fprintf(&output, "-A %s %s\n", name, entry)
		}
		return []byte(output.String()), nil
	case "-I":
		if f.failInsert && binary == "ip6tables" {
			return nil, errors.New("injected insert failure")
		}
		if args[6] != "1" {
			return nil, errors.New("must insert before redirect")
		}
		f.rules[name] = append([]string{strings.Join(args[7:], " ")}, rules...)
	case "-D":
		index := slices.Index(rules, strings.Join(args[6:], " "))
		if index < 0 {
			return nil, errors.New("rule missing")
		}
		f.rules[name] = slices.Delete(rules, index, index+1)
	default:
		return nil, fmt.Errorf("unexpected mutation: %s", action)
	}
	return nil, nil
}

func wanted(bypass bool) func(context.Context) (Scope, bool, error) {
	return func(context.Context) (Scope, bool, error) { return Scope{IPv4: bypass, IPv6: bypass}, false, nil }
}

func TestGuardTransitionAndAGHRebuild(t *testing.T) {
	f := newFirewall()
	original := make(map[string][]string)
	for name, rules := range f.rules {
		original[name] = slices.Clone(rules)
	}
	g := &Guard{LockFile: filepath.Join(t.TempDir(), "handoff.flock"), Run: f.run}
	if err := g.Sync(t.Context(), false, wanted(true)); err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		got := f.rules[c.name]
		if got[0] != strings.Join(rule("udp"), " ") || got[1] != strings.Join(rule("tcp"), " ") || !slices.Equal(got[2:], original[c.name]) {
			t.Fatalf("%s: bypass must precede, and preserve, the AGH rules: %v", c.name, got)
		}
	}
	before := f.calls
	if err := g.Sync(t.Context(), false, wanted(true)); err != nil {
		t.Fatal(err)
	}
	if f.calls != before {
		t.Fatal("unchanged state invoked firewall commands")
	}
	// AGH 独立重启后会重建不含本集成规则的链。
	f.rules[chains[0].name] = slices.Clone(original[chains[0].name])
	if err := g.Sync(t.Context(), true, func(context.Context) (Scope, bool, error) { return Scope{}, true, nil }); err != nil {
		t.Fatal(err)
	}
	if f.calls != before {
		t.Fatal("reloading core must hold firewall state")
	}
	if err := g.Sync(t.Context(), false, wanted(true)); err != nil {
		t.Fatal(err)
	}
	if len(f.rules[chains[0].name]) != len(original[chains[0].name])+2 {
		t.Fatal("AGH rebuild was not reconciled")
	}
	// 清理不能删除其他模块的规则。
	f.rules[chains[0].name] = append(f.rules[chains[0].name], "-p udp --dport 53 -m comment --comment another-owner -j RETURN")
	if err := g.Sync(t.Context(), false, wanted(false)); err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		for _, entry := range f.rules[c.name] {
			if strings.Contains(entry, owner) {
				t.Fatalf("owned rule leaked in %s", c.name)
			}
		}
		if !slices.Equal(f.rules[c.name][:len(original[c.name])], original[c.name]) {
			t.Fatal("AGH original rules changed")
		}
	}
	if !strings.Contains(f.rules[chains[0].name][len(original[chains[0].name])], "another-owner") {
		t.Fatal("unrelated rule was removed")
	}
}

func TestGuardPartialActivationConvergesWithoutDroppingWorkingBypass(t *testing.T) {
	f := newFirewall()
	f.failInsert = true
	g := &Guard{LockFile: filepath.Join(t.TempDir(), "handoff.flock"), Run: f.run}
	if err := g.Sync(t.Context(), true, wanted(true)); err == nil {
		t.Fatal("insert failure was hidden")
	}
	if !strings.Contains(f.rules[chains[0].name][0], owner) {
		t.Fatal("working IPv4 bypass was rolled back")
	}
	f.failInsert = false
	if err := g.Sync(t.Context(), true, wanted(true)); err != nil {
		t.Fatal(err)
	}
	for name, entries := range f.rules {
		if len(entries) != 5 || !strings.Contains(entries[0], owner) || !strings.Contains(entries[1], owner) {
			t.Fatalf("failed to converge %s", name)
		}
	}
}

func TestGuardHoldsOnUnverifiedCoreAndSkipsAbsentChains(t *testing.T) {
	f := newFirewall()
	f.rules = make(map[string][]string)
	g := &Guard{LockFile: filepath.Join(t.TempDir(), "handoff.flock"), Run: f.run}
	if err := g.Sync(t.Context(), true, wanted(true)); err != nil {
		t.Fatal(err)
	}
	before := f.calls
	if err := g.Sync(t.Context(), true, func(context.Context) (Scope, bool, error) { return Scope{}, true, nil }); err != nil {
		t.Fatal(err)
	}
	if f.calls != before {
		t.Fatal("uncertain state must not alter firewall")
	}
	permission := &Guard{LockFile: g.LockFile, Run: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Permission denied"), errors.New("exit 1")
	}}
	if err := permission.Sync(t.Context(), true, wanted(false)); err == nil {
		t.Fatal("permission failure was mistaken for an absent chain")
	}
}

func TestGuardKeepsAGHIPv6ProtectionWithoutProxyIPv6(t *testing.T) {
	f := newFirewall()
	g := &Guard{LockFile: filepath.Join(t.TempDir(), "handoff.flock"), Run: f.run}
	if err := g.Sync(t.Context(), true, func(context.Context) (Scope, bool, error) {
		return Scope{IPv4: true}, false, nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range chains {
		owned := strings.Contains(f.rules[c.name][0], owner)
		if owned != (c.binary == "iptables") {
			t.Fatalf("incorrect family bypass: %s", c.name)
		}
	}
}

func TestGuardResolvesStateInsideCrossProcessLock(t *testing.T) {
	f := newFirewall()
	path := filepath.Join(t.TempDir(), "handoff.flock")
	first, second := &Guard{LockFile: path, Run: f.run}, &Guard{LockFile: path, Run: f.run}
	locked, release, resolved := make(chan struct{}), make(chan struct{}), make(chan struct{})
	done := make(chan error, 2)
	go func() {
		done <- first.Sync(t.Context(), true, func(context.Context) (Scope, bool, error) {
			close(locked)
			<-release
			return Scope{IPv4: true, IPv6: true}, false, nil
		})
	}()
	<-locked
	go func() {
		done <- second.Sync(t.Context(), true, func(context.Context) (Scope, bool, error) {
			close(resolved)
			return Scope{}, false, nil
		})
	}()
	select {
	case <-resolved:
		close(release)
		t.Fatal("state resolved before acquiring the shared lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for name, rules := range f.rules {
		if len(rules) != 3 {
			t.Fatalf("older activation overwrote newer shutdown: %s", name)
		}
	}
}
