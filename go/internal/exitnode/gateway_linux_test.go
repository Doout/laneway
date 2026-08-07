//go:build linux

package exitnode

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"laneway.dev/laneway/internal/nftstate"
)

type fakeGatewayRunner struct {
	mu           sync.Mutex
	forwarding   string
	table        bool
	token        string
	staleJSON    []byte
	calls        [][]string
	failContains string
}

func (f *fakeGatewayRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.failContains != "" && strings.Contains(call, f.failContains) {
		f.failContains = ""
		return []byte("injected"), errors.New("exit status 1")
	}
	if name == "sysctl" {
		if len(args) > 0 && args[0] == "-n" {
			return []byte(f.forwarding + "\n"), nil
		}
		if len(args) > 1 && args[0] == "-w" {
			f.forwarding = strings.TrimPrefix(args[1], ipv4ForwardKey+"=")
			return nil, nil
		}
	}
	if name == "nft" {
		joined := strings.Join(args, " ")
		if joined == "-j list table inet laneway_exit" && len(f.staleJSON) != 0 {
			return append([]byte(nil), f.staleJSON...), nil
		}
		if joined == "list tables" {
			if f.table {
				return []byte("table " + gatewayNFTFamily + " laneway_exit\n"), nil
			}
			return nil, nil
		}
		if strings.HasPrefix(joined, "add table "+gatewayNFTFamily+" ") {
			f.table = true
			return nil, nil
		}
		if strings.HasPrefix(joined, "add rule "+gatewayNFTFamily+" laneway_exit laneway_owner ") {
			f.token = args[len(args)-1]
			return nil, nil
		}
		if strings.HasPrefix(joined, "list chain "+gatewayNFTFamily+" laneway_exit laneway_owner") {
			return []byte("comment \"" + f.token + "\"\n"), nil
		}
		if strings.HasPrefix(joined, "delete table "+gatewayNFTFamily+" ") {
			f.table = false
			f.staleJSON = nil
			f.token = ""
			return nil, nil
		}
		if strings.HasPrefix(joined, "add ") {
			return nil, nil
		}
	}
	return []byte("unexpected"), errors.New("unexpected command")
}

func TestLinuxGatewayInstallsIPv6NATRules(t *testing.T) {
	r := &fakeGatewayRunner{forwarding: "1"}
	manager, err := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	plan := GatewayPlan{Enabled: true, Authorized: true, OverlaySources: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	var nat bool
	for _, args := range r.calls {
		line := strings.Join(args, " ")
		nat = nat || strings.Contains(line, "add rule inet") && strings.Contains(line, "ip6 saddr 2001:db8::/64 masquerade")
	}
	if !nat {
		t.Fatalf("IPv6 NAT rule not installed: %v", r.calls)
	}
}

func gatewayPlan() GatewayPlan {
	return GatewayPlan{Enabled: true, Authorized: true, OverlaySources: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
}

func TestLinuxGatewayNATAndRestore(t *testing.T) {
	r := &fakeGatewayRunner{forwarding: "0"}
	manager, err := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), gatewayPlan()); err != nil {
		t.Fatal(err)
	}
	if r.forwarding != "1" || !r.table {
		t.Fatalf("forwarding=%s table=%v", r.forwarding, r.table)
	}
	var nat bool
	for _, args := range r.calls {
		line := strings.Join(args, " ")
		if strings.Contains(line, "ip saddr 10.42.0.0/16 masquerade") {
			nat = true
		}
	}
	if !nat {
		t.Fatal("NAT rule not installed")
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.forwarding != "0" || r.table {
		t.Fatalf("restore forwarding=%s table=%v", r.forwarding, r.table)
	}
}

func TestLinuxGatewayRollbackAndCollision(t *testing.T) {
	r := &fakeGatewayRunner{forwarding: "0", failContains: "laneway-exit-nat"}
	manager, _ := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r})
	if err := manager.Apply(context.Background(), gatewayPlan()); err == nil {
		t.Fatal("expected failure")
	}
	if r.forwarding != "0" || r.table {
		t.Fatalf("partial state forwarding=%s table=%v", r.forwarding, r.table)
	}
	r2 := &fakeGatewayRunner{forwarding: "1", table: true}
	manager2, _ := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r2})
	if err := manager2.Apply(context.Background(), gatewayPlan()); !errors.Is(err, ErrOwnership) {
		t.Fatalf("collision error=%v", err)
	}
}

func TestLinuxGatewayReclaimsExactCrashResidue(t *testing.T) {
	r := &fakeGatewayRunner{forwarding: "1", table: true}
	marker := nftstate.Marker("exit", DefaultGatewayTable, "laneway_owner", "laneway_forward", "laneway_nat", "lane0", "eth0")
	session := gatewaySessionPrefix + strings.Repeat("b", 32) + "-f0"
	r.token = session
	r.staleJSON = gatewayRulesetJSON(marker, session, false)
	manager, err := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), gatewayPlan()); err != nil {
		t.Fatal(err)
	}
	if !r.table || r.forwarding != "1" {
		t.Fatalf("recovery table=%v forwarding=%s", r.table, r.forwarding)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if r.table || r.forwarding != "0" {
		t.Fatalf("close did not restore pre-crash state table=%v forwarding=%s", r.table, r.forwarding)
	}
}

func TestLinuxGatewayRefusesMarkedResidueWithUnexpectedRule(t *testing.T) {
	r := &fakeGatewayRunner{forwarding: "1", table: true}
	marker := nftstate.Marker("exit", DefaultGatewayTable, "laneway_owner", "laneway_forward", "laneway_nat", "lane0", "eth0")
	session := gatewaySessionPrefix + strings.Repeat("b", 32) + "-f0"
	r.staleJSON = gatewayRulesetJSON(marker, session, true)
	manager, _ := NewGatewayManager(GatewayManagerConfig{InputInterface: "lane0", OutputInterface: "eth0", Runner: r})
	err := manager.Apply(context.Background(), gatewayPlan())
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("Apply error = %v", err)
	}
	if !r.table || r.forwarding != "1" {
		t.Fatalf("foreign state changed table=%v forwarding=%s", r.table, r.forwarding)
	}
}

func gatewayRulesetJSON(marker, session string, extra bool) []byte {
	object := func(kind string, value map[string]any) map[string]any { return map[string]any{kind: value} }
	identity := func(chain, comment string, handle int, expressions []any) map[string]any {
		return object("rule", map[string]any{"family": "inet", "table": "laneway_exit", "chain": chain,
			"handle": handle, "comment": comment, "expr": expressions})
	}
	counter := []any{map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}}
	prefix := netip.MustParsePrefix("10.42.0.0/16")
	objects := []map[string]any{
		object("table", map[string]any{"family": "inet", "name": "laneway_exit", "handle": 1}),
		object("chain", map[string]any{"family": "inet", "table": "laneway_exit", "name": "laneway_owner", "handle": 2}),
		object("chain", map[string]any{"family": "inet", "table": "laneway_exit", "name": "laneway_forward", "handle": 5, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}),
		object("chain", map[string]any{"family": "inet", "table": "laneway_exit", "name": "laneway_nat", "handle": 6, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}),
		identity("laneway_owner", marker, 3, counter),
		identity("laneway_owner", session, 4, counter),
		identity("laneway_forward", "laneway-exit-out", 7, []any{
			nftstate.MatchMeta("iifname", "lane0"), nftstate.MatchMeta("oifname", "eth0"),
			nftstate.MatchPrefix("ip", "saddr", prefix.Addr().String(), prefix.Bits()), nftstate.Accept(),
		}),
		identity("laneway_forward", "laneway-exit-in", 8, []any{
			nftstate.MatchMeta("iifname", "eth0"), nftstate.MatchMeta("oifname", "lane0"),
			nftstate.MatchPrefix("ip", "daddr", prefix.Addr().String(), prefix.Bits()),
			nftstate.MatchCTStates("established", "related"), nftstate.Accept(),
		}),
		identity("laneway_nat", "laneway-exit-nat", 9, []any{
			nftstate.MatchMeta("oifname", "eth0"), nftstate.MatchPrefix("ip", "saddr", prefix.Addr().String(), prefix.Bits()), nftstate.Masquerade(),
		}),
	}
	if extra {
		objects = append(objects, identity("laneway_forward", "foreign", 10, []any{nftstate.Accept()}))
	}
	raw, _ := json.Marshal(map[string]any{"nftables": objects})
	return raw
}
