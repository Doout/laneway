//go:build linux

package subnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/nftstate"
)

type fakeRunner struct {
	mu sync.Mutex

	forwarding map[string]string
	table      bool
	foreign    bool
	ownerToken string
	staleJSON  []byte
	rules      [][]string
	calls      [][]string
	failAt     int
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{forwarding: map[string]string{ipv4ForwardKey: "0", ipv6ForwardKey: "0"}}
}

func (r *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if r.failAt != 0 && len(r.calls) == r.failAt {
		return []byte("injected failure"), errors.New("exit status 1")
	}
	if name == "sysctl-test" {
		if len(args) == 2 && args[0] == "-n" {
			return []byte(r.forwarding[args[1]] + "\n"), nil
		}
		if len(args) == 2 && args[0] == "-w" {
			parts := strings.SplitN(args[1], "=", 2)
			r.forwarding[parts[0]] = parts[1]
			return []byte(args[1]), nil
		}
	}
	if name == "nft-test" {
		if slices.Equal(args, []string{"-j", "list", "table", nftFamily, "laneway"}) && len(r.staleJSON) != 0 {
			return append([]byte(nil), r.staleJSON...), nil
		}
		if slices.Equal(args, []string{"list", "tables"}) {
			if r.table {
				return []byte("table " + nftFamily + " laneway\n"), nil
			}
			return nil, nil
		}
		if len(args) == 5 && slices.Equal(args[:4], []string{"list", "chain", nftFamily, "laneway"}) {
			if !r.table || r.ownerToken == "" {
				return []byte("No such chain"), errors.New("exit status 1")
			}
			return []byte("chain " + args[4] + " { counter comment \"" + r.ownerToken + "\"; }\n"), nil
		}
		if len(args) == 4 && slices.Equal(args[:3], []string{"add", "table", nftFamily}) {
			if r.table {
				return []byte("File exists"), errors.New("exit status 1")
			}
			r.table = true
			r.foreign = false
			r.ownerToken = ""
			r.staleJSON = nil
			r.rules = nil
			return nil, nil
		}
		if len(args) == 4 && slices.Equal(args[:3], []string{"delete", "table", nftFamily}) {
			if !r.table {
				return []byte("No such file"), errors.New("exit status 1")
			}
			r.table = false
			r.ownerToken = ""
			r.rules = nil
			return nil, nil
		}
		if len(args) >= 1 && args[0] == "add" && r.table {
			r.rules = append(r.rules, append([]string(nil), args...))
			if len(args) >= 8 && args[1] == "rule" && args[4] == DefaultOwnerChain && slices.Contains(args, "comment") {
				r.ownerToken = args[len(args)-1]
			}
			return nil, nil
		}
	}
	return nil, fmt.Errorf("unexpected command: %v", call)
}

func newLinuxManager(t *testing.T, runner *fakeRunner, mutate ...func(*ForwardingManagerConfig)) ForwardingManager {
	t.Helper()
	config := ForwardingManagerConfig{
		InputInterface: "lane0", OutputInterface: "eth0",
		NFTCommand: "nft-test", SysctlCommand: "sysctl-test",
		ShutdownTimeout: time.Second, Runner: runner,
	}
	for _, fn := range mutate {
		fn(&config)
	}
	manager, err := NewForwardingManager(config)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func prefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }

func hasRule(rules [][]string, fields ...string) bool {
	for _, rule := range rules {
		found := true
		for _, field := range fields {
			if !slices.Contains(rule, field) {
				found = false
			}
		}
		if found {
			return true
		}
	}
	return false
}

func TestLinuxApplyNATIsIdempotentAndRestores(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	plan := ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{prefix("192.168.50.0/24")}}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if runner.forwarding[ipv4ForwardKey] != "1" || !runner.table {
		t.Fatalf("forwarding = %v, table = %v", runner.forwarding, runner.table)
	}
	if !hasRule(runner.rules, "daddr", "192.168.50.0/24", "masquerade") {
		t.Fatalf("missing scoped masquerade rule: %v", runner.rules)
	}
	if !hasRule(runner.rules, "saddr", "192.168.50.0/24", "lane0", "eth0") {
		t.Fatalf("missing reverse forwarding rule: %v", runner.rules)
	}
	calls := len(runner.calls)
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != calls {
		t.Fatalf("idempotent Apply made %d calls", len(runner.calls)-calls)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.forwarding[ipv4ForwardKey] != "0" || runner.table {
		t.Fatalf("restore left forwarding = %v, table = %v", runner.forwarding, runner.table)
	}
	calls = len(runner.calls)
	if err := manager.Restore(context.Background()); err != nil || len(runner.calls) != calls {
		t.Fatalf("idempotent Restore = %v; calls changed by %d", err, len(runner.calls)-calls)
	}
}

func TestLinuxRoutedModeHasNoNATState(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	if err := manager.Apply(context.Background(), ForwardingPlan{
		Mode: ModeRouted, AuthorizedPrefixes: []netip.Prefix{prefix("10.20.0.0/16")},
	}); err != nil {
		t.Fatal(err)
	}
	for _, rule := range runner.rules {
		if slices.Contains(rule, DefaultNATChain) || slices.Contains(rule, "masquerade") {
			t.Fatalf("routed mode installed NAT state: %v", rule)
		}
	}
}

func TestLinuxMixedModesOnlyNATsSelectedPrefix(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	if err := manager.Apply(context.Background(), ForwardingPlan{Routes: []ForwardingRoute{
		{Prefix: prefix("10.20.0.0/16"), Mode: ModeRouted},
		{Prefix: prefix("192.168.50.0/24"), Mode: ModeNAT},
	}}); err != nil {
		t.Fatal(err)
	}
	if hasRule(runner.rules, "daddr", "10.20.0.0/16", "masquerade") {
		t.Fatalf("routed prefix was masqueraded: %v", runner.rules)
	}
	if !hasRule(runner.rules, "daddr", "192.168.50.0/24", "masquerade") {
		t.Fatalf("NAT prefix was not masqueraded: %v", runner.rules)
	}
}

func TestLinuxIPv6UsesInetRulesAndIPv6Forwarding(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	prefix := prefix("2001:db8:50::/64")
	if err := manager.Apply(context.Background(), ForwardingPlan{Routes: []ForwardingRoute{{Prefix: prefix, Mode: ModeNAT}}}); err != nil {
		t.Fatal(err)
	}
	if runner.forwarding[ipv6ForwardKey] != "1" || runner.forwarding[ipv4ForwardKey] != "0" {
		t.Fatalf("family forwarding = %v", runner.forwarding)
	}
	if !hasRule(runner.rules, nftFamily, "ip6", "daddr", prefix.String(), "masquerade") {
		t.Fatalf("missing IPv6 NAT rule: %v", runner.rules)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.forwarding[ipv6ForwardKey] != "0" {
		t.Fatalf("IPv6 forwarding not restored: %v", runner.forwarding)
	}
}

func TestLinuxActivationRollsBackSysctlAndRules(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	// read sysctl, list tables, enable, add table, add forward chain, add NAT
	// chain, then fail the first rule.
	runner.failAt = 7
	err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("192.168.0.0/16")},
	})
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Apply error = %v", err)
	}
	if runner.forwarding[ipv4ForwardKey] != "0" || runner.table {
		t.Fatalf("rollback left forwarding = %v, table = %v", runner.forwarding, runner.table)
	}
	runner.failAt = 0
	if err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("192.168.0.0/16")},
	}); err != nil {
		t.Fatalf("Apply after rollback: %v", err)
	}
}

func TestLinuxReconcileRestoresPreviousRulesetOnFailure(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	oldPlan := ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{prefix("10.1.0.0/16")}}
	if err := manager.Apply(context.Background(), oldPlan); err != nil {
		t.Fatal(err)
	}
	// Reconcile deletes the table and then fails after creating the replacement
	// table. Rollback must remove it and recreate the previous complete plan.
	runner.failAt = len(runner.calls) + 3
	err := manager.Apply(context.Background(), ForwardingPlan{
		Mode: ModeRouted, AuthorizedPrefixes: []netip.Prefix{prefix("10.2.0.0/16")},
	})
	if err == nil {
		t.Fatal("Apply unexpectedly succeeded")
	}
	if !runner.table || !hasRule(runner.rules, "10.1.0.0/16", "masquerade") || hasRule(runner.rules, "10.2.0.0/16") {
		t.Fatalf("previous rules were not restored: %v", runner.rules)
	}
}

func TestLinuxRefusesPreexistingTableWithoutMutation(t *testing.T) {
	runner := newFakeRunner()
	runner.table = true
	runner.foreign = true
	manager := newLinuxManager(t, runner)
	err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("172.16.0.0/12")},
	})
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("Apply error = %v", err)
	}
	if !runner.table || !runner.foreign || runner.forwarding[ipv4ForwardKey] != "0" || len(runner.calls) != 2 {
		t.Fatalf("foreign state changed: table=%v foreign=%v forwarding=%v calls=%v",
			runner.table, runner.foreign, runner.forwarding, runner.calls)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !runner.table {
		t.Fatal("Restore removed foreign table")
	}
}

func TestLinuxReclaimsExactCrashResidueAndAdoptsSysctlOwnership(t *testing.T) {
	runner := newFakeRunner()
	runner.forwarding[ipv4ForwardKey] = "1"
	runner.table = true
	runner.ownerToken = subnetSessionPrefix + strings.Repeat("a", 32) + "-40-6n"
	marker := nftstate.Marker("subnet", DefaultTableName, DefaultOwnerChain, DefaultForwardChain,
		DefaultNATChain, "lane0", "eth0")
	runner.staleJSON = []byte(fmt.Sprintf(`{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"laneway","handle":1}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_owner","handle":2}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_forward","handle":5,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_postrouting","handle":6,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_owner","handle":3,"comment":%q,"expr":[{"counter":{"packets":7,"bytes":99}}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_owner","handle":4,"comment":%q,"expr":[{"counter":{"packets":0,"bytes":0}}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_forward","handle":7,"comment":"laneway-forward-out","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lane0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"192.168.50.0","len":24}}}},{"accept":null}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_forward","handle":8,"comment":"laneway-forward-in","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lane0"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.168.50.0","len":24}}}},{"accept":null}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_postrouting","handle":9,"comment":"laneway-masquerade","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lane0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"192.168.50.0","len":24}}}},{"masquerade":null}]}}
]}`, marker, runner.ownerToken))

	manager := newLinuxManager(t, runner)
	plan := ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{prefix("192.168.50.0/24")}}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if !runner.table || runner.forwarding[ipv4ForwardKey] != "1" {
		t.Fatalf("recovery state table=%v forwarding=%v", runner.table, runner.forwarding)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if runner.table || runner.forwarding[ipv4ForwardKey] != "0" {
		t.Fatalf("close did not restore pre-crash state table=%v forwarding=%v", runner.table, runner.forwarding)
	}
}

func TestLinuxRefusesMarkedCrashResidueWithUnexpectedRule(t *testing.T) {
	runner := newFakeRunner()
	runner.table = true
	marker := nftstate.Marker("subnet", DefaultTableName, DefaultOwnerChain, DefaultForwardChain,
		DefaultNATChain, "lane0", "eth0")
	session := subnetSessionPrefix + strings.Repeat("a", 32) + "-40-6n"
	runner.staleJSON = []byte(fmt.Sprintf(`{"nftables":[
{"table":{"family":"inet","name":"laneway","handle":1}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_owner","handle":2}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_forward","handle":5,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"chain":{"family":"inet","table":"laneway","name":"laneway_postrouting","handle":6,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_owner","handle":3,"comment":%q,"expr":[{"counter":{"packets":0,"bytes":0}}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_owner","handle":4,"comment":%q,"expr":[{"counter":{"packets":0,"bytes":0}}]}},
{"rule":{"family":"inet","table":"laneway","chain":"laneway_forward","handle":7,"comment":"foreign-rule","expr":[{"accept":null}]}}
]}`, marker, session))
	manager := newLinuxManager(t, runner)
	err := manager.Apply(context.Background(), ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{prefix("192.168.50.0/24")}})
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("Apply error = %v", err)
	}
	if !runner.table || runner.forwarding[ipv4ForwardKey] != "0" {
		t.Fatalf("malformed foreign state changed: table=%v forwarding=%v", runner.table, runner.forwarding)
	}
}

func TestLinuxRefusesToDeleteForeignReplacement(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	if err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("172.16.0.0/12")},
	}); err != nil {
		t.Fatal(err)
	}
	// Model another actor deleting the owned table and creating a same-named
	// replacement. The in-memory ownership flag alone must not authorize its
	// deletion.
	runner.foreign = true
	runner.ownerToken = "foreign-owner"
	err := manager.Restore(context.Background())
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("Restore error = %v", err)
	}
	if !runner.table || !runner.foreign {
		t.Fatal("foreign replacement was deleted")
	}
	if runner.forwarding[ipv4ForwardKey] != "0" {
		t.Fatalf("sysctl was not independently restored: %v", runner.forwarding)
	}
}

func TestLinuxPreservesAlreadyEnabledForwarding(t *testing.T) {
	runner := newFakeRunner()
	runner.forwarding[ipv4ForwardKey] = "1"
	manager := newLinuxManager(t, runner)
	if err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("10.0.0.0/8")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.forwarding[ipv4ForwardKey] != "1" {
		t.Fatalf("pre-enabled forwarding restored to %v", runner.forwarding)
	}
	for _, call := range runner.calls {
		if len(call) >= 3 && call[0] == "sysctl-test" && call[1] == "-w" {
			t.Fatalf("pre-enabled sysctl was unnecessarily written: %v", call)
		}
	}
}

func TestLinuxRejectsArgumentInjectionBeforeRunner(t *testing.T) {
	badConfigs := []ForwardingManagerConfig{
		{InputInterface: "lane0;flush", OutputInterface: "eth0"},
		{InputInterface: "lane0", OutputInterface: "eth 0"},
		{InputInterface: "lane0", OutputInterface: "eth0", TableName: "lane;way"},
		{InputInterface: "lane0", OutputInterface: "eth0", ForwardChain: "-bad"},
		{InputInterface: "lane0", OutputInterface: "eth0", OwnerChain: DefaultForwardChain},
		{InputInterface: "lane0", OutputInterface: "lane0"},
	}
	for _, config := range badConfigs {
		if _, err := NewForwardingManager(config); !errors.Is(err, ErrInvalid) {
			t.Errorf("NewForwardingManager(%+v) error = %v", config, err)
		}
	}

	runner := newFakeRunner()
	manager := newLinuxManager(t, runner, func(c *ForwardingManagerConfig) {
		c.InputInterface = "lane-0"
		c.OutputInterface = "eth.10"
	})
	if err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("192.0.2.0/24")},
	}); err != nil {
		t.Fatal(err)
	}
	if !hasRule(runner.rules, "lane-0", "eth.10", "192.0.2.0/24") {
		t.Fatalf("validated arguments were not passed as discrete argv: %v", runner.rules)
	}
}

func TestLinuxCloseRetriesCleanupFailure(t *testing.T) {
	runner := newFakeRunner()
	manager := newLinuxManager(t, runner)
	if err := manager.Apply(context.Background(), ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix("10.0.0.0/8")},
	}); err != nil {
		t.Fatal(err)
	}
	runner.failAt = len(runner.calls) + 1
	if err := manager.Close(); err == nil {
		t.Fatal("Close unexpectedly succeeded")
	}
	runner.failAt = 0
	if err := manager.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
}
