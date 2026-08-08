//go:build linux

package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nftstate"
)

type fakeFirewallRunner struct {
	mu        sync.Mutex
	table     bool
	state     string
	inputs    []string
	calls     [][]string
	failInput bool
	staleJSON []byte
}

func (r *fakeFirewallRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	if slices.Equal(args, []string{"list", "tables"}) {
		if r.table {
			return []byte("table inet laneway_wg\n"), nil
		}
		return nil, nil
	}
	if slices.Equal(args, []string{"-j", "list", "table", "inet", "laneway_wg"}) && r.table {
		if len(r.staleJSON) != 0 {
			return append([]byte(nil), r.staleJSON...), nil
		}
		return []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":"laneway_wg","handle":7}},`+
			`{"rule":{"comment":%q,"handle":9,"expr":[{"counter":{"packets":3,"bytes":50}}]}}]}`, r.state)), nil
	}
	return nil, fmt.Errorf("unexpected command %s %v", name, args)
}

func (r *fakeFirewallRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.inputs = append(r.inputs, string(input))
	if r.failInput {
		return []byte("injected failure"), errors.New("exit status 1")
	}
	text := string(input)
	if strings.Contains(text, "add table inet laneway_wg") {
		r.table, r.state = true, text
		r.staleJSON = nil
		return nil, nil
	}
	if strings.TrimSpace(text) == "delete table inet laneway_wg" {
		r.table, r.state = false, ""
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected input %q", text)
}

func firewallShapeJSON(t *testing.T, shape nftstate.Shape, session string) []byte {
	t.Helper()
	objects := []any{map[string]any{"table": map[string]any{"family": shape.Family, "name": shape.Table, "handle": 1}}}
	handle := 2
	for _, chain := range shape.Chains {
		value := map[string]any{"family": shape.Family, "table": shape.Table, "name": chain.Name, "handle": handle}
		handle++
		if chain.Base {
			value["type"], value["hook"], value["prio"], value["policy"] = chain.Type, chain.Hook, chain.Priority, chain.Policy
		}
		objects = append(objects, map[string]any{"chain": value})
	}
	addRule := func(chain, comment string, expr []any) {
		objects = append(objects, map[string]any{"rule": map[string]any{
			"family": shape.Family, "table": shape.Table, "chain": chain, "handle": handle, "comment": comment, "expr": expr,
		}})
		handle++
	}
	counter := []any{map[string]any{"counter": map[string]any{"packets": 7, "bytes": 91}}}
	addRule(shape.OwnerChain, shape.Marker, counter)
	addRule(shape.OwnerChain, session, counter)
	for _, rule := range shape.Rules {
		addRule(rule.Chain, rule.Comment, rule.Expr)
	}
	raw, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testFirewallPlan() FirewallPlan {
	local, peer := firewallNode(1), firewallNode(2)
	return FirewallPlan{Epoch: 3, LocalNode: local, DefaultAction: FirewallDeny,
		PeerPrefixes: map[identity.NodeID][]netip.Prefix{peer: {netip.MustParsePrefix("100.64.0.2/32")}},
		Rules: []FirewallRule{{ID: firewallID(4), Priority: 1, Action: FirewallAccept,
			SourceNodes: []identity.NodeID{peer}, DestinationNodes: []identity.NodeID{local}, Protocol: 6,
			DestinationPorts: []FirewallPortRange{{First: 443, Last: 443}}}}}
}

func newTestFirewall(t *testing.T, runner *fakeFirewallRunner) FirewallManager {
	t.Helper()
	manager, err := NewFirewallManager(FirewallConfig{Interface: "lane0", NFTCommand: "nft-test", Runner: runner, ShutdownTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestLinuxFirewallAppliesAtomicDefaultDenyAndRestores(t *testing.T) {
	runner := new(fakeFirewallRunner)
	manager := newTestFirewall(t, runner)
	if err := manager.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	if !runner.table || len(runner.inputs) != 1 {
		t.Fatalf("table=%v inputs=%d", runner.table, len(runner.inputs))
	}
	batch := runner.inputs[0]
	for _, required := range []string{
		"ip saddr 100.64.0.2/32 ip protocol 6 tcp dport 443 accept",
		"laneway_wg_in drop comment \"laneway-wg-default-deny-in\"",
		"laneway_wg_out drop comment \"laneway-wg-default-deny-out\"",
		"iifname \"lane0\" oifname \"lane0\" drop",
	} {
		if !strings.Contains(batch, required) {
			t.Fatalf("batch omitted %q:\n%s", required, batch)
		}
	}
	if err := manager.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 1 {
		t.Fatalf("idempotent apply used %d batches", len(runner.inputs))
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.table {
		t.Fatal("restore retained table")
	}
}

func TestLinuxFirewallReplacementIsOneAtomicBatch(t *testing.T) {
	runner := new(fakeFirewallRunner)
	manager := newTestFirewall(t, runner)
	plan := testFirewallPlan()
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	plan.Epoch++
	plan.Rules[0].DestinationPorts[0] = FirewallPortRange{First: 8443, Last: 8443}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 2 || !strings.HasPrefix(runner.inputs[1], "delete table inet laneway_wg\nadd table inet laneway_wg\n") ||
		!strings.Contains(runner.inputs[1], "dport 8443") {
		t.Fatalf("replacement inputs=%v", runner.inputs)
	}
}

func TestLinuxFirewallRefusesForeignOrChangedState(t *testing.T) {
	t.Run("preexisting", func(t *testing.T) {
		runner := &fakeFirewallRunner{table: true, state: "foreign"}
		manager := newTestFirewall(t, runner)
		if err := manager.Apply(context.Background(), testFirewallPlan()); !errors.Is(err, ErrFirewallOwnership) {
			t.Fatalf("error=%v", err)
		}
		if len(runner.inputs) != 0 || !runner.table {
			t.Fatal("foreign table was mutated")
		}
	})
	t.Run("changed", func(t *testing.T) {
		runner := new(fakeFirewallRunner)
		manager := newTestFirewall(t, runner)
		if err := manager.Apply(context.Background(), testFirewallPlan()); err != nil {
			t.Fatal(err)
		}
		runner.state += " external-rule"
		if err := manager.Restore(context.Background()); !errors.Is(err, ErrFirewallOwnership) {
			t.Fatalf("error=%v", err)
		}
		if !runner.table {
			t.Fatal("changed table was deleted")
		}
	})
}

func TestLinuxFirewallRecoversOnlyExactCrashResidue(t *testing.T) {
	runner := &fakeFirewallRunner{table: true}
	manager := newTestFirewall(t, runner).(*linuxFirewallManager)
	_, statements, err := compileFirewallPlan(testFirewallPlan())
	if err != nil {
		t.Fatal(err)
	}
	runner.staleJSON = firewallShapeJSON(t, manager.tableShape(statements), firewallSessionPrefix+strings.Repeat("a", 32))
	if err := manager.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 2 || strings.TrimSpace(runner.inputs[0]) != "delete table inet laneway_wg" || !runner.table {
		t.Fatalf("recovery inputs=%v table=%v", runner.inputs, runner.table)
	}
}

func TestLinuxFirewallRecoversPriorControllerSnapshot(t *testing.T) {
	runner := &fakeFirewallRunner{table: true}
	manager := newTestFirewall(t, runner).(*linuxFirewallManager)
	_, staleStatements, err := compileFirewallPlan(testFirewallPlan())
	if err != nil {
		t.Fatal(err)
	}
	runner.staleJSON = firewallShapeJSON(t, manager.tableShape(staleStatements), firewallSessionPrefix+strings.Repeat("b", 32))
	current := testFirewallPlan()
	current.Epoch++
	current.Rules[0].DestinationPorts[0] = FirewallPortRange{First: 8443, Last: 8443}
	if err := manager.Apply(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 2 || !strings.Contains(runner.inputs[1], "dport 8443") {
		t.Fatalf("prior snapshot was not replaced authoritatively: %v", runner.inputs)
	}
}

func TestLinuxFirewallRejectsMalformedStaleDynamicRule(t *testing.T) {
	runner := &fakeFirewallRunner{table: true}
	manager := newTestFirewall(t, runner).(*linuxFirewallManager)
	_, statements, err := compileFirewallPlan(testFirewallPlan())
	if err != nil {
		t.Fatal(err)
	}
	raw := firewallShapeJSON(t, manager.tableShape(statements), firewallSessionPrefix+strings.Repeat("c", 32))
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	for _, object := range document["nftables"].([]any) {
		entry := object.(map[string]any)
		rule, ok := entry["rule"].(map[string]any)
		if !ok || !strings.HasPrefix(rule["comment"].(string), "laneway-wg-rule-") {
			continue
		}
		rule["expr"] = []any{map[string]any{"jump": map[string]any{"target": manager.config.InboundChain}}}
		break
	}
	runner.staleJSON, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), testFirewallPlan()); !errors.Is(err, ErrFirewallOwnership) {
		t.Fatalf("error=%v", err)
	}
	if len(runner.inputs) != 0 || !runner.table {
		t.Fatal("malformed stale policy was mutated")
	}
}

func TestLinuxFirewallFailedAtomicReplacementKeepsPreviousState(t *testing.T) {
	runner := new(fakeFirewallRunner)
	manager := newTestFirewall(t, runner)
	if err := manager.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	previous := runner.state
	runner.failInput = true
	plan := testFirewallPlan()
	plan.Rules[0].DestinationPorts[0] = FirewallPortRange{First: 8443, Last: 8443}
	if err := manager.Apply(context.Background(), plan); err == nil {
		t.Fatal("replacement succeeded")
	}
	if !runner.table || runner.state != previous {
		t.Fatal("failed transaction changed active state")
	}
}
