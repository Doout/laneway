//go:build linux

package wireguard

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

	"laneway.dev/laneway/internal/identity"
)

type fakeFirewallRunner struct {
	mu        sync.Mutex
	table     bool
	state     string
	inputs    []string
	calls     [][]string
	failInput bool
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
		return nil, nil
	}
	if strings.TrimSpace(text) == "delete table inet laneway_wg" {
		r.table, r.state = false, ""
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected input %q", text)
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
