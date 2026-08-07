//go:build linux

package exitnode

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeResolveRunner struct {
	mu             sync.Mutex
	state          dnsState
	calls          [][]string
	failDomainOnce bool
}

func (f *fakeResolveRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	switch args[0] {
	case "dns":
		if len(args) == 2 {
			return []byte("Link 9 (lane0): " + strings.Join(f.state.servers, " ") + "\n"), nil
		}
		f.state.servers = append([]string(nil), args[2:]...)
	case "domain":
		if len(args) == 2 {
			return []byte("Link 9 (lane0): " + strings.Join(f.state.domains, " ") + "\n"), nil
		}
		if f.failDomainOnce && len(args) > 2 && args[2] == "~." {
			f.failDomainOnce = false
			return []byte("injected"), errors.New("exit status 1")
		}
		f.state.domains = append([]string(nil), args[2:]...)
	case "default-route":
		if len(args) == 2 {
			return []byte("Link 9 (lane0): " + f.state.defaultRoute + "\n"), nil
		}
		f.state.defaultRoute = args[2]
	case "revert":
		f.state = dnsState{}
	default:
		return nil, fmt.Errorf("unexpected %s", args[0])
	}
	return nil, nil
}

func TestLinuxDNSSnapshotApplyRestore(t *testing.T) {
	r := &fakeResolveRunner{state: dnsState{servers: []string{"192.0.2.53"}, domains: []string{"corp.example"}, defaultRoute: "no"}}
	manager, err := NewDNSManager(DNSManagerConfig{InterfaceName: "lane0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), validClientPlan().DNSServers); err != nil {
		t.Fatal(err)
	}
	want := dnsState{servers: []string{"10.42.0.53"}, domains: []string{"~."}, defaultRoute: "yes"}
	if !dnsStatesEqual(r.state, want) {
		t.Fatalf("state=%+v", r.state)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	prior := dnsState{servers: []string{"192.0.2.53"}, domains: []string{"corp.example"}, defaultRoute: "no"}
	if !dnsStatesEqual(r.state, prior) {
		t.Fatalf("prior not restored: %+v", r.state)
	}
}

func TestLinuxDNSRollsBackPartialApply(t *testing.T) {
	prior := dnsState{servers: []string{"192.0.2.53"}, domains: []string{"corp.example"}, defaultRoute: "no"}
	r := &fakeResolveRunner{state: cloneDNSState(prior), failDomainOnce: true}
	manager, _ := NewDNSManager(DNSManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), validClientPlan().DNSServers); err == nil {
		t.Fatal("expected error")
	}
	if !dnsStatesEqual(r.state, prior) {
		t.Fatalf("partial DNS survived: %+v", r.state)
	}
}

func TestLinuxDNSDetectsExternalReplacement(t *testing.T) {
	r := &fakeResolveRunner{}
	manager, _ := NewDNSManager(DNSManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), validClientPlan().DNSServers); err != nil {
		t.Fatal(err)
	}
	r.state.servers = []string{"8.8.8.8"}
	if err := manager.Restore(context.Background()); !errors.Is(err, ErrOwnership) {
		t.Fatalf("error=%v", err)
	}
}

func TestParseResolveValues(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want int
	}{
		{"Link 2 (lane0): 1.1.1.1 9.9.9.9", 2},
		{"Link 2 (lane0):", 0},
		{"Link 2 (lane0): none", 0},
	} {
		if got := len(parseResolveValues([]byte(tt.in))); got != tt.want {
			t.Fatalf("%q: got %d", tt.in, got)
		}
	}
}
