//go:build linux

package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
)

type fakeIPRunner struct {
	mu          sync.Mutex
	routes      map[string]string
	rules       map[string]string
	calls       [][]string
	getDevice   string
	failReplace string
}

func newFakeIPRunner() *fakeIPRunner {
	return &fakeIPRunner{routes: map[string]string{}, rules: map[string]string{}, getDevice: "eth0"}
}
func (f *fakeIPRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string{name}, args...))
	joined := strings.Join(args, " ")
	family := "-4"
	if indexOf(args, "-6") >= 0 {
		family = "-6"
	}
	if strings.Contains(joined, " rule show ") {
		return []byte(f.rules[family]), nil
	}
	if strings.Contains(joined, " rule add ") {
		priority, table := args[indexOf(args, "priority")+1], args[indexOf(args, "lookup")+1]
		f.rules[family] = priority + ": from all lookup " + table + "\n"
		return nil, nil
	}
	if strings.Contains(joined, " rule del ") {
		delete(f.rules, family)
		return nil, nil
	}
	if strings.Contains(joined, " route get ") {
		addr := args[len(args)-1]
		return []byte(fmt.Sprintf("%s via 192.0.2.1 dev %s src 192.0.2.10 uid 0 cache\n", addr, f.getDevice)), nil
	}
	if strings.Contains(joined, " route show ") {
		if indexOf(args, "exact") < 0 {
			keys := make([]string, 0, len(f.routes))
			for prefix := range f.routes {
				if (family == "-4") == strings.Contains(prefix, ".") {
					keys = append(keys, prefix)
				}
			}
			sort.Strings(keys)
			var output strings.Builder
			for _, prefix := range keys {
				output.WriteString(f.routes[prefix])
			}
			return []byte(output.String()), nil
		}
		prefix := args[len(args)-1]
		return []byte(f.routes[prefix]), nil
	}
	if strings.Contains(joined, " route replace ") {
		tableIndex := indexOf(args, "table")
		if tableIndex < 0 || tableIndex+2 >= len(args) {
			return nil, errors.New("bad replace")
		}
		prefix := args[tableIndex+2]
		if prefix == f.failReplace {
			return []byte("injected"), errors.New("exit status 2")
		}
		f.routes[prefix] = strings.Join(args[tableIndex+2:], " ") + "\n"
		return nil, nil
	}
	if strings.Contains(joined, " route del ") {
		tableIndex := indexOf(args, "table")
		prefix := args[tableIndex+2]
		delete(f.routes, prefix)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %s %s", name, joined)
}
func indexOf(values []string, want string) int {
	for i, v := range values {
		if v == want {
			return i
		}
	}
	return -1
}

func TestLinuxRoutesInstallBypassesBeforeSplitDefaultAndRestore(t *testing.T) {
	r := newFakeIPRunner()
	manager, err := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	plan := routePlanFor(validClientPlan())
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(r.routes) != 4 {
		t.Fatalf("routes=%v", r.routes)
	}
	if got := r.rules["-4"]; !strings.Contains(got, "11000: from all lookup 51820") {
		t.Fatalf("IPv4 policy rule = %q", got)
	}
	if !strings.Contains(r.routes["203.0.113.9/32"], "via 192.0.2.1 dev eth0") || !strings.Contains(r.routes["0.0.0.0/1"], "dev lane0 proto 251") {
		t.Fatalf("routes=%v", r.routes)
	}
	firstBypass, firstDefault := 999, 999
	for i, call := range r.calls {
		line := strings.Join(call, " ")
		if strings.Contains(line, "route replace") && strings.Contains(line, "/32") {
			firstBypass = i
		}
		if strings.Contains(line, "route replace") && strings.Contains(line, "0.0.0.0/1") {
			firstDefault = i
			break
		}
	}
	if firstBypass >= firstDefault {
		t.Fatalf("bypass index %d, default index %d", firstBypass, firstDefault)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.routes) != 0 {
		t.Fatalf("routes survived restore: %v", r.routes)
	}
	if len(r.rules) != 0 {
		t.Fatalf("policy rules survived restore: %v", r.rules)
	}
}

func TestLinuxRoutesRestoreDisplacedRoute(t *testing.T) {
	r := newFakeIPRunner()
	prior := "0.0.0.0/1 via 198.51.100.1 dev eth9 proto 99\n"
	r.routes["0.0.0.0/1"] = prior
	manager, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), routePlanFor(validClientPlan())); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.routes["0.0.0.0/1"] != prior {
		t.Fatalf("prior route not restored: %q", r.routes["0.0.0.0/1"])
	}
}

func TestLinuxRoutesRollbackAndOwnership(t *testing.T) {
	r := newFakeIPRunner()
	r.failReplace = "128.0.0.0/1"
	manager, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), routePlanFor(validClientPlan())); err == nil {
		t.Fatal("expected replace failure")
	}
	if len(r.routes) != 0 {
		t.Fatalf("partial routes survived: %v", r.routes)
	}
	r.failReplace = ""
	if err := manager.Apply(context.Background(), routePlanFor(validClientPlan())); err != nil {
		t.Fatal(err)
	}
	r.routes["0.0.0.0/1"] = "0.0.0.0/1 dev other proto 99\n"
	if err := manager.Restore(context.Background()); !errors.Is(err, ErrOwnership) {
		t.Fatalf("restore error=%v", err)
	}
}

func TestLinuxRoutesRejectRecursiveBypass(t *testing.T) {
	r := newFakeIPRunner()
	r.getDevice = "lane0"
	manager, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), routePlanFor(validClientPlan())); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v", err)
	}
}

func TestLinuxRoutesInstallIPv6SplitDefault(t *testing.T) {
	r := newFakeIPRunner()
	manager, err := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	plan := validClientPlan()
	plan.ExitPrefixes = append(plan.ExitPrefixes, netip.MustParsePrefix("::/0"))
	if err := manager.Apply(context.Background(), routePlanFor(plan)); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"::/1", "8000::/1"} {
		if !strings.Contains(r.routes[prefix], "dev lane0 proto 251") {
			t.Fatalf("IPv6 split default %s missing: %v", prefix, r.routes)
		}
	}
	if got := r.rules["-6"]; !strings.Contains(got, "11000: from all lookup 51820") {
		t.Fatalf("IPv6 policy rule = %q", got)
	}
	var usedIPv6 bool
	for _, call := range r.calls {
		line := strings.Join(call, " ")
		usedIPv6 = usedIPv6 || strings.Contains(line, "-6 route replace")
	}
	if !usedIPv6 {
		t.Fatalf("IPv6 route family was not used: %v", r.calls)
	}
}

func TestLinuxRoutesRejectOccupiedPolicyPriorityAndRollBackTable(t *testing.T) {
	r := newFakeIPRunner()
	r.rules["-4"] = "11000: from all lookup 99\n"
	manager, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := manager.Apply(context.Background(), routePlanFor(validClientPlan())); !errors.Is(err, ErrOwnership) {
		t.Fatalf("occupied rule error = %v", err)
	}
	if len(r.routes) != 0 {
		t.Fatalf("dedicated table survived failed policy activation: %v", r.routes)
	}
	if got := r.rules["-4"]; got != "11000: from all lookup 99\n" {
		t.Fatalf("foreign rule was changed: %q", got)
	}
}

func TestLinuxRoutesAdoptExactCrashResidueAndRejectExtras(t *testing.T) {
	r := newFakeIPRunner()
	first, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	plan := routePlanFor(validClientPlan())
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := restarted.Apply(context.Background(), plan); err != nil {
		t.Fatalf("adopt exact crash residue: %v", err)
	}
	if err := restarted.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.routes) != 0 || len(r.rules) != 0 {
		t.Fatalf("adopted residue survived restore: routes=%v rules=%v", r.routes, r.rules)
	}

	r = newFakeIPRunner()
	first, _ = NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	r.routes["198.51.100.0/24"] = "198.51.100.0/24 dev eth9 proto 99\n"
	restarted, _ = NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := restarted.Apply(context.Background(), plan); !errors.Is(err, ErrOwnership) {
		t.Fatalf("extra crash route error = %v", err)
	}
	if got := r.routes["198.51.100.0/24"]; got != "198.51.100.0/24 dev eth9 proto 99\n" {
		t.Fatalf("foreign extra route changed: %q", got)
	}
}

func TestLinuxRoutesAdoptCrashResidueAfterTUNRemovedItsRoutes(t *testing.T) {
	r := newFakeIPRunner()
	first, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	plan := routePlanFor(validClientPlan())
	if err := first.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	// Linux deletes routes that reference a non-persistent TUN when the owning
	// process dies. Native endpoint bypasses and the dedicated policy rule remain.
	delete(r.routes, "0.0.0.0/1")
	delete(r.routes, "128.0.0.0/1")
	restarted, _ := NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := restarted.Apply(context.Background(), plan); err != nil {
		t.Fatalf("adopt partial crash residue: %v", err)
	}
	if err := restarted.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.routes) != 0 || len(r.rules) != 0 {
		t.Fatalf("partially adopted residue survived restore: routes=%v rules=%v", r.routes, r.rules)
	}

	// An occupied Laneway-shaped rule without any protocol-marked route is not
	// sufficient proof of ownership.
	r = newFakeIPRunner()
	r.rules["-4"] = "11000: from all lookup 51820\n"
	restarted, _ = NewRouteManager(RouteManagerConfig{InterfaceName: "lane0", Runner: r})
	if err := restarted.Apply(context.Background(), plan); !errors.Is(err, ErrOwnership) {
		t.Fatalf("unmarked empty-table adoption error = %v", err)
	}
}
