//go:build linux

package platform

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
)

type routeCommandRunner struct {
	mu           sync.Mutex
	routes       map[string]string
	calls        [][]string
	mutations    int
	failMutation int
}

func newRouteCommandRunner(routes map[string]string) *routeCommandRunner {
	copy := make(map[string]string, len(routes))
	for key, value := range routes {
		copy[key] = value
	}
	return &routeCommandRunner{routes: copy}
}

func (r *routeCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if slices.Contains(args, "show") {
		return []byte(r.routes[args[len(args)-1]]), nil
	}
	if slices.Contains(args, "replace") || slices.Contains(args, "del") {
		r.mutations++
		if r.failMutation != 0 && r.mutations == r.failMutation {
			return []byte("injected failure"), errors.New("exit status 2")
		}
	}
	operation := indexOf(args, "replace")
	if operation >= 0 {
		table := indexOf(args, "table")
		fields := args[table+2:]
		prefix := fields[0]
		r.routes[prefix] = strings.Join(fields, " ") + "\n"
		return nil, nil
	}
	operation = indexOf(args, "del")
	if operation >= 0 {
		table := indexOf(args, "table")
		delete(r.routes, args[table+2])
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command: %v", call)
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}

func (r *routeCommandRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func newTestRouteManager(t *testing.T, runner *routeCommandRunner) RouteManager {
	t.Helper()
	manager, err := NewRouteManager(RouteManagerConfig{Runner: runner, ShutdownTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func testRoute(address string, metric uint32) Route {
	addressValue := netip.MustParseAddr(address)
	return Route{Prefix: netip.PrefixFrom(addressValue, addressValue.BitLen()), Metric: metric}
}

func ownedRouteLine(route Route) string {
	return fmt.Sprintf("%s dev lane0 proto %d metric %d\n", route.Prefix, DefaultRouteProtocol, route.Metric)
}

func TestLinuxRouteManagerUsesIPv6Family(t *testing.T) {
	route := testRoute("2001:db8::2", 10)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if slices.Contains(call, "route") && !slices.Contains(call, "-6") {
			t.Fatalf("IPv6 route command used wrong family: %v", call)
		}
	}
}

func TestLinuxRouteManagerNormalizesDefaultIPv6Metric(t *testing.T) {
	route := testRoute("2001:db8::2", 0)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	if got := runner.routes[route.Prefix.String()]; !strings.Contains(got, "metric 1024") {
		t.Fatalf("installed IPv6 route = %q, want normalized metric 1024", got)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.routes[route.Prefix.String()]; ok {
		t.Fatal("normalized IPv6 route remained after restore")
	}
}

func TestLinuxRouteManagerApplyIdempotentRestore(t *testing.T) {
	first := testRoute("100.96.0.1", 10)
	second := testRoute("100.96.0.2", 20)
	prior := "100.96.0.1/32 via 192.0.2.1 dev eth0 proto static metric 99\n"
	runner := newRouteCommandRunner(map[string]string{first.Prefix.String(): prior})
	manager := newTestRouteManager(t, runner)

	plan := RoutePlan{Routes: []Route{second, first}}
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if runner.routes[first.Prefix.String()] != ownedRouteLine(first) || runner.routes[second.Prefix.String()] != ownedRouteLine(second) {
		t.Fatalf("routes after apply = %+v", runner.routes)
	}
	calls := runner.callCount()
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if runner.callCount() != calls {
		t.Fatalf("idempotent Apply issued %d commands", runner.callCount()-calls)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.routes[first.Prefix.String()] != prior {
		t.Fatalf("prior route not restored: %q", runner.routes[first.Prefix.String()])
	}
	if _, ok := runner.routes[second.Prefix.String()]; ok {
		t.Fatal("new route remained after restore")
	}
	calls = runner.callCount()
	if err := manager.Restore(context.Background()); err != nil || runner.callCount() != calls {
		t.Fatalf("idempotent Restore = %v, calls changed by %d", err, runner.callCount()-calls)
	}
}

func TestLinuxRouteManagerReconcileAndBypass(t *testing.T) {
	first := testRoute("100.96.0.1", 10)
	second := testRoute("100.96.0.2", 20)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{first}}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), RoutePlan{
		Routes: []Route{first, second}, TransportBypass: []netip.Addr{first.Prefix.Addr()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := runner.routes[first.Prefix.String()]; ok {
		t.Fatal("transport route was not removed")
	}
	if runner.routes[second.Prefix.String()] != ownedRouteLine(second) {
		t.Fatalf("second route = %q", runner.routes[second.Prefix.String()])
	}
}

func TestLinuxRouteManagerRollsBackFailedTransaction(t *testing.T) {
	first := testRoute("100.96.0.1", 10)
	second := testRoute("100.96.0.2", 20)
	third := testRoute("100.96.0.3", 30)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{first}}); err != nil {
		t.Fatal(err)
	}
	// Installing second succeeds; installing third fails. The second route must
	// be undone and the previous first-only snapshot retained.
	runner.failMutation = runner.mutations + 2
	err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{first, second, third}})
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Apply error = %v", err)
	}
	if runner.routes[first.Prefix.String()] != ownedRouteLine(first) {
		t.Fatalf("first route changed: %+v", runner.routes)
	}
	if _, ok := runner.routes[second.Prefix.String()]; ok {
		t.Fatalf("partially installed route remained: %+v", runner.routes)
	}
	if _, ok := runner.routes[third.Prefix.String()]; ok {
		t.Fatalf("failed route appeared: %+v", runner.routes)
	}
	// A later valid reconcile proves internal ownership state also rolled back.
	runner.failMutation = 0
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{first, second}}); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxRouteManagerRefusesToRemoveForeignReplacement(t *testing.T) {
	route := testRoute("100.96.0.1", 10)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	foreign := "100.96.0.1/32 via 192.0.2.5 dev eth0 proto static metric 1\n"
	runner.routes[route.Prefix.String()] = foreign
	if err := manager.Restore(context.Background()); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("Restore error = %v", err)
	}
	if runner.routes[route.Prefix.String()] != foreign {
		t.Fatal("foreign replacement was modified")
	}
}

func TestLinuxRouteManagerRefusesToUpdateForeignReplacement(t *testing.T) {
	route := testRoute("100.96.0.1", 10)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	foreign := "100.96.0.1/32 via 192.0.2.5 dev eth0 proto static metric 1\n"
	runner.routes[route.Prefix.String()] = foreign
	updated := route
	updated.Metric = 50
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{updated}}); !errors.Is(err, ErrRouteConflict) {
		t.Fatalf("Apply error = %v", err)
	}
	if runner.routes[route.Prefix.String()] != foreign {
		t.Fatal("foreign replacement was modified")
	}
}

func TestLinuxRouteManagerRestoresDisplacedRouteWhenOwnedRouteDisappeared(t *testing.T) {
	route := testRoute("100.96.0.1", 10)
	prior := "100.96.0.1/32 via 192.0.2.1 dev eth0 proto static metric 99\n"
	runner := newRouteCommandRunner(map[string]string{route.Prefix.String(): prior})
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	delete(runner.routes, route.Prefix.String())
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.routes[route.Prefix.String()] != prior {
		t.Fatalf("prior route not restored: %q", runner.routes[route.Prefix.String()])
	}
}

func TestLinuxRouteManagerCloseRetriesAfterFailure(t *testing.T) {
	route := testRoute("100.96.0.1", 10)
	runner := newRouteCommandRunner(nil)
	manager := newTestRouteManager(t, runner)
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{route}}); err != nil {
		t.Fatal(err)
	}
	runner.failMutation = runner.mutations + 1
	if err := manager.Close(); err == nil {
		t.Fatal("Close unexpectedly succeeded")
	}
	runner.failMutation = 0
	if err := manager.Close(); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
}

func TestNewRouteManagerValidation(t *testing.T) {
	for _, config := range []RouteManagerConfig{
		{InterfaceName: "bad/name"},
		{Table: -1},
		{Protocol: 256},
		{ShutdownTimeout: -1},
	} {
		if _, err := NewRouteManager(config); !errors.Is(err, ErrInvalidRoute) {
			t.Fatalf("NewRouteManager(%+v) error = %v", config, err)
		}
	}
}
