//go:build darwin

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

type darwinRouteTestRunner struct {
	mu     sync.Mutex
	routes map[string]string
}

func (r *darwinRouteTestRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	operation := args[1]
	prefix := ""
	for _, value := range args {
		if _, err := netip.ParsePrefix(value); err == nil {
			prefix = value
		}
	}
	switch operation {
	case "get":
		name, ok := r.routes[prefix]
		if !ok {
			return []byte("destination: default\ninterface: en0\n"), nil
		}
		parsed := netip.MustParsePrefix(prefix)
		mask := "255.255.255.255"
		if parsed == netip.MustParsePrefix("10.20.0.0/16") {
			mask = "255.255.0.0"
		}
		return []byte(fmt.Sprintf("destination: %s\nmask: %s\ninterface: %s\n", parsed.Addr(), mask, name)), nil
	case "add":
		r.routes[prefix] = args[len(args)-1]
		return nil, nil
	case "delete":
		delete(r.routes, prefix)
		return nil, nil
	default:
		return nil, errors.New("unexpected route operation")
	}
}

func TestDarwinRouteManagerOwnsAndRestoresOnlyItsRoutes(t *testing.T) {
	runner := &darwinRouteTestRunner{routes: make(map[string]string)}
	manager, err := NewRouteManager(RouteManagerConfig{InterfaceName: "utun7", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("10.20.0.0/16")
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{{Prefix: prefix}}}); err != nil {
		t.Fatal(err)
	}
	if runner.routes[prefix.String()] != "utun7" {
		t.Fatalf("route was not installed: %v", runner.routes)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.routes) != 0 {
		t.Fatalf("route was not restored: %v", runner.routes)
	}
}

func TestDarwinRouteManagerRefusesExistingExactRoute(t *testing.T) {
	prefix := netip.MustParsePrefix("10.20.0.0/16")
	runner := &darwinRouteTestRunner{routes: map[string]string{prefix.String(): "en0"}}
	manager, err := NewRouteManager(RouteManagerConfig{InterfaceName: "utun7", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Apply(context.Background(), RoutePlan{Routes: []Route{{Prefix: prefix}}})
	if !errors.Is(err, ErrRouteConflict) || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("existing route error = %v", err)
	}
	if runner.routes[prefix.String()] != "en0" {
		t.Fatal("existing route was changed")
	}
}

func TestDarwinRouteOutputRequiresExactPrefixAndInterface(t *testing.T) {
	prefix := netip.MustParsePrefix("10.20.0.0/16")
	if darwinRouteMatchesPrefix("destination: default\ninterface: en0\n", prefix) {
		t.Fatal("default route matched private prefix")
	}
	output := "destination: 10.20.0.0\nmask: 255.255.0.0\ninterface: utun3\n"
	if !darwinRouteMatchesPrefix(output, prefix) || !darwinRouteUsesInterface(output, "utun3") {
		t.Fatal("exact owned route did not match")
	}
}
