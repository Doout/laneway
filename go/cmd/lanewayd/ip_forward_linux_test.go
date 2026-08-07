//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/subnet"
)

func TestDaemonIPForwardManagerOwnsOneCombinedLifecycle(t *testing.T) {
	values := map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
	var writes []string
	manager := newDaemonIPForwardManager()
	manager.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "sysctl" {
			return nil, fmt.Errorf("unexpected command %s", name)
		}
		if len(args) == 2 && args[0] == "-n" {
			return []byte(values[args[1]] + "\n"), nil
		}
		if len(args) == 2 && args[0] == "-w" {
			parts := strings.SplitN(args[1], "=", 2)
			values[parts[0]] = parts[1]
			writes = append(writes, args[1])
			return []byte(args[1] + "\n"), nil
		}
		return nil, fmt.Errorf("unexpected sysctl args %v", args)
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{ipv4: true, ipv6: true}); err != nil {
		t.Fatal(err)
	}
	// A later subnet/exit transition keeps the coordinator enabled rather than
	// transferring ownership between feature-specific managers.
	if err := manager.Apply(context.Background(), ipForwardFamilies{ipv4: true, ipv6: true}); err != nil {
		t.Fatal(err)
	}
	if values["net.ipv4.ip_forward"] != "1" || values["net.ipv6.conf.all.forwarding"] != "1" || len(writes) != 2 {
		t.Fatalf("enabled values=%v writes=%v", values, writes)
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{}); err != nil {
		t.Fatal(err)
	}
	if values["net.ipv4.ip_forward"] != "0" || values["net.ipv6.conf.all.forwarding"] != "0" || len(writes) != 4 {
		t.Fatalf("restored values=%v writes=%v", values, writes)
	}
}

func TestControllerApplySysctlFailurePreservesAcceptedSnapshot(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	old := controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60))
	old.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	old.Routes.Routes = append(old.Routes.Routes, subnetRoute(local.NodeID, "192.168.10.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
	next := nextControllerConfiguration(local, newPeer)
	next.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	next.Routes.Routes = append(next.Routes.Routes, subnetRoute(local.NodeID, "2001:db8:20::/64", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))

	values := map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
	failIPv6 := false
	forwarding := newDaemonIPForwardManager()
	forwarding.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-n" {
			return []byte(values[args[1]]), nil
		}
		parts := strings.SplitN(args[1], "=", 2)
		if failIPv6 && parts[0] == "net.ipv6.conf.all.forwarding" && parts[1] == "1" {
			failIPv6 = false
			return nil, fmt.Errorf("injected sysctl failure")
		}
		values[parts[0]] = parts[1]
		return nil, nil
	}
	table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
	subnets := &daemonSubnetManager{forwarding: subnet.NewMemoryForwardingManager()}
	routes := platform.NewMemoryRouteManager()
	if err := applyControllerConfiguration(context.Background(), old, local, table, routes, nil, policies, subnets, forwarding, nil, state); err != nil {
		t.Fatal(err)
	}
	failIPv6 = true
	if err := applyControllerConfiguration(context.Background(), next, local, table, routes, nil, policies, subnets, forwarding, nil, state); err == nil {
		t.Fatal("injected sysctl failure was accepted")
	}
	assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
	if values["net.ipv4.ip_forward"] != "1" || values["net.ipv6.conf.all.forwarding"] != "0" {
		t.Fatalf("sysctl state after rollback = %v", values)
	}
	plan, active := subnets.forwarding.(*subnet.MemoryForwardingManager).Snapshot()
	if !active || len(plan.Routes) != 1 || plan.Routes[0].Prefix != netip.MustParsePrefix("192.168.10.0/24") {
		t.Fatalf("subnet state changed on sysctl failure = %#v, %t", plan, active)
	}
}

func TestDaemonIPForwardManagerPreservesPreEnabledHost(t *testing.T) {
	values := map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"}
	writes := 0
	manager := newDaemonIPForwardManager()
	manager.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-n" {
			return []byte(values[args[1]]), nil
		}
		writes++
		return nil, nil
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{ipv4: true}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{}); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("pre-enabled forwarding was overwritten %d times", writes)
	}
}

func TestDaemonIPForwardManagerEnablesOnlyRequestedFamily(t *testing.T) {
	values := map[string]string{"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"}
	manager := newDaemonIPForwardManager()
	manager.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "-n" {
			return []byte(values[args[1]]), nil
		}
		parts := strings.SplitN(args[1], "=", 2)
		values[parts[0]] = parts[1]
		return nil, nil
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{ipv6: true}); err != nil {
		t.Fatal(err)
	}
	if values["net.ipv4.ip_forward"] != "0" || values["net.ipv6.conf.all.forwarding"] != "1" {
		t.Fatalf("family-scoped forwarding = %v", values)
	}
	if err := manager.Apply(context.Background(), ipForwardFamilies{ipv4: true}); err != nil {
		t.Fatal(err)
	}
	if values["net.ipv4.ip_forward"] != "1" || values["net.ipv6.conf.all.forwarding"] != "0" {
		t.Fatalf("family reconciliation = %v", values)
	}
}
