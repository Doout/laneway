package nodeapp

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/subnet"
)

type failOnceRouteManager struct {
	inner *platform.MemoryRouteManager
	fail  bool
}

func (m *failOnceRouteManager) Apply(ctx context.Context, plan platform.RoutePlan) error {
	if m.fail {
		m.fail = false
		return errors.New("injected OS route failure")
	}
	return m.inner.Apply(ctx, plan)
}
func (m *failOnceRouteManager) Restore(ctx context.Context) error { return m.inner.Restore(ctx) }
func (m *failOnceRouteManager) Close() error                      { return m.inner.Close() }

type failOnceForwardingManager struct {
	inner *subnet.MemoryForwardingManager
	fail  bool
}

func (m *failOnceForwardingManager) Apply(ctx context.Context, plan subnet.ForwardingPlan) error {
	if m.fail {
		m.fail = false
		return errors.New("injected subnet failure")
	}
	return m.inner.Apply(ctx, plan)
}
func (m *failOnceForwardingManager) Restore(ctx context.Context) error { return m.inner.Restore(ctx) }
func (m *failOnceForwardingManager) Close() error                      { return m.inner.Close() }

type failOnceGatewayManager struct {
	inner *exitnode.MemoryGatewayManager
	fail  bool
}

type blockingRouteManager struct {
	platform.RouteManager
	entered chan struct{}
	release chan struct{}
}

func (m blockingRouteManager) Apply(ctx context.Context, plan platform.RoutePlan) error {
	select {
	case m.entered <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-m.release:
		return m.RouteManager.Apply(ctx, plan)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *failOnceGatewayManager) Apply(ctx context.Context, plan exitnode.GatewayPlan) error {
	if m.fail {
		m.fail = false
		return errors.New("injected exit gateway failure")
	}
	return m.inner.Apply(ctx, plan)
}
func (m *failOnceGatewayManager) Restore(ctx context.Context) error { return m.inner.Restore(ctx) }
func (m *failOnceGatewayManager) Drain(ctx context.Context) error   { return m.inner.Drain(ctx) }
func (m *failOnceGatewayManager) Close() error                      { return m.inner.Close() }

func nextControllerConfiguration(local identity.NodeIdentity, peer identity.NodeID) *lanewayv1.NodeConfiguration {
	configuration := controllerTestConfiguration(local, peer, uint64(time.Now().Unix()+60))
	configuration.ConfigurationEpoch = 3
	configuration.Routes.ConfigurationEpoch = 3
	configuration.Policy.ConfigurationEpoch = 3
	configuration.Policy.DefaultAction = lanewayv1.PolicyAction_POLICY_ACTION_DENY
	return configuration
}

func TestControllerApplyInstallsDenyGuardBeforeNativeMutation(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	oldPeer := identity.NodeID(testID(3))
	newPeer := identity.NodeID(testID(4))
	table := routing.NewTable(nil)
	policies := new(policy.Table)
	routes := platform.NewMemoryRouteManager()
	state := new(controllerApplyState)
	old := controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60))
	if err := applyControllerConfiguration(context.Background(), old, local, table, routes, nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3] = 0x45, 0, 20
	copy(packet[12:16], []byte{100, 96, 0, 2})
	copy(packet[16:20], []byte{100, 96, 0, 3})
	if got := policies.Evaluate(local.NodeID, oldPeer, packet).Action; got != policy.Accept {
		t.Fatalf("initial policy action = %v", got)
	}

	blocked := blockingRouteManager{RouteManager: routes, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- applyControllerConfiguration(context.Background(), nextControllerConfiguration(local, newPeer), local,
			table, blocked, nil, policies, nil, nil, nil, state)
	}()
	<-blocked.entered
	if got := policies.Evaluate(local.NodeID, oldPeer, packet).Action; got != policy.Deny {
		t.Fatalf("packet retained old broad ACL during native mutation: %v", got)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); !ok || route.NextHop != oldPeer {
		t.Fatalf("userspace route changed before native transaction: %#v, %t", route, ok)
	}
	close(blocked.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func assertOldControllerSnapshot(t *testing.T, state *controllerApplyState, table *routing.Table, policyTable *policy.Table, oldPeer, newPeer identity.NodeID) {
	t.Helper()
	if state.accepted == nil || state.accepted.configuration.GetConfigurationEpoch() != 2 {
		t.Fatalf("accepted epoch = %#v, want 2", state.accepted)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); !ok || route.NextHop != oldPeer {
		t.Fatalf("old userspace route = %#v, %t", route, ok)
	}
	if _, ok := table.Lookup(netip.MustParseAddr("100.96.0.4")); ok {
		t.Fatal("failed snapshot's userspace route was published")
	}
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3] = 0x45, 0, 20
	copy(packet[12:16], []byte{100, 96, 0, 2})
	copy(packet[16:20], []byte{100, 96, 0, 3})
	if result := policyTable.Evaluate(localNodeIDForTest(), oldPeer, packet); result.Action != policy.Accept {
		t.Fatalf("old policy was replaced: %#v", result)
	}
	_ = newPeer
}

func localNodeIDForTest() identity.NodeID { return identity.NodeID(testID(2)) }

func TestControllerApplyRouteFailurePreservesAcceptedSnapshot(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
	routes := &failOnceRouteManager{inner: platform.NewMemoryRouteManager()}
	if err := applyControllerConfiguration(context.Background(), controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60)), local,
		table, routes, nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	routes.fail = true
	if err := applyControllerConfiguration(context.Background(), nextControllerConfiguration(local, newPeer), local,
		table, routes, nil, policies, nil, nil, nil, state); err == nil {
		t.Fatal("injected route failure was accepted")
	}
	assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
	if got := routes.inner.Routes(); len(got) != 1 || got[0].Prefix != netip.MustParsePrefix("100.96.0.3/32") {
		t.Fatalf("OS routes after rollback = %v", got)
	}
}

func TestControllerApplyPrevalidationRejectsUnsafeSnapshotsWithoutMutation(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	for name, mutate := range map[string]func(*lanewayv1.NodeConfiguration){
		"non-policy capability": func(c *lanewayv1.NodeConfiguration) { c.EnabledCapabilities = uint64(protocol.CapabilityRelayV1) },
		"unknown route kind": func(c *lanewayv1.NodeConfiguration) {
			c.Routes.Routes[1].Kind = lanewayv1.RouteKind(99)
		},
		"unroutable prefix": func(c *lanewayv1.NodeConfiguration) {
			c.Routes.Routes[1].Destination = &lanewayv1.IpPrefix{Address: []byte{127, 0, 0, 0}, PrefixLength: 8}
		},
		"missing role capability": func(c *lanewayv1.NodeConfiguration) {
			c.Routes.Routes = append(c.Routes.Routes, subnetRoute(local.NodeID, "192.168.30.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
		},
		"ambiguous peer names": func(c *lanewayv1.NodeConfiguration) {
			c.Peers = []*lanewayv1.NodePeer{
				{NodeId: oldPeer[:], Name: "gateway", OverlayAddresses: [][]byte{{100, 96, 0, 3}}},
				{NodeId: newPeer[:], Name: "gateway", OverlayAddresses: [][]byte{{100, 96, 0, 4}}},
			}
		},
		"missing route ID": func(c *lanewayv1.NodeConfiguration) { c.Routes.Routes[1].RouteId = nil },
		"duplicate route ID": func(c *lanewayv1.NodeConfiguration) {
			c.Routes.Routes[1].RouteId = append([]byte(nil), c.Routes.Routes[0].RouteId...)
		},
		"absent route peer": func(c *lanewayv1.NodeConfiguration) {
			absent := identity.NodeID(testID(9))
			c.Routes.Routes[1].ViaNodeId = absent[:]
		},
		"overlay ownership mismatch": func(c *lanewayv1.NodeConfiguration) {
			c.Routes.Routes[1].ViaNodeId = local.NodeID[:]
		},
		"duplicate overlay ownership": func(c *lanewayv1.NodeConfiguration) {
			c.Peers[1].OverlayAddresses = append(c.Peers[1].OverlayAddresses, []byte{100, 96, 0, 2})
		},
	} {
		t.Run(name, func(t *testing.T) {
			table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
			routes := platform.NewMemoryRouteManager()
			if err := applyControllerConfiguration(context.Background(), controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60)), local,
				table, routes, nil, policies, nil, nil, nil, state); err != nil {
				t.Fatal(err)
			}
			next := nextControllerConfiguration(local, newPeer)
			mutate(next)
			if err := applyControllerConfiguration(context.Background(), next, local, table, routes, nil, policies, nil, nil, nil, state); err == nil {
				t.Fatal("unsafe snapshot was accepted")
			}
			assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
		})
	}
}

func TestControllerApplyPrevalidationAcceptsNATAndRoutedExitDefaults(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	for _, mode := range []lanewayv1.RouteAdvertisementMode{
		lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT,
		lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_ROUTED,
	} {
		configuration := nextControllerConfiguration(local, identity.NodeID(testID(3)))
		configuration.EnabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
		route := exitRoute(local.NodeID)
		route.Mode = mode
		configuration.Routes.Routes = append(configuration.Routes.Routes, route)
		if _, err := prepareControllerConfiguration(configuration, local, nil, nil, nil); err != nil {
			t.Fatalf("valid exit mode %s rejected: %v", mode, err)
		}
	}
}

func TestControllerApplySubnetFailurePreservesAcceptedSnapshot(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	old := controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60))
	old.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	old.Routes.Routes = append(old.Routes.Routes, subnetRoute(local.NodeID, "192.168.10.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
	next := nextControllerConfiguration(local, newPeer)
	next.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	next.Routes.Routes = append(next.Routes.Routes, subnetRoute(local.NodeID, "192.168.20.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
	forwarding := &failOnceForwardingManager{inner: subnet.NewMemoryForwardingManager()}
	subnets := &daemonSubnetManager{forwarding: forwarding}
	table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
	if err := applyControllerConfiguration(context.Background(), old, local, table, platform.NewMemoryRouteManager(), nil, policies, subnets, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	forwarding.fail = true
	if err := applyControllerConfiguration(context.Background(), next, local, table, platform.NewMemoryRouteManager(), nil, policies, subnets, nil, nil, state); err == nil {
		t.Fatal("injected subnet failure was accepted")
	}
	assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
	plan, active := forwarding.inner.Snapshot()
	if !active || len(plan.Routes) != 1 || plan.Routes[0].Prefix != netip.MustParsePrefix("192.168.10.0/24") {
		t.Fatalf("subnet plan after rollback = %#v, %t", plan, active)
	}
}

func TestControllerApplyExitFailurePreservesAcceptedSnapshot(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
	gateway := &failOnceGatewayManager{inner: exitnode.NewMemoryGatewayManager()}
	exits := &daemonExitManagers{gateway: gateway, local: local, routeTable: table}
	old := controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60))
	if err := applyControllerConfiguration(context.Background(), old, local, table, platform.NewMemoryRouteManager(), nil, policies, nil, nil, exits, state); err != nil {
		t.Fatal(err)
	}
	next := nextControllerConfiguration(local, newPeer)
	next.EnabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
	next.Routes.Routes = append(next.Routes.Routes, exitRoute(local.NodeID))
	gateway.fail = true
	if err := applyControllerConfiguration(context.Background(), next, local, table, platform.NewMemoryRouteManager(), nil, policies, nil, nil, exits, state); err == nil {
		t.Fatal("injected exit failure was accepted")
	}
	assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
	if _, active := gateway.inner.Snapshot(); active {
		t.Fatal("failed exit snapshot remained active")
	}
}

func TestControllerApplyPublisherFailureRestoresPriorAuthorization(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: localNodeIDForTest()}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	var relay, direct []netip.Prefix
	failDirect := false
	subnets := &daemonSubnetManager{
		forwarding:       subnet.NewMemoryForwardingManager(),
		setRelayPrefixes: func(prefixes []netip.Prefix) error { relay = append([]netip.Prefix(nil), prefixes...); return nil },
		setDirectPrefixes: func(prefixes []netip.Prefix) error {
			if failDirect {
				failDirect = false
				return errors.New("injected direct publisher failure")
			}
			direct = append([]netip.Prefix(nil), prefixes...)
			return nil
		},
	}
	old := controllerTestConfiguration(local, oldPeer, uint64(time.Now().Unix()+60))
	old.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	old.Routes.Routes = append(old.Routes.Routes, subnetRoute(local.NodeID, "192.168.10.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
	next := nextControllerConfiguration(local, newPeer)
	next.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	next.Routes.Routes = append(next.Routes.Routes, subnetRoute(local.NodeID, "192.168.20.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT))
	table, policies, state := routing.NewTable(nil), new(policy.Table), new(controllerApplyState)
	routes := platform.NewMemoryRouteManager()
	if err := applyControllerConfiguration(context.Background(), old, local, table, routes, nil, policies, subnets, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	failDirect = true
	if err := applyControllerConfiguration(context.Background(), next, local, table, routes, nil, policies, subnets, nil, nil, state); err == nil {
		t.Fatal("injected publisher failure was accepted")
	}
	assertOldControllerSnapshot(t, state, table, policies, oldPeer, newPeer)
	want := []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}
	if !slices.Equal(relay, want) || !slices.Equal(direct, want) {
		t.Fatalf("authorization after rollback relay=%v direct=%v want=%v", relay, direct, want)
	}
}
