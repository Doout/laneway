package nodeapp

import (
	"context"
	"net/netip"
	"testing"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/wireguard"
)

func TestWireGuardExitSelectionCommitsPartitionBeforeNativeDefault(t *testing.T) {
	local, selected, configuration, localKey := wireGuardExitFixture(t)
	exits := wireGuardExitManagers(t, local, configuration)
	prepared, err := prepareWireGuardSnapshot(configuration, local, localKey, identity.NodeID{})
	if err != nil {
		t.Fatal(err)
	}
	wg := &fakeNodeWireGuard{public: localKey}
	state := &controllerApplyState{wireGuard: wg, accepted: &preparedControllerConfiguration{
		configuration: configuration,
		wireGuard:     &wireguard.SecureSnapshot{Peers: prepared.peers, Firewall: prepared.firewall},
	}}
	if err := setWireGuardExitSelection(context.Background(), true, selected, local, exits, state); err != nil {
		t.Fatal(err)
	}
	if exits.SelectedNode() != selected || len(wg.snapshots) != 1 {
		t.Fatalf("selected=%s snapshots=%d", exits.SelectedNode(), len(wg.snapshots))
	}
	prefixes := wg.snapshots[0].Firewall.PeerPrefixes[selected]
	if !prefixSetContainsAddress(prefixes, netip.MustParseAddr("8.8.8.8")) ||
		prefixSetContainsAddress(prefixes, netip.MustParseAddr("100.96.0.1")) {
		t.Fatalf("selected exit ownership=%v", prefixes)
	}
	if err := setWireGuardExitSelection(context.Background(), false, identity.NodeID{}, local, exits, state); err != nil {
		t.Fatal(err)
	}
	if !exits.SelectedNode().IsZero() || len(wg.snapshots) != 2 ||
		prefixSetContainsAddress(wg.snapshots[1].Firewall.PeerPrefixes[selected], netip.MustParseAddr("8.8.8.8")) {
		t.Fatalf("disable did not remove exit ownership: selected=%s snapshots=%d", exits.SelectedNode(), len(wg.snapshots))
	}
}

func TestWireGuardExitSelectionRestoresNativeDefaultWhenSnapshotFails(t *testing.T) {
	local, selected, configuration, localKey := wireGuardExitFixture(t)
	exits := wireGuardExitManagers(t, local, configuration)
	prepared, err := prepareWireGuardSnapshot(configuration, local, localKey, selected)
	if err != nil {
		t.Fatal(err)
	}
	wg := &fakeNodeWireGuard{public: localKey, failSnapshot: true}
	state := &controllerApplyState{wireGuard: wg, accepted: &preparedControllerConfiguration{
		configuration: configuration,
		wireGuard:     &wireguard.SecureSnapshot{Peers: prepared.peers, Firewall: prepared.firewall},
	}}
	if err := exits.SetSelection(context.Background(), true, selected); err != nil {
		t.Fatal(err)
	}
	if err := setWireGuardExitSelection(context.Background(), false, identity.NodeID{}, local, exits, state); err == nil {
		t.Fatal("injected WireGuard failure was accepted")
	}
	if exits.SelectedNode() != selected {
		t.Fatalf("failed snapshot did not restore selected exit: %s", exits.SelectedNode())
	}
	if state.accepted.wireGuard.Firewall.PeerPrefixes[selected] == nil {
		t.Fatal("failed snapshot replaced the accepted WireGuard state")
	}
}

func TestWireGuardExitSelectionStaysFailClosedWhenSnapshotRollbackFails(t *testing.T) {
	local, selected, configuration, localKey := wireGuardExitFixture(t)
	exits := wireGuardExitManagers(t, local, configuration)
	prepared, err := prepareWireGuardSnapshot(configuration, local, localKey, selected)
	if err != nil {
		t.Fatal(err)
	}
	wg := &fakeNodeWireGuard{public: localKey, failSnapshots: 2}
	state := &controllerApplyState{wireGuard: wg, accepted: &preparedControllerConfiguration{
		configuration: configuration,
		wireGuard:     &wireguard.SecureSnapshot{Peers: prepared.peers, Firewall: prepared.firewall},
	}}
	if err := exits.SetSelection(context.Background(), true, selected); err != nil {
		t.Fatal(err)
	}
	if err := setWireGuardExitSelection(context.Background(), false, identity.NodeID{}, local, exits, state); err == nil {
		t.Fatal("snapshot and rollback failures were accepted")
	}
	if !exits.SelectedNode().IsZero() {
		t.Fatalf("unsafe native default was restored after WireGuard rollback failure: %s", exits.SelectedNode())
	}
}

func wireGuardExitFixture(t *testing.T) (identity.NodeIdentity, identity.NodeID, *lanewayv1.NodeConfiguration, wireguard.PublicKey) {
	t.Helper()
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	localKey, exitKey := snapshotKey(t), snapshotKey(t)
	configuration := &lanewayv1.NodeConfiguration{ConfigurationEpoch: 7,
		Peers: []*lanewayv1.NodePeer{
			{NodeId: local.NodeID[:], OverlayAddresses: [][]byte{{100, 96, 0, 1}}, WireguardPublicKey: localKey.Bytes()},
			{NodeId: selected[:], OverlayAddresses: [][]byte{{100, 96, 0, 2}}, WireguardPublicKey: exitKey.Bytes()},
		},
		Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
			{Destination: snapshotPrefix("100.96.0.1/32"), ViaNodeId: local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{Destination: snapshotPrefix("100.96.0.2/32"), ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{Destination: snapshotPrefix("0.0.0.0/0"), ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT},
		}},
		Policy: &lanewayv1.PolicySnapshot{DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY},
	}
	return local, selected, configuration, localKey
}

func wireGuardExitManagers(t *testing.T, local identity.NodeIdentity, configuration *lanewayv1.NodeConfiguration) *daemonExitManagers {
	t.Helper()
	client, err := exitnode.NewClientManager(exitnode.NewMemoryRouteManager(), exitnode.NewMemoryDNSManager(), 0)
	if err != nil {
		t.Fatal(err)
	}
	exits := &daemonExitManagers{
		client: client, local: local, failureMode: exitnode.FailureModeClosed, failureModeConfigured: true,
		bypass: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		dns:    []netip.Addr{netip.MustParseAddr("1.1.1.1")}, routeTable: routing.NewTable(nil),
		pathHealthy: func(identity.NodeID) bool { return true },
	}
	if err := exits.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	return exits
}
