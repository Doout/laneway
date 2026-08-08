package nodeapp

import (
	"context"
	"errors"
	"testing"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/wireguard"
)

type fakeNodeWireGuard struct {
	public       wireguard.PublicKey
	events       []string
	snapshots    []wireguard.SecureSnapshot
	failSnapshot bool
	closed       bool
}

func (f *fakeNodeWireGuard) Name() string                   { return "lane0" }
func (f *fakeNodeWireGuard) MTU() int                       { return 1280 }
func (f *fakeNodeWireGuard) PublicKey() wireguard.PublicKey { return f.public }
func (f *fakeNodeWireGuard) RunRelay(ctx context.Context, _ *wireguard.RelayMux) error {
	<-ctx.Done()
	return ctx.Err()
}
func (f *fakeNodeWireGuard) RelayMetrics() wireguard.RelayEndpointMetrics {
	return wireguard.RelayEndpointMetrics{}
}
func (f *fakeNodeWireGuard) ApplyGuard(context.Context, wireguard.FirewallPlan) error {
	f.events = append(f.events, "guard")
	return nil
}
func (f *fakeNodeWireGuard) RestoreGuard(context.Context) error {
	f.events = append(f.events, "restore-guard")
	return nil
}
func (f *fakeNodeWireGuard) ApplySnapshot(_ context.Context, snapshot wireguard.SecureSnapshot) error {
	f.events = append(f.events, "snapshot")
	if f.failSnapshot {
		f.failSnapshot = false
		return errors.New("injected WireGuard snapshot failure")
	}
	f.snapshots = append(f.snapshots, snapshot)
	return nil
}
func (f *fakeNodeWireGuard) Close() error { f.closed = true; return nil }

func controllerWireGuardConfiguration(t *testing.T, local identity.NodeIdentity, peer identity.NodeID, epoch uint64) (*lanewayv1.NodeConfiguration, wireguard.PublicKey) {
	t.Helper()
	configuration := controllerTestConfiguration(local, peer, uint64(time.Now().Unix()+60))
	configuration.ConfigurationEpoch, configuration.Routes.ConfigurationEpoch, configuration.Policy.ConfigurationEpoch = epoch, epoch, epoch
	localKey, peerKey := snapshotKey(t), snapshotKey(t)
	configuration.Peers[0].WireguardPublicKey = localKey.Bytes()
	configuration.Peers[1].WireguardPublicKey = peerKey.Bytes()
	return configuration, localKey
}

func TestControllerApplyCommitsWireGuardUnderDenyGuard(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	configuration, localKey := controllerWireGuardConfiguration(t, local, peer, 2)
	wg := &fakeNodeWireGuard{public: localKey}
	state := &controllerApplyState{wireGuard: wg}
	if err := applyControllerConfiguration(context.Background(), configuration, local, routing.NewTable(nil),
		platform.NewMemoryRouteManager(), nil, new(policy.Table), nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	if got := stringsJoin(wg.events); got != "guard,snapshot" {
		t.Fatalf("events=%s", got)
	}
	if len(wg.snapshots) != 1 || len(wg.snapshots[0].Peers) != 1 || wg.snapshots[0].Peers[0].NodeID != peer {
		t.Fatalf("snapshots=%+v", wg.snapshots)
	}
}

func TestControllerApplyRestoresWireGuardSnapshotAfterNativeFailure(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	oldConfiguration, localKey := controllerWireGuardConfiguration(t, local, oldPeer, 2)
	wg := &fakeNodeWireGuard{public: localKey}
	state := &controllerApplyState{wireGuard: wg}
	routes := &failOnceRouteManager{inner: platform.NewMemoryRouteManager()}
	if err := applyControllerConfiguration(context.Background(), oldConfiguration, local, routing.NewTable(nil), routes,
		nil, new(policy.Table), nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	newConfiguration := controllerTestConfiguration(local, newPeer, uint64(time.Now().Unix()+60))
	newConfiguration.ConfigurationEpoch, newConfiguration.Routes.ConfigurationEpoch, newConfiguration.Policy.ConfigurationEpoch = 3, 3, 3
	newConfiguration.Peers[0].WireguardPublicKey = localKey.Bytes()
	newConfiguration.Peers[1].WireguardPublicKey = snapshotKey(t).Bytes()
	routes.fail = true
	if err := applyControllerConfiguration(context.Background(), newConfiguration, local, routing.NewTable(nil), routes,
		nil, new(policy.Table), nil, nil, nil, state); err == nil {
		t.Fatal("route failure accepted")
	}
	if got := stringsJoin(wg.events); got != "guard,snapshot,guard,snapshot" {
		t.Fatalf("events=%s", got)
	}
	if len(wg.snapshots) != 2 || wg.snapshots[1].Peers[0].NodeID != oldPeer {
		t.Fatalf("snapshots=%+v", wg.snapshots)
	}
}

func TestControllerApplyWireGuardFailureRollsBackNativeAndEncryptedState(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	oldPeer, newPeer := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	oldConfiguration, localKey := controllerWireGuardConfiguration(t, local, oldPeer, 2)
	wg := &fakeNodeWireGuard{public: localKey}
	state := &controllerApplyState{wireGuard: wg}
	routes, table, policies := platform.NewMemoryRouteManager(), routing.NewTable(nil), new(policy.Table)
	if err := applyControllerConfiguration(context.Background(), oldConfiguration, local, table, routes,
		nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	newConfiguration := controllerTestConfiguration(local, newPeer, uint64(time.Now().Unix()+60))
	newConfiguration.ConfigurationEpoch, newConfiguration.Routes.ConfigurationEpoch, newConfiguration.Policy.ConfigurationEpoch = 3, 3, 3
	newConfiguration.Peers[0].WireguardPublicKey = localKey.Bytes()
	newConfiguration.Peers[1].WireguardPublicKey = snapshotKey(t).Bytes()
	wg.failSnapshot = true
	if err := applyControllerConfiguration(context.Background(), newConfiguration, local, table, routes,
		nil, policies, nil, nil, nil, state); err == nil {
		t.Fatal("WireGuard failure accepted")
	}
	if got := routes.Routes(); len(got) != 1 || got[0].Prefix.String() != "100.96.0.3/32" {
		t.Fatalf("routes=%v", got)
	}
	if len(wg.snapshots) != 2 || wg.snapshots[1].Peers[0].NodeID != oldPeer {
		t.Fatalf("snapshots=%+v", wg.snapshots)
	}
}

func TestControllerExpiryClearsWireGuardPeersAndPolicy(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	configuration, localKey := controllerWireGuardConfiguration(t, local, peer, 2)
	wg := &fakeNodeWireGuard{public: localKey}
	state := &controllerApplyState{wireGuard: wg}
	table, routes, policies := routing.NewTable(nil), platform.NewMemoryRouteManager(), new(policy.Table)
	if err := applyControllerConfiguration(context.Background(), configuration, local, table, routes,
		nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	expired := failClosedNodeConfiguration(configuration, local)
	expired.ValidUntilUnixSeconds = uint64(time.Now().Add(-time.Second).Unix())
	if err := applyControllerConfiguration(context.Background(), expired, local, table, routes,
		nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	last := wg.snapshots[len(wg.snapshots)-1]
	if len(last.Peers) != 0 || len(last.Firewall.Rules) != 0 || last.Firewall.DefaultAction != wireguard.FirewallDeny {
		t.Fatalf("fail-closed snapshot=%+v", last)
	}
}

func stringsJoin(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += ","
		}
		result += value
	}
	return result
}
