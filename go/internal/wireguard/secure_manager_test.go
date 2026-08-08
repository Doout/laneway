package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
)

type fakeSecureDevice struct {
	public     PublicKey
	peers      []ManagedPeer
	events     *[]string
	applyCount int
	failAt     int
	closed     bool
}

func (d *fakeSecureDevice) Name() string              { return "lane0" }
func (d *fakeSecureDevice) MTU() int                  { return 1280 }
func (d *fakeSecureDevice) ListenPort() uint16        { return 51820 }
func (d *fakeSecureDevice) PublicKey() PublicKey      { return d.public }
func (d *fakeSecureDevice) Addresses() []netip.Prefix { return nil }
func (d *fakeSecureDevice) Peers() []ManagedPeer      { return cloneManagedPeers(d.peers) }
func (d *fakeSecureDevice) ApplyPeers(_ context.Context, peers []ManagedPeer) error {
	d.applyCount++
	*d.events = append(*d.events, "peers")
	if d.applyCount == d.failAt {
		return errors.New("injected peer failure")
	}
	d.peers = cloneManagedPeers(peers)
	return nil
}
func (d *fakeSecureDevice) RelayMetrics() RelayEndpointMetrics { return RelayEndpointMetrics{} }
func (d *fakeSecureDevice) CarrierMetrics() CarrierMuxMetrics  { return CarrierMuxMetrics{} }
func (d *fakeSecureDevice) CarrierPathMetrics() pathmanager.Metrics {
	return pathmanager.Metrics{}
}
func (d *fakeSecureDevice) SelectedCarrier(identity.NodeID) string { return "wireguard-relay-quic" }
func (d *fakeSecureDevice) CarrierSummary() string                 { return "wireguard-relay-quic" }
func (d *fakeSecureDevice) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (d *fakeSecureDevice) PathAvailable(identity.NodeID) bool { return true }
func (d *fakeSecureDevice) RunRelay(ctx context.Context, _ *RelayMux, _ pathmanager.PathKind, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}
func (d *fakeSecureDevice) Attach(identity.NodeID, pathmanager.PathKind, pathmanager.PacketPath) error {
	return nil
}
func (d *fakeSecureDevice) Detach(identity.NodeID, string) bool { return false }
func (d *fakeSecureDevice) Close() error {
	d.closed = true
	*d.events = append(*d.events, "device-close")
	return nil
}

type fakeSecureFirewall struct {
	events     *[]string
	applyCount int
	failAt     int
	plans      []FirewallPlan
	closed     bool
}

func (f *fakeSecureFirewall) Apply(_ context.Context, plan FirewallPlan) error {
	f.applyCount++
	label := "policy"
	if len(plan.Rules) == 0 {
		label = "guard"
	}
	*f.events = append(*f.events, label)
	if f.applyCount == f.failAt {
		return errors.New("injected firewall failure")
	}
	f.plans = append(f.plans, cloneFirewallPlan(plan))
	return nil
}
func (f *fakeSecureFirewall) Restore(context.Context) error {
	*f.events = append(*f.events, "firewall-restore")
	return nil
}
func (f *fakeSecureFirewall) Close() error {
	f.closed = true
	*f.events = append(*f.events, "firewall-close")
	return nil
}

func secureSnapshot(t *testing.T, local identity.NodeID, peer ManagedPeer) SecureSnapshot {
	t.Helper()
	return SecureSnapshot{Peers: []ManagedPeer{peer}, Firewall: FirewallPlan{Epoch: 1, LocalNode: local,
		PeerPrefixes:  map[identity.NodeID][]netip.Prefix{peer.NodeID: append([]netip.Prefix(nil), peer.AllowedIPs...)},
		DefaultAction: FirewallDeny, Rules: []FirewallRule{{ID: firewallID(7), Action: FirewallAccept,
			SourceNodes: []identity.NodeID{peer.NodeID}, DestinationNodes: []identity.NodeID{local}, Protocol: 256}}}}
}

func TestSecureManagerCommitsGuardPeersThenPolicy(t *testing.T) {
	var events []string
	_, localKey := deviceKey(t)
	device := &fakeSecureDevice{public: localKey, events: &events}
	firewall := &fakeSecureFirewall{events: &events}
	manager, err := newSecureManager(device, firewall)
	if err != nil {
		t.Fatal(err)
	}
	peer := managedPeer(t, 40, "100.96.0.40/32")
	if err := manager.ApplySnapshot(context.Background(), secureSnapshot(t, firewallNode(1), peer)); err != nil {
		t.Fatal(err)
	}
	if got := stringsJoin(events); got != "guard,peers,policy" {
		t.Fatalf("events=%s", got)
	}
}

func TestSecureManagerExternalGuardRestoresCommittedPolicy(t *testing.T) {
	var events []string
	_, localKey := deviceKey(t)
	device := &fakeSecureDevice{public: localKey, events: &events}
	firewall := &fakeSecureFirewall{events: &events}
	manager, _ := newSecureManager(device, firewall)
	peer := managedPeer(t, 44, "100.96.0.44/32")
	snapshot := secureSnapshot(t, firewallNode(1), peer)
	if err := manager.ApplySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	events = nil
	if err := manager.ApplyGuard(context.Background(), snapshot.Firewall); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreGuard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := stringsJoin(events); got != "guard,policy" {
		t.Fatalf("events=%s", got)
	}
}

func TestSecureManagerRollsBackWithoutPublishingBroaderState(t *testing.T) {
	var events []string
	_, localKey := deviceKey(t)
	oldPeer := managedPeer(t, 41, "100.96.0.41/32")
	device := &fakeSecureDevice{public: localKey, peers: []ManagedPeer{oldPeer}, events: &events}
	firewall := &fakeSecureFirewall{events: &events, failAt: 2}
	manager, _ := newSecureManager(device, firewall)
	previous := secureSnapshot(t, firewallNode(1), oldPeer)
	manager.current = &previous
	newPeer := managedPeer(t, 42, "100.96.0.42/32")
	err := manager.ApplySnapshot(context.Background(), secureSnapshot(t, firewallNode(1), newPeer))
	if err == nil {
		t.Fatal("apply succeeded")
	}
	if len(device.peers) != 1 || device.peers[0].NodeID != oldPeer.NodeID {
		t.Fatalf("peers=%+v", device.peers)
	}
	if got := stringsJoin(events); got != "guard,peers,policy,peers,policy" {
		t.Fatalf("events=%s", got)
	}
}

func TestSecureManagerRejectsOwnershipMismatchBeforeMutation(t *testing.T) {
	var events []string
	_, localKey := deviceKey(t)
	device := &fakeSecureDevice{public: localKey, events: &events}
	firewall := &fakeSecureFirewall{events: &events}
	manager, _ := newSecureManager(device, firewall)
	peer := managedPeer(t, 43, "100.96.0.43/32")
	snapshot := secureSnapshot(t, firewallNode(1), peer)
	snapshot.Firewall.PeerPrefixes[peer.NodeID] = []netip.Prefix{netip.MustParsePrefix("100.96.0.44/32")}
	if err := manager.ApplySnapshot(context.Background(), snapshot); !errors.Is(err, ErrInvalidFirewall) {
		t.Fatalf("error=%v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%v", events)
	}
}

func TestSecureManagerCloseKeepsGuardUntilDeviceIsGone(t *testing.T) {
	var events []string
	_, localKey := deviceKey(t)
	device := &fakeSecureDevice{public: localKey, events: &events}
	firewall := &fakeSecureFirewall{events: &events}
	manager, _ := newSecureManager(device, firewall)
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if got := stringsJoin(events); got != "peers,device-close,firewall-close" {
		t.Fatalf("events=%s", got)
	}
	if !device.closed || !firewall.closed {
		t.Fatal("components not closed")
	}
}

func stringsJoin(values []string) string {
	result := ""
	for index, value := range values {
		if index != 0 {
			result += ","
		}
		result += value
	}
	return result
}
