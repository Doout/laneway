package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/protocol"
)

type fakeManagedDevice struct {
	name       string
	mtu        int
	listenPort uint16
	addresses  []netip.Prefix
	peers      []Peer
	fail       bool
	closed     bool
}

func (d *fakeManagedDevice) Name() string       { return d.name }
func (d *fakeManagedDevice) MTU() int           { return d.mtu }
func (d *fakeManagedDevice) ListenPort() uint16 { return d.listenPort }
func (d *fakeManagedDevice) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), d.addresses...)
}
func (d *fakeManagedDevice) Peers() []Peer { return clonePeers(d.peers) }
func (d *fakeManagedDevice) ApplyPeers(_ context.Context, peers []Peer) error {
	if d.fail {
		d.fail = false
		return errors.New("injected device failure")
	}
	d.peers = clonePeers(peers)
	return nil
}
func (d *fakeManagedDevice) Close() error { d.closed = true; return nil }

func testManager(t *testing.T) (*Manager, *fakeManagedDevice, PublicKey, *net.UDPConn) {
	t.Helper()
	kernel := openRelayKernelSocket(t)
	device := &fakeManagedDevice{name: "lane0", mtu: 1280, listenPort: kernel.LocalAddr().(*net.UDPAddr).AddrPort().Port()}
	endpoint, err := NewRelayEndpoint(RelayEndpointConfig{KernelEndpoint: kernel.LocalAddr().(*net.UDPAddr).AddrPort(), MaxPeers: 8})
	if err != nil {
		t.Fatal(err)
	}
	_, local := deviceKey(t)
	manager := newManager(device, endpoint, local)
	t.Cleanup(func() { _ = manager.Close() })
	return manager, device, local, kernel
}

func managedPeer(t *testing.T, node byte, address string) ManagedPeer {
	t.Helper()
	_, key := deviceKey(t)
	return ManagedPeer{NodeID: relayNode(node), PublicKey: key, AllowedIPs: []netip.Prefix{netip.MustParsePrefix(address)}}
}

func TestManagerCommitsDeviceAndStableRelayEndpoints(t *testing.T) {
	manager, device, _, _ := testManager(t)
	first := managedPeer(t, 31, "100.96.0.31/32")
	if err := manager.ApplyPeers(context.Background(), []ManagedPeer{first}); err != nil {
		t.Fatal(err)
	}
	firstEndpoint := device.peers[0].Endpoint
	second := managedPeer(t, 32, "100.96.0.32/32")
	if err := manager.ApplyPeers(context.Background(), []ManagedPeer{second, first}); err != nil {
		t.Fatal(err)
	}
	endpoints := manager.endpoint.Endpoints()
	if endpoints[first.NodeID] != firstEndpoint || len(device.peers) != 2 {
		t.Fatalf("stable endpoint=%s want=%s device peers=%+v", endpoints[first.NodeID], firstEndpoint, device.peers)
	}
	if got := manager.Peers(); len(got) != 2 || got[0].NodeID != first.NodeID || got[1].NodeID != second.NodeID {
		t.Fatalf("managed peers = %+v", got)
	}
}

func TestManagerKernelFailurePreservesExactOldSnapshot(t *testing.T) {
	manager, device, _, _ := testManager(t)
	first := managedPeer(t, 33, "100.96.0.33/32")
	if err := manager.ApplyPeers(context.Background(), []ManagedPeer{first}); err != nil {
		t.Fatal(err)
	}
	beforePeers, beforeEndpoints := manager.Peers(), manager.endpoint.Endpoints()
	device.fail = true
	second := managedPeer(t, 34, "100.96.0.34/32")
	if err := manager.ApplyPeers(context.Background(), []ManagedPeer{second}); err == nil {
		t.Fatal("injected device failure was ignored")
	}
	if !reflect.DeepEqual(manager.Peers(), beforePeers) || !reflect.DeepEqual(manager.endpoint.Endpoints(), beforeEndpoints) {
		t.Fatalf("failed transaction changed peers=%+v endpoints=%+v", manager.Peers(), manager.endpoint.Endpoints())
	}
	if len(device.peers) != 1 || device.peers[0].PublicKey != first.PublicKey {
		t.Fatalf("device snapshot changed after failure: %+v", device.peers)
	}
}

func TestManagerRejectsIdentityAndRouteConflictsBeforeMutation(t *testing.T) {
	manager, device, local, _ := testManager(t)
	peer := managedPeer(t, 35, "10.0.0.0/24")
	localPeer := peer
	localPeer.PublicKey = local
	for _, peers := range [][]ManagedPeer{
		{localPeer},
		{peer, peer},
		{peer, managedPeer(t, 36, "10.0.0.1/32")},
	} {
		if err := manager.ApplyPeers(context.Background(), peers); !errors.Is(err, ErrInvalidPeer) {
			t.Fatalf("invalid snapshot error = %v", err)
		}
		if len(device.peers) != 0 || len(manager.endpoint.Endpoints()) != 0 {
			t.Fatal("invalid snapshot mutated manager")
		}
	}
}

func TestManagerRuntimePrefersDirectAndKeepsRelayFallback(t *testing.T) {
	manager, _, _, kernel := testManager(t)
	peer := managedPeer(t, 37, "100.96.0.37/32")
	if err := manager.ApplyPeers(context.Background(), []ManagedPeer{peer}); err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- manager.Run(runCtx) }()
	carrier := newFakeRelayCarrier()
	relayMux, err := NewRelayMux(carrier, protocol.CapabilityE2EPacketV1)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayMux.SetBinding(RelayBinding{Peer: peer.NodeID, Handle: 81, MaxPacketPayload: 2048}); err != nil {
		t.Fatal(err)
	}
	relayCtx, cancelRelay := context.WithCancel(context.Background())
	relayDone := make(chan error, 1)
	go func() { relayDone <- manager.RunRelay(relayCtx, relayMux, pathmanager.PathRelayQUIC, "relay-test") }()
	deadline := time.Now().Add(2 * time.Second)
	for !manager.PathAvailable(peer.NodeID) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	packet := wireGuardInitiation()
	peerEndpoint := manager.endpoint.Endpoints()[peer.NodeID]
	if _, err := kernel.WriteToUDPAddrPort(packet, peerEndpoint); err != nil {
		t.Fatal(err)
	}
	select {
	case <-carrier.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("relay fallback did not receive kernel packet")
	}

	direct := newTestCarrierPath("direct-test", peer.NodeID)
	if err := manager.Attach(peer.NodeID, pathmanager.PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.WriteToUDPAddrPort(packet, peerEndpoint); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for direct.sentCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if direct.sentCount() != 1 {
		t.Fatalf("direct sends=%d", direct.sentCount())
	}
	select {
	case <-carrier.sent:
		t.Fatal("relay used while direct path was healthy")
	case <-time.After(100 * time.Millisecond):
	}
	direct.recv <- pathmanager.ReceivedPacket{Peer: peer.NodeID, Packet: packet}
	buffer := make([]byte, 256)
	if err := kernel.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, source, err := kernel.ReadFromUDPAddrPort(buffer)
	if err != nil || source != peerEndpoint || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("inbound source=%s equal=%t error=%v", source, bytes.Equal(buffer[:n], packet), err)
	}

	cancelRelay()
	if err := <-relayDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("relay error=%v", err)
	}
	cancelRun()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
}
