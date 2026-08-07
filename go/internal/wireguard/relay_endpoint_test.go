package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

func openRelayKernelSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func newTestRelayEndpoint(t *testing.T, kernel *net.UDPConn, peers ...byte) (*RelayEndpoint, []identityNode) {
	t.Helper()
	endpoint, err := NewRelayEndpoint(RelayEndpointConfig{KernelEndpoint: kernel.LocalAddr().(*net.UDPAddr).AddrPort(), MaxPeers: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	ids := make([]identityNode, 0, len(peers))
	nodes := make([]identity.NodeID, 0, len(peers))
	for _, value := range peers {
		node := relayNode(value)
		ids = append(ids, identityNode{node})
		nodes = append(nodes, node)
	}
	if err := endpoint.ApplyPeers(context.Background(), nodes); err != nil {
		t.Fatal(err)
	}
	return endpoint, ids
}

// identityNode keeps test return values explicit without allowing accidental
// mutation of the map keys used by RelayEndpoint.
type identityNode struct{ identity.NodeID }

func startTestRelaySession(t *testing.T, endpoint *RelayEndpoint, peer identity.NodeID) (*fakeRelayCarrier, context.CancelFunc, <-chan error) {
	t.Helper()
	carrier := newFakeRelayCarrier()
	mux, err := NewRelayMux(carrier, protocol.CapabilityE2EPacketV1)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SetBinding(RelayBinding{Peer: peer, Handle: 41, MaxPacketPayload: 1280}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- endpoint.RunRelay(ctx, mux) }()
	return carrier, cancel, done
}

func stopTestRelaySession(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("relay session error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay session did not stop")
	}
}

func TestRelayEndpointCarriesOpaquePacketsInBothDirections(t *testing.T) {
	kernel := openRelayKernelSocket(t)
	endpoint, peers := newTestRelayEndpoint(t, kernel, 21)
	peer := peers[0].NodeID
	carrier, cancel, done := startTestRelaySession(t, endpoint, peer)
	defer stopTestRelaySession(t, cancel, done)

	packet := wireGuardInitiation()
	peerEndpoint := endpoint.Endpoints()[peer]
	if _, err := kernel.WriteToUDPAddrPort(packet, peerEndpoint); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-carrier.sent:
		header, payload, err := protocol.DecodeFrame(frame)
		if err != nil || header.RouteHandle != 41 || header.Flags != protocol.PacketFlagE2EEncrypted || !bytes.Equal(payload, packet) {
			t.Fatalf("outbound header=%#v payload_equal=%t error=%v", header, bytes.Equal(payload, packet), err)
		}
		carrier.received <- frame
	case <-time.After(2 * time.Second):
		t.Fatal("kernel packet was not relayed")
	}

	buffer := make([]byte, 256)
	if err := kernel.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, source, err := kernel.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if source != peerEndpoint || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("inbound source=%s payload_equal=%t", source, bytes.Equal(buffer[:n], packet))
	}
	metrics := waitRelayEndpointMetrics(t, endpoint, func(metrics RelayEndpointMetrics) bool {
		return metrics.PacketsSent == 1 && metrics.PacketsReceived == 1
	})
	if metrics.PacketsSent != 1 || metrics.PacketsReceived != 1 || metrics.PacketsDropped != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func waitRelayEndpointMetrics(t *testing.T, endpoint *RelayEndpoint, ready func(RelayEndpointMetrics) bool) RelayEndpointMetrics {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		metrics := endpoint.Metrics()
		if ready(metrics) {
			return metrics
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for relay endpoint metrics: %+v", metrics)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRelayEndpointRejectsNonKernelSources(t *testing.T) {
	kernel := openRelayKernelSocket(t)
	endpoint, peers := newTestRelayEndpoint(t, kernel, 22)
	peer := peers[0].NodeID
	carrier, cancel, done := startTestRelaySession(t, endpoint, peer)
	defer stopTestRelaySession(t, cancel, done)

	attacker := openRelayKernelSocket(t)
	if _, err := attacker.WriteToUDPAddrPort(wireGuardInitiation(), endpoint.Endpoints()[peer]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-carrier.sent:
		t.Fatal("packet from a non-kernel source was relayed")
	case <-time.After(300 * time.Millisecond):
	}
	metrics := endpoint.Metrics()
	if metrics.UnknownSources != 1 || metrics.PacketsDropped != 1 || metrics.PacketsSent != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestRelayEndpointPeerReplacementIsStableAndRevokesImmediately(t *testing.T) {
	kernel := openRelayKernelSocket(t)
	endpoint, peers := newTestRelayEndpoint(t, kernel, 23, 24)
	retained, removed := peers[0].NodeID, peers[1].NodeID
	before := endpoint.Endpoints()
	if err := endpoint.ApplyPeers(context.Background(), []identity.NodeID{retained}); err != nil {
		t.Fatal(err)
	}
	after := endpoint.Endpoints()
	if after[retained] != before[retained] {
		t.Fatalf("retained endpoint changed from %s to %s", before[retained], after[retained])
	}
	if _, present := after[removed]; present {
		t.Fatal("removed peer endpoint remains published")
	}
	replacement, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(before[removed]))
	if err != nil {
		t.Fatalf("removed peer socket was not closed: %v", err)
	}
	_ = replacement.Close()
}

func TestRelayEndpointAddsPeerDuringActiveSession(t *testing.T) {
	kernel := openRelayKernelSocket(t)
	endpoint, peers := newTestRelayEndpoint(t, kernel, 26)
	first, added := peers[0].NodeID, relayNode(27)
	carrier := newFakeRelayCarrier()
	mux, err := NewRelayMux(carrier, protocol.CapabilityE2EPacketV1)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.ReplaceBindings([]RelayBinding{
		{Peer: first, Handle: 51, MaxPacketPayload: 1280},
		{Peer: added, Handle: 52, MaxPacketPayload: 1280},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- endpoint.RunRelay(ctx, mux) }()
	defer stopTestRelaySession(t, cancel, done)
	if err := endpoint.ApplyPeers(context.Background(), []identity.NodeID{first, added}); err != nil {
		t.Fatal(err)
	}
	if _, err := kernel.WriteToUDPAddrPort(wireGuardInitiation(), endpoint.Endpoints()[added]); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-carrier.sent:
		header, _, err := protocol.DecodeFrame(frame)
		if err != nil || header.RouteHandle != 52 {
			t.Fatalf("added peer header=%#v error=%v", header, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new peer worker was not activated")
	}
}

func TestRelayEndpointConfigurationAndPeerSetFailClosed(t *testing.T) {
	if _, err := NewRelayEndpoint(RelayEndpointConfig{KernelEndpoint: netip.MustParseAddrPort("192.0.2.1:51820")}); !errors.Is(err, ErrInvalidRelayEndpoint) {
		t.Fatalf("non-loopback kernel endpoint error = %v", err)
	}
	kernel := openRelayKernelSocket(t)
	endpoint, _ := newTestRelayEndpoint(t, kernel)
	zero := identity.NodeID{}
	if err := endpoint.ApplyPeers(context.Background(), []identity.NodeID{zero}); !errors.Is(err, ErrInvalidRelayEndpoint) {
		t.Fatalf("zero peer error = %v", err)
	}
	peer := relayNode(25)
	if err := endpoint.ApplyPeers(context.Background(), []identity.NodeID{peer, peer}); !errors.Is(err, ErrInvalidRelayEndpoint) {
		t.Fatalf("duplicate peer error = %v", err)
	}
	if len(endpoint.Peers()) != 0 {
		t.Fatal("invalid peer set was published")
	}
}
