package relay_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nodeservice"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/relay"
	"laneway.dev/laneway/internal/relayservice"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/tcpfallback"
	"laneway.dev/laneway/internal/transport"
)

type failFirstRelayDialer struct {
	failures int32
	calls    atomic.Int32
}

func (d *failFirstRelayDialer) DialRelay(ctx context.Context, address string, tlsConfig *tls.Config, config *transport.Config) (*transport.Conn, error) {
	if d.calls.Add(1) <= d.failures {
		return nil, errors.New("injected initial UDP failure")
	}
	return transport.Dial(ctx, address, tlsConfig, config)
}

func TestNodesFallBackToTCPWhenQUICUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(11))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(12))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(13))}
	addressA, addressB := netip.MustParseAddr("100.97.0.1"), netip.MustParseAddr("100.97.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	tcpConfig := &tcpfallback.Config{
		HandshakeTimeout: time.Second, WriteTimeout: time.Second,
		IdleTimeout: 3 * time.Second, KeepAlivePeriod: time.Second,
		QueueDepth: 16, MaxPacketPayload: 1200 + protocol.PacketHeaderSize,
	}
	listener, err := tcpfallback.Listen("127.0.0.1:0", serverTLS, tcpConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		Registry: relay.Config{
			MaxSessions: 8, MaxHandlesPerSession: 8, OutboundQueueCapacity: 8,
			MaxPacketPayload: 1200, DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest,
		},
		TCPFallback: tcpConfig, MaxPacketPayload: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTCP(ctx, listener) }()

	tunA, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "tcpA", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressA, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunA.Close()
	tunB, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "tcpB", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressB, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunB.Close()

	// UDP has no listener at this address. QUIC fails quickly, then each node
	// establishes the configured TCP fallback without starting a second packet
	// pump.
	unavailableQUIC := listener.Addr().String()
	serviceA := newFallbackNode(t, nodeA, clientATLS, unavailableQUIC, listener.Addr().String(), tunA, nodeB.NodeID, addressB, tcpConfig)
	serviceB := newFallbackNode(t, nodeB, clientBTLS, unavailableQUIC, listener.Addr().String(), tunB, nodeA.NodeID, addressA, tcpConfig)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	eventually(t, ctx, func() bool { return server.Registry().Metrics().Bindings == 2 })
	if serviceA.Metrics().TCPConnections != 1 || serviceB.Metrics().TCPConnections != 1 ||
		serviceA.Metrics().QUICFailures == 0 || serviceB.Metrics().QUICFailures == 0 {
		t.Fatalf("fallback metrics A=%+v B=%+v", serviceA.Metrics(), serviceB.Metrics())
	}

	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("tcp fallback integration"))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		payload, receiveErr := tunB.Receive(ctx)
		if receiveErr == nil {
			received <- payload
		}
	}()
	for {
		if err := tunA.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-received:
			if string(got) != string(packet) {
				t.Fatalf("received packet differs: %x", got)
			}
			cancel()
			waitDone(t, serverDone)
			waitDone(t, nodeDone)
			waitDone(t, nodeDone)
			return
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("timed out waiting for TCP fallback packet")
		}
	}
}

func TestQUICAndTCPShareRelayRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(21))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(22))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(23))}
	addressA, addressB := netip.MustParseAddr("100.98.0.1"), netip.MustParseAddr("100.98.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	tcpConfig := &tcpfallback.Config{
		HandshakeTimeout: time.Second, WriteTimeout: time.Second,
		IdleTimeout: 3 * time.Second, KeepAlivePeriod: time.Second,
		QueueDepth: 16, MaxPacketPayload: 1200 + protocol.PacketHeaderSize,
	}
	quicListener, err := transport.Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer quicListener.Close()
	tcpListener, err := tcpfallback.Listen("127.0.0.1:0", serverTLS, tcpConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	server, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		Registry: relay.Config{
			MaxSessions: 8, MaxHandlesPerSession: 8, OutboundQueueCapacity: 8,
			MaxPacketPayload: 1200, DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest,
		},
		TCPFallback: tcpConfig, MaxPacketPayload: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTransports(ctx, quicListener, tcpListener) }()

	tunA, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "mixedA", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressA, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunA.Close()
	tunB, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "mixedB", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressB, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunB.Close()
	serviceA := newNode(t, nodeA, clientATLS, quicListener.Addr().String(), tunA, nodeB.NodeID, addressB)
	serviceB := newFallbackNode(t, nodeB, clientBTLS, tcpListener.Addr().String(), tcpListener.Addr().String(), tunB, nodeA.NodeID, addressA, tcpConfig)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	eventually(t, ctx, func() bool { return server.Registry().Metrics().Bindings == 2 })
	if serviceA.Metrics().TCPConnections != 0 || serviceB.Metrics().TCPConnections != 1 {
		t.Fatalf("carrier selection A=%+v B=%+v", serviceA.Metrics(), serviceB.Metrics())
	}
	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("cross-carrier"))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		payload, receiveErr := tunB.Receive(ctx)
		if receiveErr == nil {
			received <- payload
		}
	}()
	for {
		if err := tunA.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-received:
			if string(got) != string(packet) {
				t.Fatalf("received packet differs: %x", got)
			}
			cancel()
			waitDone(t, serverDone)
			waitDone(t, nodeDone)
			waitDone(t, nodeDone)
			return
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("timed out waiting for cross-carrier packet")
		}
	}
}

func TestHealthyTCPFallbackPromotesBackToQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(31))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(32))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(33))}
	addressA, addressB := netip.MustParseAddr("100.99.0.1"), netip.MustParseAddr("100.99.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	tcpConfig := &tcpfallback.Config{HandshakeTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: 3 * time.Second, KeepAlivePeriod: time.Second, QueueDepth: 16, MaxPacketPayload: 1200 + protocol.PacketHeaderSize}
	quicListener, err := transport.Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer quicListener.Close()
	tcpListener, err := tcpfallback.Listen("127.0.0.1:0", serverTLS, tcpConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	server, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		Registry:    relay.Config{MaxSessions: 8, MaxHandlesPerSession: 8, OutboundQueueCapacity: 8, MaxPacketPayload: 1200, DuplicatePolicy: relay.ReplaceDuplicate, QueuePolicy: relay.DropNewest},
		TCPFallback: tcpConfig, MaxPacketPayload: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTransports(ctx, quicListener, tcpListener) }()
	tunA, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "recoverA", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressA, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	tunB, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "recoverB", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressB, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunA.Close()
	defer tunB.Close()
	dialer := &failFirstRelayDialer{failures: 1}
	serviceA := newRecoveryNode(t, nodeA, clientATLS, quicListener.Addr().String(), tcpListener.Addr().String(), tunA, nodeB.NodeID, addressB, tcpConfig, dialer)
	serviceB := newNode(t, nodeB, clientBTLS, quicListener.Addr().String(), tunB, nodeA.NodeID, addressA)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	eventually(t, ctx, func() bool { return serviceA.Metrics().TCPConnections == 1 })
	eventually(t, ctx, func() bool {
		return dialer.calls.Load() >= 2 && serviceA.Metrics().Connections >= 2 && serviceA.SelectedCarrier() == "relay-quic" && server.Registry().Metrics().Bindings == 2
	})
	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("quic recovered"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tunA.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	got, err := tunB.Receive(ctx)
	if err != nil || string(got) != string(packet) {
		t.Fatalf("post-promotion packet = %x, %v", got, err)
	}
	cancel()
	waitDone(t, serverDone)
	waitDone(t, nodeDone)
	waitDone(t, nodeDone)
}

func newFallbackNode(t *testing.T, id identity.NodeIdentity, tlsConfig *tls.Config, quicAddress, tcpAddress string,
	tun platform.TUNDevice, peer identity.NodeID, peerAddress netip.Addr, tcpConfig *tcpfallback.Config,
) *nodeservice.Service {
	t.Helper()
	snapshot, err := routing.NewSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: id, BootID: randomID(t), RelayAddress: quicAddress, TLSConfig: tlsConfig,
		Transport:          &transport.Config{HandshakeIdleTimeout: 100 * time.Millisecond, MaxIdleTimeout: time.Second, KeepAlivePeriod: 100 * time.Millisecond},
		TCPFallbackAddress: tcpAddress, TCPFallback: tcpConfig,
		Routes: routing.NewTable(snapshot), Packets: tunAdapter{tun},
		MaxControlPayload: protocol.DefaultMaxControlFrame, MaxRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newRecoveryNode(t *testing.T, id identity.NodeIdentity, tlsConfig *tls.Config, quicAddress, tcpAddress string,
	tun platform.TUNDevice, peer identity.NodeID, peerAddress netip.Addr, tcpConfig *tcpfallback.Config, dialer nodeservice.RelayDialer,
) *nodeservice.Service {
	t.Helper()
	snapshot, err := routing.NewSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: id, BootID: randomID(t), RelayAddress: quicAddress, TLSConfig: tlsConfig,
		Transport:          &transport.Config{HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 3 * time.Second, KeepAlivePeriod: 100 * time.Millisecond},
		TCPFallbackAddress: tcpAddress, TCPFallback: tcpConfig, RelayDialer: dialer, QUICRecoveryInterval: 50 * time.Millisecond,
		Routes: routing.NewTable(snapshot), Packets: tunAdapter{tun}, MaxControlPayload: protocol.DefaultMaxControlFrame, MaxRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
