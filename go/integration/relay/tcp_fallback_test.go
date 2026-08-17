package relay_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/platform"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/relay"
	"github.com/Doout/laneway/go/internal/relayservice"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
	"github.com/Doout/laneway/go/internal/wireguard"
)

type capturedWireGuardRelay struct {
	ready chan *wireguard.RelayMux
}

func newCapturedWireGuardRelay() *capturedWireGuardRelay {
	return &capturedWireGuardRelay{ready: make(chan *wireguard.RelayMux, 1)}
}

func (h *capturedWireGuardRelay) RunRelay(ctx context.Context, mux *wireguard.RelayMux, kind pathmanager.PathKind, _ string) error {
	if kind != pathmanager.PathTCPFallback {
		return errors.New("unexpected WireGuard carrier")
	}
	for len(mux.Peers()) == 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-mux.Changes():
		}
	}
	select {
	case h.ready <- mux:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return ctx.Err()
}

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

func TestWireGuardCiphertextCrossesTCPFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(61))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(62))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(63))}
	addressA, addressB := netip.MustParseAddr("100.101.0.1"), netip.MustParseAddr("100.101.0.2")
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

	handlerA, handlerB := newCapturedWireGuardRelay(), newCapturedWireGuardRelay()
	unavailableQUIC := listener.Addr().String()
	newNode := func(local identity.NodeIdentity, tlsConfig *tls.Config, peer identity.NodeID, handler *capturedWireGuardRelay) *nodeservice.Service {
		routes := routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(addressB, 32), NextHop: peer}}))
		if local == nodeB {
			routes = routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(addressA, 32), NextHop: peer}}))
		}
		service, serviceErr := nodeservice.New(nodeservice.Config{
			Identity: local, BootID: randomID(t), RelayAddress: unavailableQUIC, TLSConfig: tlsConfig,
			Transport:          &transport.Config{HandshakeIdleTimeout: 100 * time.Millisecond, MaxIdleTimeout: 2 * time.Second, KeepAlivePeriod: 500 * time.Millisecond},
			TCPFallbackAddress: listener.Addr().String(), TCPFallback: tcpConfig, Routes: routes,
			WireGuardRelay: handler, MaxControlPayload: protocol.DefaultMaxControlFrame, MaxRoutes: 8,
		})
		if serviceErr != nil {
			t.Fatal(serviceErr)
		}
		return service
	}
	serviceA := newNode(nodeA, clientATLS, nodeB.NodeID, handlerA)
	serviceB := newNode(nodeB, clientBTLS, nodeA.NodeID, handlerB)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	var muxA, muxB *wireguard.RelayMux
	select {
	case muxA = <-handlerA.ready:
	case <-ctx.Done():
		t.Fatal("timed out waiting for node A WireGuard TCP binding")
	}
	select {
	case muxB = <-handlerB.ready:
	case <-ctx.Done():
		t.Fatal("timed out waiting for node B WireGuard TCP binding")
	}
	// A structurally valid WireGuard handshake initiation remains opaque to the
	// relay. Its exact bytes must arrive bound to the authenticated sender.
	ciphertext := make([]byte, 148)
	binary.LittleEndian.PutUint32(ciphertext, 1)
	if err := muxA.Send(ctx, nodeB.NodeID, ciphertext); err != nil {
		t.Fatal(err)
	}
	received, err := muxB.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer received.Release()
	if received.Peer != nodeA.NodeID || string(received.Packet) != string(ciphertext) {
		t.Fatalf("WireGuard TCP packet peer=%s size=%d", received.Peer, len(received.Packet))
	}
	cancel()
	waitDone(t, serverDone)
	waitDone(t, nodeDone)
	waitDone(t, nodeDone)
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
	var got []byte
	for {
		if err := tunA.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		receiveCtx, receiveCancel := context.WithTimeout(ctx, 200*time.Millisecond)
		got, err = tunB.Receive(receiveCtx)
		receiveCancel()
		if err == nil && string(got) == string(packet) {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("post-promotion packet = %x, %v", got, err)
		}
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
