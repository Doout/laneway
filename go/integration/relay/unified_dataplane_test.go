package relay_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/dataplane"
	"github.com/Doout/laneway/go/internal/directpath"
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
)

func TestUnifiedDataPlaneCarriesPacketsOverRelayQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(31))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(32))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(33))}
	addressA, addressB := netip.MustParseAddr("100.98.0.1"), netip.MustParseAddr("100.98.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	listener, err := transport.Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := unifiedRelay(t, nodeA, nodeB, addressA, addressB)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx, listener) }()
	tunA := unifiedTUN(t, "unifiedA", addressA)
	defer tunA.Close()
	tunB := unifiedTUN(t, "unifiedB", addressB)
	defer tunB.Close()
	serviceA, engineA := newUnifiedNode(t, nodeA, clientATLS, listener.Addr().String(), "", nil, tunA, nodeB.NodeID, addressA, addressB)
	serviceB, engineB := newUnifiedNode(t, nodeB, clientBTLS, listener.Addr().String(), "", nil, tunB, nodeA.NodeID, addressB, addressA)
	runUnifiedExchange(t, ctx, cancel, server, serviceA, serviceB, engineA, engineB, tunA, tunB, addressA, addressB, serverDone)
}

func TestUnifiedDataPlaneCarriesPacketsOverTCPFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(41))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(42))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(43))}
	addressA, addressB := netip.MustParseAddr("100.99.0.1"), netip.MustParseAddr("100.99.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	tcpConfig := &tcpfallback.Config{HandshakeTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: 3 * time.Second, KeepAlivePeriod: time.Second, QueueDepth: 16, MaxPacketPayload: 1200 + protocol.PacketHeaderSize}
	listener, err := tcpfallback.Listen("127.0.0.1:0", serverTLS, tcpConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := unifiedRelay(t, nodeA, nodeB, addressA, addressB)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ServeTCP(ctx, listener) }()
	tunA := unifiedTUN(t, "unifiedTCPA", addressA)
	defer tunA.Close()
	tunB := unifiedTUN(t, "unifiedTCPB", addressB)
	defer tunB.Close()
	unavailable := "127.0.0.1:1"
	serviceA, engineA := newUnifiedNode(t, nodeA, clientATLS, unavailable, listener.Addr().String(), tcpConfig, tunA, nodeB.NodeID, addressA, addressB)
	serviceB, engineB := newUnifiedNode(t, nodeB, clientBTLS, unavailable, listener.Addr().String(), tcpConfig, tunB, nodeA.NodeID, addressB, addressA)
	runUnifiedExchange(t, ctx, cancel, server, serviceA, serviceB, engineA, engineB, tunA, tunB, addressA, addressB, serverDone)
}

func TestUnifiedDataPlanePromotesRealDirectPathAndFallsBackToRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(51))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(52))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(53))}
	addressA, addressB := netip.MustParseAddr("100.100.0.1"), netip.MustParseAddr("100.100.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)
	listener, err := transport.Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := unifiedRelay(t, nodeA, nodeB, addressA, addressB)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx, listener) }()
	tunA, tunB := unifiedTUN(t, "directA", addressA), unifiedTUN(t, "directB", addressB)
	defer tunA.Close()
	defer tunB.Close()
	serviceA, engineA, controllerA, endpointA, managerA := newDirectUnifiedNode(t, nodeA, clientATLS, listener.Addr().String(), tunA, nodeB.NodeID, addressA, addressB)
	serviceB, engineB, controllerB, endpointB, managerB := newDirectUnifiedNode(t, nodeB, clientBTLS, listener.Addr().String(), tunB, nodeA.NodeID, addressB, addressA)
	defer endpointA.Close()
	defer endpointB.Close()
	nodeDone, engineDone, directDone := make(chan error, 2), make(chan error, 2), make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	go func() { engineDone <- engineA.Run(ctx) }()
	go func() { engineDone <- engineB.Run(ctx) }()
	go func() { directDone <- controllerA.Run(ctx) }()
	go func() { directDone <- controllerB.Run(ctx) }()
	eventually(t, ctx, func() bool {
		pathA, pathB := managerA.BestPath(nodeB.NodeID), managerB.BestPath(nodeA.NodeID)
		return pathA != nil && pathB != nil && len(pathA.Name()) >= len("direct-quic/") && pathA.Name()[:len("direct-quic/")] == "direct-quic/" && len(pathB.Name()) >= len("direct-quic/") && pathB.Name()[:len("direct-quic/")] == "direct-quic/"
	})
	packet, _ := nodeservice.IPv4Packet(addressA, addressB, []byte("direct selected"))
	forwardedBefore := server.Registry().Metrics().ForwardedPackets
	if err := tunA.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	received, err := tunB.Receive(ctx)
	if err != nil || string(received) != string(packet) {
		t.Fatalf("direct receive=%x err=%v", received, err)
	}
	time.Sleep(30 * time.Millisecond)
	if forwarded := server.Registry().Metrics().ForwardedPackets; forwarded != forwardedBefore {
		t.Fatalf("direct packet traversed relay: before=%d after=%d", forwardedBefore, forwarded)
	}
	directPath := managerA.BestPath(nodeB.NodeID)
	managerA.MarkFailed(nodeB.NodeID, directPath.Name())
	if best := managerA.BestPath(nodeB.NodeID); best == nil || best.Name() != "relay-quic" {
		t.Fatalf("direct failure did not select relay: %v", best)
	}
	fallbackPacket, _ := nodeservice.IPv4Packet(addressA, addressB, []byte("relay fallback"))
	if err := tunA.Inject(ctx, fallbackPacket); err != nil {
		t.Fatal(err)
	}
	received, err = tunB.Receive(ctx)
	if err != nil || string(received) != string(fallbackPacket) {
		t.Fatalf("fallback receive=%x err=%v", received, err)
	}
	eventually(t, ctx, func() bool { return server.Registry().Metrics().ForwardedPackets > forwardedBefore })
	cancel()
	waitDone(t, serverDone)
	for range 2 {
		waitDone(t, nodeDone)
		waitDone(t, engineDone)
		waitDone(t, directDone)
	}
}

func newDirectUnifiedNode(t *testing.T, local identity.NodeIdentity, tlsConfig *tls.Config, relayAddress string, tun *platform.MemoryTUN, peer identity.NodeID, localAddress, peerAddress netip.Addr) (*nodeservice.Service, *dataplane.Engine, *dataplane.DirectController, *directpath.Endpoint, *pathmanager.Manager) {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := directpath.NewEndpoint(socket, local, directpath.Credentials{Roots: tlsConfig.RootCAs, Certificate: tlsConfig.Certificates[0]}, directpath.Config{CandidatePolicy: directpath.CandidatePolicy{AllowLoopback: true}})
	if err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	routes := routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}}))
	manager := pathmanager.MustNew(pathmanager.Config{})
	engine, err := dataplane.New(dataplane.Config{Identity: local, Routes: routes, Packets: tunAdapter{tun}, Paths: manager, LocalAddresses: []netip.Addr{localAddress}, MaxPacketSize: 1200})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := dataplane.NewDirectController(dataplane.DirectConfig{Local: local, Endpoint: endpoint, Paths: engine, Authorizer: dataplane.RouteAuthorizer{Routes: routes}, CandidatePolicy: directpath.CandidatePolicy{AllowLoopback: true}, ProbeInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: local, BootID: randomID(t), RelayAddress: relayAddress, TLSConfig: tlsConfig, RelayDialer: endpoint,
		Routes: routes, Packets: tunAdapter{tun}, DataPlane: engine, CandidateSink: controller,
		LocalCandidate: &lanewayv1.EndpointCandidate{Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP}, MaxRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, engine, controller, endpoint, manager
}

func unifiedRelay(t *testing.T, nodeA, nodeB identity.NodeIdentity, addressA, addressB netip.Addr) *relayservice.Server {
	t.Helper()
	server, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		Registry:         relay.Config{MaxSessions: 8, MaxHandlesPerSession: 8, OutboundQueueCapacity: 8, MaxPacketPayload: 1200, DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest},
		MaxPacketPayload: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func unifiedTUN(t *testing.T, name string, address netip.Addr) *platform.MemoryTUN {
	t.Helper()
	tun, err := platform.NewMemoryTUN(platform.TUNConfig{Name: name, MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(address, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

func newUnifiedNode(t *testing.T, local identity.NodeIdentity, tlsConfig *tls.Config, relayAddress, tcpAddress string, tcpConfig *tcpfallback.Config, tun platform.TUNDevice, peer identity.NodeID, localAddress, peerAddress netip.Addr) (*nodeservice.Service, *dataplane.Engine) {
	t.Helper()
	routes := routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}}))
	manager := pathmanager.MustNew(pathmanager.Config{})
	engine, err := dataplane.New(dataplane.Config{Identity: local, Routes: routes, Packets: tunAdapter{tun}, Paths: manager, LocalAddresses: []netip.Addr{localAddress}, MaxPacketSize: 1200})
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: local, BootID: randomID(t), RelayAddress: relayAddress, TLSConfig: tlsConfig,
		Transport:          &transport.Config{HandshakeIdleTimeout: 150 * time.Millisecond, MaxIdleTimeout: 3 * time.Second, KeepAlivePeriod: time.Second},
		TCPFallbackAddress: tcpAddress, TCPFallback: tcpConfig, Routes: routes, Packets: tunAdapter{tun}, DataPlane: engine,
		MaxControlPayload: protocol.DefaultMaxControlFrame, MaxRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, engine
}

func runUnifiedExchange(t *testing.T, ctx context.Context, cancel context.CancelFunc, server *relayservice.Server, serviceA, serviceB *nodeservice.Service, engineA, engineB *dataplane.Engine, tunA, tunB *platform.MemoryTUN, addressA, addressB netip.Addr, serverDone <-chan error) {
	t.Helper()
	nodeDone, engineDone := make(chan error, 2), make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	go func() { engineDone <- engineA.Run(ctx) }()
	go func() { engineDone <- engineB.Run(ctx) }()
	eventually(t, ctx, func() bool { return server.Registry().Metrics().Bindings == 2 })
	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("unified dataplane"))
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
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
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
			waitDone(t, engineDone)
			waitDone(t, engineDone)
			return
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("timed out waiting for unified packet")
		}
	}
}
