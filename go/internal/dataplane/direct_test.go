package dataplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/directpath"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/routing"
)

type directTestAuthority struct {
	material    pki.Material
	certificate *x509.Certificate
}

type dynamicCandidateAuthority struct {
	enabled bool
	maximum int
	ttl     time.Duration
}

func (a *dynamicCandidateAuthority) CandidateExchangeEnabled() bool      { return a.enabled }
func (a *dynamicCandidateAuthority) CandidateExchangeMaxCandidates() int { return a.maximum }
func (a *dynamicCandidateAuthority) CandidateExchangeTTL() time.Duration { return a.ttl }

func newDirectTestAuthority(t *testing.T) directTestAuthority {
	t.Helper()
	material, certificate, err := pki.NewAuthority("dataplane direct test", time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return directTestAuthority{material: material, certificate: certificate}
}

func directCredentials(t *testing.T, authority directTestAuthority, node identity.NodeIdentity) directpath.Credentials {
	t.Helper()
	material, leaf, err := pki.IssueNode(authority.certificate, authority.material.PrivateKey, node, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.certificate)
	return directpath.Credentials{Roots: roots, Certificate: tls.Certificate{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey, Leaf: leaf}}
}

func directEndpoint(t *testing.T, node identity.NodeIdentity, credentials directpath.Credentials) *directpath.Endpoint {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := directpath.NewEndpoint(socket, node, credentials, directpath.Config{CandidatePolicy: directpath.CandidatePolicy{AllowLoopback: true}})
	if err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func directCandidate(t *testing.T, endpoint *directpath.Endpoint, peer identity.NodeID) directpath.Candidate {
	t.Helper()
	address, ok := endpoint.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("endpoint address = %T", endpoint.Addr())
	}
	return directpath.Candidate{NodeID: peer, Address: address.AddrPort(), Priority: 1}
}

func directEngine(t *testing.T, local identity.NodeIdentity, localAddress, peerAddress netip.Addr, peer identity.NodeID) (*Engine, *memoryPackets, *pathmanager.Manager, *routing.Table) {
	t.Helper()
	packets := newMemoryPackets()
	manager := pathmanager.MustNew(pathmanager.Config{})
	routes := routing.NewTable(routing.MustSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}}))
	engine, err := New(Config{Identity: local, Routes: routes, Packets: packets, Paths: manager, LocalAddresses: []netip.Addr{localAddress}, MaxPacketSize: 1200})
	if err != nil {
		t.Fatal(err)
	}
	return engine, packets, manager, routes
}

func TestDirectControllerCandidateValidationBoundsAndExpiry(t *testing.T) {
	authority := newDirectTestAuthority(t)
	network := networkID(1)
	local := identity.NodeIdentity{NetworkID: network, NodeID: nodeID(1)}
	peer := nodeID(2)
	endpoint := directEndpoint(t, local, directCredentials(t, authority, local))
	engine, _, _, routes := directEngine(t, local, netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), peer)
	controller, err := NewDirectController(DirectConfig{
		Local: local, Endpoint: endpoint, Engine: engine, Authorizer: RouteAuthorizer{Routes: routes},
		CandidatePolicy: directpath.CandidatePolicy{MaxCandidates: 1, AllowLoopback: true}, CandidateTTL: time.Second, MaxCandidatePeers: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := directCandidate(t, endpoint, peer).Proto()
	if err := controller.HandleCandidate(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	candidates := controller.Candidates(peer, time.Now())
	if len(candidates) != 1 {
		t.Fatalf("candidates = %#v", candidates)
	}
	candidates[0].Priority = 99
	if controller.Candidates(peer, time.Now())[0].Priority != 1 {
		t.Fatal("candidate store was mutable")
	}
	second := proto.Clone(message).(*lanewayv1.EndpointCandidate)
	second.Port++
	if err := controller.HandleCandidate(context.Background(), second); !errors.Is(err, directpath.ErrTooManyCandidates) {
		t.Fatalf("candidate bound error = %v", err)
	}
	unauthorized := proto.Clone(message).(*lanewayv1.EndpointCandidate)
	unauthorized.NodeId = append([]byte(nil), local.NodeID[:]...)
	if err := controller.HandleCandidate(context.Background(), unauthorized); !errors.Is(err, ErrCandidateUnauthorized) {
		t.Fatalf("unauthorized error = %v", err)
	}
	malformed := proto.Clone(message).(*lanewayv1.EndpointCandidate)
	malformed.Port = 0
	if err := controller.HandleCandidate(context.Background(), malformed); !errors.Is(err, directpath.ErrInvalidCandidate) {
		t.Fatalf("malformed error = %v", err)
	}
	if got := controller.Candidates(peer, time.Now().Add(2*time.Second)); len(got) != 0 {
		t.Fatalf("expired candidates = %#v", got)
	}
}

func TestDirectControllerAppliesDynamicCandidateAuthority(t *testing.T) {
	certificateAuthority := newDirectTestAuthority(t)
	local := identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)}
	peer := nodeID(2)
	endpoint := directEndpoint(t, local, directCredentials(t, certificateAuthority, local))
	engine, _, _, routes := directEngine(t, local, netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), peer)
	authority := &dynamicCandidateAuthority{enabled: true, maximum: 1, ttl: time.Second}
	controller, err := NewDirectController(DirectConfig{
		Local: local, Endpoint: endpoint, Engine: engine, Authorizer: RouteAuthorizer{Routes: routes},
		CandidateAuthority: authority, CandidatePolicy: directpath.CandidatePolicy{MaxCandidates: 2, AllowLoopback: true}, CandidateTTL: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	message := directCandidate(t, endpoint, peer).Proto()
	if err := controller.HandleCandidate(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	second := proto.Clone(message).(*lanewayv1.EndpointCandidate)
	second.Port++
	if err := controller.HandleCandidate(context.Background(), second); !errors.Is(err, directpath.ErrTooManyCandidates) {
		t.Fatalf("dynamic candidate maximum error = %v", err)
	}
	if candidates := controller.Candidates(peer, time.Now().Add(2*time.Second)); len(candidates) != 0 {
		t.Fatalf("dynamic TTL retained candidates: %#v", candidates)
	}
	authority.enabled = false
	if err := controller.HandleCandidate(context.Background(), message); !errors.Is(err, ErrCandidateUnauthorized) {
		t.Fatalf("disabled candidate authority error = %v", err)
	}
}

func TestUnifiedEngineRealDirectQUICEndToEnd(t *testing.T) {
	authority := newDirectTestAuthority(t)
	network := networkID(1)
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: nodeID(1)}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: nodeID(2)}
	addressA := netip.MustParseAddr("100.64.0.1")
	addressB := netip.MustParseAddr("100.64.0.2")
	engineA, packetsA, managerA, routesA := directEngine(t, nodeA, addressA, addressB, nodeB.NodeID)
	engineB, packetsB, managerB, routesB := directEngine(t, nodeB, addressB, addressA, nodeA.NodeID)
	endpointA := directEndpoint(t, nodeA, directCredentials(t, authority, nodeA))
	endpointB := directEndpoint(t, nodeB, directCredentials(t, authority, nodeB))
	policy := directpath.CandidatePolicy{AllowLoopback: true}
	controllerA, err := NewDirectController(DirectConfig{Local: nodeA, Endpoint: endpointA, Engine: engineA, Authorizer: RouteAuthorizer{Routes: routesA}, CandidatePolicy: policy, ProbeInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	controllerB, err := NewDirectController(DirectConfig{Local: nodeB, Endpoint: endpointB, Engine: engineB, Authorizer: RouteAuthorizer{Routes: routesB}, CandidatePolicy: policy, ProbeInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := controllerA.HandleCandidate(context.Background(), directCandidate(t, endpointB, nodeB.NodeID).Proto()); err != nil {
		t.Fatal(err)
	}
	if err := controllerB.HandleCandidate(context.Background(), directCandidate(t, endpointA, nodeA.NodeID).Proto()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	engineResults := make(chan error, 2)
	go func() { engineResults <- engineA.Run(ctx) }()
	go func() { engineResults <- engineB.Run(ctx) }()
	controllerResults := make(chan error, 2)
	go func() { controllerResults <- controllerA.Run(ctx) }()
	go func() { controllerResults <- controllerB.Run(ctx) }()
	var token directpath.ProbeToken
	token[0] = 1
	start := time.Now().Add(50 * time.Millisecond)
	connectResults := make(chan error, 2)
	go func() { connectResults <- controllerA.ProbeAndConnect(ctx, nodeB.NodeID, token, start) }()
	go func() { connectResults <- controllerB.ProbeAndConnect(ctx, nodeA.NodeID, token, start) }()
	for range 2 {
		if err := <-connectResults; err != nil {
			t.Fatalf("probe/connect error = %v", err)
		}
	}
	eventually(t, func() bool { return managerA.BestPath(nodeB.NodeID) != nil && managerB.BestPath(nodeA.NodeID) != nil })
	packet := ipv4(addressA, addressB)
	packetsA.input <- packet
	select {
	case received := <-packetsB.output:
		if string(received) != string(packet) {
			t.Fatalf("received packet = %x", received)
		}
	case <-ctx.Done():
		t.Fatal("direct packet was not delivered")
	}
	eventually(t, func() bool { return engineA.Metrics().PacketsSent == 1 && engineB.Metrics().PacketsReceived == 1 })
	if managerA.BestPath(nodeB.NodeID).Name() == "" {
		t.Fatalf("A=%+v B=%+v", engineA.Metrics(), engineB.Metrics())
	}
	cancel()
	for range 2 {
		if err := <-engineResults; !errors.Is(err, context.Canceled) {
			t.Fatalf("engine error = %v", err)
		}
	}
	for range 2 {
		if err := <-controllerResults; !errors.Is(err, context.Canceled) {
			t.Fatalf("controller error = %v", err)
		}
	}
}
