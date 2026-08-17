package directpath

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/revocation"
)

type testAuthority struct {
	material    pki.Material
	certificate *x509.Certificate
}

func newTestAuthority(t *testing.T) testAuthority {
	t.Helper()
	material, certificate, err := pki.NewAuthority("directpath test CA", time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return testAuthority{material: material, certificate: certificate}
}

func credentialsForNode(t *testing.T, authority testAuthority, node identity.NodeIdentity, roots ...*x509.Certificate) Credentials {
	t.Helper()
	material, leaf, err := pki.IssueNode(authority.certificate, authority.material.PrivateKey, node, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if len(roots) == 0 {
		roots = []*x509.Certificate{authority.certificate}
	}
	for _, root := range roots {
		pool.AddCert(root)
	}
	return Credentials{Roots: pool, Certificate: tls.Certificate{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey, Leaf: leaf}}
}

func newTestEndpoint(t *testing.T, local identity.NodeIdentity, credentials Credentials) *Endpoint {
	return newTestEndpointMode(t, local, credentials, PayloadIP)
}

func newTestEndpointMode(t *testing.T, local identity.NodeIdentity, credentials Credentials, mode PayloadMode) *Endpoint {
	t.Helper()
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := NewEndpoint(packetConn, local, credentials, Config{PayloadMode: mode, CandidatePolicy: CandidatePolicy{AllowLoopback: true}})
	if err != nil {
		_ = packetConn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func TestWireGuardDirectPathUsesDistinctALPNAndOpaqueValidation(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	endpointA := newTestEndpointMode(t, a, credentialsForNode(t, authority, a), PayloadWireGuard)
	endpointB := newTestEndpointMode(t, b, credentialsForNode(t, authority, b), PayloadWireGuard)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan acceptResult, 1)
	go func() { path, err := endpointB.Accept(ctx); accepted <- acceptResult{path, err} }()
	pathA, err := endpointA.Dial(ctx, endpointCandidate(t, endpointB, b.NodeID), b)
	if err != nil {
		t.Fatal(err)
	}
	defer pathA.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.path.Close()
	payload := make([]byte, 148)
	payload[0] = 1
	if err := pathA.Send(ctx, b.NodeID, payload); err != nil {
		t.Fatal(err)
	}
	received, err := result.path.Receive(ctx)
	if err != nil || string(received.Packet) != string(payload) || received.Peer != a.NodeID {
		t.Fatalf("received=%+v error=%v", received, err)
	}
	if err := pathA.Send(ctx, b.NodeID, ipv4Packet()); !errors.Is(err, protocol.ErrInvalidWireGuard) {
		t.Fatalf("plaintext IP accepted: %v", err)
	}
}

type acceptResult struct {
	path *Path
	err  error
}

func TestWireGuardDirectALPNRejectsLegacyPeer(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	wireGuardEndpoint := newTestEndpointMode(t, a, credentialsForNode(t, authority, a), PayloadWireGuard)
	legacyEndpoint := newTestEndpoint(t, b, credentialsForNode(t, authority, b))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() { _, err := legacyEndpoint.Accept(ctx); accepted <- err }()
	if _, err := wireGuardEndpoint.Dial(ctx, endpointCandidate(t, legacyEndpoint, b.NodeID), b); err == nil {
		t.Fatal("WireGuard direct endpoint negotiated legacy ALPN")
	}
	if err := <-accepted; err == nil {
		t.Fatal("legacy endpoint accepted WireGuard ALPN")
	}
}

func endpointCandidate(t *testing.T, endpoint *Endpoint, node identity.NodeID) Candidate {
	t.Helper()
	udp, ok := endpoint.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("endpoint address type = %T", endpoint.Addr())
	}
	return Candidate{NodeID: node, Address: udp.AddrPort(), Priority: 1}
}

func ipv4Packet() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, byte(len(packet))
	packet[8] = 64
	packet[9] = 1
	packet[12], packet[16] = 10, 10
	packet[15], packet[19] = 1, 2
	return packet
}

func TestLoopbackMutualTLSDirectPacketPathAndProbe(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	revokedA := new(revocation.Set)
	credentialsA := credentialsForNode(t, authority, a)
	credentialsB := credentialsForNode(t, authority, b)
	credentialsA.Revocations = revokedA
	endpointA := newTestEndpoint(t, a, credentialsA)
	endpointB := newTestEndpoint(t, b, credentialsB)
	candidateA := endpointCandidate(t, endpointA, a.NodeID)
	candidateB := endpointCandidate(t, endpointB, b.NodeID)

	// A non-QUIC rendezvous probe uses the same UDP socket later used by QUIC.
	var token ProbeToken
	token[0] = 1
	request, _ := (ProbePacket{Token: token, Sender: a.NodeID, Recipient: b.NodeID}).MarshalBinary()
	if _, err := endpointA.ProbeWriter().WriteTo(request, net.UDPAddrFromAddrPort(candidateB.Address)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probeResult := make(chan error, 1)
	go func() {
		source, err := endpointA.ReadProbe(ctx, b.NodeID, token, []Candidate{candidateB})
		if err == nil && source != candidateB.Address {
			err = errors.New("unexpected probe response source")
		}
		probeResult <- err
	}()
	if source, err := endpointB.ReadProbe(ctx, a.NodeID, token, []Candidate{candidateA}); err != nil || source != candidateA.Address {
		t.Fatalf("B probe source = %s, %v", source, err)
	}
	if err := <-probeResult; err != nil {
		t.Fatalf("A probe response: %v", err)
	}

	accepted := make(chan acceptResult, 1)
	go func() { path, err := endpointB.Accept(ctx); accepted <- acceptResult{path, err} }()
	pathA, err := endpointA.Dial(ctx, candidateB, b)
	if err != nil {
		t.Fatal(err)
	}
	defer pathA.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	pathB := result.path
	defer pathB.Close()

	if pathA.MaxPayload(b.NodeID) != DefaultMaxPacketPayload || pathA.MaxPayload(a.NodeID) != 0 {
		t.Fatal("path payload limit was not peer-bound")
	}
	if health := pathA.Health(b.NodeID); health.State != pathmanager.HealthHealthy {
		t.Fatalf("health = %#v", health)
	}
	packet := ipv4Packet()
	if err := pathA.Send(ctx, b.NodeID, packet); err != nil {
		t.Fatal(err)
	}
	received, err := pathB.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if received.Peer != a.NodeID || string(received.Packet) != string(packet) {
		t.Fatalf("received = %#v", received)
	}
	if err := pathB.Send(ctx, a.NodeID, packet); err != nil {
		t.Fatal(err)
	}
	if received, err = pathA.Receive(ctx); err != nil || received.Peer != b.NodeID {
		t.Fatalf("reverse receive = %#v, %v", received, err)
	}

	if err := pathA.Send(ctx, a.NodeID, packet); !errors.Is(err, ErrWrongPeer) {
		t.Fatalf("wrong peer error = %v", err)
	}
	if err := pathA.Send(ctx, b.NodeID, []byte{0}); !errors.Is(err, protocol.ErrInvalidIPPacket) {
		t.Fatalf("malformed packet error = %v", err)
	}
	if err := pathA.Send(ctx, b.NodeID, make([]byte, DefaultMaxPacketPayload+1)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("large packet error = %v", err)
	}
	if err := revokedA.Replace([][]byte{credentialsB.Certificate.Leaf.SerialNumber.Bytes()}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for pathA.Health(b.NodeID).State != pathmanager.HealthFailed && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if health := pathA.Health(b.NodeID); health.State != pathmanager.HealthFailed {
		t.Fatalf("revoked direct path remained active: %#v", health)
	}
}

func TestPathEndpointHandlerBracketsAuthenticatedPathLifetime(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	endpointA := newTestEndpoint(t, a, credentialsForNode(t, authority, a))
	endpointB := newTestEndpoint(t, b, credentialsForNode(t, authority, b))
	var mu sync.Mutex
	var updates [][]netip.Addr
	if err := endpointA.SetPathEndpointHandler(func(addresses []netip.Addr) error {
		mu.Lock()
		updates = append(updates, append([]netip.Addr(nil), addresses...))
		mu.Unlock()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan *Path, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		path, err := endpointB.Accept(ctx)
		if err != nil {
			acceptErrors <- err
			return
		}
		accepted <- path
	}()
	pathA, err := endpointA.Dial(ctx, endpointCandidate(t, endpointB, b.NodeID), b)
	if err != nil {
		t.Fatal(err)
	}
	var pathB *Path
	select {
	case pathB = <-accepted:
	case err := <-acceptErrors:
		t.Fatal(err)
	}
	defer pathB.Close()
	mu.Lock()
	if len(updates) < 2 || len(updates[len(updates)-1]) != 1 || updates[len(updates)-1][0] != endpointCandidate(t, endpointB, b.NodeID).Address.Addr().Unmap() {
		t.Fatalf("path endpoint updates after authentication = %#v", updates)
	}
	mu.Unlock()
	if err := pathA.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(updates[len(updates)-1]) != 0 {
		t.Fatalf("path endpoint bypass remained after close: %#v", updates)
	}
}

func TestCandidateEndpointReservationPrecedesDirectHandshake(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	endpointA := newTestEndpoint(t, a, credentialsForNode(t, authority, a))
	endpointB := newTestEndpoint(t, b, credentialsForNode(t, authority, b))
	var updates [][]netip.Addr
	if err := endpointA.SetPathEndpointHandler(func(addresses []netip.Addr) error {
		updates = append(updates, append([]netip.Addr(nil), addresses...))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	candidate := endpointCandidate(t, endpointB, b.NodeID)
	reservation, err := endpointA.ReservePathEndpoints([]Candidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	want := candidate.Address.Addr().Unmap()
	if len(updates) < 2 || len(updates[len(updates)-1]) != 1 || updates[len(updates)-1][0] != want {
		t.Fatalf("candidate was not bypassed before handshake: %#v", updates)
	}
	if err := reservation.Release(); err != nil {
		t.Fatal(err)
	}
	if len(updates[len(updates)-1]) != 0 {
		t.Fatalf("candidate reservation survived release: %#v", updates)
	}
}

func TestReadProbeSkipsStaleRendezvousPacket(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	endpointA := newTestEndpoint(t, a, credentialsForNode(t, authority, a))
	endpointB := newTestEndpoint(t, b, credentialsForNode(t, authority, b))
	candidateA := endpointCandidate(t, endpointA, a.NodeID)
	candidateB := endpointCandidate(t, endpointB, b.NodeID)

	var stale, current ProbeToken
	stale[0], current[0] = 1, 2
	for _, token := range []ProbeToken{stale, current} {
		request, err := (ProbePacket{Token: token, Sender: a.NodeID, Recipient: b.NodeID}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := endpointA.ProbeWriter().WriteTo(request, net.UDPAddrFromAddrPort(candidateB.Address)); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	source, err := endpointB.ReadProbe(ctx, a.NodeID, current, []Candidate{candidateA})
	if err != nil {
		t.Fatal(err)
	}
	if source != candidateA.Address {
		t.Fatalf("probe source = %s, want %s", source, candidateA.Address)
	}
}

func TestDirectTransportRejectsCrossNetworkAndExactNodeMismatch(t *testing.T) {
	authority := newTestAuthority(t)
	networkA := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	networkB := testNetwork(t, "303132333435363738393a3b3c3d3e3f")
	a := identity.NodeIdentity{NetworkID: networkA, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: networkA, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	c := identity.NodeIdentity{NetworkID: networkB, NodeID: testNode(t, "404142434445464748494a4b4c4d4e4f")}
	endpointA := newTestEndpoint(t, a, credentialsForNode(t, authority, a))
	endpointB := newTestEndpoint(t, b, credentialsForNode(t, authority, b))
	endpointC := newTestEndpoint(t, c, credentialsForNode(t, authority, c))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Candidate points at B, but an exact expected C identity is required.
	wrongCandidate := endpointCandidate(t, endpointB, c.NodeID)
	expectedCInA := identity.NodeIdentity{NetworkID: networkA, NodeID: c.NodeID}
	if _, err := endpointA.Dial(ctx, wrongCandidate, expectedCInA); err == nil {
		t.Fatal("exact node mismatch was accepted")
	}
	// Candidate points at C and carries C's node ID, but C belongs to another network.
	crossCandidate := endpointCandidate(t, endpointC, c.NodeID)
	if _, err := endpointA.Dial(ctx, crossCandidate, expectedCInA); err == nil {
		t.Fatal("cross-network peer was accepted")
	}
}

func TestDirectTransportRejectsUntrustedClientCertificate(t *testing.T) {
	trusted := newTestAuthority(t)
	untrusted := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	serverNode := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	clientNode := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	server := newTestEndpoint(t, serverNode, credentialsForNode(t, trusted, serverNode))
	// The client trusts both roots so it can authenticate the server; the server
	// trusts only the production root and must reject the client's other chain.
	clientCredentials := credentialsForNode(t, untrusted, clientNode, trusted.certificate, untrusted.certificate)
	client := newTestEndpoint(t, clientNode, clientCredentials)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() { _, err := server.Accept(ctx); accepted <- err }()
	if _, err := client.Dial(ctx, endpointCandidate(t, server, serverNode.NodeID), serverNode); err == nil {
		t.Fatal("untrusted client certificate was accepted")
	}
	if err := <-accepted; err == nil {
		t.Fatal("server accepted untrusted client certificate")
	}
}

func TestNewEndpointRejectsCertificateIdentityMismatch(t *testing.T) {
	authority := newTestAuthority(t)
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	a := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	b := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "202122232425262728292a2b2c2d2e2f")}
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if _, err := NewEndpoint(packetConn, a, credentialsForNode(t, authority, b), Config{CandidatePolicy: CandidatePolicy{AllowLoopback: true}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestNewEndpointRejectsUntrustedLocalCertificate(t *testing.T) {
	trusted := newTestAuthority(t)
	untrusted := newTestAuthority(t)
	node := identity.NodeIdentity{
		NetworkID: testNetwork(t, "000102030405060708090a0b0c0d0e0f"),
		NodeID:    testNode(t, "101112131415161718191a1b1c1d1e1f"),
	}
	credentials := credentialsForNode(t, untrusted, node, trusted.certificate)
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if _, err := NewEndpoint(packetConn, node, credentials, Config{CandidatePolicy: CandidatePolicy{AllowLoopback: true}}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("untrusted local certificate error = %v", err)
	}
}

func TestIdentityPrefaceRejectsMalformedAndWrongClaims(t *testing.T) {
	network := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	node := identity.NodeIdentity{NetworkID: network, NodeID: testNode(t, "101112131415161718191a1b1c1d1e1f")}
	preface := identityPreface(node)
	if err := validateIdentityPreface(preface, node); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0]++ },
		func(p []byte) { p[4]++ },
		func(p []byte) { p[5]++ },
		func(p []byte) { p[21]++ },
	} {
		malformed := append([]byte(nil), preface...)
		mutate(malformed)
		if err := validateIdentityPreface(malformed, node); !errors.Is(err, ErrPeerIdentity) {
			t.Fatalf("malformed identity error = %v", err)
		}
	}
	if err := validateIdentityPreface(preface[:len(preface)-1], node); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("short identity error = %v", err)
	}
}

func TestReadProbeRejectsUnadvertisedSource(t *testing.T) {
	// The source validation is independently testable without waiting on a socket.
	peer := testNode(t, "101112131415161718191a1b1c1d1e1f")
	advertised := Candidate{NodeID: peer, Address: netip.MustParseAddrPort("127.0.0.1:1234")}
	if _, err := ValidateCandidates([]Candidate{advertised}, peer, CandidatePolicy{}); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("unsafe loopback candidate error = %v", err)
	}
}

func TestUnmapAddrPortCanonicalizesIPv4MappedSources(t *testing.T) {
	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.10]:4434")
	if got, want := unmapAddrPort(mapped), netip.MustParseAddrPort("192.0.2.10:4434"); got != want {
		t.Fatalf("unmap address = %s, want %s", got, want)
	}
	native := netip.MustParseAddrPort("[2001:db8::10]:4434")
	if got := unmapAddrPort(native); got != native {
		t.Fatalf("native IPv6 address changed to %s", got)
	}
}

func TestDialOptionsAreBounded(t *testing.T) {
	if normalized, err := (DialOptions{}).normalized(time.Second); err != nil || normalized.Attempts != DefaultDialAttempts || normalized.AttemptTimeout != time.Second {
		t.Fatalf("default options = %#v, %v", normalized, err)
	}
	for _, invalid := range []DialOptions{
		{Attempts: MaxDialAttempts + 1},
		{Attempts: 1, AttemptTimeout: 31 * time.Second},
		{Attempts: 1, RetryDelay: -time.Second},
	} {
		if _, err := invalid.normalized(time.Second); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("options %#v error = %v", invalid, err)
		}
	}
}
