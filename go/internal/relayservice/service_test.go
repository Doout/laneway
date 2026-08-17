package relayservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/agent"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/revocation"
	"github.com/Doout/laneway/go/internal/transport"
	"google.golang.org/protobuf/proto"
)

type testClient struct {
	conn    *transport.Conn
	codec   *relayCodec
	binding *lanewayv1.RouteHandleBinding
}

type testMaterial struct {
	server  *tls.Config
	clients map[identity.NodeIdentity]*tls.Config
}

func TestQUICRelayLifecycle(t *testing.T) {
	network, err := identity.NewNetworkID()
	if err != nil {
		t.Fatal(err)
	}
	nodeAID, _ := identity.NewNodeID()
	nodeBID, _ := identity.NewNodeID()
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: nodeAID}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: nodeBID}
	addressA := netip.MustParseAddr("100.64.0.1")
	addressB := netip.MustParseAddr("100.64.0.2")

	material := newTestMaterial(t, network, nodeA, nodeB)
	var policyAllows atomic.Bool
	policyAllows.Store(true)
	listener, err := transport.Listen("127.0.0.1:0", material.server, &transport.Config{
		HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 5 * time.Second, KeepAlivePeriod: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	server, err := New(Config{
		Authorizer: StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		PacketPolicy: PacketPolicyFunc(func(source, destination identity.NodeIdentity, packet []byte) bool {
			return source == nodeA && destination == nodeB && policyAllows.Load() ||
				source == nodeB && destination == nodeA && policyAllows.Load()
		}),
		MaxConcurrentSessions: 2,
		ConfigurationEpoch:    7,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancelServe := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveCtx, listener) }()

	clientA := connectTestClient(t, listener.Addr().String(), material.clients[nodeA], nodeA, addressA)
	defer clientA.conn.Close()
	clientB := connectTestClient(t, listener.Addr().String(), material.clients[nodeB], nodeB, addressB)

	clientA.binding = readBinding(t, clientA, nodeB.NodeID)
	clientB.binding = readBinding(t, clientB, nodeA.NodeID)
	if clientA.binding.GetMaxPacketPayload() == 0 || clientB.binding.GetMaxPacketPayload() == 0 {
		t.Fatal("relay advertised a zero packet limit")
	}

	assertForwarded(t, clientA, clientB, addressA, addressB)
	assertForwarded(t, clientB, clientA, addressB, addressA)
	policyAllows.Store(false)
	assertNotForwarded(t, clientA, clientB, addressA, addressB)
	policyAllows.Store(true)
	assertForwarded(t, clientA, clientB, addressA, addressB)
	if err := clientA.conn.SendDatagram([]byte{1}); err != nil {
		t.Fatal(err)
	}

	// A valid route handle cannot be used to spoof a source outside the
	// certificate-bound assignment. The bad packet is dropped, and the session
	// remains usable afterward.
	spoof, err := protocol.EncodePacket(nil, protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: clientA.binding.GetRouteHandle(),
	}, ipv4Packet(netip.MustParseAddr("100.64.0.99"), addressB))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientA.conn.SendDatagram(spoof); err != nil {
		t.Fatal(err)
	}
	short, shortCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer shortCancel()
	if frame, err := clientB.conn.ReceiveDatagram(short); err == nil {
		t.Fatalf("spoofed packet was forwarded: %x", frame)
	}
	assertForwarded(t, clientA, clientB, addressA, addressB)
	deadline := time.Now().Add(time.Second)
	for {
		metrics := server.Metrics()
		if metrics.ConnectionsAccepted == 2 && metrics.PolicyDrops == 1 && metrics.AuthorizationFailures >= 1 &&
			metrics.MalformedInput >= 1 && metrics.Registry.DroppedSource >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operational metrics did not classify input: %+v", metrics)
		}
		time.Sleep(time.Millisecond)
	}

	// RelayEnvelope releases are legal after registration and do not tear down
	// the authenticated connection.
	if err := clientB.codec.write(clientB.conn.ControlStream(), &lanewayv1.RouteHandleRelease{
		RouteHandle: clientB.binding.GetRouteHandle(),
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := server.Registry().Lookup(network, nodeB.NodeID); !ok {
		t.Fatal("a valid client handle release disconnected node B")
	}

	oldAHandle := clientA.binding.GetRouteHandle()
	if err := clientB.conn.Close(); err != nil {
		t.Fatal(err)
	}
	release := readRelay(t, clientA).GetRouteHandleRelease()
	if release == nil || release.GetRouteHandle() != oldAHandle {
		t.Fatalf("disconnect release = %#v, want handle %d", release, oldAHandle)
	}
	eventually(t, time.Second, func() bool {
		_, ok := server.Registry().Lookup(network, nodeB.NodeID)
		return !ok
	})

	cancelServe()
	select {
	case err := <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after cancellation")
	}
	select {
	case <-clientA.conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("active client was not closed on server cancellation")
	}
	if _, ok := server.Registry().Lookup(network, nodeA.NodeID); ok {
		t.Fatal("node A remained registered after server cancellation")
	}
}

func assertNotForwarded(t *testing.T, sender, recipient *testClient, source, destination netip.Addr) {
	t.Helper()
	payload := ipv4Packet(source, destination)
	frame, err := protocol.EncodePacket(nil, protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: sender.binding.GetRouteHandle(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.conn.SendDatagram(frame); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if forwarded, err := recipient.conn.ReceiveDatagram(ctx); err == nil {
		t.Fatalf("policy-denied packet was forwarded: %x", forwarded)
	}
}

func connectTestClient(t *testing.T, address string, tlsConfig *tls.Config, id identity.NodeIdentity, overlay netip.Addr) *testClient {
	return connectTestClientCapabilities(t, address, tlsConfig, id, overlay, agent.RequiredRelayCapabilities)
}

func connectTestClientCapabilities(t *testing.T, address string, tlsConfig *tls.Config, id identity.NodeIdentity, overlay netip.Addr, capabilities protocol.Capability) *testClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, address, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	bootID, _ := identity.NewID()
	handshake, err := agent.NewClientHandshake(id, bootID, protocol.Version{Major: protocol.ProtocolMajor1}, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := handshake.HelloEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	writeProtoFrame(t, conn, hello)
	response := new(lanewayv1.ControlEnvelope)
	readProtoFrame(t, conn, response)
	parameters, err := handshake.AcceptWelcome(response, protocol.DefaultMaxControlFrame)
	if err != nil {
		t.Fatal(err)
	}
	if parameters.ConfigurationEpoch != 7 || len(parameters.OverlayAddresses) != 1 || parameters.OverlayAddresses[0] != overlay {
		t.Fatalf("Welcome parameters = %#v", parameters)
	}
	codec := newRelayCodec(parameters.EffectiveMaxControlPayload)
	if err := codec.write(conn.ControlStream(), &lanewayv1.RelayRegister{
		SessionId: append([]byte(nil), parameters.SessionID[:]...), RequestedMaxRoutes: 16,
	}); err != nil {
		t.Fatal(err)
	}
	return &testClient{conn: conn, codec: codec}
}

func TestRelayRendezvousRewritesUntrustedCandidatesToObservedEndpoints(t *testing.T) {
	network, _ := identity.NewNetworkID()
	nodeAID, _ := identity.NewNodeID()
	nodeBID, _ := identity.NewNodeID()
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: nodeAID}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: nodeBID}
	addressA, addressB := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	material := newTestMaterial(t, network, nodeA, nodeB)
	listener, err := transport.Listen("127.0.0.1:0", material.server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := New(Config{
		Authorizer: StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		MaxConcurrentSessions: 2, ConfigurationEpoch: 7, CandidateMinInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	defer func() { cancel(); <-done }()
	capabilities := agent.RequiredRelayCapabilities | protocol.CapabilityDirectPeerV1
	clientA := connectTestClientCapabilities(t, listener.Addr().String(), material.clients[nodeA], nodeA, addressA, capabilities)
	defer clientA.conn.Close()
	clientB := connectTestClientCapabilities(t, listener.Addr().String(), material.clients[nodeB], nodeB, addressB, capabilities)
	defer clientB.conn.Close()
	_ = readBinding(t, clientA, nodeB.NodeID)
	_ = readBinding(t, clientB, nodeA.NodeID)
	malicious := &lanewayv1.EndpointCandidate{
		NodeId: make([]byte, identity.IDSize), IpAddress: []byte{203, 0, 113, 99}, Port: 65535,
		Transport:       lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_TLS_TCP,
		RendezvousToken: bytes.Repeat([]byte{0xff}, identity.IDSize), ProbeStartUnixNano: 1,
	}
	if err := clientA.codec.write(clientA.conn.ControlStream(), malicious); err != nil {
		t.Fatal(err)
	}
	if err := clientB.codec.write(clientB.conn.ControlStream(), malicious); err != nil {
		t.Fatal(err)
	}
	candidateForA := readRelay(t, clientA).GetEndpointCandidate()
	candidateForB := readRelay(t, clientB).GetEndpointCandidate()
	if candidateForA == nil || candidateForB == nil {
		t.Fatalf("candidates A=%#v B=%#v", candidateForA, candidateForB)
	}
	assertObservedCandidate(t, candidateForA, nodeB.NodeID, clientB.conn.LocalAddr())
	assertObservedCandidate(t, candidateForB, nodeA.NodeID, clientA.conn.LocalAddr())
	if len(candidateForA.GetRendezvousToken()) != identity.IDSize || !bytes.Equal(candidateForA.GetRendezvousToken(), candidateForB.GetRendezvousToken()) || candidateForA.GetProbeStartUnixNano() != candidateForB.GetProbeStartUnixNano() || candidateForA.GetProbeStartUnixNano() <= uint64(time.Now().UnixNano()) {
		t.Fatalf("coordination mismatch A=%#v B=%#v", candidateForA, candidateForB)
	}
	// A long-lived session may publish again after the bounded rate window, so
	// failed or degraded direct paths can retry without reconnecting the relay.
	time.Sleep(25 * time.Millisecond)
	if err := clientA.codec.write(clientA.conn.ControlStream(), malicious); err != nil {
		t.Fatal(err)
	}
	retryForA := readRelay(t, clientA).GetEndpointCandidate()
	retryForB := readRelay(t, clientB).GetEndpointCandidate()
	if retryForA == nil || retryForB == nil || bytes.Equal(retryForA.GetRendezvousToken(), candidateForA.GetRendezvousToken()) {
		t.Fatalf("fresh rendezvous retry A=%#v B=%#v", retryForA, retryForB)
	}
	// Publishing faster than the configured floor is a protocol violation and
	// closes only the offending authenticated session.
	if err := clientA.codec.write(clientA.conn.ControlStream(), malicious); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clientA.conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("too-frequent candidate publication did not close the session")
	}
}

func assertObservedCandidate(t *testing.T, candidate *lanewayv1.EndpointCandidate, peer identity.NodeID, local net.Addr) {
	t.Helper()
	udp, ok := local.(*net.UDPAddr)
	if !ok {
		t.Fatalf("local address = %T", local)
	}
	observed := udp.AddrPort()
	gotIP, ok := netip.AddrFromSlice(candidate.GetIpAddress())
	ipMatches := ok && gotIP.Unmap() == observed.Addr().Unmap()
	// quic-go may expose a wildcard client LocalAddr while the server correctly
	// observes the concrete loopback source selected by the kernel.
	if observed.Addr().IsUnspecified() {
		ipMatches = ok && gotIP.IsLoopback()
	}
	if !ipMatches || candidate.GetPort() != uint32(observed.Port()) || !bytes.Equal(candidate.GetNodeId(), peer[:]) || candidate.GetTransport() != lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP {
		t.Fatalf("candidate = %#v, observed = %s", candidate, observed)
	}
}

func readBinding(t *testing.T, client *testClient, peer identity.NodeID) *lanewayv1.RouteHandleBinding {
	t.Helper()
	binding := readRelay(t, client).GetRouteHandleBinding()
	if binding == nil || binding.GetRouteHandle() == 0 || string(binding.GetPeerNodeId()) != string(peer[:]) {
		t.Fatalf("invalid binding %#v for peer %x", binding, peer)
	}
	return binding
}

func readRelay(t *testing.T, client *testClient) *lanewayv1.RelayEnvelope {
	t.Helper()
	if err := client.conn.ControlStream().SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer client.conn.ControlStream().SetReadDeadline(time.Time{}) //nolint:errcheck
	envelope, err := client.codec.read(client.conn.ControlStream())
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func assertForwarded(t *testing.T, sender, recipient *testClient, source, destination netip.Addr) {
	t.Helper()
	payload := ipv4Packet(source, destination)
	frame, err := protocol.EncodePacket(nil, protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: sender.binding.GetRouteHandle(),
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.conn.SendDatagram(frame); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	forwarded, err := recipient.conn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	header, gotPayload, err := protocol.DecodePacket(forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if header.RouteHandle != recipient.binding.GetRouteHandle() {
		t.Fatalf("rewritten handle = %d, want %d", header.RouteHandle, recipient.binding.GetRouteHandle())
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("forwarded payload changed: %x != %x", gotPayload, payload)
	}
}

func ipv4Packet(source, destination netip.Addr) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	return packet
}

func writeProtoFrame(t *testing.T, conn *transport.Conn, message proto.Message) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := (protocol.ControlFramer{MaxPayload: protocol.DefaultMaxControlFrame}).Write(conn.ControlStream(), payload); err != nil {
		t.Fatal(err)
	}
}

func readProtoFrame(t *testing.T, conn *transport.Conn, message proto.Message) {
	t.Helper()
	payload, err := (protocol.ControlFramer{MaxPayload: protocol.DefaultMaxControlFrame}).Read(conn.ControlStream())
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(payload, message); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met")
}

func newTestMaterial(t *testing.T, network identity.NetworkID, nodes ...identity.NodeIdentity) testMaterial {
	t.Helper()
	now := time.Now()
	ca, caCert, err := pki.NewAuthority("relay service test CA", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serviceID, _ := identity.NewID()
	server, _, err := pki.IssueService(caCert, ca.PrivateKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: serviceID, Role: pki.RoleRelay,
	}, nil, nil, now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writeMaterial(t, caFile, pki.CertificatePEM(ca.CertificateDER))
	serverCert, serverKey := writeLeaf(t, dir, "relay", server)
	serverTLS, err := transport.LoadServerTLSConfig(caFile, serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clients := make(map[identity.NodeIdentity]*tls.Config, len(nodes))
	for i, node := range nodes {
		leaf, _, err := pki.IssueNode(caCert, ca.PrivateKey, node, now, 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		cert, key := writeLeaf(t, dir, "node-"+string(rune('a'+i)), leaf)
		clientTLS, err := transport.LoadClientTLSConfig(caFile, cert, key)
		if err != nil {
			t.Fatal(err)
		}
		clients[node] = clientTLS
	}
	return testMaterial{server: serverTLS, clients: clients}
}

func writeLeaf(t *testing.T, dir, name string, material pki.Material) (string, string) {
	t.Helper()
	keyPEM, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, name+".pem")
	key := filepath.Join(dir, name+"-key.pem")
	writeMaterial(t, cert, pki.CertificatePEM(material.CertificateDER))
	writeMaterial(t, key, keyPEM)
	return cert, key
}

func writeMaterial(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStaticAuthorizerCopiesAssignments(t *testing.T) {
	network, _ := identity.NewNetworkID()
	node, _ := identity.NewNodeID()
	id := identity.NodeIdentity{NetworkID: network, NodeID: node}
	authorizer := StaticAuthorizer{id: {
		OverlayAddresses:   []netip.Addr{netip.MustParseAddr("100.64.1.1")},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.1.1/32")},
	}}
	assignment, err := authorizer.Authorize(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	assignment.OverlayAddresses[0] = netip.MustParseAddr("100.64.1.2")
	again, _ := authorizer.Authorize(context.Background(), id)
	if again.OverlayAddresses[0] != netip.MustParseAddr("100.64.1.1") {
		t.Fatal("StaticAuthorizer returned aliased storage")
	}
	unknownNode, _ := identity.NewNodeID()
	if _, err := authorizer.Authorize(context.Background(), identity.NodeIdentity{NetworkID: network, NodeID: unknownNode}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown authorization error = %v", err)
	}
}

func TestRelayCodecRejectsSkippedSequence(t *testing.T) {
	envelope := &lanewayv1.RelayEnvelope{
		SchemaVersion: relaySchemaVersion, Sequence: 2,
		Body: &lanewayv1.RelayEnvelope_RouteHandleRelease{RouteHandleRelease: &lanewayv1.RouteHandleRelease{RouteHandle: 1}},
	}
	payload, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var framed []byte
	writer := appendWriter{target: &framed}
	if err := (protocol.ControlFramer{MaxPayload: protocol.DefaultMaxControlFrame}).Write(writer, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := newRelayCodec(protocol.DefaultMaxControlFrame).read(bytes.NewReader(framed)); !errors.Is(err, ErrUnexpectedSequence) {
		t.Fatalf("codec error = %v", err)
	}
}

func FuzzRelayCodecRead(f *testing.F) {
	var valid bytes.Buffer
	if err := newRelayCodec(protocol.DefaultMaxControlFrame).write(&valid, &lanewayv1.RouteHandleRelease{RouteHandle: 1}); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = newRelayCodec(protocol.DefaultMaxControlFrame).read(bytes.NewReader(wire))
	})
}

type reauthorizeConnection struct {
	closed atomic.Int32
	doneCh chan struct{}
}

type retryAcceptor struct {
	calls atomic.Int32
	conn  packetConnection
}

func (a *retryAcceptor) accept(ctx context.Context) (packetConnection, error) {
	switch a.calls.Add(1) {
	case 1:
		return nil, errors.New("rejected test handshake")
	case 2:
		return a.conn, nil
	default:
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func TestAcceptLoopSurvivesOneUntrustedHandshake(t *testing.T) {
	connection := &reauthorizeConnection{doneCh: make(chan struct{})}
	server := &Server{conns: make(map[packetConnection]struct{}), active: make(map[identity.NodeIdentity]*wireSession)}
	acceptor := &retryAcceptor{conn: connection}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.acceptLoop(ctx, acceptor, make(chan struct{}, 1)) }()
	deadline := time.Now().Add(time.Second)
	for {
		metrics := server.Metrics()
		if metrics.AcceptFailures == 1 && metrics.ConnectionsAccepted == 1 && metrics.AuthorizationFailures == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("accept metrics = %+v", metrics)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("accept loop error = %v", err)
	}
	server.wg.Wait()
}

func (c *reauthorizeConnection) peerNodeIdentity() (identity.NodeIdentity, bool) {
	return identity.NodeIdentity{}, false
}
func (c *reauthorizeConnection) peerCertificateSerial() []byte { return []byte{1} }
func (c *reauthorizeConnection) controlStream() io.ReadWriter  { return nil }
func (c *reauthorizeConnection) receivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error) {
	return nil, nil, io.EOF
}
func (c *reauthorizeConnection) sendPacket(context.Context, []byte) error { return io.EOF }
func (c *reauthorizeConnection) done() <-chan struct{}                    { return c.doneCh }
func (c *reauthorizeConnection) observedUDPEndpoint() (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}
func (c *reauthorizeConnection) close() error {
	c.closed.Add(1)
	return nil
}

func TestReauthorizeClosesChangedAndRevokedSessions(t *testing.T) {
	network, _ := identity.NewNetworkID()
	nodeID, _ := identity.NewNodeID()
	id := identity.NodeIdentity{NetworkID: network, NodeID: nodeID}
	original := Authorization{
		OverlayAddresses:   []netip.Addr{netip.MustParseAddr("100.64.9.1")},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.9.1/32")},
	}
	authorizer := new(AtomicAuthorizer)
	if err := authorizer.Replace(map[identity.NodeIdentity]Authorization{id: original}); err != nil {
		t.Fatal(err)
	}
	connection := &reauthorizeConnection{doneCh: make(chan struct{})}
	wire := &wireSession{identity: id, authorization: cloneAuthorization(original), conn: connection}
	server := &Server{config: Config{Authorizer: authorizer}, active: map[identity.NodeIdentity]*wireSession{id: wire}}
	if closed, err := server.Reauthorize(context.Background()); err != nil || closed != 0 {
		t.Fatalf("unchanged closed=%d err=%v", closed, err)
	}
	changed := cloneAuthorization(original)
	changed.AuthorizedPrefixes = append(changed.AuthorizedPrefixes, netip.MustParsePrefix("192.168.9.0/24"))
	if err := authorizer.Replace(map[identity.NodeIdentity]Authorization{id: changed}); err != nil {
		t.Fatal(err)
	}
	if closed, err := server.Reauthorize(context.Background()); err != nil || closed != 1 || connection.closed.Load() != 1 {
		t.Fatalf("changed closed=%d calls=%d err=%v", closed, connection.closed.Load(), err)
	}
	if err := authorizer.Replace(map[identity.NodeIdentity]Authorization{}); err != nil {
		t.Fatal(err)
	}
	if closed, err := server.Reauthorize(context.Background()); err != nil || closed != 1 || connection.closed.Load() != 2 {
		t.Fatalf("revoked closed=%d calls=%d err=%v", closed, connection.closed.Load(), err)
	}
	if err := authorizer.Replace(map[identity.NodeIdentity]Authorization{id: original}); err != nil {
		t.Fatal(err)
	}
	revoked := new(revocation.Set)
	server.config.Revocations = revoked
	wire.serial = []byte{1}
	if err := revoked.Replace([][]byte{{1}}); err != nil {
		t.Fatal(err)
	}
	if closed, err := server.Reauthorize(context.Background()); err != nil || closed != 1 || connection.closed.Load() != 3 {
		t.Fatalf("certificate-revoked closed=%d calls=%d err=%v", closed, connection.closed.Load(), err)
	}
}

type appendWriter struct{ target *[]byte }

func (w appendWriter) Write(p []byte) (int, error) {
	*w.target = append(*w.target, p...)
	return len(p), nil
}
