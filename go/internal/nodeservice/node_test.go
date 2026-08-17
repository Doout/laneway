package nodeservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/agent"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/transport"
	"github.com/Doout/laneway/go/internal/wireguard"
)

type fakePackets struct{}

func (fakePackets) ReadPacket(context.Context, []byte) (int, error) { return 0, context.Canceled }
func (fakePackets) WritePacket(context.Context, []byte) error       { return nil }

type fakeWireGuardRelayHandler struct{}

func (fakeWireGuardRelayHandler) RunRelay(ctx context.Context, _ *wireguard.RelayMux, _ pathmanager.PathKind, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

type recordingCandidateSink struct {
	messages []*lanewayv1.EndpointCandidate
}

func (s *recordingCandidateSink) HandleCandidate(_ context.Context, candidate *lanewayv1.EndpointCandidate) error {
	s.messages = append(s.messages, candidate)
	return nil
}

type inertEncryptedCarrier struct{ done chan struct{} }

func (inertEncryptedCarrier) SendPacket(context.Context, []byte) error { return nil }
func (inertEncryptedCarrier) ReceivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	return nil, nil, ctx.Err()
}
func (c inertEncryptedCarrier) Done() <-chan struct{} { return c.done }
func (inertEncryptedCarrier) Close() error            { return nil }

type testRelayAuthority struct {
	targets []RelayTarget
	change  chan struct{}
}

func (a *testRelayAuthority) RelayTargets() []RelayTarget {
	return append([]RelayTarget(nil), a.targets...)
}
func (a *testRelayAuthority) RelayAuthorityChanges() <-chan struct{} { return a.change }

type recordingRelayDialer struct {
	mu        sync.Mutex
	addresses []string
	tls       []*tls.Config
}

func (d *recordingRelayDialer) DialRelay(_ context.Context, address string, config *tls.Config, _ *transport.Config) (*transport.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.tls = append(d.tls, config)
	d.mu.Unlock()
	return nil, errors.New("unreachable")
}

func TestBindingTableReplaceAndRelease(t *testing.T) {
	var table bindingTable
	table.byPeer = make(map[identity.NodeID]uint32)
	table.byHandle = make(map[uint32]identity.NodeID)
	peerA, peerB := testNodeID(1), testNodeID(2)
	table.set(peerA, 10)
	table.set(peerA, 11)
	if _, ok := table.peer(10); ok {
		t.Fatal("old handle retained")
	}
	table.set(peerB, 11)
	if _, ok := table.handle(peerA); ok {
		t.Fatal("old peer retained after handle reuse")
	}
	if got, ok := table.peer(11); !ok || got != peerB {
		t.Fatalf("handle lookup = %v, %v", got, ok)
	}
	if !table.release(11) || table.release(11) {
		t.Fatal("release was not one-shot")
	}
}

func TestIPv4Packet(t *testing.T) {
	source := netip.MustParseAddr("100.96.0.1")
	destination := netip.MustParseAddr("100.96.0.2")
	packet, err := IPv4Packet(source, destination, []byte("laneway"))
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.ValidateIPPayload(packet); err != nil {
		t.Fatal(err)
	}
	gotSource, gotDestination, ok := packetAddresses(packet)
	if !ok || gotSource != source || gotDestination != destination {
		t.Fatalf("addresses = %s, %s, %v", gotSource, gotDestination, ok)
	}
}

func TestHandshakeAndRegister(t *testing.T) {
	service := testService(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		framer := protocol.ControlFramer{MaxPayload: protocol.DefaultMaxControlFrame}
		hello := new(lanewayv1.ControlEnvelope)
		if err := readMessage(server, framer, hello); err != nil {
			serverErr <- err
			return
		}
		if hello.GetHello() == nil || hello.GetHello().GetCapabilities() != uint64(agentCaps()) {
			serverErr <- ErrControlBody
			return
		}
		sessionID := testID(9)
		welcome := &lanewayv1.ControlEnvelope{
			SchemaVersion: 1,
			Sequence:      1,
			Body: &lanewayv1.ControlEnvelope_Welcome{Welcome: &lanewayv1.Welcome{
				SessionId:          sessionID[:],
				OverlayAddresses:   [][]byte{{100, 96, 0, 1}},
				Capabilities:       uint64(agentCaps()),
				MaxControlPayload:  protocol.DefaultMaxControlFrame,
				MaxPacketPayload:   1500,
				ConfigurationEpoch: 1,
			}},
		}
		if err := writeMessage(server, framer, welcome); err != nil {
			serverErr <- err
			return
		}
		register := new(lanewayv1.RelayEnvelope)
		if err := readMessage(server, framer, register); err != nil {
			serverErr <- err
			return
		}
		if register.GetRegister() == nil || register.GetSequence() != 1 || register.GetRegister().GetRequestedMaxRoutes() != DefaultMaxRoutes {
			serverErr <- ErrControlBody
			return
		}
		serverErr <- nil
	}()
	params, err := service.handshake(client)
	if err != nil {
		t.Fatal(err)
	}
	if params.ConfigurationEpoch != 1 || params.OverlayAddresses[0] != netip.MustParseAddr("100.96.0.1") {
		t.Fatalf("session parameters: %#v", params)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	config := testConfig(t)
	config.BootID = identity.ID{}
	if _, err := New(config); err == nil {
		t.Fatal("zero boot ID accepted")
	}
}

func TestWireGuardRelayConfigurationIsExclusiveAndAdvertisesE2E(t *testing.T) {
	config := testConfig(t)
	config.WireGuardRelay = fakeWireGuardRelayHandler{}
	if _, err := New(config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mixed plaintext/encrypted config error = %v", err)
	}
	config.Packets = nil
	sink := new(recordingCandidateSink)
	config.CandidateSink = sink
	config.LocalCandidate = &lanewayv1.EndpointCandidate{Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP}
	service, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := service.AdvertisedCapabilities()
	if !capabilities.Has(protocol.CapabilityE2EPacketV1) || !capabilities.Has(protocol.CapabilityDirectPeerV1) {
		t.Fatalf("advertised capabilities = %s", capabilities)
	}
	service.metrics.carrier.Store(carrierQUIC)
	if got := service.SelectedCarrier(); got != "wireguard-relay-quic" {
		t.Fatalf("QUIC carrier = %q", got)
	}
	service.metrics.carrier.Store(carrierTCP)
	if got := service.SelectedCarrier(); got != "wireguard-relay-tcp" {
		t.Fatalf("TCP carrier = %q", got)
	}
	plain := testService(t)
	if plain.AdvertisedCapabilities().Has(protocol.CapabilityE2EPacketV1) {
		t.Fatal("plaintext service advertised encrypted packet support")
	}
}

func TestWireGuardControlLoopPublishesAndReleasesSessionBindings(t *testing.T) {
	service := testService(t)
	params := agent.SessionParameters{EffectiveMaxControlPayload: protocol.DefaultMaxControlFrame, Capabilities: protocol.CapabilityDirectPeerV1}
	peer := testNodeID(8)
	newMux := func(t *testing.T) *wireguard.RelayMux {
		t.Helper()
		mux, err := wireguard.NewRelayMux(inertEncryptedCarrier{done: make(chan struct{})}, protocol.CapabilityE2EPacketV1)
		if err != nil {
			t.Fatal(err)
		}
		return mux
	}
	remoteError := &lanewayv1.RelayEnvelope_Error{Error: &lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, Detail: "stop"}}

	mux := newMux(t)
	var stream bytes.Buffer
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 1,
		Body: &lanewayv1.RelayEnvelope_RouteHandleBinding{RouteHandleBinding: &lanewayv1.RouteHandleBinding{
			PeerNodeId: peer[:], RouteHandle: 17, MaxPacketPayload: 1280,
		}}}); err != nil {
		t.Fatal(err)
	}
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 2, Body: remoteError}); err != nil {
		t.Fatal(err)
	}
	if err := service.controlLoopWireGuard(context.Background(), &stream, params, mux); err == nil {
		t.Fatal("remote stop was accepted")
	}
	if peers := mux.Peers(); len(peers) != 1 || peers[0] != peer {
		t.Fatalf("published peers = %v", peers)
	}

	stream.Reset()
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 1,
		Body: &lanewayv1.RelayEnvelope_RouteHandleRelease{RouteHandleRelease: &lanewayv1.RouteHandleRelease{RouteHandle: 17}}}); err != nil {
		t.Fatal(err)
	}
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 2, Body: remoteError}); err != nil {
		t.Fatal(err)
	}
	if err := service.controlLoopWireGuard(context.Background(), &stream, params, mux); err == nil {
		t.Fatal("remote stop was accepted")
	}
	if peers := mux.Peers(); len(peers) != 0 {
		t.Fatalf("released peers = %v", peers)
	}

	sink := new(recordingCandidateSink)
	service.config.CandidateSink = sink
	stream.Reset()
	candidate := &lanewayv1.EndpointCandidate{NodeId: peer[:], Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP}
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 1,
		Body: &lanewayv1.RelayEnvelope_EndpointCandidate{EndpointCandidate: candidate}}); err != nil {
		t.Fatal(err)
	}
	if err := writeMessage(&stream, params.ControlFramer(), &lanewayv1.RelayEnvelope{SchemaVersion: 1, Sequence: 2, Body: remoteError}); err != nil {
		t.Fatal(err)
	}
	if err := service.controlLoopWireGuard(context.Background(), &stream, params, mux); err == nil {
		t.Fatal("remote stop was accepted")
	}
	if len(sink.messages) != 1 || !bytes.Equal(sink.messages[0].GetNodeId(), peer[:]) || sink.messages[0].GetTransport() != candidate.GetTransport() {
		t.Fatalf("candidates=%v", sink.messages)
	}
}

func TestControllerRelayTargetsAreTriedInDeterministicOrder(t *testing.T) {
	config := testConfig(t)
	config.TLSConfig.VerifyConnection = func(tls.ConnectionState) error { return nil }
	dialer := new(recordingRelayDialer)
	config.RelayDialer = dialer
	config.RelayServiceID = testID(4)
	config.RelayAuthority = &testRelayAuthority{change: make(chan struct{}), targets: []RelayTarget{
		{ServiceID: testID(9), Address: "127.0.0.1:9009"},
		{ServiceID: testID(4), Address: "127.0.0.1:9004"},
	}}
	service, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.dialQUIC(context.Background()); err == nil {
		t.Fatal("unreachable controller relays unexpectedly connected")
	}
	if want := []string{"127.0.0.1:9004", "127.0.0.1:9009"}; !reflect.DeepEqual(dialer.addresses, want) {
		t.Fatalf("relay dial order = %v, want %v", dialer.addresses, want)
	}
	certificate := func(service identity.ID) *x509.Certificate {
		uri, err := (identity.AuthenticatedIdentity{
			NetworkID: config.Identity.NetworkID, Role: identity.IdentityRoleRelay, SubjectID: service,
		}).URI()
		if err != nil {
			t.Fatal(err)
		}
		return &x509.Certificate{URIs: []*url.URL{uri}}
	}
	if err := dialer.tls[0].VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate(testID(4))}}); err != nil {
		t.Fatalf("alternate relay exact identity was rejected: %v", err)
	}
	if err := dialer.tls[0].VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate(testID(9))}}); err == nil {
		t.Fatal("wrong relay identity was accepted for alternate target")
	}
}

func TestCandidatePublisherRetriesWithinLongLivedSession(t *testing.T) {
	service := testService(t)
	service.config.LocalCandidate = &lanewayv1.EndpointCandidate{Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP}
	service.config.DirectRendezvousInterval = 10 * time.Millisecond
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	params := agent.SessionParameters{EffectiveMaxControlPayload: protocol.DefaultMaxControlFrame}
	go func() { done <- service.candidatePublishLoop(ctx, server, params, 3) }()
	for want := uint64(3); want <= 4; want++ {
		envelope := new(lanewayv1.RelayEnvelope)
		if err := readMessage(client, params.ControlFramer(), envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.GetSequence() != want || envelope.GetEndpointCandidate() == nil {
			t.Fatalf("published candidate = %#v, want sequence %d", envelope, want)
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("publisher stop = %v", err)
	}
}

func testService(t *testing.T) *Service {
	t.Helper()
	service, err := New(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testConfig(t *testing.T) Config {
	t.Helper()
	snapshot, err := routing.NewSnapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Identity:     identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: testNodeID(2)},
		BootID:       testID(3),
		RelayAddress: "127.0.0.1:1",
		TLSConfig:    &tls.Config{},
		Routes:       routing.NewTable(snapshot),
		Packets:      fakePackets{},
	}
}

func testID(last byte) identity.ID {
	var id identity.ID
	id[len(id)-1] = last
	return id
}

func testNodeID(last byte) identity.NodeID { return identity.NodeID(testID(last)) }

func agentCaps() protocol.Capability {
	return protocol.CapabilityRelayV1 | protocol.CapabilityQUICDatagramV1
}
