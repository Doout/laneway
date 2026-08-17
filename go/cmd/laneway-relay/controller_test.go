package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/policy"
	"github.com/Doout/laneway/go/internal/revocation"
)

func TestRelayPacketPolicyAllowsAuthorizedReturnTraffic(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	client := identity.NodeID(relayTestID(2))
	connector := identity.NodeID(relayTestID(3))
	acceptID := relayTestID(4)
	denyID := relayTestID(5)
	acceptRule := &lanewayv1.PolicyRule{
		RuleId: acceptID[:], Priority: 100, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
		Selector: &lanewayv1.TrafficSelector{
			SourceNodeIds:       [][]byte{client[:]},
			DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: []byte{10, 240, 64, 6}, PrefixLength: 32}},
			IpProtocol:          lanewayv1.IpProtocol_IP_PROTOCOL_ANY,
		},
	}
	engine, err := policy.Compile(&lanewayv1.PolicySnapshot{
		NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{acceptRule},
	})
	if err != nil {
		t.Fatal(err)
	}
	forward := relayIPv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("10.240.64.6"))
	reply := relayIPv4Packet(netip.MustParseAddr("10.240.64.6"), netip.MustParseAddr("100.96.0.2"))
	if !relayPacketAllowed(engine, client, connector, forward) {
		t.Fatal("relay denied authorized initiating traffic")
	}
	if !relayPacketAllowed(engine, connector, client, reply) {
		t.Fatal("relay denied authorized Connector return traffic")
	}

	engine, err = policy.Compile(&lanewayv1.PolicySnapshot{
		NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{
			{RuleId: denyID[:], Priority: 50, Action: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
				Selector: &lanewayv1.TrafficSelector{SourceNodeIds: [][]byte{connector[:]}, DestinationNodeIds: [][]byte{client[:]}, IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY}},
			acceptRule,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if relayPacketAllowed(engine, connector, client, reply) {
		t.Fatal("relay return handling overrode an explicit deny")
	}
}

func TestControllerRelayStatePublishesCompleteSnapshots(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	nodeID := identity.NodeID(relayTestID(2))
	revoked := new(revocation.Set)
	state, err := newControllerRelayState(network, revoked)
	if err != nil {
		t.Fatal(err)
	}
	node := identity.NodeIdentity{NetworkID: network, NodeID: nodeID}
	if _, err := state.Authorize(context.Background(), node); err == nil {
		t.Fatal("uninitialized controller state authorized a node")
	}
	configuration := relayTestConfiguration(network, nodeID, 4, lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT)
	configuration.RevokedCertificateSerials = [][]byte{{0x12, 0x34}}
	if err := state.Replace(configuration); err != nil {
		t.Fatal(err)
	}
	if state.Epoch() != 4 {
		t.Fatalf("epoch = %d", state.Epoch())
	}
	if !revoked.IsRevoked([]byte{0x12, 0x34}) {
		t.Fatal("controller relay revocation snapshot was not published")
	}
	authorization, err := state.Authorize(context.Background(), node)
	if err != nil || len(authorization.OverlayAddresses) != 1 || len(authorization.AuthorizedPrefixes) != 2 {
		t.Fatalf("authorization = %#v, %v", authorization, err)
	}
	packet := relayIPv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("192.168.50.2"))
	if !state.Allow(node, node, packet) {
		t.Fatal("compiled accept policy denied a valid packet")
	}

	configuration.Policy.DefaultAction = lanewayv1.PolicyAction_POLICY_ACTION_DENY
	if !state.Allow(node, node, packet) {
		t.Fatal("mutating source protobuf changed an installed snapshot")
	}
	if err := state.Replace(relayTestConfiguration(network, nodeID, 4, lanewayv1.PolicyAction_POLICY_ACTION_DENY)); err == nil {
		t.Fatal("non-advancing controller epoch accepted")
	}
	if state.Epoch() != 4 || !state.Allow(node, node, packet) {
		t.Fatal("rejected replacement changed published state")
	}
	if err := state.Replace(relayTestConfiguration(network, nodeID, 5, lanewayv1.PolicyAction_POLICY_ACTION_DENY)); err != nil {
		t.Fatal(err)
	}
	if state.Allow(node, node, packet) {
		t.Fatal("replacement deny policy was not published")
	}
}

func TestControllerRelayStateFailsClosedAtLeaseExpiryAndRenews(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	nodeID := identity.NodeID(relayTestID(2))
	node := identity.NodeIdentity{NetworkID: network, NodeID: nodeID}
	state, err := newControllerRelayState(network)
	if err != nil {
		t.Fatal(err)
	}
	configuration := relayTestConfiguration(network, nodeID, 1, lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT)
	if err := state.Replace(configuration); err != nil {
		t.Fatal(err)
	}
	current := state.current.Load()
	state.current.Store(&controllerRelaySnapshot{
		epoch: current.epoch, validUntil: time.Now().Unix() - 1,
		authorizer: current.authorizer, policy: current.policy,
	})
	if _, err := state.Authorize(context.Background(), node); err == nil {
		t.Fatal("expired relay snapshot authorized a node")
	}
	packet := relayIPv4Packet(netip.MustParseAddr("100.96.0.2"), netip.MustParseAddr("192.168.50.2"))
	if state.Allow(node, node, packet) {
		t.Fatal("expired relay snapshot allowed a packet")
	}
	if err := state.Renew(uint64(time.Now().Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	renewedUntil := state.ValidUntil()
	if err := state.Renew(uint64(renewedUntil.Add(-time.Minute).Unix())); err == nil {
		t.Fatal("controller relay accepted a shorter lease deadline")
	}
	if !state.ValidUntil().Equal(renewedUntil) {
		t.Fatal("rejected shorter lease changed the relay deadline")
	}
	if _, err := state.Authorize(context.Background(), node); err != nil {
		t.Fatalf("renewed relay snapshot did not restore authorization: %v", err)
	}
}

func TestCompileRelayConfigurationRejectsInconsistentSnapshots(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	node := identity.NodeID(relayTestID(2))
	tests := map[string]func(*lanewayv1.RelayConfiguration){
		"wrong network": func(c *lanewayv1.RelayConfiguration) { c.NetworkId[15]++ },
		"policy epoch":  func(c *lanewayv1.RelayConfiguration) { c.Policy.ConfigurationEpoch++ },
		"permissive policy default": func(c *lanewayv1.RelayConfiguration) {
			c.Policy.DefaultAction = lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT
		},
		"zero node": func(c *lanewayv1.RelayConfiguration) {
			c.Peers[0].NodeId = make([]byte, identity.IDSize)
		},
		"missing host prefix": func(c *lanewayv1.RelayConfiguration) {
			c.Peers[0].AuthorizedPrefixes = c.Peers[0].AuthorizedPrefixes[1:]
		},
		"duplicate node": func(c *lanewayv1.RelayConfiguration) { c.Peers = append(c.Peers, c.Peers[0]) },
		"duplicate overlay": func(c *lanewayv1.RelayConfiguration) {
			other := identity.NodeID(relayTestID(3))
			peer := relayTestConfiguration(network, other, c.ConfigurationEpoch, c.Policy.DefaultAction).Peers[0]
			peer.OverlayAddresses[0] = append([]byte(nil), c.Peers[0].OverlayAddresses[0]...)
			peer.AuthorizedPrefixes[0] = c.Peers[0].AuthorizedPrefixes[0]
			c.Peers = append(c.Peers, peer)
		},
	}
	for name, edit := range tests {
		t.Run(name, func(t *testing.T) {
			configuration := relayTestConfiguration(network, node, 1, lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT)
			edit(configuration)
			if _, err := compileRelayConfiguration(configuration, network); err == nil {
				t.Fatal("invalid relay configuration accepted")
			}
		})
	}
}

func TestCompileRelayConfigurationRequiresExactLocalCertificateHealth(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	configuration := relayTestConfiguration(network, identity.NodeID(relayTestID(2)), 1, lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT)
	health := &relayCertificateHealth{serial: []byte{7}, notAfter: uint64(time.Now().Add(time.Hour).Unix()), renewAfter: uint64(time.Now().Add(-time.Minute).Unix())}
	if _, err := compileRelayConfiguration(configuration, network, health); err == nil {
		t.Fatal("missing relay certificate health was accepted")
	}
	configuration.CertificateHealth = &lanewayv1.CertificateHealth{PresentedSerial: []byte{7}, NotAfterUnixSeconds: health.notAfter, RenewAfterUnixSeconds: health.renewAfter}
	if _, err := compileRelayConfiguration(configuration, network, health); err != nil {
		t.Fatal(err)
	}
}

func TestRunRelayConfigurationUpdatesRetriesAndReauthorizes(t *testing.T) {
	network := identity.NetworkID(relayTestID(1))
	node := identity.NodeID(relayTestID(2))
	source := &relaySequenceSource{responses: []relaySequenceResponse{
		{err: errors.New("temporary controller failure")},
		{configuration: relayTestConfiguration(network, node, 1, lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT)},
		{configuration: relayTestConfiguration(network, node, 2, lanewayv1.PolicyAction_POLICY_ACTION_DENY)},
		{configuration: &lanewayv1.RelayConfiguration{ValidUntilUnixSeconds: uint64(time.Now().Add(time.Hour).Unix())}, unchanged: true},
	}}
	state, _ := newControllerRelayState(network)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	var reauthorized atomic.Int32
	var reported atomic.Int32
	go func() {
		done <- runRelayConfigurationUpdates(ctx, 5*time.Millisecond, source, state, func(context.Context) error {
			reauthorized.Add(1)
			return nil
		}, ready, func(error) { reported.Add(1) })
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial relay configuration did not become ready")
	}
	relayEventually(t, time.Second, func() bool { return state.Epoch() == 2 })
	if reported.Load() == 0 || reauthorized.Load() < 2 {
		t.Fatalf("reported=%d reauthorized=%d", reported.Load(), reauthorized.Load())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("update loop error = %v", err)
	}
	if source.knownEpochs()[0] != 0 {
		t.Fatal("initial request did not ask for a complete snapshot")
	}
}

type relaySequenceResponse struct {
	configuration *lanewayv1.RelayConfiguration
	unchanged     bool
	err           error
}

type relaySequenceSource struct {
	mu        sync.Mutex
	responses []relaySequenceResponse
	known     []uint64
	calls     int
}

func (s *relaySequenceSource) RelayConfiguration(_ context.Context, known uint64) (*lanewayv1.RelayConfiguration, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.known = append(s.known, known)
	index := s.calls
	s.calls++
	if index >= len(s.responses) {
		index = len(s.responses) - 1
	}
	response := s.responses[index]
	return response.configuration, response.unchanged, response.err
}

func (s *relaySequenceSource) knownEpochs() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.known...)
}

func relayTestConfiguration(network identity.NetworkID, node identity.NodeID, epoch uint64, defaultAction lanewayv1.PolicyAction) *lanewayv1.RelayConfiguration {
	overlay := netip.MustParseAddr("100.96.0.2")
	subnet := netip.MustParsePrefix("192.168.50.0/24")
	return &lanewayv1.RelayConfiguration{
		NetworkId: append([]byte(nil), network[:]...), ConfigurationEpoch: epoch,
		ValidUntilUnixSeconds: uint64(time.Now().Add(time.Hour).Unix()),
		Peers: []*lanewayv1.RelayPeerAuthorization{{
			NodeId: append([]byte(nil), node[:]...), OverlayAddresses: [][]byte{append([]byte(nil), overlay.AsSlice()...)},
			AuthorizedPrefixes: []*lanewayv1.IpPrefix{
				{Address: append([]byte(nil), overlay.AsSlice()...), PrefixLength: 32},
				{Address: append([]byte(nil), subnet.Addr().AsSlice()...), PrefixLength: 24},
			},
		}},
		Policy: relayTestPolicy(network, epoch, defaultAction == lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT),
	}
}

func relayTestPolicy(network identity.NetworkID, epoch uint64, allow bool) *lanewayv1.PolicySnapshot {
	snapshot := &lanewayv1.PolicySnapshot{
		NetworkId: append([]byte(nil), network[:]...), ConfigurationEpoch: epoch,
		DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
	}
	if allow {
		ruleID := relayTestID(9)
		snapshot.Rules = []*lanewayv1.PolicyRule{{
			RuleId: ruleID[:], Priority: 1, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
			Selector: &lanewayv1.TrafficSelector{IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY},
		}}
	}
	return snapshot
}

func TestControllerRelayCertificateRenewalTracksClockBoundary(t *testing.T) {
	state, err := newControllerRelayState(identity.NetworkID(relayTestID(1)))
	if err != nil {
		t.Fatal(err)
	}
	threshold := time.Unix(2_000_000_000, 0).UTC()
	state.current.Store(&controllerRelaySnapshot{
		certificateRenewAfter: uint64(threshold.Unix()), certificateNotAfter: uint64(threshold.Add(time.Hour).Unix()),
	})
	if needed, renewAfter, _ := state.certificateHealthAt(threshold.Add(-time.Second)); needed || renewAfter != uint64(threshold.Unix()) {
		t.Fatalf("health before threshold = %t, %d", needed, renewAfter)
	}
	if needed, _, _ := state.certificateHealthAt(threshold); !needed {
		t.Fatal("renewal was not needed at the exact threshold")
	}
	state.current.Store(&controllerRelaySnapshot{renewalNeeded: true, certificateRenewAfter: uint64(threshold.Add(time.Hour).Unix())})
	if needed, _, _ := state.certificateHealthAt(threshold); !needed {
		t.Fatal("forced renewal state was not preserved")
	}
}

func relayIPv4Packet(source, destination netip.Addr) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[9] = byte(lanewayv1.IpProtocol_IP_PROTOCOL_ICMP)
	source4, destination4 := source.As4(), destination.As4()
	copy(packet[12:16], source4[:])
	copy(packet[16:20], destination4[:])
	return packet
}

func relayTestID(last byte) identity.ID {
	var id identity.ID
	id[len(id)-1] = last
	return id
}

func relayEventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
