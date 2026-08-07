package directpath

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
)

func testNetwork(t *testing.T, text string) identity.NetworkID {
	t.Helper()
	id, err := identity.ParseNetworkID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testNode(t *testing.T, text string) identity.NodeID {
	t.Helper()
	id, err := identity.ParseNodeID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testAuth(network identity.NetworkID, node identity.NodeID) identity.AuthenticatedIdentity {
	return identity.NodeIdentity{NetworkID: network, NodeID: node}.AuthenticatedIdentity()
}

func TestCandidateProtoValidationAndCanonicalization(t *testing.T) {
	node := testNode(t, "101112131415161718191a1b1c1d1e1f")
	policy := CandidatePolicy{AllowLoopback: true}
	message := &lanewayv1.EndpointCandidate{
		NodeId: node[:], IpAddress: netip.MustParseAddr("127.0.0.1").AsSlice(), Port: 443,
		Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP, Priority: 9,
	}
	candidate, err := CandidateFromProto(message, node, policy)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Address != netip.MustParseAddrPort("127.0.0.1:443") || candidate.Priority != 9 {
		t.Fatalf("candidate = %#v", candidate)
	}
	if roundTrip := candidate.Proto(); roundTrip.Transport != lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP || len(roundTrip.IpAddress) != 4 {
		t.Fatalf("round trip = %#v", roundTrip)
	}

	tests := []struct {
		name   string
		mutate func(*lanewayv1.EndpointCandidate)
	}{
		{"wrong node", func(m *lanewayv1.EndpointCandidate) { m.NodeId[0]++ }},
		{"short node", func(m *lanewayv1.EndpointCandidate) { m.NodeId = m.NodeId[:15] }},
		{"bad IP length", func(m *lanewayv1.EndpointCandidate) { m.IpAddress = []byte{1, 2, 3} }},
		{"zero port", func(m *lanewayv1.EndpointCandidate) { m.Port = 0 }},
		{"large port", func(m *lanewayv1.EndpointCandidate) { m.Port = 65536 }},
		{"wrong transport", func(m *lanewayv1.EndpointCandidate) {
			m.Transport = lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_TLS_TCP
		}},
		{"unspecified", func(m *lanewayv1.EndpointCandidate) { m.IpAddress = []byte{0, 0, 0, 0} }},
		{"multicast", func(m *lanewayv1.EndpointCandidate) { m.IpAddress = []byte{224, 0, 0, 1} }},
		{"broadcast", func(m *lanewayv1.EndpointCandidate) { m.IpAddress = []byte{255, 255, 255, 255} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyMessage := &lanewayv1.EndpointCandidate{NodeId: append([]byte(nil), message.NodeId...), IpAddress: append([]byte(nil), message.IpAddress...), Port: message.Port, Transport: message.Transport, Priority: message.Priority}
			test.mutate(copyMessage)
			if _, err := CandidateFromProto(copyMessage, node, policy); !errors.Is(err, ErrInvalidCandidate) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := CandidateFromProto(message, node, CandidatePolicy{}); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("loopback default policy error = %v", err)
	}
}

func TestValidateCandidatesBoundsDedupAndOrder(t *testing.T) {
	node := testNode(t, "101112131415161718191a1b1c1d1e1f")
	policy := CandidatePolicy{MaxCandidates: 2}
	a := Candidate{NodeID: node, Address: netip.MustParseAddrPort("10.0.0.2:2"), Priority: 10}
	b := Candidate{NodeID: node, Address: netip.MustParseAddrPort("10.0.0.1:1"), Priority: 1}
	ordered, err := ValidateCandidates([]Candidate{a, b}, node, policy)
	if err != nil {
		t.Fatal(err)
	}
	if ordered[0] != b || ordered[1] != a {
		t.Fatalf("ordered = %#v", ordered)
	}
	if _, err := ValidateCandidates([]Candidate{a, a}, node, policy); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := ValidateCandidates([]Candidate{a, b, a}, node, policy); !errors.Is(err, ErrTooManyCandidates) {
		t.Fatalf("bound error = %v", err)
	}
}

func TestRendezvousAuthenticationNetworkIsolationExpiryAndCopies(t *testing.T) {
	networkA := testNetwork(t, "000102030405060708090a0b0c0d0e0f")
	networkB := testNetwork(t, "202122232425262728292a2b2c2d2e2f")
	nodeA := testNode(t, "303132333435363738393a3b3c3d3e3f")
	nodeB := testNode(t, "404142434445464748494a4b4c4d4e4f")
	now := time.Unix(100, 0)
	rendezvous, err := NewRendezvous(CandidatePolicy{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate := Candidate{NodeID: nodeB, Address: netip.MustParseAddrPort("10.0.0.2:443"), Priority: 1}
	if err := rendezvous.Publish(testAuth(networkA, nodeB), []Candidate{candidate}, now); err != nil {
		t.Fatal(err)
	}
	got, err := rendezvous.Lookup(testAuth(networkA, nodeA), nodeB, now)
	if err != nil || len(got) != 1 || got[0] != candidate {
		t.Fatalf("lookup = %#v, %v", got, err)
	}
	got[0].Priority = 99
	again, _ := rendezvous.Lookup(testAuth(networkA, nodeA), nodeB, now)
	if again[0].Priority != 1 {
		t.Fatal("lookup exposed mutable rendezvous storage")
	}
	cross, err := rendezvous.Lookup(testAuth(networkB, nodeA), nodeB, now)
	if err != nil || len(cross) != 0 {
		t.Fatalf("cross-network lookup = %#v, %v", cross, err)
	}
	if expired, _ := rendezvous.Lookup(testAuth(networkA, nodeA), nodeB, now.Add(time.Second)); len(expired) != 0 {
		t.Fatalf("expired candidates = %#v", expired)
	}
	spoofed := candidate
	spoofed.NodeID = nodeA
	if err := rendezvous.Publish(testAuth(networkA, nodeB), []Candidate{spoofed}, now); !errors.Is(err, ErrInvalidCandidate) {
		t.Fatalf("spoof publish error = %v", err)
	}
	service := testAuth(networkA, nodeB)
	service.Role = identity.IdentityRoleRelay
	if err := rendezvous.Publish(service, []Candidate{candidate}, now); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("service publish error = %v", err)
	}
}
