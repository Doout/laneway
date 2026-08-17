package nodeapp

import (
	"fmt"
	"net/netip"
	"testing"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/wireguard"
)

func snapshotKey(t *testing.T) wireguard.PublicKey {
	t.Helper()
	_, public, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func snapshotPrefix(value string) *lanewayv1.IpPrefix {
	prefix := netip.MustParsePrefix(value)
	return &lanewayv1.IpPrefix{Address: prefix.Addr().AsSlice(), PrefixLength: uint32(prefix.Bits())}
}

func TestPrepareWireGuardSnapshotBindsKeysRoutesExitAndPolicy(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer, exit := identity.NodeID(testID(3)), identity.NodeID(testID(4))
	localKey, peerKey, exitKey := snapshotKey(t), snapshotKey(t), snapshotKey(t)
	ruleID := testID(9)
	configuration := &lanewayv1.NodeConfiguration{ConfigurationEpoch: 8,
		Peers: []*lanewayv1.NodePeer{
			{NodeId: local.NodeID[:], Name: "local", OverlayAddresses: [][]byte{{100, 96, 0, 1}}, WireguardPublicKey: localKey.Bytes()},
			{NodeId: peer[:], Name: "peer", OverlayAddresses: [][]byte{{100, 96, 0, 2}}, WireguardPublicKey: peerKey.Bytes()},
			{NodeId: exit[:], Name: "exit", OverlayAddresses: [][]byte{{100, 96, 0, 3}}, WireguardPublicKey: exitKey.Bytes()},
		},
		Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
			{Destination: snapshotPrefix("100.96.0.1/32"), ViaNodeId: local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{Destination: snapshotPrefix("100.96.0.2/32"), ViaNodeId: peer[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{Destination: snapshotPrefix("192.168.50.0/24"), ViaNodeId: peer[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_SUBNET},
			{Destination: snapshotPrefix("100.96.0.3/32"), ViaNodeId: exit[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{Destination: snapshotPrefix("0.0.0.0/0"), ViaNodeId: exit[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT},
		}},
		Policy: &lanewayv1.PolicySnapshot{DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY, Rules: []*lanewayv1.PolicyRule{{
			RuleId: ruleID[:], Priority: 5, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
			Selector: &lanewayv1.TrafficSelector{SourceNodeIds: [][]byte{peer[:]}, DestinationNodeIds: [][]byte{local.NodeID[:]},
				IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_TCP, DestinationPorts: []*lanewayv1.PortRange{{First: 443, Last: 443}}},
		}}},
	}
	prepared, err := prepareWireGuardSnapshot(configuration, local, localKey, identity.NodeID{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.peers) != 2 || len(prepared.firewall.Rules) != 1 {
		t.Fatalf("prepared=%+v", prepared)
	}
	prefixes := prepared.firewall.PeerPrefixes
	if !containsPrefix(prefixes[peer], "100.96.0.2/32") || !containsPrefix(prefixes[peer], "192.168.50.0/24") ||
		containsPrefix(prefixes[exit], "0.0.0.0/0") || prepared.firewall.Rules[0].Protocol != 6 ||
		prepared.firewall.Rules[0].DestinationPorts[0].First != 443 {
		t.Fatalf("firewall=%+v", prepared.firewall)
	}
	prepared, err = prepareWireGuardSnapshot(configuration, local, localKey, exit)
	if err != nil {
		t.Fatal(err)
	}
	exitPrefixes := prepared.firewall.PeerPrefixes[exit]
	if prefixSetContainsAddress(exitPrefixes, netip.MustParseAddr("100.96.0.1")) ||
		prefixSetContainsAddress(exitPrefixes, netip.MustParseAddr("100.96.0.2")) ||
		prefixSetContainsAddress(exitPrefixes, netip.MustParseAddr("192.168.50.10")) ||
		prefixSetContainsAddress(exitPrefixes, netip.IPv4Unspecified()) ||
		prefixSetContainsAddress(exitPrefixes, netip.MustParseAddr("224.0.0.1")) ||
		!prefixSetContainsAddress(exitPrefixes, netip.MustParseAddr("1.1.1.1")) {
		t.Fatalf("partitioned exit ownership=%v", exitPrefixes)
	}
	if err := requireDisjointPeerPrefixes(prepared.peers); err != nil {
		t.Fatalf("partitioned peers overlap: %v", err)
	}
}

func TestPrepareWireGuardSnapshotRejectsIdentityKeyAndExitMismatches(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	localKey, peerKey := snapshotKey(t), snapshotKey(t)
	base := func() *lanewayv1.NodeConfiguration {
		return &lanewayv1.NodeConfiguration{ConfigurationEpoch: 1,
			Peers: []*lanewayv1.NodePeer{
				{NodeId: local.NodeID[:], OverlayAddresses: [][]byte{{100, 96, 0, 1}}, WireguardPublicKey: localKey.Bytes()},
				{NodeId: peer[:], OverlayAddresses: [][]byte{{100, 96, 0, 2}}, WireguardPublicKey: peerKey.Bytes()},
			}, Routes: &lanewayv1.RouteSnapshot{},
			Policy: &lanewayv1.PolicySnapshot{DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY}}
	}
	wrongKey := base()
	wrongKey.Peers[0].WireguardPublicKey = peerKey.Bytes()
	if _, err := prepareWireGuardSnapshot(wrongKey, local, localKey, identity.NodeID{}); err == nil {
		t.Fatal("wrong local key accepted")
	}
	missing := base()
	missing.Peers = missing.Peers[1:]
	if _, err := prepareWireGuardSnapshot(missing, local, localKey, identity.NodeID{}); err == nil {
		t.Fatal("missing local node accepted")
	}
	if _, err := prepareWireGuardSnapshot(base(), local, localKey, identity.NodeID(testID(8))); err == nil {
		t.Fatal("absent exit accepted")
	}
}

func containsPrefix(prefixes []netip.Prefix, value string) bool {
	want := netip.MustParsePrefix(value)
	for _, prefix := range prefixes {
		if prefix == want {
			return true
		}
	}
	return false
}

func prefixSetContainsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func requireDisjointPeerPrefixes(peers []wireguard.ManagedPeer) error {
	for left, peer := range peers {
		for _, prefix := range peer.AllowedIPs {
			for right := left + 1; right < len(peers); right++ {
				for _, other := range peers[right].AllowedIPs {
					if prefix.Addr().BitLen() == other.Addr().BitLen() &&
						(prefix.Contains(other.Addr()) || other.Contains(prefix.Addr())) {
						return fmt.Errorf("%s and %s", prefix, other)
					}
				}
			}
		}
	}
	return nil
}
