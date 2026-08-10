package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nodeservice"
)

func TestCompileEvaluateAndOrdering(t *testing.T) {
	network, sourceNode, destinationNode := id(1), identity.NodeID(id(2)), identity.NodeID(id(3))
	denyID, acceptID := id(9), id(8)
	snapshot := &lanewayv1.PolicySnapshot{
		NetworkId: network[:], ConfigurationEpoch: 7,
		DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{
			{RuleId: acceptID[:], Priority: 20, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT, Selector: selector(sourceNode, destinationNode, 22)},
			{RuleId: denyID[:], Priority: 10, Action: lanewayv1.PolicyAction_POLICY_ACTION_DENY, Selector: selector(sourceNode, destinationNode, 22)},
		},
	}
	engine, err := Compile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	packet := tcpPacket(t, "100.96.0.1", "100.96.0.2", 22)
	result := engine.Evaluate(sourceNode, destinationNode, packet)
	if result.Action != Deny || !result.Matched || result.RuleID != denyID {
		t.Fatalf("result = %#v", result)
	}
	packet = tcpPacket(t, "100.96.0.1", "100.96.0.2", 443)
	if result := engine.Evaluate(sourceNode, destinationNode, packet); result.Action != Deny || result.Matched {
		t.Fatalf("default result = %#v", result)
	}
}

func TestTableFailClosedAndReplace(t *testing.T) {
	var table Table
	packet := tcpPacket(t, "100.96.0.1", "100.96.0.2", 22)
	if table.Evaluate(identity.NodeID{}, identity.NodeID{}, packet).Action != Deny {
		t.Fatal("empty table did not fail closed")
	}
	if err := table.Replace(nil); err == nil {
		t.Fatal("nil engine accepted")
	}
}

func TestEvaluateReturnMatchesInitiatingSelectorInReverse(t *testing.T) {
	network, client, connector := id(1), identity.NodeID(id(2)), identity.NodeID(id(3))
	ruleID := id(8)
	engine, err := Compile(&lanewayv1.PolicySnapshot{
		NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{{
			RuleId: ruleID[:], Priority: 100, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
			Selector: &lanewayv1.TrafficSelector{
				SourceNodeIds:       [][]byte{client[:]},
				DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: []byte{10, 240, 64, 6}, PrefixLength: 32}},
				IpProtocol:          lanewayv1.IpProtocol_IP_PROTOCOL_TCP,
				DestinationPorts:    []*lanewayv1.PortRange{{First: 22, Last: 22}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	packet := tcpPacketPorts(t, "10.240.64.6", "100.96.0.2", 22, 49152)
	if result := engine.Evaluate(connector, client, packet); result.Action != Deny || result.Matched {
		t.Fatalf("ordinary return evaluation = %#v", result)
	}
	if result := engine.EvaluateReturn(connector, client, packet); result.Action != Accept || !result.Matched || result.RuleID != ruleID {
		t.Fatalf("reverse evaluation = %#v", result)
	}
	wrongPort := tcpPacketPorts(t, "10.240.64.6", "100.96.0.2", 23, 49152)
	if result := engine.EvaluateReturn(connector, client, wrongPort); result.Action != Deny || result.Matched {
		t.Fatalf("wrong source port matched return selector: %#v", result)
	}
}

func TestCompileRejectsUnsafeZeroValues(t *testing.T) {
	network := id(1)
	for _, snapshot := range []*lanewayv1.PolicySnapshot{
		nil,
		{NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_UNSPECIFIED},
		{NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY, Rules: []*lanewayv1.PolicyRule{{}}},
	} {
		if _, err := Compile(snapshot); err == nil {
			t.Fatalf("invalid snapshot accepted: %#v", snapshot)
		}
	}
}

func selector(source, destination identity.NodeID, port uint32) *lanewayv1.TrafficSelector {
	return &lanewayv1.TrafficSelector{
		SourceNodeIds: [][]byte{append([]byte(nil), source[:]...)}, DestinationNodeIds: [][]byte{append([]byte(nil), destination[:]...)},
		SourcePrefixes:      []*lanewayv1.IpPrefix{{Address: []byte{100, 96, 0, 0}, PrefixLength: 16}},
		DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: []byte{100, 96, 0, 0}, PrefixLength: 16}},
		IpProtocol:          lanewayv1.IpProtocol_IP_PROTOCOL_TCP,
		DestinationPorts:    []*lanewayv1.PortRange{{First: port, Last: port}},
	}
}

func tcpPacket(t *testing.T, source, destination string, port uint16) []byte {
	return tcpPacketPorts(t, source, destination, 49152, port)
}

func tcpPacketPorts(t *testing.T, source, destination string, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	packet, err := nodeservice.IPv4Packet(netip.MustParseAddr(source), netip.MustParseAddr(destination), make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	return packet
}

func id(last byte) identity.ID {
	var value identity.ID
	value[len(value)-1] = last
	return value
}
