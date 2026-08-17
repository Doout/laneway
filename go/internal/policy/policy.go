// Package policy compiles controller ACL snapshots into immutable packet-path
// evaluators. Evaluation performs no allocation and never consults storage.
package policy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

var ErrInvalidPolicy = errors.New("invalid Laneway policy")

type Action uint8

const (
	Deny Action = iota
	Accept
)

type Result struct {
	Action  Action
	RuleID  identity.ID
	Matched bool
}

type Engine struct {
	epoch         uint64
	network       identity.NetworkID
	rules         []compiledRule
	defaultAction Action
}

type compiledRule struct {
	id                  identity.ID
	priority            uint32
	action              Action
	sourceNodes         []identity.NodeID
	destinationNodes    []identity.NodeID
	sourcePrefixes      []netip.Prefix
	destinationPrefixes []netip.Prefix
	protocol            int32
	ports               []portRange
}

type portRange struct{ first, last uint16 }

func Compile(snapshot *lanewayv1.PolicySnapshot) (*Engine, error) {
	if snapshot == nil || len(snapshot.GetNetworkId()) != identity.IDSize {
		return nil, ErrInvalidPolicy
	}
	var network identity.NetworkID
	copy(network[:], snapshot.GetNetworkId())
	if network.IsZero() {
		return nil, ErrInvalidPolicy
	}
	defaultAction, err := compileAction(snapshot.GetDefaultAction())
	if err != nil {
		return nil, err
	}
	engine := &Engine{epoch: snapshot.GetConfigurationEpoch(), network: network, defaultAction: defaultAction}
	seen := make(map[identity.ID]struct{}, len(snapshot.GetRules()))
	for i, input := range snapshot.GetRules() {
		rule, err := compileRule(input)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %d: %v", ErrInvalidPolicy, i, err)
		}
		if _, duplicate := seen[rule.id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate rule ID", ErrInvalidPolicy)
		}
		seen[rule.id] = struct{}{}
		engine.rules = append(engine.rules, rule)
	}
	sort.Slice(engine.rules, func(i, j int) bool {
		if engine.rules[i].priority != engine.rules[j].priority {
			return engine.rules[i].priority < engine.rules[j].priority
		}
		return bytes.Compare(engine.rules[i].id[:], engine.rules[j].id[:]) < 0
	})
	return engine, nil
}

func compileRule(input *lanewayv1.PolicyRule) (compiledRule, error) {
	if input == nil || len(input.GetRuleId()) != identity.IDSize || input.GetSelector() == nil {
		return compiledRule{}, ErrInvalidPolicy
	}
	var rule compiledRule
	copy(rule.id[:], input.GetRuleId())
	if rule.id.IsZero() {
		return compiledRule{}, ErrInvalidPolicy
	}
	rule.priority = input.GetPriority()
	action, err := compileAction(input.GetAction())
	if err != nil {
		return compiledRule{}, err
	}
	rule.action = action
	selector := input.GetSelector()
	if selector.GetIpProtocol() == lanewayv1.IpProtocol_IP_PROTOCOL_UNSPECIFIED {
		return compiledRule{}, errors.New("IP protocol is unspecified")
	}
	rule.protocol = int32(selector.GetIpProtocol())
	if rule.protocol != int32(lanewayv1.IpProtocol_IP_PROTOCOL_ANY) && (rule.protocol < 0 || rule.protocol > 255) {
		return compiledRule{}, errors.New("invalid IP protocol")
	}
	if rule.sourceNodes, err = compileNodes(selector.GetSourceNodeIds()); err != nil {
		return compiledRule{}, err
	}
	if rule.destinationNodes, err = compileNodes(selector.GetDestinationNodeIds()); err != nil {
		return compiledRule{}, err
	}
	if rule.sourcePrefixes, err = compilePrefixes(selector.GetSourcePrefixes()); err != nil {
		return compiledRule{}, err
	}
	if rule.destinationPrefixes, err = compilePrefixes(selector.GetDestinationPrefixes()); err != nil {
		return compiledRule{}, err
	}
	for _, inputRange := range selector.GetDestinationPorts() {
		if inputRange == nil || inputRange.GetFirst() == 0 || inputRange.GetFirst() > inputRange.GetLast() || inputRange.GetLast() > 65535 {
			return compiledRule{}, errors.New("invalid destination port range")
		}
		rule.ports = append(rule.ports, portRange{uint16(inputRange.GetFirst()), uint16(inputRange.GetLast())})
	}
	if len(rule.ports) != 0 && rule.protocol != 6 && rule.protocol != 17 && rule.protocol != int32(lanewayv1.IpProtocol_IP_PROTOCOL_ANY) {
		return compiledRule{}, errors.New("ports require TCP, UDP, or ANY")
	}
	return rule, nil
}

func compileAction(action lanewayv1.PolicyAction) (Action, error) {
	switch action {
	case lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT:
		return Accept, nil
	case lanewayv1.PolicyAction_POLICY_ACTION_DENY:
		return Deny, nil
	default:
		return Deny, errors.New("policy action is unspecified")
	}
}

func compileNodes(values [][]byte) ([]identity.NodeID, error) {
	result := make([]identity.NodeID, 0, len(values))
	for _, value := range values {
		if len(value) != identity.IDSize {
			return nil, errors.New("node ID has invalid length")
		}
		var node identity.NodeID
		copy(node[:], value)
		if node.IsZero() {
			return nil, errors.New("node ID is zero")
		}
		result = append(result, node)
	}
	return result, nil
}

func compilePrefixes(values []*lanewayv1.IpPrefix) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if value == nil {
			return nil, errors.New("prefix is nil")
		}
		var address netip.Addr
		switch len(value.GetAddress()) {
		case 4:
			var raw [4]byte
			copy(raw[:], value.GetAddress())
			address = netip.AddrFrom4(raw)
		case 16:
			var raw [16]byte
			copy(raw[:], value.GetAddress())
			address = netip.AddrFrom16(raw)
			if address.Is4In6() {
				return nil, errors.New("noncanonical IPv4-mapped prefix")
			}
		default:
			return nil, errors.New("prefix address has invalid length")
		}
		if value.GetPrefixLength() > uint32(address.BitLen()) {
			return nil, errors.New("prefix length is invalid")
		}
		prefix := netip.PrefixFrom(address, int(value.GetPrefixLength()))
		if prefix != prefix.Masked() {
			return nil, errors.New("prefix has host bits")
		}
		result = append(result, prefix)
	}
	return result, nil
}

func (e *Engine) Evaluate(sourceNode, destinationNode identity.NodeID, packet []byte) Result {
	parsed, ok := parsePacket(packet)
	if !ok {
		return Result{Action: Deny}
	}
	for i := range e.rules {
		rule := &e.rules[i]
		if rule.matches(sourceNode, destinationNode, parsed) {
			return Result{Action: rule.action, RuleID: rule.id, Matched: true}
		}
	}
	return Result{Action: e.defaultAction}
}

// EvaluateReturn evaluates a packet as return traffic for a selector written
// in the initiating direction. Node IDs, address prefixes, and transport ports
// are matched in reverse while rule priority and action remain unchanged.
func (e *Engine) EvaluateReturn(sourceNode, destinationNode identity.NodeID, packet []byte) Result {
	parsed, ok := parsePacket(packet)
	if !ok {
		return Result{Action: Deny}
	}
	for i := range e.rules {
		rule := &e.rules[i]
		if rule.matchesReturn(sourceNode, destinationNode, parsed) {
			return Result{Action: rule.action, RuleID: rule.id, Matched: true}
		}
	}
	return Result{Action: e.defaultAction}
}

type packetFields struct {
	source, destination netip.Addr
	protocol            uint8
	sourcePort          uint16
	destinationPort     uint16
	hasPort             bool
}

func parsePacket(packet []byte) (packetFields, bool) {
	if protocol.ValidateIPPayload(packet) != nil {
		return packetFields{}, false
	}
	var result packetFields
	var transportOffset int
	switch packet[0] >> 4 {
	case 4:
		var source, destination [4]byte
		copy(source[:], packet[12:16])
		copy(destination[:], packet[16:20])
		result.source, result.destination = netip.AddrFrom4(source), netip.AddrFrom4(destination)
		result.protocol = packet[9]
		transportOffset = int(packet[0]&0xf) * 4
		if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			transportOffset = len(packet)
		}
	case 6:
		var source, destination [16]byte
		copy(source[:], packet[8:24])
		copy(destination[:], packet[24:40])
		result.source, result.destination = netip.AddrFrom16(source), netip.AddrFrom16(destination)
		result.protocol = packet[6]
		transportOffset = 40
	}
	if (result.protocol == 6 || result.protocol == 17) && len(packet) >= transportOffset+4 {
		result.sourcePort = binary.BigEndian.Uint16(packet[transportOffset : transportOffset+2])
		result.destinationPort = binary.BigEndian.Uint16(packet[transportOffset+2 : transportOffset+4])
		result.hasPort = true
	}
	return result, true
}

func (r *compiledRule) matches(sourceNode, destinationNode identity.NodeID, packet packetFields) bool {
	if !matchesNode(r.sourceNodes, sourceNode) || !matchesNode(r.destinationNodes, destinationNode) ||
		!matchesPrefix(r.sourcePrefixes, packet.source) || !matchesPrefix(r.destinationPrefixes, packet.destination) {
		return false
	}
	if r.protocol != int32(lanewayv1.IpProtocol_IP_PROTOCOL_ANY) && r.protocol != int32(packet.protocol) {
		return false
	}
	if len(r.ports) == 0 {
		return true
	}
	if !packet.hasPort {
		return false
	}
	for _, port := range r.ports {
		if packet.destinationPort >= port.first && packet.destinationPort <= port.last {
			return true
		}
	}
	return false
}

func (r *compiledRule) matchesReturn(sourceNode, destinationNode identity.NodeID, packet packetFields) bool {
	if !matchesNode(r.sourceNodes, destinationNode) || !matchesNode(r.destinationNodes, sourceNode) ||
		!matchesPrefix(r.sourcePrefixes, packet.destination) || !matchesPrefix(r.destinationPrefixes, packet.source) {
		return false
	}
	if r.protocol != int32(lanewayv1.IpProtocol_IP_PROTOCOL_ANY) && r.protocol != int32(packet.protocol) {
		return false
	}
	if len(r.ports) == 0 {
		return true
	}
	if !packet.hasPort {
		return false
	}
	for _, port := range r.ports {
		if packet.sourcePort >= port.first && packet.sourcePort <= port.last {
			return true
		}
	}
	return false
}

func matchesNode(values []identity.NodeID, node identity.NodeID) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == node {
			return true
		}
	}
	return false
}

func matchesPrefix(values []netip.Prefix, address netip.Addr) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value.Contains(address) {
			return true
		}
	}
	return false
}

func (e *Engine) Epoch() uint64                 { return e.epoch }
func (e *Engine) NetworkID() identity.NetworkID { return e.network }
func (e *Engine) RuleCount() int                { return len(e.rules) }

type Table struct{ current atomic.Pointer[Engine] }

func (t *Table) Replace(engine *Engine) error {
	if engine == nil {
		return ErrInvalidPolicy
	}
	t.current.Store(engine)
	return nil
}

func (t *Table) Evaluate(sourceNode, destinationNode identity.NodeID, packet []byte) Result {
	engine := t.current.Load()
	if engine == nil {
		return Result{Action: Deny}
	}
	return engine.Evaluate(sourceNode, destinationNode, packet)
}

func (t *Table) EvaluateReturn(sourceNode, destinationNode identity.NodeID, packet []byte) Result {
	engine := t.current.Load()
	if engine == nil {
		return Result{Action: Deny}
	}
	return engine.EvaluateReturn(sourceNode, destinationNode, packet)
}
