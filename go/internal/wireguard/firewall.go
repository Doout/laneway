package wireguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"laneway.dev/laneway/internal/identity"
)

const (
	DefaultFirewallRuleLimit     = 4096
	DefaultFirewallTable         = "laneway_wg"
	DefaultFirewallOwnerChain    = "laneway_owner"
	DefaultFirewallInboundChain  = "laneway_wg_in"
	DefaultFirewallOutboundChain = "laneway_wg_out"
)

var (
	ErrInvalidFirewall   = errors.New("wireguard: invalid firewall policy")
	ErrFirewallClosed    = errors.New("wireguard: firewall is closed")
	ErrFirewallOwnership = errors.New("wireguard: firewall state is not owned by this process")
)

type FirewallCommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
	RunInput(context.Context, []byte, string, ...string) ([]byte, error)
}

type FirewallConfig struct {
	Interface       string
	Table           string
	OwnerChain      string
	InboundChain    string
	OutboundChain   string
	NFTCommand      string
	ShutdownTimeout time.Duration
	Runner          FirewallCommandRunner
}

type FirewallManager interface {
	Apply(context.Context, FirewallPlan) error
	Restore(context.Context) error
	Close() error
}

type FirewallAction uint8

const (
	FirewallDeny FirewallAction = iota
	FirewallAccept
)

// FirewallRule is one controller rule before direction and address-family
// expansion. Protocol is an IP protocol number; 256 means any protocol.
type FirewallRule struct {
	ID                  identity.ID
	Priority            uint32
	Action              FirewallAction
	SourceNodes         []identity.NodeID
	DestinationNodes    []identity.NodeID
	SourcePrefixes      []netip.Prefix
	DestinationPrefixes []netip.Prefix
	Protocol            int32
	DestinationPorts    []FirewallPortRange
}

type FirewallPortRange struct{ First, Last uint16 }

// FirewallPlan is an exact, default-deny controller snapshot. PeerPrefixes is
// the same non-overlapping cryptokey-routing ownership committed to the
// WireGuard device. It is used to translate authenticated NodeID selectors
// without trusting packet-supplied identity metadata.
type FirewallPlan struct {
	Epoch            uint64
	LocalNode        identity.NodeID
	PeerPrefixes     map[identity.NodeID][]netip.Prefix
	Rules            []FirewallRule
	DefaultAction    FirewallAction
	MaxExpandedRules int
}

type firewallDirection uint8

const (
	firewallInbound firewallDirection = iota
	firewallOutbound
)

type firewallStatement struct {
	Direction              firewallDirection
	Action                 FirewallAction
	RuleID                 identity.ID
	Family                 int
	SourceOwnerPrefix      netip.Prefix
	DestinationOwnerPrefix netip.Prefix
	SourcePrefix           netip.Prefix
	DestinationPrefix      netip.Prefix
	Protocol               int32
	Port                   FirewallPortRange
}

func compileFirewallPlan(input FirewallPlan) (FirewallPlan, []firewallStatement, error) {
	if input.Epoch == 0 || input.LocalNode.IsZero() || input.DefaultAction != FirewallDeny {
		return FirewallPlan{}, nil, ErrInvalidFirewall
	}
	limit := input.MaxExpandedRules
	if limit == 0 {
		limit = DefaultFirewallRuleLimit
	}
	if limit < 1 {
		return FirewallPlan{}, nil, fmt.Errorf("%w: invalid expanded rule limit", ErrInvalidFirewall)
	}
	result := input
	result.MaxExpandedRules = limit
	result.PeerPrefixes = make(map[identity.NodeID][]netip.Prefix, len(input.PeerPrefixes))
	var owned []netip.Prefix
	for node, prefixes := range input.PeerPrefixes {
		if node.IsZero() || node == input.LocalNode {
			return FirewallPlan{}, nil, fmt.Errorf("%w: invalid peer owner", ErrInvalidFirewall)
		}
		for _, prefix := range prefixes {
			if !validFirewallPrefix(prefix, true) {
				return FirewallPlan{}, nil, fmt.Errorf("%w: invalid peer prefix %q", ErrInvalidFirewall, prefix)
			}
			for _, previous := range owned {
				if previous.Addr().BitLen() == prefix.Addr().BitLen() &&
					(previous.Contains(prefix.Addr()) || prefix.Contains(previous.Addr())) {
					return FirewallPlan{}, nil, fmt.Errorf("%w: overlapping peer prefix %s", ErrInvalidFirewall, prefix)
				}
			}
			owned = append(owned, prefix)
			result.PeerPrefixes[node] = append(result.PeerPrefixes[node], prefix)
		}
		sortPrefixes(result.PeerPrefixes[node])
	}
	result.Rules = append([]FirewallRule(nil), input.Rules...)
	seen := make(map[identity.ID]struct{}, len(result.Rules))
	for index := range result.Rules {
		rule := &result.Rules[index]
		if rule.ID.IsZero() {
			return FirewallPlan{}, nil, fmt.Errorf("%w: rule %d has zero ID", ErrInvalidFirewall, index)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return FirewallPlan{}, nil, fmt.Errorf("%w: duplicate rule ID", ErrInvalidFirewall)
		}
		seen[rule.ID] = struct{}{}
		if rule.Action != FirewallAccept && rule.Action != FirewallDeny {
			return FirewallPlan{}, nil, fmt.Errorf("%w: invalid action", ErrInvalidFirewall)
		}
		if rule.Protocol != 1 && rule.Protocol != 6 && rule.Protocol != 17 && rule.Protocol != 58 && rule.Protocol != 256 {
			return FirewallPlan{}, nil, fmt.Errorf("%w: invalid protocol", ErrInvalidFirewall)
		}
		if len(rule.DestinationPorts) != 0 && rule.Protocol != 6 && rule.Protocol != 17 && rule.Protocol != 256 {
			return FirewallPlan{}, nil, fmt.Errorf("%w: ports require TCP, UDP, or any", ErrInvalidFirewall)
		}
		if err := validateFirewallNodes(rule.SourceNodes, input.LocalNode, input.PeerPrefixes); err != nil {
			return FirewallPlan{}, nil, err
		}
		if err := validateFirewallNodes(rule.DestinationNodes, input.LocalNode, input.PeerPrefixes); err != nil {
			return FirewallPlan{}, nil, err
		}
		for _, prefixes := range [][]netip.Prefix{rule.SourcePrefixes, rule.DestinationPrefixes} {
			for _, prefix := range prefixes {
				if !validFirewallPrefix(prefix, false) {
					return FirewallPlan{}, nil, fmt.Errorf("%w: invalid selector prefix %q", ErrInvalidFirewall, prefix)
				}
			}
		}
		for _, port := range rule.DestinationPorts {
			if port.First == 0 || port.First > port.Last {
				return FirewallPlan{}, nil, fmt.Errorf("%w: invalid port range", ErrInvalidFirewall)
			}
		}
	}
	sort.SliceStable(result.Rules, func(i, j int) bool {
		if result.Rules[i].Priority != result.Rules[j].Priority {
			return result.Rules[i].Priority < result.Rules[j].Priority
		}
		return bytes.Compare(result.Rules[i].ID[:], result.Rules[j].ID[:]) < 0
	})
	statements := make([]firewallStatement, 0)
	for _, rule := range result.Rules {
		for _, direction := range []firewallDirection{firewallInbound, firewallOutbound} {
			expanded := expandFirewallRule(result, rule, direction)
			if len(statements)+len(expanded) > limit {
				return FirewallPlan{}, nil, fmt.Errorf("%w: expanded rule limit %d exceeded", ErrInvalidFirewall, limit)
			}
			statements = append(statements, expanded...)
		}
	}
	return result, statements, nil
}

func validateFirewallNodes(nodes []identity.NodeID, local identity.NodeID, peers map[identity.NodeID][]netip.Prefix) error {
	seen := make(map[identity.NodeID]struct{}, len(nodes))
	for _, node := range nodes {
		if node.IsZero() {
			return fmt.Errorf("%w: zero node selector", ErrInvalidFirewall)
		}
		if _, duplicate := seen[node]; duplicate {
			return fmt.Errorf("%w: duplicate node selector", ErrInvalidFirewall)
		}
		if node != local {
			if _, present := peers[node]; !present {
				return fmt.Errorf("%w: node selector references absent peer", ErrInvalidFirewall)
			}
		}
		seen[node] = struct{}{}
	}
	return nil
}

func validFirewallPrefix(prefix netip.Prefix, peer bool) bool {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Addr().IsMulticast() {
		return false
	}
	return !peer || !prefix.Addr().IsUnspecified() || prefix.Bits() == 0
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
}

func expandFirewallRule(plan FirewallPlan, rule FirewallRule, direction firewallDirection) []firewallStatement {
	if direction == firewallInbound && !nodeSelectorMatches(rule.DestinationNodes, plan.LocalNode) {
		return nil
	}
	if direction == firewallOutbound && !nodeSelectorMatches(rule.SourceNodes, plan.LocalNode) {
		return nil
	}
	ownerPrefixes := []netip.Prefix{{}}
	if direction == firewallInbound && len(rule.SourceNodes) != 0 {
		ownerPrefixes = prefixesForRemoteNodes(rule.SourceNodes, plan.LocalNode, plan.PeerPrefixes)
	}
	if direction == firewallOutbound && len(rule.DestinationNodes) != 0 {
		ownerPrefixes = prefixesForRemoteNodes(rule.DestinationNodes, plan.LocalNode, plan.PeerPrefixes)
	}
	if len(ownerPrefixes) == 0 {
		return nil
	}
	sources := rule.SourcePrefixes
	if len(sources) == 0 {
		sources = []netip.Prefix{{}}
	}
	destinations := rule.DestinationPrefixes
	if len(destinations) == 0 {
		destinations = []netip.Prefix{{}}
	}
	protocols := []int32{rule.Protocol}
	if rule.Protocol == 256 && len(rule.DestinationPorts) != 0 {
		protocols = []int32{6, 17}
	}
	ports := rule.DestinationPorts
	if len(ports) == 0 {
		ports = []FirewallPortRange{{}}
	}
	var result []firewallStatement
	for _, owner := range ownerPrefixes {
		for _, source := range sources {
			for _, destination := range destinations {
				if !compatiblePrefixFamilies(owner, source, destination) {
					continue
				}
				for _, protocol := range protocols {
					for _, family := range firewallFamilies([]netip.Prefix{owner, source, destination}, protocol) {
						for _, port := range ports {
							statement := firewallStatement{Direction: direction, Action: rule.Action, RuleID: rule.ID,
								Family: family, SourcePrefix: source, DestinationPrefix: destination, Protocol: protocol, Port: port}
							if direction == firewallInbound {
								statement.SourceOwnerPrefix = owner
							} else {
								statement.DestinationOwnerPrefix = owner
							}
							result = append(result, statement)
						}
					}
				}
			}
		}
	}
	return result
}

func firewallFamilies(prefixes []netip.Prefix, protocol int32) []int {
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			if prefix.Addr().Is4() {
				return []int{4}
			}
			return []int{6}
		}
	}
	if protocol == 256 {
		return []int{0}
	}
	if protocol == 1 {
		return []int{4}
	}
	if protocol == 58 {
		return []int{6}
	}
	return []int{4, 6}
}

func nodeSelectorMatches(nodes []identity.NodeID, node identity.NodeID) bool {
	if len(nodes) == 0 {
		return true
	}
	for _, candidate := range nodes {
		if candidate == node {
			return true
		}
	}
	return false
}

func prefixesForRemoteNodes(nodes []identity.NodeID, local identity.NodeID, peers map[identity.NodeID][]netip.Prefix) []netip.Prefix {
	var result []netip.Prefix
	for _, node := range nodes {
		if node != local {
			result = append(result, peers[node]...)
		}
	}
	return result
}

func compatiblePrefixFamilies(prefixes ...netip.Prefix) bool {
	bits := 0
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		if bits != 0 && bits != prefix.Addr().BitLen() {
			return false
		}
		bits = prefix.Addr().BitLen()
	}
	return true
}
