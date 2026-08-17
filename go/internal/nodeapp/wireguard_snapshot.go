package nodeapp

import (
	"fmt"
	"net/netip"
	"sort"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/wireguard"
)

const maxWireGuardExitPrefixes = 8192

type preparedWireGuardSnapshot struct {
	peers    []wireguard.ManagedPeer
	firewall wireguard.FirewallPlan
}

func prepareWireGuardSnapshot(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity,
	localPublicKey wireguard.PublicKey, selectedExit identity.NodeID,
) (preparedWireGuardSnapshot, error) {
	if configuration == nil || configuration.GetConfigurationEpoch() == 0 || configuration.GetPolicy() == nil || configuration.GetRoutes() == nil {
		return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard snapshot is incomplete")
	}
	owners := make(map[identity.NodeID][]netip.Prefix, len(configuration.GetPeers()))
	keys := make(map[identity.NodeID]wireguard.PublicKey, len(configuration.GetPeers()))
	localPresent := false
	for index, peer := range configuration.GetPeers() {
		if len(peer.GetNodeId()) != identity.IDSize {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard peer %d has invalid node ID", index)
		}
		var node identity.NodeID
		copy(node[:], peer.GetNodeId())
		key, err := wireguard.ParsePublicKey(peer.GetWireguardPublicKey())
		if err != nil {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard peer %s key: %w", node, err)
		}
		if _, duplicate := keys[node]; duplicate {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard peer snapshot duplicates %s", node)
		}
		keys[node] = key
		for addressIndex, raw := range peer.GetOverlayAddresses() {
			address, ok := netip.AddrFromSlice(raw)
			if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
				return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard peer %s overlay address %d is invalid", node, addressIndex)
			}
			owners[node] = append(owners[node], netip.PrefixFrom(address, address.BitLen()))
		}
		if node == local.NodeID {
			localPresent = true
			if key != localPublicKey {
				return preparedWireGuardSnapshot{}, fmt.Errorf("controller WireGuard key does not match the local private key")
			}
		}
	}
	if !localPresent {
		return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard peer snapshot omits the local node")
	}
	exitFamilies := make(map[int]struct{}, 2)
	for index, route := range configuration.GetRoutes().GetRoutes() {
		if len(route.GetViaNodeId()) != identity.IDSize {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard route %d has invalid owner", index)
		}
		var owner identity.NodeID
		copy(owner[:], route.GetViaNodeId())
		if _, present := keys[owner]; !present {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard route %d owner is absent", index)
		}
		prefix, err := protoPrefix(route.GetDestination())
		if err != nil {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard route %d: %w", index, err)
		}
		switch route.GetKind() {
		case lanewayv1.RouteKind_ROUTE_KIND_OVERLAY, lanewayv1.RouteKind_ROUTE_KIND_SUBNET:
			owners[owner] = appendUniquePrefix(owners[owner], prefix)
		case lanewayv1.RouteKind_ROUTE_KIND_EXIT:
			if owner == selectedExit {
				if prefix.Bits() != 0 {
					return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard exit route %d is not a default", index)
				}
				exitFamilies[prefix.Addr().BitLen()] = struct{}{}
			}
		default:
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard route %d has unknown kind", index)
		}
	}
	if !selectedExit.IsZero() {
		if _, present := keys[selectedExit]; !present {
			return preparedWireGuardSnapshot{}, fmt.Errorf("selected wireguard exit is absent")
		}
		if len(exitFamilies) == 0 {
			return preparedWireGuardSnapshot{}, fmt.Errorf("selected wireguard exit has no authorized default route")
		}
		var protected []netip.Prefix
		for _, prefixes := range owners {
			protected = append(protected, prefixes...)
		}
		exitPrefixes, err := partitionedExitPrefixes(exitFamilies, protected, maxWireGuardExitPrefixes)
		if err != nil {
			return preparedWireGuardSnapshot{}, err
		}
		owners[selectedExit] = append(owners[selectedExit], exitPrefixes...)
	}
	peers := make([]wireguard.ManagedPeer, 0, len(keys)-1)
	peerPrefixes := make(map[identity.NodeID][]netip.Prefix, len(keys)-1)
	for node, key := range keys {
		if node == local.NodeID {
			continue
		}
		prefixes := append([]netip.Prefix(nil), owners[node]...)
		peers = append(peers, wireguard.ManagedPeer{NodeID: node, PublicKey: key, AllowedIPs: prefixes})
		peerPrefixes[node] = prefixes
	}
	policy := configuration.GetPolicy()
	firewall := wireguard.FirewallPlan{Epoch: configuration.GetConfigurationEpoch(), LocalNode: local.NodeID,
		PeerPrefixes: peerPrefixes, DefaultAction: wireguard.FirewallDeny}
	if policy.GetDefaultAction() != lanewayv1.PolicyAction_POLICY_ACTION_DENY {
		return preparedWireGuardSnapshot{}, fmt.Errorf("WireGuard policy must default deny")
	}
	for index, input := range policy.GetRules() {
		if input == nil || input.GetSelector() == nil || len(input.GetRuleId()) != identity.IDSize {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard policy rule %d is invalid", index)
		}
		var rule wireguard.FirewallRule
		copy(rule.ID[:], input.GetRuleId())
		rule.Priority = input.GetPriority()
		switch input.GetAction() {
		case lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT:
			rule.Action = wireguard.FirewallAccept
		case lanewayv1.PolicyAction_POLICY_ACTION_DENY:
			rule.Action = wireguard.FirewallDeny
		default:
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard policy rule %d has invalid action", index)
		}
		rule.Protocol = int32(input.GetSelector().GetIpProtocol())
		var err error
		if rule.SourceNodes, err = wireGuardNodeIDs(input.GetSelector().GetSourceNodeIds()); err != nil {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard policy rule %d sources: %w", index, err)
		}
		if rule.DestinationNodes, err = wireGuardNodeIDs(input.GetSelector().GetDestinationNodeIds()); err != nil {
			return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard policy rule %d destinations: %w", index, err)
		}
		for _, value := range input.GetSelector().GetSourcePrefixes() {
			prefix, prefixErr := protoPrefix(value)
			if prefixErr != nil {
				return preparedWireGuardSnapshot{}, prefixErr
			}
			rule.SourcePrefixes = append(rule.SourcePrefixes, prefix)
		}
		for _, value := range input.GetSelector().GetDestinationPrefixes() {
			prefix, prefixErr := protoPrefix(value)
			if prefixErr != nil {
				return preparedWireGuardSnapshot{}, prefixErr
			}
			rule.DestinationPrefixes = append(rule.DestinationPrefixes, prefix)
		}
		for _, value := range input.GetSelector().GetDestinationPorts() {
			if value == nil || value.GetFirst() > 65535 || value.GetLast() > 65535 {
				return preparedWireGuardSnapshot{}, fmt.Errorf("wireguard policy rule %d has invalid port", index)
			}
			rule.DestinationPorts = append(rule.DestinationPorts, wireguard.FirewallPortRange{First: uint16(value.GetFirst()), Last: uint16(value.GetLast())})
		}
		firewall.Rules = append(firewall.Rules, rule)
	}
	return preparedWireGuardSnapshot{peers: peers, firewall: firewall}, nil
}

// partitionedExitPrefixes returns the exact complement of protected identity
// and subnet ownership for each controller-authorized default family. This
// gives the exit peer default-route behavior without overlapping another
// peer's WireGuard AllowedIPs. Incoming packets therefore retain an
// unambiguous cryptographic owner, including packets with spoofed overlay or
// protected subnet source addresses.
func partitionedExitPrefixes(families map[int]struct{}, protected []netip.Prefix, limit int) ([]netip.Prefix, error) {
	if limit < 1 {
		return nil, fmt.Errorf("wireguard exit prefix limit is invalid")
	}
	var result []netip.Prefix
	for _, bits := range []int{32, 128} {
		if _, enabled := families[bits]; !enabled {
			continue
		}
		root := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		if bits == 128 {
			root = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
		}
		available := []netip.Prefix{root}
		reservedPrefixes := protected
		if bits == 32 {
			reservedPrefixes = append(append([]netip.Prefix(nil), protected...),
				netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("224.0.0.0/4"))
		} else {
			reservedPrefixes = append(append([]netip.Prefix(nil), protected...),
				netip.MustParsePrefix("::/128"), netip.MustParsePrefix("ff00::/8"))
		}
		for _, reserved := range reservedPrefixes {
			if !reserved.IsValid() || reserved.Addr().BitLen() != bits {
				continue
			}
			var next []netip.Prefix
			for _, prefix := range available {
				next = append(next, subtractPrefix(prefix, reserved.Masked())...)
				if len(result)+len(next) > limit {
					return nil, fmt.Errorf("wireguard exit cryptokey-routing partition exceeds %d prefixes", limit)
				}
			}
			available = next
		}
		result = append(result, available...)
		if len(result) > limit {
			return nil, fmt.Errorf("wireguard exit cryptokey-routing partition exceeds %d prefixes", limit)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func subtractPrefix(base, reserved netip.Prefix) []netip.Prefix {
	if base.Addr().BitLen() != reserved.Addr().BitLen() || !base.Contains(reserved.Addr()) {
		return []netip.Prefix{base}
	}
	if reserved.Bits() <= base.Bits() {
		return nil
	}
	left, right := splitPrefix(base)
	return append(subtractPrefix(left, reserved), subtractPrefix(right, reserved)...)
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	nextBits := prefix.Bits() + 1
	address := prefix.Addr()
	if address.Is4() {
		left := address.As4()
		right := left
		bit := nextBits - 1
		right[bit/8] |= byte(1 << (7 - bit%8))
		return netip.PrefixFrom(netip.AddrFrom4(left), nextBits), netip.PrefixFrom(netip.AddrFrom4(right), nextBits)
	}
	left := address.As16()
	right := left
	bit := nextBits - 1
	right[bit/8] |= byte(1 << (7 - bit%8))
	return netip.PrefixFrom(netip.AddrFrom16(left), nextBits), netip.PrefixFrom(netip.AddrFrom16(right), nextBits)
}

func wireGuardNodeIDs(values [][]byte) ([]identity.NodeID, error) {
	result := make([]identity.NodeID, 0, len(values))
	for _, value := range values {
		if len(value) != identity.IDSize {
			return nil, fmt.Errorf("invalid node ID")
		}
		var node identity.NodeID
		copy(node[:], value)
		result = append(result, node)
	}
	return result, nil
}

func appendUniquePrefix(prefixes []netip.Prefix, prefix netip.Prefix) []netip.Prefix {
	for _, existing := range prefixes {
		if existing == prefix {
			return prefixes
		}
	}
	return append(prefixes, prefix)
}
