package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/Doout/laneway/go/internal/identity"
)

type ManagedAccessPolicy struct {
	Managed             bool
	Rules               []ACLRule
	AuthorizedExitNodes []identity.NodeID
}

type accessPolicySelector struct {
	SourceNodeIDs       []string             `json:"source_node_ids,omitempty"`
	DestinationNodeIDs  []string             `json:"destination_node_ids,omitempty"`
	DestinationPrefixes []accessPolicyPrefix `json:"destination_prefixes,omitempty"`
	IPProtocol          string               `json:"ip_protocol"`
	DestinationPorts    []accessPolicyPort   `json:"destination_ports,omitempty"`
}

type accessPolicyPrefix struct {
	Address      string `json:"address"`
	PrefixLength uint32 `json:"prefix_length"`
}

type accessPolicyPort struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
}

// ManagedAccessPolicyForNode compiles the additive direct and Team grants for
// one user-bound node. The returned deny rule is a hard boundary: manually
// managed ACL rules cannot broaden a managed user's access.
func (s *Store) ManagedAccessPolicyForNode(ctx context.Context, networkID identity.NetworkID, nodeID identity.NodeID) (ManagedAccessPolicy, error) {
	var userRaw []byte
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM nodes WHERE id=? AND network_id=?`, idBytes(nodeID), idBytes(networkID)).Scan(&userRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedAccessPolicy{}, ErrNotFound
	}
	if err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("read node access user: %w", err)
	}
	if len(userRaw) == 0 {
		return ManagedAccessPolicy{}, nil
	}
	userID, err := scanID(userRaw)
	if err != nil {
		return ManagedAccessPolicy{}, err
	}
	var enabled int
	if err := s.db.QueryRowContext(ctx, `SELECT enabled FROM access_users WHERE id=? AND network_id=?`, idBytes(userID), idBytes(networkID)).Scan(&enabled); err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("read access user policy state: %w", err)
	}

	sourceRows, err := s.db.QueryContext(ctx, `SELECT id FROM nodes WHERE network_id=? AND user_id=? AND revoked_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at>?) ORDER BY id`, idBytes(networkID), idBytes(userID), unix(s.now()))
	if err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("read access user nodes: %w", err)
	}
	var sourceIDs []identity.ID
	for sourceRows.Next() {
		var raw []byte
		if err := sourceRows.Scan(&raw); err != nil {
			sourceRows.Close()
			return ManagedAccessPolicy{}, fmt.Errorf("scan access user node: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			sourceRows.Close()
			return ManagedAccessPolicy{}, err
		}
		sourceIDs = append(sourceIDs, id)
	}
	if err := sourceRows.Close(); err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("close access user nodes: %w", err)
	}
	if err := sourceRows.Err(); err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("iterate access user nodes: %w", err)
	}
	result := ManagedAccessPolicy{Managed: true}
	if len(sourceIDs) == 0 {
		return result, nil
	}
	sourceStrings := encodedIDs(sourceIDs)
	if enabled == 1 {
		activeNodes, err := s.ActiveNodes(ctx, networkID)
		if err != nil {
			return ManagedAccessPolicy{}, err
		}
		routes, err := s.ApprovedRoutes(ctx, networkID)
		if err != nil {
			return ManagedAccessPolicy{}, err
		}
		grantRows, err := s.db.QueryContext(ctx, `SELECT g.id,g.target_kind,g.node_id FROM access_grants g
			WHERE g.network_id=? AND ((g.subject_kind='user' AND g.user_id=?) OR
			(g.subject_kind='team' AND g.team_id IN (SELECT team_id FROM access_team_members WHERE network_id=? AND user_id=?)))
			ORDER BY g.id`, idBytes(networkID), idBytes(userID), idBytes(networkID), idBytes(userID))
		if err != nil {
			return ManagedAccessPolicy{}, fmt.Errorf("read effective access grants: %w", err)
		}
		nodesByID := make(map[identity.NodeID]Node, len(activeNodes))
		for _, node := range activeNodes {
			nodesByID[node.ID] = node
		}
		seenExits := make(map[identity.NodeID]struct{})
		for grantRows.Next() {
			var grantRaw, nodeRaw []byte
			var targetKind string
			if err := grantRows.Scan(&grantRaw, &targetKind, &nodeRaw); err != nil {
				grantRows.Close()
				return ManagedAccessPolicy{}, fmt.Errorf("scan effective access grant: %w", err)
			}
			grantID, err := scanID(grantRaw)
			if err != nil {
				grantRows.Close()
				return ManagedAccessPolicy{}, err
			}
			selector := accessPolicySelector{SourceNodeIDs: sourceStrings, IPProtocol: "IP_PROTOCOL_ANY"}
			switch AccessTargetKind(targetKind) {
			case AccessTargetNetwork:
				selector.DestinationNodeIDs, selector.DestinationPrefixes = privateNetworkDestinations(activeNodes, routes)
			case AccessTargetNode:
				targetID, err := scanID(nodeRaw)
				if err != nil {
					grantRows.Close()
					return ManagedAccessPolicy{}, err
				}
				target := identity.NodeID(targetID)
				node, ok := nodesByID[target]
				if !ok {
					continue
				}
				selector.DestinationNodeIDs = encodedIDs([]identity.ID{targetID})
				selector.DestinationPrefixes = nodeOverlayPrefixes(node)
			case AccessTargetExit:
				targetID, err := scanID(nodeRaw)
				if err != nil {
					grantRows.Close()
					return ManagedAccessPolicy{}, err
				}
				target := identity.NodeID(targetID)
				if !approvedExit(routes, target) {
					continue
				}
				selector.DestinationNodeIDs = encodedIDs([]identity.ID{targetID})
				selector.DestinationPrefixes = []accessPolicyPrefix{prefixJSON(netip.MustParsePrefix("0.0.0.0/0"))}
				if _, exists := seenExits[target]; !exists {
					seenExits[target] = struct{}{}
					result.AuthorizedExitNodes = append(result.AuthorizedExitNodes, target)
				}
			default:
				grantRows.Close()
				return ManagedAccessPolicy{}, errors.New("corrupt effective access grant target")
			}
			if len(selector.DestinationNodeIDs) == 0 || len(selector.DestinationPrefixes) == 0 {
				continue
			}
			canonical, err := json.Marshal(selector)
			if err != nil {
				grantRows.Close()
				return ManagedAccessPolicy{}, fmt.Errorf("encode effective access grant: %w", err)
			}
			result.Rules = append(result.Rules, ACLRule{ID: grantID, NetworkID: networkID, Priority: 0, Action: ACLActionAccept, SelectorJSON: string(canonical), Description: "Managed user access grant", Enabled: true})
		}
		if err := grantRows.Close(); err != nil {
			return ManagedAccessPolicy{}, fmt.Errorf("close effective access grants: %w", err)
		}
		if err := grantRows.Err(); err != nil {
			return ManagedAccessPolicy{}, fmt.Errorf("iterate effective access grants: %w", err)
		}
		namedRules, err := s.compileNamedAccessRules(ctx, networkID, userID, sourceStrings, activeNodes, routes)
		if err != nil {
			return ManagedAccessPolicy{}, err
		}
		result.Rules = append(result.Rules, namedRules...)
	}

	denySelector, err := json.Marshal(accessPolicySelector{SourceNodeIDs: sourceStrings, IPProtocol: "IP_PROTOCOL_ANY"})
	if err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("encode managed access boundary: %w", err)
	}
	denyHash := sha256.Sum256(append([]byte("laneway-managed-user-deny-v1:"), userID[:]...))
	var denyID identity.ID
	copy(denyID[:], denyHash[:len(denyID)])
	result.Rules = append(result.Rules, ACLRule{ID: denyID, NetworkID: networkID, Priority: 1, Action: ACLActionDeny, SelectorJSON: string(denySelector), Description: "Managed user default deny", Enabled: true})
	sort.SliceStable(result.Rules, func(i, j int) bool {
		if result.Rules[i].Priority != result.Rules[j].Priority {
			return result.Rules[i].Priority < result.Rules[j].Priority
		}
		return result.Rules[i].ID.String() < result.Rules[j].ID.String()
	})
	sort.Slice(result.AuthorizedExitNodes, func(i, j int) bool {
		return result.AuthorizedExitNodes[i].String() < result.AuthorizedExitNodes[j].String()
	})
	return result, nil
}

type namedAccessGrantTarget struct {
	grantID     identity.ID
	targetKind  AccessResourceTargetKind
	nodeID      *identity.NodeID
	routeID     *identity.ID
	routeNodeID *identity.NodeID
	routePrefix netip.Prefix
	prefix      netip.Prefix
	serviceID   identity.ID
	protocol    AccessServiceProtocol
}

func (s *Store) compileNamedAccessRules(ctx context.Context, networkID identity.NetworkID, userID identity.ID,
	sourceNodeIDs []string, activeNodes []Node, routes []Route) ([]ACLRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rg.id,r.target_kind,r.node_id,r.route_id,r.route_node_id,
		r.route_prefix_address,r.route_prefix_length,r.prefix_address,r.prefix_length,s.id,s.protocol,s.ports_sealed
		FROM access_resource_grants rg
		JOIN access_resources r ON r.id=rg.resource_id AND r.network_id=rg.network_id
		JOIN access_services s ON s.id=rg.service_id AND s.network_id=rg.network_id
		WHERE rg.network_id=? AND r.enabled=1 AND s.enabled=1 AND
		((rg.subject_kind='user' AND rg.user_id=?) OR
		 (rg.subject_kind='team' AND rg.team_id IN
		  (SELECT team_id FROM access_team_members WHERE network_id=? AND user_id=?)))
		ORDER BY rg.id`, idBytes(networkID), idBytes(userID), idBytes(networkID), idBytes(userID))
	if err != nil {
		return nil, fmt.Errorf("read effective named access grants: %w", err)
	}
	var grants []namedAccessGrantTarget
	for rows.Next() {
		var grantRaw, nodeRaw, routeRaw, routeNodeRaw, routePrefixRaw, prefixRaw, serviceRaw []byte
		var targetKind, protocol string
		var routePrefixLength, prefixLength sql.NullInt64
		var portsSealed int
		if err := rows.Scan(&grantRaw, &targetKind, &nodeRaw, &routeRaw, &routeNodeRaw, &routePrefixRaw,
			&routePrefixLength, &prefixRaw, &prefixLength, &serviceRaw, &protocol, &portsSealed); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan effective named access grant: %w", err)
		}
		grantID, err := scanID(grantRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		serviceID, err := scanID(serviceRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		grant := namedAccessGrantTarget{grantID: grantID, targetKind: AccessResourceTargetKind(targetKind),
			serviceID: serviceID, protocol: AccessServiceProtocol(protocol)}
		if !grant.targetKind.Valid() || !grant.protocol.Valid() || portsSealed != 1 {
			rows.Close()
			return nil, errors.New("corrupt named access grant selector")
		}
		switch grant.targetKind {
		case AccessResourceTargetNode:
			nodeID, err := scanID(nodeRaw)
			if err != nil || len(routeRaw) != 0 || len(routeNodeRaw) != 0 || len(routePrefixRaw) != 0 ||
				routePrefixLength.Valid || len(prefixRaw) != 0 || prefixLength.Valid {
				rows.Close()
				return nil, errors.New("corrupt named node resource")
			}
			value := identity.NodeID(nodeID)
			grant.nodeID = &value
		case AccessResourceTargetPrefix:
			routeID, err := scanID(routeRaw)
			if err != nil || len(nodeRaw) != 0 || !routePrefixLength.Valid || !prefixLength.Valid {
				rows.Close()
				return nil, errors.New("corrupt named prefix resource")
			}
			routeNodeID, err := scanID(routeNodeRaw)
			if err != nil {
				rows.Close()
				return nil, errors.New("corrupt named prefix resource")
			}
			routeAddress, routeOK := netip.AddrFromSlice(routePrefixRaw)
			grant.routePrefix = netip.PrefixFrom(routeAddress, int(routePrefixLength.Int64))
			address, resourceOK := netip.AddrFromSlice(prefixRaw)
			grant.prefix = netip.PrefixFrom(address, int(prefixLength.Int64))
			if !routeOK || !resourceOK || routeAddress.Is4In6() || !grant.routePrefix.IsValid() ||
				grant.routePrefix != grant.routePrefix.Masked() || grant.routePrefix.Bits() == 0 || address.Is4In6() ||
				!grant.prefix.IsValid() || grant.prefix != grant.prefix.Masked() || grant.prefix.Bits() == 0 ||
				grant.routePrefix.Addr().BitLen() != grant.prefix.Addr().BitLen() ||
				grant.routePrefix.Bits() > grant.prefix.Bits() || !grant.routePrefix.Contains(grant.prefix.Addr()) {
				rows.Close()
				return nil, errors.New("corrupt named prefix resource")
			}
			grant.routeID = &routeID
			value := identity.NodeID(routeNodeID)
			grant.routeNodeID = &value
		}
		grants = append(grants, grant)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close effective named access grants: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effective named access grants: %w", err)
	}

	portsByService := make(map[identity.ID][]AccessPortRange)
	portRows, err := s.db.QueryContext(ctx, `SELECT p.service_id,p.first_port,p.last_port FROM access_service_ports p
		JOIN access_services s ON s.id=p.service_id WHERE s.network_id=? ORDER BY p.service_id,p.first_port,p.last_port`, idBytes(networkID))
	if err != nil {
		return nil, fmt.Errorf("read effective named service ports: %w", err)
	}
	for portRows.Next() {
		var serviceRaw []byte
		var first, last uint32
		if err := portRows.Scan(&serviceRaw, &first, &last); err != nil {
			portRows.Close()
			return nil, fmt.Errorf("scan effective named service ports: %w", err)
		}
		serviceID, err := scanID(serviceRaw)
		if err != nil {
			portRows.Close()
			return nil, err
		}
		if first == 0 || first > last || last > 65535 {
			portRows.Close()
			return nil, errors.New("corrupt named service port range")
		}
		portsByService[serviceID] = append(portsByService[serviceID], AccessPortRange{First: uint16(first), Last: uint16(last)})
	}
	if err := portRows.Close(); err != nil {
		return nil, fmt.Errorf("close effective named service ports: %w", err)
	}
	if err := portRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effective named service ports: %w", err)
	}

	nodesByID := make(map[identity.NodeID]Node, len(activeNodes))
	for _, node := range activeNodes {
		nodesByID[node.ID] = node
	}
	routesByID := make(map[identity.ID]Route, len(routes))
	for _, route := range routes {
		routesByID[route.ID] = route
	}
	result := make([]ACLRule, 0, len(grants))
	for _, grant := range grants {
		selector := accessPolicySelector{SourceNodeIDs: sourceNodeIDs, IPProtocol: accessServiceProtocolJSON(grant.protocol)}
		if selector.IPProtocol == "" {
			return nil, errors.New("corrupt named service protocol")
		}
		ports := portsByService[grant.serviceID]
		canonicalPorts, err := canonicalAccessPortRanges(grant.protocol, ports)
		if err != nil || !equalAccessPortRanges(canonicalPorts, ports) {
			return nil, errors.New("corrupt named service ports")
		}
		selector.DestinationPorts = make([]accessPolicyPort, 0, len(ports))
		for _, portRange := range ports {
			selector.DestinationPorts = append(selector.DestinationPorts,
				accessPolicyPort{First: uint32(portRange.First), Last: uint32(portRange.Last)})
		}
		switch grant.targetKind {
		case AccessResourceTargetNode:
			node, ok := nodesByID[*grant.nodeID]
			if !ok {
				continue
			}
			selector.DestinationNodeIDs = encodedIDs([]identity.ID{identity.ID(node.ID)})
			selector.DestinationPrefixes = nodeOverlayPrefixes(node)
		case AccessResourceTargetPrefix:
			route, ok := routesByID[*grant.routeID]
			if !ok || route.NodeID != *grant.routeNodeID || route.Prefix != grant.routePrefix || route.Kind != RouteKindSubnet ||
				route.Prefix.Addr().BitLen() != grant.prefix.Addr().BitLen() || route.Prefix.Bits() > grant.prefix.Bits() ||
				!route.Prefix.Contains(grant.prefix.Addr()) {
				continue
			}
			selector.DestinationNodeIDs = encodedIDs([]identity.ID{identity.ID(route.NodeID)})
			selector.DestinationPrefixes = []accessPolicyPrefix{prefixJSON(grant.prefix)}
		}
		if len(selector.DestinationNodeIDs) == 0 || len(selector.DestinationPrefixes) == 0 {
			continue
		}
		canonical, err := json.Marshal(selector)
		if err != nil {
			return nil, fmt.Errorf("encode effective named access grant: %w", err)
		}
		result = append(result, ACLRule{ID: grant.grantID, NetworkID: networkID, Priority: 0, Action: ACLActionAccept,
			SelectorJSON: string(canonical), Description: "Managed named resource access grant", Enabled: true})
	}
	return result, nil
}

func accessServiceProtocolJSON(protocol AccessServiceProtocol) string {
	switch protocol {
	case AccessServiceAny:
		return "IP_PROTOCOL_ANY"
	case AccessServiceTCP:
		return "IP_PROTOCOL_TCP"
	case AccessServiceUDP:
		return "IP_PROTOCOL_UDP"
	case AccessServiceICMP:
		return "IP_PROTOCOL_ICMP"
	case AccessServiceICMPv6:
		return "IP_PROTOCOL_ICMPV6"
	default:
		return ""
	}
}

func encodedIDs(values []identity.ID) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, base64.StdEncoding.EncodeToString(value[:]))
	}
	return result
}

func prefixJSON(prefix netip.Prefix) accessPolicyPrefix {
	return accessPolicyPrefix{Address: base64.StdEncoding.EncodeToString(prefix.Addr().AsSlice()), PrefixLength: uint32(prefix.Bits())}
}

func nodeOverlayPrefixes(node Node) []accessPolicyPrefix {
	var result []accessPolicyPrefix
	if node.IPv4Address.IsValid() {
		result = append(result, prefixJSON(netip.PrefixFrom(node.IPv4Address, node.IPv4Address.BitLen())))
	}
	if node.IPv6Address.IsValid() {
		result = append(result, prefixJSON(netip.PrefixFrom(node.IPv6Address, node.IPv6Address.BitLen())))
	}
	return result
}

func privateNetworkDestinations(nodes []Node, routes []Route) ([]string, []accessPolicyPrefix) {
	ids := make([]identity.ID, 0, len(nodes))
	prefixes := make([]accessPolicyPrefix, 0, len(nodes)*2+len(routes))
	seenNodes := make(map[identity.NodeID]struct{}, len(nodes))
	for _, node := range nodes {
		ids = append(ids, identity.ID(node.ID))
		seenNodes[node.ID] = struct{}{}
		prefixes = append(prefixes, nodeOverlayPrefixes(node)...)
	}
	for _, route := range routes {
		if route.Kind == RouteKindSubnet {
			prefixes = append(prefixes, prefixJSON(route.Prefix))
			if _, exists := seenNodes[route.NodeID]; !exists {
				ids = append(ids, identity.ID(route.NodeID))
				seenNodes[route.NodeID] = struct{}{}
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	return encodedIDs(ids), prefixes
}

func approvedExit(routes []Route, nodeID identity.NodeID) bool {
	for _, route := range routes {
		if route.Kind == RouteKindExit && route.NodeID == nodeID {
			return true
		}
	}
	return false
}
