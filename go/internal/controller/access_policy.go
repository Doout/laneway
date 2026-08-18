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
}

type accessPolicyPrefix struct {
	Address      string `json:"address"`
	PrefixLength uint32 `json:"prefix_length"`
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
	}

	denySelector, err := json.Marshal(accessPolicySelector{SourceNodeIDs: sourceStrings, IPProtocol: "IP_PROTOCOL_ANY"})
	if err != nil {
		return ManagedAccessPolicy{}, fmt.Errorf("encode managed access boundary: %w", err)
	}
	denyHash := sha256.Sum256(append([]byte("laneway-managed-user-deny-v1:"), userID[:]...))
	var denyID identity.ID
	copy(denyID[:], denyHash[:len(denyID)])
	result.Rules = append(result.Rules, ACLRule{ID: denyID, NetworkID: networkID, Priority: 1, Action: ACLActionDeny, SelectorJSON: string(denySelector), Description: "Managed user default deny", Enabled: true})
	sort.Slice(result.AuthorizedExitNodes, func(i, j int) bool {
		return result.AuthorizedExitNodes[i].String() < result.AuthorizedExitNodes[j].String()
	})
	return result, nil
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
