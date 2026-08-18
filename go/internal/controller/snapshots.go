package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/Doout/laneway/go/internal/identity"
)

type RelayAuthorization struct {
	NodeID           identity.NodeID
	OverlayAddresses []netip.Addr
	Prefixes         []netip.Prefix
}

// ActiveNodes returns the deterministic, non-secret peer directory included
// in node snapshots. Node names are operator selectors only; every consumer
// must continue to authenticate and authorize the corresponding NodeID.
func (s *Store) ActiveNodes(ctx context.Context, networkID identity.NetworkID) ([]Node, error) {
	now := unix(s.now())
	rows, err := s.db.QueryContext(ctx, `SELECT n.id,n.name,n.enabled_capabilities,n.created_at,a.address,a6.address,n.enrollment_class,n.lease_expires_at,n.wireguard_public_key,n.user_id
		FROM nodes n LEFT JOIN overlay_addresses a ON a.id=(
			SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND oa.released_at IS NULL AND length(oa.address)=4
			ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		LEFT JOIN overlay_addresses a6 ON a6.id=(
			SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND oa.released_at IS NULL AND length(oa.address)=16
			ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		WHERE n.network_id=? AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?) ORDER BY n.name,n.id`, idBytes(networkID), now)
	if err != nil {
		return nil, fmt.Errorf("read active nodes: %w", err)
	}
	defer rows.Close()
	var result []Node
	for rows.Next() {
		var idRaw, address4, address6, wireGuardPublicKey, userRaw []byte
		var name string
		var capabilities, created int64
		var class string
		var lease sql.NullInt64
		if err := rows.Scan(&idRaw, &name, &capabilities, &created, &address4, &address6, &class, &lease, &wireGuardPublicKey, &userRaw); err != nil {
			return nil, fmt.Errorf("scan active node: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		enrollmentClass := EnrollmentClass(class)
		if !enrollmentClass.Valid() || (enrollmentClass == EnrollmentClassEphemeral) != lease.Valid {
			return nil, errors.New("corrupt active node enrollment class")
		}
		wireGuardKey, err := scanWireGuardPublicKey(wireGuardPublicKey)
		if err != nil {
			return nil, err
		}
		node := Node{ID: identity.NodeID(id), NetworkID: networkID, Name: name, EnabledCapabilities: uint64(capabilities), CreatedAt: fromUnix(created), EnrollmentClass: enrollmentClass, LeaseExpiresAt: nullableTime(lease), WireGuardPublicKey: wireGuardKey}
		if len(userRaw) != 0 {
			userID, err := scanID(userRaw)
			if err != nil {
				return nil, err
			}
			node.UserID = &userID
		}
		if len(address4) != 0 {
			if node.IPv4Address, _ = netip.AddrFromSlice(address4); !node.IPv4Address.Is4() {
				return nil, errors.New("corrupt node IPv4 overlay address")
			}
		}
		if len(address6) != 0 {
			if node.IPv6Address, _ = netip.AddrFromSlice(address6); !node.IPv6Address.Is6() || node.IPv6Address.Is4In6() {
				return nil, errors.New("corrupt node IPv6 overlay address")
			}
		}
		result = append(result, node)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active nodes: %w", err)
	}
	return result, nil
}

// OverlayRoutes returns the active controller-assigned host routes for every
// non-revoked node in a network. The overlay-address row ID is stable for the
// lifetime of the assignment and therefore also serves as the route ID.
func (s *Store) OverlayRoutes(ctx context.Context, networkID identity.NetworkID) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,a.node_id,a.address,a.prefix_length,a.created_at
		FROM overlay_addresses a JOIN nodes n ON n.id=a.node_id
		WHERE a.network_id=? AND a.released_at IS NULL AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?)
		ORDER BY a.prefix_length DESC,a.address ASC,a.id ASC`, idBytes(networkID), unix(s.now()))
	if err != nil {
		return nil, fmt.Errorf("read overlay routes: %w", err)
	}
	defer rows.Close()
	var routes []Route
	for rows.Next() {
		var idRaw, nodeRaw, address []byte
		var bits int
		var created int64
		if err := rows.Scan(&idRaw, &nodeRaw, &address, &bits, &created); err != nil {
			return nil, fmt.Errorf("scan overlay route: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		nodeID, err := scanID(nodeRaw)
		if err != nil {
			return nil, err
		}
		addr, ok := netip.AddrFromSlice(address)
		if !ok || addr.Is4In6() {
			return nil, errors.New("corrupt overlay address")
		}
		prefix := netip.PrefixFrom(addr, bits)
		if !prefix.IsValid() || prefix != prefix.Masked() || bits != addr.BitLen() {
			return nil, errors.New("corrupt overlay host route")
		}
		routes = append(routes, Route{
			ID: id, NetworkID: networkID, NodeID: identity.NodeID(nodeID), Prefix: prefix,
			Kind: RouteKindOverlay, Mode: RouteModeNone, State: RouteStateApproved, CreatedAt: fromUnix(created),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate overlay routes: %w", err)
	}
	return routes, nil
}

// RelayAuthorizations returns one complete, deterministic authorization set
// for all active nodes in a network. Every node owns its overlay host address
// plus its currently approved subnet or exit prefixes.
func (s *Store) RelayAuthorizations(ctx context.Context, networkID identity.NetworkID) ([]RelayAuthorization, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT n.id,a.address FROM nodes n
		JOIN overlay_addresses a ON a.node_id=n.id AND a.released_at IS NULL
		WHERE n.network_id=? AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?) ORDER BY n.id,a.address`, idBytes(networkID), unix(s.now()))
	if err != nil {
		return nil, fmt.Errorf("read relay nodes: %w", err)
	}
	byNode := make(map[identity.NodeID]int)
	var result []RelayAuthorization
	for rows.Next() {
		var nodeRaw, addressRaw []byte
		if err := rows.Scan(&nodeRaw, &addressRaw); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan relay node: %w", err)
		}
		nodeValue, err := scanID(nodeRaw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		address, ok := netip.AddrFromSlice(addressRaw)
		if !ok || address.Is4In6() {
			rows.Close()
			return nil, errors.New("corrupt overlay address")
		}
		nodeID := identity.NodeID(nodeValue)
		index, exists := byNode[nodeID]
		if !exists {
			index = len(result)
			byNode[nodeID] = index
			result = append(result, RelayAuthorization{NodeID: nodeID})
		}
		result[index].OverlayAddresses = append(result[index].OverlayAddresses, address)
		result[index].Prefixes = append(result[index].Prefixes, netip.PrefixFrom(address, address.BitLen()))
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close relay nodes: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate relay nodes: %w", err)
	}
	routes, err := s.ApprovedRoutes(ctx, networkID)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if index, ok := byNode[route.NodeID]; ok {
			result[index].Prefixes = append(result[index].Prefixes, route.Prefix)
		}
	}
	return result, nil
}

// ApprovedRoutes returns the currently usable routes for a network in the
// controller's deterministic route-selection order.
func (s *Store) ApprovedRoutes(ctx context.Context, networkID identity.NetworkID) ([]Route, error) {
	now := unix(s.now())
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.node_id,r.prefix_address,r.prefix_length,r.kind,r.mode,r.metric,
		r.valid_until,r.created_at,r.approved_at FROM routes r JOIN nodes n ON n.id=r.node_id
		WHERE r.network_id=? AND r.state='approved' AND (r.valid_until IS NULL OR r.valid_until>?)
		AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?)
		ORDER BY r.prefix_length DESC,r.metric ASC,r.id ASC`, idBytes(networkID), now, now)
	if err != nil {
		return nil, fmt.Errorf("read approved routes: %w", err)
	}
	defer rows.Close()
	var routes []Route
	for rows.Next() {
		var idRaw, nodeRaw, address []byte
		var bits int
		var kind, mode string
		var metric uint32
		var valid, approved sql.NullInt64
		var created int64
		if err := rows.Scan(&idRaw, &nodeRaw, &address, &bits, &kind, &mode, &metric, &valid, &created, &approved); err != nil {
			return nil, fmt.Errorf("scan approved route: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		nodeID, err := scanID(nodeRaw)
		if err != nil {
			return nil, err
		}
		addr, ok := netip.AddrFromSlice(address)
		if !ok {
			return nil, errors.New("corrupt route address")
		}
		prefix := netip.PrefixFrom(addr, bits)
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return nil, errors.New("corrupt route prefix")
		}
		routes = append(routes, Route{
			ID: id, NetworkID: networkID, NodeID: identity.NodeID(nodeID), Prefix: prefix,
			Kind: RouteKind(kind), Mode: RouteMode(mode), Metric: metric, State: RouteStateApproved,
			ValidUntil: nullableTime(valid), CreatedAt: fromUnix(created), ApprovedAt: nullableTime(approved),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approved routes: %w", err)
	}
	return routes, nil
}

// NetworkRoutes returns recent route records, including withdrawn and rejected
// advertisements, for administrative inspection.
func (s *Store) NetworkRoutes(ctx context.Context, networkID identity.NetworkID, limit int) ([]Route, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: route limit must be 1..1000", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,node_id,prefix_address,prefix_length,kind,mode,metric,state,
		valid_until,created_at,approved_at,withdrawn_at FROM routes WHERE network_id=?
		ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("read network routes: %w", err)
	}
	return scanNetworkRoutes(rows, networkID)
}

func scanNetworkRoutes(rows *sql.Rows, networkID identity.NetworkID) ([]Route, error) {
	defer rows.Close()
	routes := make([]Route, 0)
	for rows.Next() {
		var idRaw, nodeRaw, address []byte
		var bits int
		var kind, mode, state string
		var metric uint32
		var valid, approved, withdrawn sql.NullInt64
		var created int64
		if err := rows.Scan(&idRaw, &nodeRaw, &address, &bits, &kind, &mode, &metric, &state,
			&valid, &created, &approved, &withdrawn); err != nil {
			return nil, fmt.Errorf("scan network route: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		nodeID, err := scanID(nodeRaw)
		if err != nil {
			return nil, err
		}
		addr, ok := netip.AddrFromSlice(address)
		if !ok {
			return nil, errors.New("corrupt route address")
		}
		prefix := netip.PrefixFrom(addr, bits)
		if !prefix.IsValid() || prefix != prefix.Masked() {
			return nil, errors.New("corrupt route prefix")
		}
		routes = append(routes, Route{
			ID: id, NetworkID: networkID, NodeID: identity.NodeID(nodeID), Prefix: prefix,
			Kind: RouteKind(kind), Mode: RouteMode(mode), Metric: metric, State: RouteState(state),
			ValidUntil: nullableTime(valid), CreatedAt: fromUnix(created), ApprovedAt: nullableTime(approved),
			WithdrawnAt: nullableTime(withdrawn),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate network routes: %w", err)
	}
	return routes, nil
}

// EnabledACLRules returns the active policy rules in evaluation order.
func (s *Store) EnabledACLRules(ctx context.Context, networkID identity.NetworkID) ([]ACLRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,priority,action,selector_json,description,created_at,updated_at
		FROM acl_rules WHERE network_id=? AND enabled=1 ORDER BY priority ASC,id ASC`, idBytes(networkID))
	if err != nil {
		return nil, fmt.Errorf("read ACL rules: %w", err)
	}
	defer rows.Close()
	var rules []ACLRule
	for rows.Next() {
		var idRaw []byte
		var rule ACLRule
		var created, updated int64
		if err := rows.Scan(&idRaw, &rule.Priority, &rule.Action, &rule.SelectorJSON, &rule.Description, &created, &updated); err != nil {
			return nil, fmt.Errorf("scan ACL rule: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		rule.ID, rule.NetworkID, rule.Enabled = id, networkID, true
		rule.CreatedAt, rule.UpdatedAt = fromUnix(created), fromUnix(updated)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ACL rules: %w", err)
	}
	// Keep ordering independent of SQLite's BLOB collation details.
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].ID.String() < rules[j].ID.String()
	})
	return rules, nil
}

// CertificateBySerial reads an immutable certificate record. Serial numbers
// are globally unique in a controller database.
func (s *Store) CertificateBySerial(ctx context.Context, serial []byte) (Certificate, error) {
	if len(serial) < 1 || len(serial) > 32 {
		return Certificate{}, fmt.Errorf("%w: certificate serial", ErrInvalid)
	}
	var idRaw, networkRaw, nodeRaw, der []byte
	var notBefore, notAfter, created int64
	var revoked sql.NullInt64
	var reason string
	err := s.db.QueryRowContext(ctx, `SELECT id,network_id,node_id,der,not_before,not_after,created_at,
		revoked_at,revocation_reason FROM certificates WHERE serial=?`, serial).
		Scan(&idRaw, &networkRaw, &nodeRaw, &der, &notBefore, &notAfter, &created, &revoked, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("read certificate by serial: %w", err)
	}
	id, err := scanID(idRaw)
	if err != nil {
		return Certificate{}, err
	}
	networkID, err := scanID(networkRaw)
	if err != nil {
		return Certificate{}, err
	}
	nodeID, err := scanID(nodeRaw)
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{
		ID: id, NetworkID: identity.NetworkID(networkID), NodeID: identity.NodeID(nodeID),
		Serial: append([]byte(nil), serial...), DER: append([]byte(nil), der...),
		NotBefore: fromUnix(notBefore), NotAfter: fromUnix(notAfter), CreatedAt: fromUnix(created),
		RevokedAt: nullableTime(revoked), RevocationReason: reason,
	}, nil
}
