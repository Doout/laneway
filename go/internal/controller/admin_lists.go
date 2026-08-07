package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"laneway.dev/laneway/internal/identity"
)

func validateListLimit(limit int) error {
	if limit < 1 || limit > 1000 {
		return fmt.Errorf("%w: list limit must be 1..1000", ErrInvalid)
	}
	return nil
}

// Networks returns bounded deterministic administrative inventory.
func (s *Store) Networks(ctx context.Context, limit int) ([]Network, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,ipv4_address,ipv4_prefix_length,
		ipv6_address,ipv6_prefix_length,configuration_epoch,created_at
		FROM networks ORDER BY created_at,id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	defer rows.Close()
	var result []Network
	for rows.Next() {
		var idRaw, address4, address6 []byte
		var name string
		var bits4 int
		var bits6 sql.NullInt64
		var epoch uint64
		var created int64
		if err := rows.Scan(&idRaw, &name, &address4, &bits4, &address6, &bits6, &epoch, &created); err != nil {
			return nil, fmt.Errorf("scan network inventory: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		addr4, ok := netip.AddrFromSlice(address4)
		if !ok || !addr4.Is4() {
			return nil, errors.New("corrupt network IPv4 pool")
		}
		network := Network{ID: identity.NetworkID(id), Name: name, IPv4Pool: netip.PrefixFrom(addr4, bits4), ConfigurationEpoch: epoch, CreatedAt: fromUnix(created)}
		if len(address6) != 0 {
			addr6, ok := netip.AddrFromSlice(address6)
			if !ok || !addr6.Is6() || addr6.Is4In6() || !bits6.Valid {
				return nil, errors.New("corrupt network IPv6 pool")
			}
			network.IPv6Pool = netip.PrefixFrom(addr6, int(bits6.Int64))
		}
		result = append(result, network)
	}
	return result, rows.Err()
}

// NetworkNodes returns active and revoked nodes so administrative record IDs
// remain discoverable after a revocation.
func (s *Store) NetworkNodes(ctx context.Context, networkID identity.NetworkID, limit int) ([]Node, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT n.id,n.name,n.enabled_capabilities,n.created_at,n.revoked_at,a.address,a6.address
		FROM nodes n LEFT JOIN overlay_addresses a ON a.id=(SELECT oa.id FROM overlay_addresses oa
			WHERE oa.node_id=n.id AND oa.released_at IS NULL AND length(oa.address)=4 ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		LEFT JOIN overlay_addresses a6 ON a6.id=(SELECT oa.id FROM overlay_addresses oa
			WHERE oa.node_id=n.id AND oa.released_at IS NULL AND length(oa.address)=16 ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		WHERE n.network_id=? ORDER BY n.created_at,n.id LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	var result []Node
	for rows.Next() {
		var idRaw, address4, address6 []byte
		var name string
		var capabilities uint64
		var created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&idRaw, &name, &capabilities, &created, &revoked, &address4, &address6); err != nil {
			return nil, fmt.Errorf("scan node inventory: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		node := Node{ID: identity.NodeID(id), NetworkID: networkID, Name: name, EnabledCapabilities: capabilities, CreatedAt: fromUnix(created), RevokedAt: nullableTime(revoked)}
		if len(address4) != 0 {
			node.IPv4Address, _ = netip.AddrFromSlice(address4)
			if !node.IPv4Address.Is4() {
				return nil, errors.New("corrupt node IPv4 overlay")
			}
		}
		if len(address6) != 0 {
			node.IPv6Address, _ = netip.AddrFromSlice(address6)
			if !node.IPv6Address.Is6() || node.IPv6Address.Is4In6() {
				return nil, errors.New("corrupt node IPv6 overlay")
			}
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

func (s *Store) NetworkRelays(ctx context.Context, networkID identity.NetworkID, limit int) ([]Relay, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,service_id,node_id,name,endpoint,enabled,created_at
		FROM relays WHERE network_id=? ORDER BY created_at,id LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("list relays: %w", err)
	}
	defer rows.Close()
	var result []Relay
	for rows.Next() {
		var idRaw, serviceRaw, nodeRaw []byte
		var name, endpoint string
		var enabled bool
		var created int64
		if err := rows.Scan(&idRaw, &serviceRaw, &nodeRaw, &name, &endpoint, &enabled, &created); err != nil {
			return nil, fmt.Errorf("scan relay inventory: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		service, err := scanID(serviceRaw)
		if err != nil {
			return nil, err
		}
		var node *identity.NodeID
		if len(nodeRaw) != 0 {
			value, err := scanID(nodeRaw)
			if err != nil {
				return nil, err
			}
			parsed := identity.NodeID(value)
			node = &parsed
		}
		result = append(result, Relay{ID: id, NetworkID: networkID, ServiceID: service, NodeID: node, Name: name, Endpoint: endpoint, Enabled: enabled, CreatedAt: fromUnix(created)})
	}
	return result, rows.Err()
}

func (s *Store) NetworkACLRules(ctx context.Context, networkID identity.NetworkID, limit int) ([]ACLRule, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,priority,action,selector_json,description,enabled,created_at,updated_at
		FROM acl_rules WHERE network_id=? ORDER BY priority,id LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("list ACL rules: %w", err)
	}
	defer rows.Close()
	var result []ACLRule
	for rows.Next() {
		var idRaw []byte
		var priority uint32
		var action, selector, description string
		var enabled bool
		var created, updated int64
		if err := rows.Scan(&idRaw, &priority, &action, &selector, &description, &enabled, &created, &updated); err != nil {
			return nil, fmt.Errorf("scan ACL inventory: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		result = append(result, ACLRule{ID: id, NetworkID: networkID, Priority: priority, Action: ACLAction(action), SelectorJSON: selector, Description: description, Enabled: enabled, CreatedAt: fromUnix(created), UpdatedAt: fromUnix(updated)})
	}
	return result, rows.Err()
}

func (s *Store) NetworkCertificates(ctx context.Context, networkID identity.NetworkID, limit int) ([]Certificate, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,node_id,serial,not_before,not_after,created_at,revoked_at,revocation_reason
		FROM certificates WHERE network_id=? ORDER BY created_at,id LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()
	var result []Certificate
	for rows.Next() {
		var idRaw, nodeRaw, serial []byte
		var notBefore, notAfter, created int64
		var revoked sql.NullInt64
		var reason string
		if err := rows.Scan(&idRaw, &nodeRaw, &serial, &notBefore, &notAfter, &created, &revoked, &reason); err != nil {
			return nil, fmt.Errorf("scan certificate inventory: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		node, err := scanID(nodeRaw)
		if err != nil {
			return nil, err
		}
		result = append(result, Certificate{ID: id, NetworkID: networkID, NodeID: identity.NodeID(node), Serial: append([]byte(nil), serial...), NotBefore: fromUnix(notBefore), NotAfter: fromUnix(notAfter), CreatedAt: fromUnix(created), RevokedAt: nullableTime(revoked), RevocationReason: reason})
	}
	return result, rows.Err()
}
