package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/netvalidate"
)

func (s *Store) RegisterRelay(ctx context.Context, networkID identity.NetworkID, serviceID identity.ID, nodeID *identity.NodeID, name, endpoint string) (Relay, uint64, error) {
	if networkID.IsZero() || serviceID.IsZero() {
		return Relay{}, 0, fmt.Errorf("%w: relay network and service identity", ErrInvalid)
	}
	if err := validateName("relay", name); err != nil {
		return Relay{}, 0, err
	}
	endpoint, err := netvalidate.CanonicalHostPort(endpoint)
	if err != nil {
		return Relay{}, 0, fmt.Errorf("%w: relay endpoint", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return Relay{}, 0, err
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relay{}, 0, err
	}
	defer tx.Rollback()
	var networkExists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM networks WHERE id=?`, idBytes(networkID)).Scan(&networkExists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Relay{}, 0, ErrNotFound
		}
		return Relay{}, 0, err
	}
	var enabledRelays int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM relays WHERE network_id=? AND enabled=1`, idBytes(networkID)).Scan(&enabledRelays); err != nil {
		return Relay{}, 0, err
	}
	if enabledRelays >= netvalidate.MaxRelayEndpoints {
		return Relay{}, 0, fmt.Errorf("%w: network already has %d enabled relays", ErrInvalid, netvalidate.MaxRelayEndpoints)
	}
	var nodeBytes any
	if nodeID != nil {
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL`, idBytes(*nodeID), idBytes(networkID)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return Relay{}, 0, ErrNotFound
		}
		if err != nil {
			return Relay{}, 0, err
		}
		nodeBytes = idBytes(*nodeID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO relays
		(id,network_id,service_id,node_id,name,endpoint,enabled,created_at) VALUES(?,?,?,?,?,?,1,?)`,
		idBytes(id), idBytes(networkID), idBytes(serviceID), nodeBytes, name, endpoint, unix(now)); err != nil {
		if isConstraint(err) {
			return Relay{}, 0, fmt.Errorf("%w: relay service identity, name, or endpoint", ErrConflict)
		}
		return Relay{}, 0, err
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return Relay{}, 0, err
	}
	details := fmt.Sprintf(`{"service_id":%q}`, serviceID.String())
	if err := auditTx(ctx, tx, networkID, nil, "relay.register", "relay", &id, details, now); err != nil {
		return Relay{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return Relay{}, 0, err
	}
	return Relay{ID: id, NetworkID: networkID, ServiceID: serviceID, NodeID: nodeID, Name: name, Endpoint: endpoint, Enabled: true, CreatedAt: now}, epoch, nil
}

// AuthorizeRelay requires an exact network/service identity binding on an
// enabled relay record. Rows migrated from older schemas have a NULL
// service_id and therefore intentionally cannot authorize a certificate.
func (s *Store) AuthorizeRelay(ctx context.Context, networkID identity.NetworkID, serviceID identity.ID) error {
	if networkID.IsZero() || serviceID.IsZero() {
		return ErrNotFound
	}
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM relays
		WHERE network_id=? AND service_id=? AND enabled=1`, idBytes(networkID), idBytes(serviceID)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize relay: %w", err)
	}
	return nil
}

// ActiveRelays returns the deterministic controller-authoritative discovery
// set for a network. Disabled services are deliberately absent so a fresh
// configuration snapshot withdraws them immediately.
func (s *Store) ActiveRelays(ctx context.Context, networkID identity.NetworkID) ([]Relay, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: relay network identity", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,service_id,node_id,name,endpoint,created_at
		FROM relays WHERE network_id=? AND enabled=1 AND service_id IS NOT NULL ORDER BY id LIMIT ?`, idBytes(networkID), netvalidate.MaxRelayEndpoints+1)
	if err != nil {
		return nil, fmt.Errorf("read active relays: %w", err)
	}
	defer rows.Close()
	var result []Relay
	for rows.Next() {
		var idRaw, serviceRaw []byte
		var nodeRaw []byte
		var name, endpoint string
		var created int64
		if err := rows.Scan(&idRaw, &serviceRaw, &nodeRaw, &name, &endpoint, &created); err != nil {
			return nil, fmt.Errorf("scan active relay: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		serviceID, err := scanID(serviceRaw)
		if err != nil {
			return nil, err
		}
		var nodeID *identity.NodeID
		if len(nodeRaw) != 0 {
			value, err := scanID(nodeRaw)
			if err != nil {
				return nil, err
			}
			parsed := identity.NodeID(value)
			nodeID = &parsed
		}
		result = append(result, Relay{
			ID: id, NetworkID: networkID, ServiceID: serviceID, NodeID: nodeID,
			Name: name, Endpoint: endpoint, Enabled: true, CreatedAt: fromUnix(created),
		})
		if len(result) > netvalidate.MaxRelayEndpoints {
			return nil, fmt.Errorf("%w: active relay set exceeds %d", ErrInvalid, netvalidate.MaxRelayEndpoints)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active relays: %w", err)
	}
	return result, nil
}

// DisableRelay durably revokes a relay service identity. Disabling changes the
// network epoch so authorized relays refresh their snapshots promptly.
func (s *Store) DisableRelay(ctx context.Context, relayID identity.ID) (uint64, error) {
	if relayID.IsZero() {
		return 0, fmt.Errorf("%w: relay ID", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var networkRaw []byte
	var enabled bool
	if err := tx.QueryRowContext(ctx, `SELECT network_id,enabled FROM relays WHERE id=?`, idBytes(relayID)).Scan(&networkRaw, &enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if !enabled {
		return 0, fmt.Errorf("%w: relay already disabled", ErrConflict)
	}
	networkValue, err := scanID(networkRaw)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkValue)
	result, err := tx.ExecContext(ctx, `UPDATE relays SET enabled=0 WHERE id=? AND enabled=1`, idBytes(relayID))
	if err != nil {
		return 0, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: relay concurrently disabled", ErrConflict)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditTx(ctx, tx, networkID, nil, "relay.disable", "relay", &relayID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return epoch, nil
}

// UpdateRelay atomically changes operator-facing discovery data and the
// enabled state while preserving the certificate-bound service identity.
func (s *Store) UpdateRelay(ctx context.Context, relayID identity.ID, name, endpoint string, enabled bool) (Relay, uint64, error) {
	if relayID.IsZero() {
		return Relay{}, 0, fmt.Errorf("%w: relay ID", ErrInvalid)
	}
	if err := validateName("relay", name); err != nil {
		return Relay{}, 0, err
	}
	endpoint, err := netvalidate.CanonicalHostPort(endpoint)
	if err != nil {
		return Relay{}, 0, fmt.Errorf("%w: relay endpoint", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relay{}, 0, err
	}
	defer tx.Rollback()
	var networkRaw, serviceRaw, nodeRaw []byte
	var previousName, previousEndpoint string
	var previousEnabled bool
	var created int64
	if err := tx.QueryRowContext(ctx, `SELECT network_id,service_id,node_id,name,endpoint,enabled,created_at FROM relays WHERE id=?`, idBytes(relayID)).
		Scan(&networkRaw, &serviceRaw, &nodeRaw, &previousName, &previousEndpoint, &previousEnabled, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Relay{}, 0, ErrNotFound
		}
		return Relay{}, 0, err
	}
	if len(serviceRaw) == 0 {
		return Relay{}, 0, fmt.Errorf("%w: legacy relay has no certificate service identity", ErrConflict)
	}
	if enabled && !previousEnabled {
		var enabledRelays int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM relays WHERE network_id=? AND enabled=1`, networkRaw).Scan(&enabledRelays); err != nil {
			return Relay{}, 0, err
		}
		if enabledRelays >= netvalidate.MaxRelayEndpoints {
			return Relay{}, 0, fmt.Errorf("%w: network already has %d enabled relays", ErrInvalid, netvalidate.MaxRelayEndpoints)
		}
	}
	if previousName == name && previousEndpoint == endpoint && previousEnabled == enabled {
		return Relay{}, 0, fmt.Errorf("%w: relay update makes no change", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE relays SET name=?,endpoint=?,enabled=? WHERE id=?`, name, endpoint, enabled, idBytes(relayID))
	if err != nil {
		if isConstraint(err) {
			return Relay{}, 0, fmt.Errorf("%w: relay name or endpoint", ErrConflict)
		}
		return Relay{}, 0, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return Relay{}, 0, err
		}
		return Relay{}, 0, fmt.Errorf("%w: relay concurrently changed", ErrConflict)
	}
	networkValue, err := scanID(networkRaw)
	if err != nil {
		return Relay{}, 0, err
	}
	serviceValue, err := scanID(serviceRaw)
	if err != nil {
		return Relay{}, 0, err
	}
	networkID := identity.NetworkID(networkValue)
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return Relay{}, 0, err
	}
	details := fmt.Sprintf(`{"name":%q,"endpoint":%q,"enabled":%t}`, name, endpoint, enabled)
	if err := auditTx(ctx, tx, networkID, nil, "relay.update", "relay", &relayID, details, now); err != nil {
		return Relay{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return Relay{}, 0, err
	}
	var nodeID *identity.NodeID
	if len(nodeRaw) != 0 {
		nodeValue, err := scanID(nodeRaw)
		if err != nil {
			return Relay{}, 0, err
		}
		parsed := identity.NodeID(nodeValue)
		nodeID = &parsed
	}
	return Relay{ID: relayID, NetworkID: networkID, ServiceID: serviceValue, NodeID: nodeID, Name: name, Endpoint: endpoint, Enabled: enabled, CreatedAt: fromUnix(created)}, epoch, nil
}
