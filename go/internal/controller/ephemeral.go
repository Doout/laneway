package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/identity"
)

const (
	MaxExpireBatch            = 1024
	ExpiredEphemeralRetention = 7 * 24 * time.Hour
)

// NextEphemeralExpiry is the earliest active ephemeral authorization boundary
// in a network. Every node and relay snapshot is capped by this value so an
// established path cannot retain the user beyond its identity lease.
func (s *Store) NextEphemeralExpiry(ctx context.Context, networkID identity.NetworkID) (*time.Time, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	now := s.now()
	var expiry sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(lease_expires_at) FROM nodes
		WHERE network_id=? AND enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at>?`, idBytes(networkID), unix(now)).Scan(&expiry); err != nil {
		return nil, fmt.Errorf("read next ephemeral expiry: %w", err)
	}
	if !expiry.Valid {
		return nil, nil
	}
	value := fromUnix(expiry.Int64)
	return &value, nil
}

// ExpireEphemeral revokes a bounded batch of expired identities and releases
// all authorization derived from them in one transaction. The network epoch is
// incremented once per affected network so relay and node snapshots fail closed
// before a released overlay address can be reassigned.
func (s *Store) ExpireEphemeral(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > MaxExpireBatch {
		return 0, fmt.Errorf("%w: expiry batch must be in [1,%d]", ErrInvalid, MaxExpireBatch)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin ephemeral expiry: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,network_id,lease_expires_at FROM nodes
		WHERE enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at<=?
		ORDER BY lease_expires_at,id LIMIT ?`, unix(now), limit)
	if err != nil {
		return 0, fmt.Errorf("select expired ephemeral identities: %w", err)
	}
	type expired struct {
		node    identity.NodeID
		network identity.NetworkID
		lease   time.Time
	}
	var expiredNodes []expired
	for rows.Next() {
		var nodeRaw, networkRaw []byte
		var lease int64
		if err := rows.Scan(&nodeRaw, &networkRaw, &lease); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan expired ephemeral identity: %w", err)
		}
		nodeID, err := scanID(nodeRaw)
		if err != nil {
			rows.Close()
			return 0, err
		}
		networkID, err := scanID(networkRaw)
		if err != nil {
			rows.Close()
			return 0, err
		}
		expiredNodes = append(expiredNodes, expired{node: identity.NodeID(nodeID), network: identity.NetworkID(networkID), lease: fromUnix(lease)})
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close expired ephemeral identities: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate expired ephemeral identities: %w", err)
	}
	affectedNetworks := make(map[identity.NetworkID]struct{})
	for _, item := range expiredNodes {
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET revoked_at=?,name=substr(name,1,210)||'~expired~'||lower(hex(id))
			WHERE id=? AND revoked_at IS NULL AND enrollment_class='ephemeral' AND lease_expires_at<=?`, unix(now), idBytes(item.node), unix(now))
		if err != nil {
			return 0, fmt.Errorf("revoke expired ephemeral identity: %w", err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if changed != 1 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL`, unix(now), idBytes(item.node)); err != nil {
			return 0, fmt.Errorf("release expired ephemeral addresses: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at=?,revocation_reason='ephemeral lease expired' WHERE node_id=? AND revoked_at IS NULL`, unix(now), idBytes(item.node)); err != nil {
			return 0, fmt.Errorf("revoke expired ephemeral certificates: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE node_id=? AND state IN ('advertised','approved')`, unix(now), idBytes(item.node)); err != nil {
			return 0, fmt.Errorf("withdraw expired ephemeral routes: %w", err)
		}
		target := identity.ID(item.node)
		details := fmt.Sprintf(`{"lease_expires_at":%d}`, item.lease.Unix())
		if err := auditTx(ctx, tx, item.network, nil, "ephemeral.expire", "node", &target, details, now); err != nil {
			return 0, err
		}
		affectedNetworks[item.network] = struct{}{}
	}
	for networkID := range affectedNetworks {
		if _, err := incrementEpochTx(ctx, tx, networkID); err != nil {
			return 0, err
		}
	}
	// Preserve audit events, but bound abandoned session rows and their
	// cascading certificate/address records after a documented recovery window.
	cutoff := unix(now.Add(-ExpiredEphemeralRetention))
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id IN (
		SELECT id FROM nodes WHERE enrollment_class='ephemeral' AND revoked_at IS NOT NULL AND lease_expires_at<=?
		ORDER BY lease_expires_at,id LIMIT ?)`, cutoff, limit); err != nil {
		return 0, fmt.Errorf("prune retained ephemeral identities: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE id IN (
		SELECT id FROM enrollment_tokens WHERE enrollment_class='ephemeral' AND expires_at<=?
		ORDER BY expires_at,id LIMIT ?)`, cutoff, limit); err != nil {
		return 0, fmt.Errorf("prune retained ephemeral enrollment tokens: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit ephemeral expiry: %w", err)
	}
	return len(expiredNodes), nil
}
