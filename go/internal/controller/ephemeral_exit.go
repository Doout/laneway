package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

const (
	EphemeralExitHeartbeatInterval = 10 * time.Second
	EphemeralExitSuspectAfter      = 20 * time.Second
	EphemeralExitRevokeAfter       = 60 * time.Second
)

// HeartbeatEphemeralExit advances only the live lease for the exact
// certificate-bound identity and generation. A heartbeat at or after the
// revoke boundary is terminal and cannot recreate the session.
func (s *Store) HeartbeatEphemeralExit(ctx context.Context, nodeID identity.NodeID, generation uint64) (EphemeralExitSession, error) {
	if nodeID.IsZero() || generation == 0 || generation > uint64(^uint64(0)>>1) {
		return EphemeralExitSession{}, fmt.Errorf("%w: ephemeral Exit identity and generation are required", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EphemeralExitSession{}, fmt.Errorf("begin ephemeral Exit heartbeat: %w", err)
	}
	defer tx.Rollback()
	var networkRaw []byte
	var storedGeneration, lastHeartbeat, createdAt, identityLease int64
	err = tx.QueryRowContext(ctx, `SELECT s.network_id,s.generation,s.last_heartbeat_at,s.created_at,n.lease_expires_at
		FROM ephemeral_exit_sessions s JOIN nodes n ON n.id=s.node_id AND n.network_id=s.network_id
		WHERE s.node_id=? AND s.terminated_at IS NULL AND n.revoked_at IS NULL
		  AND n.enrollment_class='ephemeral' AND n.enabled_capabilities=?`,
		idBytes(nodeID), int64(protocol.CapabilityExitNodeV1)).Scan(&networkRaw, &storedGeneration, &lastHeartbeat, &createdAt, &identityLease)
	if errors.Is(err, sql.ErrNoRows) {
		return EphemeralExitSession{}, ErrPermissionDenied
	}
	if err != nil {
		return EphemeralExitSession{}, fmt.Errorf("read ephemeral Exit session: %w", err)
	}
	networkIDRaw, err := scanID(networkRaw)
	if err != nil {
		return EphemeralExitSession{}, err
	}
	if uint64(storedGeneration) != generation || !now.Before(fromUnix(identityLease)) {
		return EphemeralExitSession{}, ErrPermissionDenied
	}
	// The durable revoke deadline is checked in the write predicate, making a
	// heartbeat racing the terminal sweeper lose closed at the exact boundary.
	suspectAt, revokeAt := now.Add(EphemeralExitSuspectAfter), now.Add(EphemeralExitRevokeAfter)
	result, err := tx.ExecContext(ctx, `UPDATE ephemeral_exit_sessions
		SET last_heartbeat_at=?,suspect_at=?,revoke_at=?
		WHERE node_id=? AND generation=? AND terminated_at IS NULL AND revoke_at>?`,
		unix(now), unix(suspectAt), unix(revokeAt), idBytes(nodeID), int64(generation), unix(now))
	if err != nil {
		return EphemeralExitSession{}, fmt.Errorf("advance ephemeral Exit heartbeat: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return EphemeralExitSession{}, ErrPermissionDenied
	}
	networkID := identity.NetworkID(networkIDRaw)
	if !fromUnix(lastHeartbeat).Add(EphemeralExitSuspectAfter).After(now) {
		target := identity.ID(nodeID)
		if err := auditActorTx(ctx, tx, &networkID, adminauth.IDActor(adminauth.ActorNode, identity.ID(nodeID)),
			"ephemeral_exit.session.reconnect", "node", &target,
			fmt.Sprintf(`{"generation":%d}`, generation), now); err != nil {
			return EphemeralExitSession{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return EphemeralExitSession{}, fmt.Errorf("commit ephemeral Exit heartbeat: %w", err)
	}
	return EphemeralExitSession{NodeID: nodeID, NetworkID: networkID, Generation: generation,
		LastHeartbeatAt: now, SuspectAt: suspectAt, RevokeAt: revokeAt, CreatedAt: fromUnix(createdAt)}, nil
}

// EphemeralExitSession returns live lease metadata without extending it.
func (s *Store) EphemeralExitSession(ctx context.Context, nodeID identity.NodeID) (EphemeralExitSession, error) {
	if nodeID.IsZero() {
		return EphemeralExitSession{}, fmt.Errorf("%w: node ID", ErrInvalid)
	}
	var networkRaw []byte
	var generation, heartbeat, suspect, revoke, created int64
	err := s.db.QueryRowContext(ctx, `SELECT network_id,generation,last_heartbeat_at,suspect_at,revoke_at,created_at
		FROM ephemeral_exit_sessions WHERE node_id=? AND terminated_at IS NULL`, idBytes(nodeID)).
		Scan(&networkRaw, &generation, &heartbeat, &suspect, &revoke, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return EphemeralExitSession{}, ErrNotFound
	}
	if err != nil {
		return EphemeralExitSession{}, fmt.Errorf("read ephemeral Exit session: %w", err)
	}
	networkID, err := scanID(networkRaw)
	if err != nil {
		return EphemeralExitSession{}, err
	}
	return EphemeralExitSession{NodeID: nodeID, NetworkID: identity.NetworkID(networkID), Generation: uint64(generation),
		LastHeartbeatAt: fromUnix(heartbeat), SuspectAt: fromUnix(suspect), RevokeAt: fromUnix(revoke), CreatedAt: fromUnix(created)}, nil
}

// ExpireDisconnectedEphemeralExits atomically terminates a bounded set of
// heartbeat leases, revokes their certificates, withdraws routes, releases
// addresses, advances each affected network epoch, and records stable audits.
func (s *Store) ExpireDisconnectedEphemeralExits(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > MaxExpireBatch {
		return 0, fmt.Errorf("%w: expiry batch must be in [1,%d]", ErrInvalid, MaxExpireBatch)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin ephemeral Exit expiry: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT node_id,network_id,generation,revoke_at FROM ephemeral_exit_sessions
		WHERE terminated_at IS NULL AND revoke_at<=? ORDER BY revoke_at,node_id LIMIT ?`, unix(now), limit)
	if err != nil {
		return 0, fmt.Errorf("select disconnected ephemeral Exits: %w", err)
	}
	type candidate struct {
		node       identity.NodeID
		network    identity.NetworkID
		generation uint64
		revokeAt   time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var nodeRaw, networkRaw []byte
		var generation, revokeAt int64
		if err := rows.Scan(&nodeRaw, &networkRaw, &generation, &revokeAt); err != nil {
			rows.Close()
			return 0, err
		}
		nodeID, nodeErr := scanID(nodeRaw)
		networkID, networkErr := scanID(networkRaw)
		if nodeErr != nil || networkErr != nil || generation < 1 {
			rows.Close()
			return 0, errors.Join(nodeErr, networkErr, errors.New("corrupt ephemeral Exit session"))
		}
		candidates = append(candidates, candidate{identity.NodeID(nodeID), identity.NetworkID(networkID), uint64(generation), fromUnix(revokeAt)})
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	affectedNetworks := make(map[identity.NetworkID]struct{})
	revoked := 0
	for _, item := range candidates {
		result, err := tx.ExecContext(ctx, `UPDATE ephemeral_exit_sessions SET terminated_at=?
			WHERE node_id=? AND generation=? AND terminated_at IS NULL AND revoke_at<=?`,
			unix(now), idBytes(item.node), int64(item.generation), unix(now))
		if err != nil {
			return 0, err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE nodes SET revoked_at=?,name=substr(name,1,207)||'~expired-exit~'||lower(hex(id))
			WHERE id=? AND revoked_at IS NULL`, unix(now), idBytes(item.node)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL`, unix(now), idBytes(item.node)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at=?,revocation_reason='ephemeral Exit heartbeat expired'
			WHERE node_id=? AND revoked_at IS NULL`, unix(now), idBytes(item.node)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=?
			WHERE node_id=? AND state IN ('advertised','approved')`, unix(now), idBytes(item.node)); err != nil {
			return 0, err
		}
		target := identity.ID(item.node)
		if err := auditActorTx(ctx, tx, &item.network, adminauth.SystemActor(), "ephemeral_exit.lease.revoke", "node", &target,
			fmt.Sprintf(`{"generation":%d,"revoke_at":%d}`, item.generation, item.revokeAt.Unix()), now); err != nil {
			return 0, err
		}
		affectedNetworks[item.network] = struct{}{}
		revoked++
	}
	for networkID := range affectedNetworks {
		if _, err := incrementEpochTx(ctx, tx, networkID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit ephemeral Exit expiry: %w", err)
	}
	return revoked, nil
}
