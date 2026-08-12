package controller

import (
	"context"
	"fmt"

	"laneway.dev/laneway/internal/identity"
)

func (s *Store) AuditEvents(ctx context.Context, networkID identity.NetworkID, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor_node_id,action,target_type,target_id,details_json,created_at
        FROM audit_events WHERE network_id=? ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()
	events := make([]AuditEvent, 0)
	for rows.Next() {
		var idRaw, actorRaw, targetRaw []byte
		var event AuditEvent
		var created int64
		if err := rows.Scan(&idRaw, &actorRaw, &event.Action, &event.TargetType, &targetRaw, &event.Details, &created); err != nil {
			return nil, err
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		event.ID, event.NetworkID, event.CreatedAt = id, networkID, fromUnix(created)
		if actorRaw != nil {
			a, err := scanID(actorRaw)
			if err != nil {
				return nil, err
			}
			n := identity.NodeID(a)
			event.ActorNodeID = &n
		}
		if targetRaw != nil {
			t, err := scanID(targetRaw)
			if err != nil {
				return nil, err
			}
			event.TargetID = &t
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
