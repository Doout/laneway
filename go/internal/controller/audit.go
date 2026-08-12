package controller

import (
	"context"
	"database/sql"
	"fmt"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

type administratorMutationContextKey struct{}

type administratorMutationAuthorization struct {
	actor     adminauth.Actor
	operation adminauth.Operation
	networkID *identity.NetworkID
}

// WithAdministratorMutationActor binds the authenticated static root bearer to
// a management mutation. Browser administrator sessions are deliberately
// rejected until their exact session, credential, deadline, role, and scope
// can all be revalidated inside the mutation's SQL transaction.
func WithAdministratorMutationActor(ctx context.Context, actor adminauth.Actor, operation adminauth.Operation, networkID *identity.NetworkID) (context.Context, error) {
	if ctx == nil || !actor.Valid() || actor.Kind != adminauth.ActorServicePrincipal ||
		!operation.Valid() || (!operation.NetworkScoped() && networkID != nil) {
		return nil, fmt.Errorf("%w: administrator mutation authorization", ErrInvalid)
	}
	authorization := administratorMutationAuthorization{actor: adminauth.Actor{Kind: actor.Kind}, operation: operation}
	if actor.ID != nil {
		copyID := *actor.ID
		authorization.actor.ID = &copyID
	}
	if networkID != nil {
		copyID := *networkID
		if copyID.IsZero() {
			return nil, fmt.Errorf("%w: administrator mutation network", ErrInvalid)
		}
		authorization.networkID = &copyID
	}
	return context.WithValue(ctx, administratorMutationContextKey{}, authorization), nil
}

func administratorMutationAuthorizationFrom(ctx context.Context) (administratorMutationAuthorization, bool) {
	value, ok := ctx.Value(administratorMutationContextKey{}).(administratorMutationAuthorization)
	return value, ok
}

// AuditAdministratorMutation records a management mutation that has no
// durable controller row of its own, such as an in-memory bootstrap bundle.
// Durable Store mutations must continue to audit within their own transaction.
func (s *Store) AuditAdministratorMutation(ctx context.Context, action, targetType, details string) error {
	authorization, ok := administratorMutationAuthorizationFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: missing administrator mutation authorization", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := authorizeAdministratorMutationTx(ctx, tx, authorization.actor, authorization.operation, authorization.networkID); err != nil {
		return err
	}
	if err := auditActorTx(ctx, tx, authorization.networkID, authorization.actor, action, targetType, nil, details, s.now()); err != nil {
		return err
	}
	return tx.Commit()
}

// AdministratorAuditMutation records the bootstrap bundle mutation, whose
// payload is intentionally ephemeral and therefore has no durable resource
// row. The exact global route decision is revalidated in the audit write
// transaction; durable resource mutations audit in their own Store methods.
func (s *Store) AdministratorAuditMutation(ctx context.Context, decision adminauth.Decision, action, targetType, details string) error {
	if action != "bootstrap_bundle.create" || targetType != "bootstrap_bundle" {
		return fmt.Errorf("%w: unsupported non-resource administrator audit", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := s.authorizeAdministratorGlobalResourceTx(ctx, tx, decision,
		administratorBootstrapCreatePolicy, adminauth.GlobalTarget())
	if err != nil {
		return err
	}
	if err := auditActorTx(ctx, tx, nil, actor, action, targetType, nil, details, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit authorized administrator audit: %w", err)
	}
	return nil
}

func (s *Store) AuditEvents(ctx context.Context, networkID identity.NetworkID, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at
		FROM audit_events WHERE network_id=? ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	return scanAuditEvents(rows)
}

func (s *Store) AdministratorAuditEvents(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAuditListPolicy, networkID); err != nil {
		return nil, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at
		FROM audit_events WHERE network_id=? ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("query authorized audit events: %w", err)
	}
	events, err := scanAuditEvents(rows)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// AdministratorGlobalAuditEvents returns the global lifecycle stream and all
// network-scoped events after revalidating the exact owner/root decision in
// the same read transaction. Ordering matches the existing audit APIs.
func (s *Store) AdministratorGlobalAuditEvents(ctx context.Context, decision adminauth.Decision, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorGlobalResourceTx(ctx, tx, decision,
		administratorGlobalAuditListPolicy, adminauth.GlobalTarget()); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at
		FROM audit_events ORDER BY created_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query authorized global audit events: %w", err)
	}
	events, err := scanAuditEvents(rows)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// GlobalAuditEvents returns global authentication/recovery records alongside
// network-scoped administrative and node events. NetworkScope is nil only for
// a genuinely global event.
func (s *Store) GlobalAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at
		FROM audit_events ORDER BY created_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query global audit events: %w", err)
	}
	return scanAuditEvents(rows)
}

func scanAuditEvents(rows *sql.Rows) ([]AuditEvent, error) {
	defer rows.Close()
	events := make([]AuditEvent, 0)
	for rows.Next() {
		var idRaw, networkRaw, actorRaw, targetRaw []byte
		var event AuditEvent
		var actorKind string
		var created int64
		if err := rows.Scan(&idRaw, &networkRaw, &actorKind, &actorRaw, &event.Action, &event.TargetType, &targetRaw, &event.Details, &created); err != nil {
			return nil, err
		}
		id, err := scanID(idRaw)
		if err != nil {
			return nil, err
		}
		event.ID, event.CreatedAt = id, fromUnix(created)
		if networkRaw != nil {
			network, err := scanID(networkRaw)
			if err != nil {
				return nil, err
			}
			networkID := identity.NetworkID(network)
			event.NetworkID, event.NetworkScope = networkID, &networkID
		}
		event.Actor.Kind = adminauth.ActorKind(actorKind)
		if actorRaw != nil {
			a, err := scanID(actorRaw)
			if err != nil {
				return nil, err
			}
			event.Actor.ID = &a
			if event.Actor.Kind == adminauth.ActorNode {
				n := identity.NodeID(a)
				event.ActorNodeID = &n
			}
		}
		if !event.Actor.Valid() {
			return nil, fmt.Errorf("corrupt audit actor kind %q", actorKind)
		}
		if targetRaw != nil {
			target, err := scanID(targetRaw)
			if err != nil {
				return nil, err
			}
			event.TargetID = &target
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
