package controller

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

type administratorMutationContextKey struct{}

// AuditPageCursor is the durable sort key of the final event returned by an
// audit page. API layers encode it as an opaque token; Store callers must not
// construct cursors from anything other than a previously returned page.
type AuditPageCursor struct {
	CreatedAt time.Time
	ID        identity.ID
}

// AuditPage contains one deterministic slice of the audit stream. NextCursor
// is nil only when the query proved there are no older records.
type AuditPage struct {
	Events     []AuditEvent
	NextCursor *AuditPageCursor
}

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
	page, err := s.AuditEventsPage(ctx, networkID, limit, nil)
	return page.Events, err
}

// AuditEventsPage returns a complete, resumable network audit page ordered
// newest first. Rows inserted after the first request do not duplicate or skip
// records while a caller continues from the returned cursor.
func (s *Store) AuditEventsPage(ctx context.Context, networkID identity.NetworkID, limit int, cursor *AuditPageCursor) (AuditPage, error) {
	if networkID.IsZero() {
		return AuditPage{}, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	return queryAuditEventsPage(ctx, s.db, &networkID, limit, cursor)
}

func (s *Store) AdministratorAuditEvents(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, limit int) ([]AuditEvent, error) {
	page, err := s.administratorAuditEventsPage(ctx, decision, networkID, limit, nil, administratorAuditListPolicy)
	return page.Events, err
}

// AdministratorAuditEventsPage is the authorized network-scoped audit cursor
// read. Authorization and page selection share one database transaction.
func (s *Store) AdministratorAuditEventsPage(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, limit int, cursor *AuditPageCursor) (AuditPage, error) {
	return s.administratorAuditEventsPage(ctx, decision, networkID, limit, cursor, administratorAuditPageListPolicy)
}

func (s *Store) administratorAuditEventsPage(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID,
	limit int, cursor *AuditPageCursor, policy adminauth.RoutePolicy) (AuditPage, error) {
	if err := validateAuditPage(limit, cursor); err != nil {
		return AuditPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditPage{}, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, policy, networkID); err != nil {
		return AuditPage{}, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return AuditPage{}, err
	}
	page, err := queryAuditEventsPage(ctx, tx, &networkID, limit, cursor)
	if err != nil {
		return AuditPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditPage{}, err
	}
	return page, nil
}

// AdministratorGlobalAuditEvents returns the global lifecycle stream and all
// network-scoped events after revalidating the exact owner/root decision in
// the same read transaction. Ordering matches the existing audit APIs.
func (s *Store) AdministratorGlobalAuditEvents(ctx context.Context, decision adminauth.Decision, limit int) ([]AuditEvent, error) {
	page, err := s.administratorGlobalAuditEventsPage(ctx, decision, limit, nil, administratorGlobalAuditListPolicy)
	return page.Events, err
}

// AdministratorGlobalAuditEventsPage returns a resumable global audit stream
// after revalidating the exact owner/root decision in the read transaction.
func (s *Store) AdministratorGlobalAuditEventsPage(ctx context.Context, decision adminauth.Decision, limit int, cursor *AuditPageCursor) (AuditPage, error) {
	return s.administratorGlobalAuditEventsPage(ctx, decision, limit, cursor, administratorGlobalAuditPageListPolicy)
}

func (s *Store) administratorGlobalAuditEventsPage(ctx context.Context, decision adminauth.Decision, limit int,
	cursor *AuditPageCursor, policy adminauth.RoutePolicy) (AuditPage, error) {
	if err := validateAuditPage(limit, cursor); err != nil {
		return AuditPage{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditPage{}, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorGlobalResourceTx(ctx, tx, decision,
		policy, adminauth.GlobalTarget()); err != nil {
		return AuditPage{}, err
	}
	page, err := queryAuditEventsPage(ctx, tx, nil, limit, cursor)
	if err != nil {
		return AuditPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditPage{}, err
	}
	return page, nil
}

// GlobalAuditEvents returns global authentication/recovery records alongside
// network-scoped administrative and node events. NetworkScope is nil only for
// a genuinely global event.
func (s *Store) GlobalAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	page, err := s.GlobalAuditEventsPage(ctx, limit, nil)
	return page.Events, err
}

// GlobalAuditEventsPage returns a resumable global audit page for internal
// controller consumers that do not use the administrator authorization layer.
func (s *Store) GlobalAuditEventsPage(ctx context.Context, limit int, cursor *AuditPageCursor) (AuditPage, error) {
	return queryAuditEventsPage(ctx, s.db, nil, limit, cursor)
}

type auditPageQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func validateAuditPage(limit int, cursor *AuditPageCursor) error {
	if limit < 1 || limit > 1000 {
		return fmt.Errorf("%w: audit limit must be 1..1000", ErrInvalid)
	}
	if cursor == nil {
		return nil
	}
	createdAt := cursor.CreatedAt.UTC()
	if cursor.ID.IsZero() || createdAt.IsZero() || !createdAt.Equal(createdAt.Truncate(time.Second)) {
		return fmt.Errorf("%w: invalid audit cursor", ErrInvalid)
	}
	return nil
}

func queryAuditEventsPage(ctx context.Context, queryer auditPageQueryer, networkID *identity.NetworkID,
	limit int, cursor *AuditPageCursor) (AuditPage, error) {
	if err := validateAuditPage(limit, cursor); err != nil {
		return AuditPage{}, err
	}
	conditions := make([]string, 0, 2)
	arguments := make([]any, 0, 5)
	if networkID != nil {
		if networkID.IsZero() {
			return AuditPage{}, fmt.Errorf("%w: network ID", ErrInvalid)
		}
		conditions = append(conditions, "network_id=?")
		arguments = append(arguments, idBytes(*networkID))
	}
	if cursor != nil {
		conditions = append(conditions, "(created_at<? OR (created_at=? AND id<?))")
		createdAt := unix(cursor.CreatedAt)
		arguments = append(arguments, createdAt, createdAt, idBytes(cursor.ID))
	}
	query := `SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at FROM audit_events`
	if len(conditions) != 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY created_at DESC,id DESC LIMIT ?"
	arguments = append(arguments, limit+1)
	rows, err := queryer.QueryContext(ctx, query, arguments...)
	if err != nil {
		return AuditPage{}, fmt.Errorf("query audit event page: %w", err)
	}
	events, err := scanAuditEvents(rows)
	if err != nil {
		return AuditPage{}, err
	}
	page := AuditPage{Events: events}
	if len(events) > limit {
		page.Events = events[:limit]
		last := page.Events[len(page.Events)-1]
		page.NextCursor = &AuditPageCursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return page, nil
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
