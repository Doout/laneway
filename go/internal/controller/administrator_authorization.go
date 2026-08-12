package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

type administratorDecisionAuthorization struct {
	actor     adminauth.Actor
	principal *adminauth.Principal
}

// authorizeAdministratorDecisionTx turns an early, immutable routing decision
// into durable authority for exactly one Store transaction. It deliberately
// reloads every mutable authorization input from SQLite: the root identity or
// exact session, credential, principal role, enabled state, and network grants.
//
// Object-target callers must first compare the decision's object ID with their
// requested object and resolve that object's canonical network in this same
// transaction. A global operation passes nil for canonicalNetworkID.
func (s *Store) authorizeAdministratorDecisionTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision, canonicalNetworkID *identity.NetworkID) (adminauth.Actor, error) {
	authorization, err := s.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return adminauth.Actor{}, err
	}
	if err := authorizeAdministratorDecisionScope(authorization, decision, canonicalNetworkID); err != nil {
		return adminauth.Actor{}, err
	}
	return authorization.actor, nil
}

// administratorDecisionPrincipalTx authorizes a filtered global list. A nil
// principal identifies the root service principal and therefore no filtering;
// a session principal contains its current durable grants.
func (s *Store) administratorDecisionPrincipalTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision) (adminauth.Actor, *adminauth.Principal, error) {
	if !decision.Valid() || decision.Target().Kind() != adminauth.DecisionTargetFiltered ||
		decision.Operation() != adminauth.OperationNetworkList {
		return adminauth.Actor{}, nil, fmt.Errorf("%w: invalid filtered administrator decision", ErrInvalid)
	}
	authorization, err := s.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return adminauth.Actor{}, nil, err
	}
	if err := authorizeAdministratorDecisionScope(authorization, decision, nil); err != nil {
		return adminauth.Actor{}, nil, err
	}
	return authorization.actor, authorization.principal, nil
}

// authenticateAdministratorDecisionSubjectTx must run before an ObjectTarget
// lookup. It prevents missing-versus-existing objects from becoming a credential
// oracle while retaining the principal snapshot for canonical scope checks.
func (s *Store) authenticateAdministratorDecisionSubjectTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision) (administratorDecisionAuthorization, error) {
	var result administratorDecisionAuthorization
	if tx == nil || !decision.Valid() {
		return result, fmt.Errorf("%w: invalid administrator decision", ErrInvalid)
	}
	subject := decision.Subject()
	if (decision.Operation() == adminauth.OperationRecoveryManage ||
		decision.Operation() == adminauth.OperationRootTokenRotate) &&
		subject.Kind() != adminauth.SubjectRootServicePrincipal {
		return result, ErrPermissionDenied
	}
	switch subject.Kind() {
	case adminauth.SubjectRootServicePrincipal:
		var rootRaw []byte
		if err := tx.QueryRowContext(ctx, `SELECT root_service_principal_id
			FROM administrator_auth_state WHERE singleton=1`).Scan(&rootRaw); err != nil {
			return result, fmt.Errorf("revalidate administrator root subject: %w", err)
		}
		rootID, err := scanID(rootRaw)
		if err != nil || subject.ActorID() != rootID {
			return result, ErrCredentialInvalid
		}
		result.actor = subject.Actor()
		return result, nil

	case adminauth.SubjectAdministratorSession:
		sessionID, ok := subject.SessionID()
		if !ok {
			return result, ErrSessionInvalid
		}
		session, err := administratorSessionBy(ctx, tx, "s.id=?", idBytes(sessionID))
		if err != nil || session.PrincipalID != subject.ActorID() || session.RevokedAt != nil {
			return result, ErrSessionInvalid
		}
		now := s.now()
		if now.Before(session.LastSeenAt) || !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
			return result, ErrSessionInvalid
		}
		record, err := administratorRecord(ctx, tx, `p.id=?`, idBytes(session.PrincipalID))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return result, err
		}
		if err != nil || !record.Principal.Enabled || record.Credential.ID != session.CredentialID {
			return result, ErrSessionInvalid
		}
		if !adminauth.RoleAllows(record.Principal.Role, decision.Operation()) {
			return result, ErrPermissionDenied
		}
		newIdle := now.Add(session.IdleTimeout)
		if newIdle.After(session.AbsoluteExpiresAt) {
			newIdle = session.AbsoluteExpiresAt
		}
		updated, err := tx.ExecContext(ctx, `UPDATE administrator_sessions
			SET last_seen_at=?,idle_expires_at=?
			WHERE id=? AND revoked_at IS NULL AND last_seen_at=?
			AND idle_expires_at>? AND absolute_expires_at>?`,
			unix(now), unix(newIdle), idBytes(session.ID), unix(session.LastSeenAt), unix(now), unix(now))
		if err != nil {
			return result, err
		}
		if affected, _ := updated.RowsAffected(); affected != 1 {
			return result, ErrSessionInvalid
		}
		principal := record.Principal
		principal.NetworkIDs = slices.Clone(principal.NetworkIDs)
		result.actor, result.principal = subject.Actor(), &principal
		return result, nil

	default:
		return result, ErrCredentialInvalid
	}
}

func authorizeAdministratorDecisionScope(authorization administratorDecisionAuthorization, decision adminauth.Decision,
	canonicalNetworkID *identity.NetworkID) error {
	if !decision.Valid() || !authorization.actor.Valid() {
		return fmt.Errorf("%w: invalid administrator scope authorization", ErrInvalid)
	}
	networkScoped := decision.Operation().NetworkScoped()
	if networkScoped != (canonicalNetworkID != nil) || canonicalNetworkID != nil && canonicalNetworkID.IsZero() {
		return fmt.Errorf("%w: administrator decision scope mismatch", ErrInvalid)
	}
	switch decision.Target().Kind() {
	case adminauth.DecisionTargetNetwork:
		targetNetwork, ok := decision.Target().NetworkID()
		if !ok || canonicalNetworkID == nil || targetNetwork != *canonicalNetworkID {
			return fmt.Errorf("%w: administrator decision network mismatch", ErrInvalid)
		}
	case adminauth.DecisionTargetObject:
		// Exact object binding is checked by the caller before authentication;
		// only its canonical network is supplied here after the object lookup.
	case adminauth.DecisionTargetGlobal, adminauth.DecisionTargetFiltered:
		if canonicalNetworkID != nil {
			return fmt.Errorf("%w: global administrator decision has a network", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: invalid administrator decision target", ErrInvalid)
	}
	if authorization.principal != nil &&
		!adminauth.Authorize(*authorization.principal, decision.Operation(), canonicalNetworkID) {
		return ErrPermissionDenied
	}
	return nil
}

func decisionObjectMatches(decision adminauth.Decision, objectID identity.ID, operation adminauth.Operation) error {
	if !decision.Valid() || decision.Operation() != operation || objectID.IsZero() {
		return fmt.Errorf("%w: invalid administrator object decision", ErrInvalid)
	}
	targetID, ok := decision.Target().ObjectID()
	if !ok || targetID != objectID {
		return fmt.Errorf("%w: administrator object decision mismatch", ErrInvalid)
	}
	return nil
}

func isAdministratorAuthorizationFailure(err error) bool {
	return errors.Is(err, ErrCredentialInvalid) || errors.Is(err, ErrSessionInvalid) || errors.Is(err, ErrPermissionDenied)
}
