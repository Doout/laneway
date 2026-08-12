package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

func normalizeAdministratorSessionOptions(options AdministratorSessionOptions) (AdministratorSessionOptions, error) {
	defaults := adminauth.DefaultSessionPolicy()
	if options.IdleTimeout == 0 {
		options.IdleTimeout = defaults.IdleLifetime
	}
	if options.AbsoluteTimeout == 0 {
		options.AbsoluteTimeout = defaults.AbsoluteLifetime
	}
	if options.MaxActive == 0 {
		options.MaxActive = defaults.MaximumSessions
	}
	if options.IdleTimeout%time.Second != 0 || options.AbsoluteTimeout%time.Second != 0 {
		return options, fmt.Errorf("%w: administrator session lifetimes must use whole seconds", ErrInvalid)
	}
	if err := (adminauth.SessionPolicy{IdleLifetime: options.IdleTimeout, AbsoluteLifetime: options.AbsoluteTimeout,
		MaximumSessions: options.MaxActive}).Validate(); err != nil {
		return options, fmt.Errorf("%w: invalid administrator session limits", ErrInvalid)
	}
	return options, nil
}

// CreateAdministratorSession returns the only copies of the new bearer and
// CSRF secrets. Only their purpose-separated SHA-256 digests are persisted.
func (s *Store) CreateAdministratorSession(ctx context.Context, principalID, credentialID identity.ID, options AdministratorSessionOptions) (AdministratorSession, string, string, error) {
	var result AdministratorSession
	options, err := normalizeAdministratorSessionOptions(options)
	if err != nil || principalID.IsZero() || credentialID.IsZero() {
		if err != nil {
			return result, "", "", err
		}
		return result, "", "", fmt.Errorf("%w: zero administrator or credential ID", ErrInvalid)
	}
	token, tokenHash, err := adminauth.NewSecret(adminauth.SecretSession, nil)
	if err != nil {
		return result, "", "", err
	}
	csrf, csrfHash, err := adminauth.NewSecret(adminauth.SecretCSRF, nil)
	if err != nil {
		return result, "", "", err
	}
	now := s.now()
	idleExpires, absoluteExpires, err := adminauth.SessionDeadlines(now, now, adminauth.SessionPolicy{
		IdleLifetime: options.IdleTimeout, AbsoluteLifetime: options.AbsoluteTimeout, MaximumSessions: options.MaxActive,
	})
	if err != nil {
		return result, "", "", err
	}
	sessionID, err := newID()
	if err != nil {
		return result, "", "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, "", "", err
	}
	defer tx.Rollback()
	var principalEnabled int
	var credentialRevoked sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT p.enabled,c.revoked_at
		FROM administrator_principals p JOIN administrator_credentials c ON c.principal_id=p.id
		WHERE p.id=? AND c.id=? AND c.credential_type='password'`, idBytes(principalID), idBytes(credentialID)).
		Scan(&principalEnabled, &credentialRevoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, "", "", ErrCredentialInvalid
		}
		return result, "", "", err
	}
	if principalEnabled != 1 || credentialRevoked.Valid {
		return result, "", "", ErrCredentialInvalid
	}
	if options.PreviousSessionID != nil {
		var previousPrincipal, previousCredential []byte
		var previousIdleLifetime, previousIdle, previousAbsolute int64
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT principal_id,credential_id,idle_lifetime_seconds,idle_expires_at,absolute_expires_at,revoked_at
			FROM administrator_sessions WHERE id=?`, idBytes(*options.PreviousSessionID)).
			Scan(&previousPrincipal, &previousCredential, &previousIdleLifetime, &previousIdle, &previousAbsolute, &revoked); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return result, "", "", ErrSessionInvalid
			}
			return result, "", "", err
		}
		previous, err := scanID(previousPrincipal)
		previousCredentialID, credentialErr := scanID(previousCredential)
		if err != nil || credentialErr != nil || previous != principalID || previousCredentialID != credentialID || revoked.Valid ||
			previousIdleLifetime < int64(time.Minute/time.Second) || previousIdleLifetime > int64(24*time.Hour/time.Second) ||
			!now.Before(fromUnix(previousIdle)) || !now.Before(fromUnix(previousAbsolute)) {
			return result, "", "", ErrSessionInvalid
		}
		options.IdleTimeout = time.Duration(previousIdleLifetime) * time.Second
		absoluteExpires = fromUnix(previousAbsolute)
		idleExpires = now.Add(options.IdleTimeout)
		if idleExpires.After(absoluteExpires) {
			idleExpires = absoluteExpires
		}
		rotated, err := revokeAdministratorSessionTx(ctx, tx, *options.PreviousSessionID,
			adminauth.IDActor(adminauth.ActorAdministrator, principalID), "administrator.session.revoke", "rotated", now)
		if err != nil {
			return result, "", "", err
		}
		if !rotated {
			return result, "", "", ErrSessionInvalid
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,idle_expires_at,absolute_expires_at FROM administrator_sessions
		WHERE principal_id=? AND revoked_at IS NULL ORDER BY created_at,id`, idBytes(principalID))
	if err != nil {
		return result, "", "", err
	}
	var active, expired []identity.ID
	for rows.Next() {
		var raw []byte
		var idle, absolute int64
		if err := rows.Scan(&raw, &idle, &absolute); err != nil {
			rows.Close()
			return result, "", "", err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return result, "", "", err
		}
		if idle <= unix(now) || absolute <= unix(now) {
			expired = append(expired, id)
		} else {
			active = append(active, id)
		}
	}
	if err := rows.Close(); err != nil {
		return result, "", "", err
	}
	if err := rows.Err(); err != nil {
		return result, "", "", err
	}
	for _, expiredID := range expired {
		if _, err := revokeAdministratorSessionTx(ctx, tx, expiredID, adminauth.SystemActor(),
			"administrator.session.expire", "expired", now); err != nil {
			return result, "", "", err
		}
	}
	for len(active) >= options.MaxActive {
		revoked, err := revokeAdministratorSessionTx(ctx, tx, active[0],
			adminauth.IDActor(adminauth.ActorAdministrator, principalID), "administrator.session.revoke",
			"concurrent session limit", now)
		if err != nil {
			return result, "", "", err
		}
		if !revoked {
			return result, "", "", ErrConflict
		}
		active = active[1:]
	}
	var previousBytes any
	if options.PreviousSessionID != nil {
		previousBytes = idBytes(*options.PreviousSessionID)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO administrator_sessions
		(id,principal_id,credential_id,token_hash,csrf_hash,previous_session_id,created_at,last_seen_at,idle_lifetime_seconds,idle_expires_at,absolute_expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, idBytes(sessionID), idBytes(principalID), idBytes(credentialID), tokenHash[:], csrfHash[:],
		previousBytes, unix(now), unix(now), int64(options.IdleTimeout/time.Second), unix(idleExpires), unix(absoluteExpires))
	if err != nil {
		if isConstraint(err) {
			return result, "", "", ErrConflict
		}
		return result, "", "", fmt.Errorf("create administrator session: %w", err)
	}
	target := sessionID
	action := "administrator.login"
	if options.PreviousSessionID != nil {
		action = "administrator.session.rotate"
	}
	if err := auditActorTx(ctx, tx, nil, adminauth.IDActor(adminauth.ActorAdministrator, principalID),
		action, "administrator_session", &target, `{}`, now); err != nil {
		return result, "", "", err
	}
	if err := tx.Commit(); err != nil {
		return result, "", "", err
	}
	result = AdministratorSession{ID: sessionID, PrincipalID: principalID, CredentialID: credentialID,
		TokenHash: tokenHash, CSRFHash: csrfHash, PreviousSessionID: options.PreviousSessionID,
		CreatedAt: now, LastSeenAt: now, IdleTimeout: options.IdleTimeout,
		IdleExpiresAt: idleExpires, AbsoluteExpiresAt: absoluteExpires}
	return result, token, csrf, nil
}

// AuthenticateAdministratorSession checks every durable authentication state:
// session, both deadlines, active credential, enabled principal, and scopes.
func (s *Store) AuthenticateAdministratorSession(ctx context.Context, token string) (AdministratorSession, adminauth.Principal, error) {
	var session AdministratorSession
	var principal adminauth.Principal
	digest, err := adminauth.HashSecret(adminauth.SecretSession, token)
	if err != nil {
		return session, principal, ErrSessionInvalid
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return session, principal, err
	}
	defer tx.Rollback()
	session, err = administratorSessionBy(ctx, tx, "s.token_hash=?", digest[:])
	if err != nil {
		return session, principal, err
	}
	if session.RevokedAt != nil {
		return session, principal, ErrSessionInvalid
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		if _, err := revokeAdministratorSessionTx(ctx, tx, session.ID, adminauth.SystemActor(),
			"administrator.session.expire", "expired", now); err != nil {
			return session, principal, err
		}
		if err := tx.Commit(); err != nil {
			return session, principal, err
		}
		return session, principal, ErrSessionExpired
	}
	record, recordErr := administratorRecord(ctx, tx, `p.id=?`, idBytes(session.PrincipalID))
	if recordErr != nil && !errors.Is(recordErr, ErrNotFound) {
		return session, principal, recordErr
	}
	if recordErr != nil || !record.Principal.Enabled || record.Credential.ID != session.CredentialID {
		if _, err := revokeAdministratorSessionTx(ctx, tx, session.ID, adminauth.SystemActor(),
			"administrator.session.revoke", "credential invalidated", now); err != nil {
			return session, principal, err
		}
		if err := tx.Commit(); err != nil {
			return session, principal, err
		}
		return session, principal, ErrSessionInvalid
	}
	if err := tx.Commit(); err != nil {
		return session, principal, err
	}
	return session, record.Principal, nil
}

func (s *Store) TouchAdministratorSession(ctx context.Context, sessionID identity.ID) (AdministratorSession, error) {
	var result AdministratorSession
	if sessionID.IsZero() {
		return result, ErrSessionInvalid
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	result, err = administratorSessionBy(ctx, tx, "s.id=?", idBytes(sessionID))
	if err != nil {
		return result, err
	}
	if result.RevokedAt != nil {
		return result, ErrSessionInvalid
	}
	if !now.Before(result.IdleExpiresAt) || !now.Before(result.AbsoluteExpiresAt) {
		if _, err := revokeAdministratorSessionTx(ctx, tx, result.ID, adminauth.SystemActor(),
			"administrator.session.expire", "expired", now); err != nil {
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return result, ErrSessionExpired
	}
	var credentialActive int
	if err := tx.QueryRowContext(ctx, `SELECT count(*)
		FROM administrator_principals p JOIN administrator_credentials c ON c.principal_id=p.id
		WHERE p.id=? AND p.enabled=1 AND c.id=? AND c.credential_type='password' AND c.revoked_at IS NULL`,
		idBytes(result.PrincipalID), idBytes(result.CredentialID)).Scan(&credentialActive); err != nil {
		return result, err
	}
	if credentialActive != 1 {
		if _, err := revokeAdministratorSessionTx(ctx, tx, result.ID, adminauth.SystemActor(),
			"administrator.session.revoke", "credential invalidated", now); err != nil {
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return result, ErrSessionInvalid
	}
	newIdle := now.Add(result.IdleTimeout)
	if newIdle.After(result.AbsoluteExpiresAt) {
		newIdle = result.AbsoluteExpiresAt
	}
	updated, err := tx.ExecContext(ctx, `UPDATE administrator_sessions SET last_seen_at=?,idle_expires_at=?
		WHERE id=? AND revoked_at IS NULL AND idle_expires_at>? AND absolute_expires_at>?`,
		unix(now), unix(newIdle), idBytes(sessionID), unix(now), unix(now))
	if err != nil {
		return result, err
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return result, ErrSessionExpired
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result.LastSeenAt, result.IdleExpiresAt = now, newIdle
	return result, nil
}

func (s *Store) RevokeAdministratorSession(ctx context.Context, actor adminauth.Actor, sessionID identity.ID, reason string) error {
	if !actor.Valid() || sessionID.IsZero() || len(reason) < 1 || len(reason) > adminauth.MaxSessionReason {
		return fmt.Errorf("%w: invalid administrator session revocation", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	revoked, err := revokeAdministratorSessionTx(ctx, tx, sessionID, actor,
		"administrator.session.revoke", reason, now)
	if err != nil {
		return err
	}
	if !revoked {
		var found int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions WHERE id=?`, idBytes(sessionID)).Scan(&found); err != nil {
			return err
		}
		if found == 0 {
			return ErrNotFound
		}
		return tx.Commit()
	}
	return tx.Commit()
}

func revokeAdministratorSessionTx(ctx context.Context, tx *sql.Tx, sessionID identity.ID, actor adminauth.Actor,
	action, reason string, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE administrator_sessions SET revoked_at=?,revocation_reason=?
		WHERE id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(sessionID))
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		return false, nil
	}
	target := sessionID
	if err := auditActorTx(ctx, tx, nil, actor, action, "administrator_session", &target,
		fmt.Sprintf(`{"reason":%q}`, reason), now); err != nil {
		return false, err
	}
	return true, nil
}

type rowScanner interface {
	Scan(...any) error
}

func administratorSessionBy(ctx context.Context, queryer rowQueryer, predicate string, argument any) (AdministratorSession, error) {
	row := queryer.QueryRowContext(ctx, `SELECT s.id,s.principal_id,s.credential_id,s.token_hash,s.csrf_hash,
		s.previous_session_id,s.created_at,s.last_seen_at,s.idle_lifetime_seconds,s.idle_expires_at,s.absolute_expires_at,s.revoked_at,s.revocation_reason
		FROM administrator_sessions s WHERE `+predicate, argument)
	return scanAdministratorSession(row)
}

func scanAdministratorSession(scanner rowScanner) (AdministratorSession, error) {
	var result AdministratorSession
	var idRaw, principalRaw, credentialRaw, tokenRaw, csrfRaw, previousRaw []byte
	var created, lastSeen, idleLifetime, idleExpires, absoluteExpires int64
	var revoked sql.NullInt64
	err := scanner.Scan(&idRaw, &principalRaw, &credentialRaw, &tokenRaw, &csrfRaw, &previousRaw,
		&created, &lastSeen, &idleLifetime, &idleExpires, &absoluteExpires, &revoked, &result.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrSessionInvalid
	}
	if err != nil {
		return result, err
	}
	result.ID, err = scanID(idRaw)
	if err != nil {
		return result, err
	}
	result.PrincipalID, err = scanID(principalRaw)
	if err != nil {
		return result, err
	}
	result.CredentialID, err = scanID(credentialRaw)
	if err != nil {
		return result, err
	}
	if len(tokenRaw) != sha256.Size || len(csrfRaw) != sha256.Size {
		return result, errors.New("corrupt administrator session secret hash")
	}
	copy(result.TokenHash[:], tokenRaw)
	copy(result.CSRFHash[:], csrfRaw)
	if previousRaw != nil {
		previous, err := scanID(previousRaw)
		if err != nil {
			return result, err
		}
		result.PreviousSessionID = &previous
	}
	result.CreatedAt, result.LastSeenAt = fromUnix(created), fromUnix(lastSeen)
	if idleLifetime < int64(time.Minute/time.Second) || idleLifetime > int64(24*time.Hour/time.Second) {
		return result, errors.New("corrupt administrator session idle lifetime")
	}
	result.IdleTimeout = time.Duration(idleLifetime) * time.Second
	result.IdleExpiresAt, result.AbsoluteExpiresAt = fromUnix(idleExpires), fromUnix(absoluteExpires)
	wantIdle := result.LastSeenAt.Add(result.IdleTimeout)
	if wantIdle.After(result.AbsoluteExpiresAt) {
		wantIdle = result.AbsoluteExpiresAt
	}
	if !result.IdleExpiresAt.Equal(wantIdle) || result.LastSeenAt.Before(result.CreatedAt) ||
		!result.AbsoluteExpiresAt.After(result.CreatedAt) {
		return result, errors.New("corrupt administrator session lifetime")
	}
	result.RevokedAt = nullableTime(revoked)
	return result, nil
}
