package controller

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
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

// AdministratorPasswordCandidate performs the constant-shape lookup used
// before bounded Argon2 verification. Account absence, disabled state, and a
// missing active credential are deliberately represented by an unusable
// candidate rather than distinguishable errors.
func (s *Store) AdministratorPasswordCandidate(ctx context.Context, username string) (AdministratorPasswordCandidate, error) {
	var candidate AdministratorPasswordCandidate
	if !adminauth.ValidateUsername(username) {
		return candidate, nil
	}
	var principalRaw, credentialRaw []byte
	var passwordHash sql.NullString
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT p.id,p.enabled,c.id,c.secret_hash
		FROM administrator_principals p
		LEFT JOIN administrator_credentials c ON c.principal_id=p.id
			AND c.credential_type='password' AND c.revoked_at IS NULL
		WHERE p.username=?`, username).Scan(&principalRaw, &enabled, &credentialRaw, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return AdministratorPasswordCandidate{}, nil
	}
	if err != nil {
		return candidate, fmt.Errorf("read administrator password candidate: %w", err)
	}
	if credentialRaw == nil || !passwordHash.Valid {
		return AdministratorPasswordCandidate{}, nil
	}
	candidate.PasswordHash = passwordHash.String
	principalID, principalErr := scanID(principalRaw)
	credentialID, credentialErr := scanID(credentialRaw)
	if principalErr != nil || credentialErr != nil || validatePasswordHash(candidate.PasswordHash) != nil {
		return AdministratorPasswordCandidate{}, errors.New("corrupt administrator password candidate")
	}
	candidate.PrincipalID, candidate.CredentialID = principalID, credentialID
	candidate.Usable = enabled == 1
	return candidate, nil
}

// CreateAdministratorSessionAfterPassword is the only normal login session
// creator. Password verification occurs before this call; the exact immutable
// credential IDs are revalidated by CreateAdministratorSession in its write
// transaction so replacement or disablement racing verification fails closed.
func (s *Store) CreateAdministratorSessionAfterPassword(ctx context.Context, candidate AdministratorPasswordCandidate,
	options AdministratorSessionOptions) (AdministratorSession, string, string, error) {
	if !candidate.Usable || candidate.PrincipalID.IsZero() || candidate.CredentialID.IsZero() ||
		validatePasswordHash(candidate.PasswordHash) != nil {
		return AdministratorSession{}, "", "", ErrCredentialInvalid
	}
	return s.CreateAdministratorSession(ctx, candidate.PrincipalID, candidate.CredentialID, options)
}

// CreateAdministratorSession returns the only copies of the new bearer and
// CSRF secrets. Only their purpose-separated SHA-256 digests are persisted.
// It is a low-level compatibility/test primitive; production password login
// must call CreateAdministratorSessionAfterPassword so the verified candidate
// is carried into the transaction.
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
	sessionID, err := newID()
	if err != nil {
		return result, "", "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, "", "", err
	}
	defer tx.Rollback()
	now := s.now()
	idleExpires, absoluteExpires, err := adminauth.SessionDeadlines(now, now, adminauth.SessionPolicy{
		IdleLifetime: options.IdleTimeout, AbsoluteLifetime: options.AbsoluteTimeout, MaximumSessions: options.MaxActive,
	})
	if err != nil {
		return result, "", "", err
	}
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
		var previousLastSeen, previousIdleLifetime, previousMaximumSessions, previousIdle, previousAbsolute int64
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT principal_id,credential_id,last_seen_at,idle_lifetime_seconds,maximum_sessions,idle_expires_at,absolute_expires_at,revoked_at
			FROM administrator_sessions WHERE id=?`, idBytes(*options.PreviousSessionID)).
			Scan(&previousPrincipal, &previousCredential, &previousLastSeen, &previousIdleLifetime, &previousMaximumSessions, &previousIdle, &previousAbsolute, &revoked); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return result, "", "", ErrSessionInvalid
			}
			return result, "", "", err
		}
		previous, err := scanID(previousPrincipal)
		previousCredentialID, credentialErr := scanID(previousCredential)
		if err != nil || credentialErr != nil || previous != principalID || previousCredentialID != credentialID || revoked.Valid ||
			previousIdleLifetime < int64(time.Minute/time.Second) || previousIdleLifetime > int64(24*time.Hour/time.Second) ||
			previousMaximumSessions < 1 || previousMaximumSessions > 20 ||
			now.Before(fromUnix(previousLastSeen)) ||
			!now.Before(fromUnix(previousIdle)) || !now.Before(fromUnix(previousAbsolute)) {
			return result, "", "", ErrSessionInvalid
		}
		options.IdleTimeout = time.Duration(previousIdleLifetime) * time.Second
		options.MaxActive = int(previousMaximumSessions)
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
	rows, err := tx.QueryContext(ctx, `SELECT id,created_at,last_seen_at,idle_expires_at,absolute_expires_at FROM administrator_sessions
		WHERE principal_id=? AND revoked_at IS NULL ORDER BY created_at,id`, idBytes(principalID))
	if err != nil {
		return result, "", "", err
	}
	var active, expired []AdministratorSession
	for rows.Next() {
		var raw []byte
		var created, lastSeen, idle, absolute int64
		if err := rows.Scan(&raw, &created, &lastSeen, &idle, &absolute); err != nil {
			rows.Close()
			return result, "", "", err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return result, "", "", err
		}
		session := AdministratorSession{ID: id, CreatedAt: fromUnix(created), LastSeenAt: fromUnix(lastSeen)}
		if idle <= unix(now) || absolute <= unix(now) {
			expired = append(expired, session)
		} else {
			active = append(active, session)
		}
	}
	if err := rows.Close(); err != nil {
		return result, "", "", err
	}
	if err := rows.Err(); err != nil {
		return result, "", "", err
	}
	for _, expiredSession := range expired {
		if _, err := revokeAdministratorSessionTx(ctx, tx, expiredSession.ID, adminauth.SystemActor(),
			"administrator.session.expire", "expired",
			administratorSessionRevocationTime(now, expiredSession)); err != nil {
			return result, "", "", err
		}
	}
	for len(active) >= options.MaxActive {
		revoked, err := revokeAdministratorSessionTx(ctx, tx, active[0].ID,
			adminauth.IDActor(adminauth.ActorAdministrator, principalID), "administrator.session.revoke",
			"concurrent session limit", administratorSessionRevocationTime(now, active[0]))
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
		(id,principal_id,credential_id,token_hash,csrf_hash,previous_session_id,created_at,last_seen_at,idle_lifetime_seconds,maximum_sessions,idle_expires_at,absolute_expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, idBytes(sessionID), idBytes(principalID), idBytes(credentialID), tokenHash[:], csrfHash[:],
		previousBytes, unix(now), unix(now), int64(options.IdleTimeout/time.Second), options.MaxActive, unix(idleExpires), unix(absoluteExpires))
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
		MaximumSessions: options.MaxActive,
		IdleExpiresAt:   idleExpires, AbsoluteExpiresAt: absoluteExpires}
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return session, principal, err
	}
	defer tx.Rollback()
	now := s.now()
	session, err = administratorSessionBy(ctx, tx, "s.token_hash=?", digest[:])
	if err != nil {
		return session, principal, err
	}
	if session.RevokedAt != nil {
		return session, principal, ErrSessionInvalid
	}
	if now.Before(session.LastSeenAt) {
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

// AuthenticateAndTouchAdministratorSession authenticates and slides the idle
// deadline in one transaction. The returned principal is the current durable
// role/scope snapshot used only for early authorization; mutations revalidate
// it again inside their own transactions.
func (s *Store) AuthenticateAndTouchAdministratorSession(ctx context.Context, token string) (AdministratorSession, adminauth.Principal, error) {
	var session AdministratorSession
	var principal adminauth.Principal
	digest, err := adminauth.HashSecret(adminauth.SecretSession, token)
	if err != nil {
		return session, principal, ErrSessionInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return session, principal, err
	}
	defer tx.Rollback()
	now := s.now()
	session, err = administratorSessionBy(ctx, tx, "s.token_hash=?", digest[:])
	if err != nil {
		return session, principal, err
	}
	if session.RevokedAt != nil {
		return session, principal, ErrSessionInvalid
	}
	if now.Before(session.LastSeenAt) {
		return session, principal, ErrSessionInvalid
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
		if _, revokeErr := revokeAdministratorSessionTx(ctx, tx, session.ID, adminauth.SystemActor(),
			"administrator.session.expire", "expired", now); revokeErr != nil {
			return session, principal, revokeErr
		}
		if err := tx.Commit(); err != nil {
			return session, principal, err
		}
		return session, principal, ErrSessionExpired
	}
	record, err := administratorRecord(ctx, tx, `p.id=?`, idBytes(session.PrincipalID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return session, principal, err
	}
	if err != nil || !record.Principal.Enabled || record.Credential.ID != session.CredentialID {
		if _, revokeErr := revokeAdministratorSessionTx(ctx, tx, session.ID, adminauth.SystemActor(),
			"administrator.session.revoke", "credential invalidated", now); revokeErr != nil {
			return session, principal, revokeErr
		}
		if err := tx.Commit(); err != nil {
			return session, principal, err
		}
		return session, principal, ErrSessionInvalid
	}
	newIdle := now.Add(session.IdleTimeout)
	if newIdle.After(session.AbsoluteExpiresAt) {
		newIdle = session.AbsoluteExpiresAt
	}
	updated, err := tx.ExecContext(ctx, `UPDATE administrator_sessions SET last_seen_at=?,idle_expires_at=?
		WHERE id=? AND revoked_at IS NULL AND last_seen_at=? AND idle_expires_at>? AND absolute_expires_at>?`,
		unix(now), unix(newIdle), idBytes(session.ID), unix(session.LastSeenAt), unix(now), unix(now))
	if err != nil {
		return session, principal, err
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return session, principal, ErrSessionInvalid
	}
	if err := tx.Commit(); err != nil {
		return session, principal, err
	}
	session.LastSeenAt, session.IdleExpiresAt = now, newIdle
	return session, record.Principal, nil
}

// RotateAdministratorSession revokes one exact predecessor and creates its
// sole successor. Lifetime and concurrency policy are inherited from the
// predecessor; callers cannot extend them during rotation.
func (s *Store) RotateAdministratorSession(ctx context.Context, subject adminauth.Subject) (AdministratorSession, string, string, error) {
	if !subject.Valid() || subject.Kind() != adminauth.SubjectAdministratorSession {
		return AdministratorSession{}, "", "", ErrSessionInvalid
	}
	sessionID, ok := subject.SessionID()
	if !ok {
		return AdministratorSession{}, "", "", ErrSessionInvalid
	}
	previous, err := administratorSessionBy(ctx, s.db, "s.id=?", idBytes(sessionID))
	if err != nil {
		return AdministratorSession{}, "", "", err
	}
	if previous.PrincipalID != subject.ActorID() {
		return AdministratorSession{}, "", "", ErrSessionInvalid
	}
	return s.CreateAdministratorSession(ctx, previous.PrincipalID, previous.CredentialID,
		AdministratorSessionOptions{PreviousSessionID: &sessionID})
}

// LogoutAdministratorSession invalidates the caller's complete rotation
// family. A logout queued behind a successful rotation therefore revokes the
// newly-created successor before it can be used, while a rotation queued
// behind logout fails its predecessor recheck. HTTP callers should clear
// cookies even when this returns ErrSessionInvalid.
func (s *Store) LogoutAdministratorSession(ctx context.Context, subject adminauth.Subject) error {
	if !subject.Valid() || subject.Kind() != adminauth.SubjectAdministratorSession {
		return ErrSessionInvalid
	}
	sessionID, ok := subject.SessionID()
	if !ok {
		return ErrSessionInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	session, err := administratorSessionBy(ctx, tx, "s.id=?", idBytes(sessionID))
	if err != nil {
		return err
	}
	if session.PrincipalID != subject.ActorID() {
		return ErrSessionInvalid
	}
	if session.RevokedAt != nil && session.RevocationReason != "rotated" {
		return ErrSessionInvalid
	}
	if session.RevokedAt == nil && (!now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt)) {
		if _, err := revokeAdministratorSessionTx(ctx, tx, session.ID, adminauth.SystemActor(),
			"administrator.session.expire", "expired", now); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return ErrSessionInvalid
	}
	family, err := administratorSessionFamilyTx(ctx, tx, session.ID)
	if err != nil {
		return err
	}
	for _, member := range family {
		if member.PrincipalID != subject.ActorID() {
			return errors.New("corrupt administrator session rotation family")
		}
		if member.RevokedAt != nil {
			continue
		}
		if _, err := revokeAdministratorSessionTx(ctx, tx, member.ID, subject.Actor(),
			"administrator.logout", "logout", administratorSessionRevocationTime(now, member)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LogoutAdministratorSessionBySecrets is the browser logout credential path.
// It intentionally does not depend on normal session authentication: a rotate
// response and logout request may cross in flight, leaving the supplied token
// as a rotation predecessor by the time the request reaches SQLite. The exact
// bearer and CSRF digests are checked together before the complete successor
// family is revoked in one immediate transaction.
func (s *Store) LogoutAdministratorSessionBySecrets(ctx context.Context, sessionToken, csrfToken string) error {
	tokenHash, err := adminauth.HashSecret(adminauth.SecretSession, sessionToken)
	if err != nil {
		return ErrSessionInvalid
	}
	csrfHash, err := adminauth.HashSecret(adminauth.SecretCSRF, csrfToken)
	if err != nil {
		return ErrSessionInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	session, err := administratorSessionBy(ctx, tx, "s.token_hash=?", tokenHash[:])
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return ErrSessionInvalid
		}
		return err
	}
	if subtle.ConstantTimeCompare(session.CSRFHash[:], csrfHash[:]) != 1 {
		return ErrSessionInvalid
	}
	if session.RevokedAt != nil && session.RevocationReason != "rotated" {
		return ErrSessionInvalid
	}
	family, err := administratorSessionFamilyTx(ctx, tx, session.ID)
	if err != nil {
		return err
	}
	actor := adminauth.IDActor(adminauth.ActorAdministrator, session.PrincipalID)
	for _, member := range family {
		if member.PrincipalID != session.PrincipalID {
			return errors.New("corrupt administrator session rotation family")
		}
		if member.RevokedAt != nil {
			continue
		}
		if _, err := revokeAdministratorSessionTx(ctx, tx, member.ID, actor,
			"administrator.logout", "logout", administratorSessionRevocationTime(now, member)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TouchAdministratorSession is a low-level compatibility/test primitive.
// Browser authentication must use AuthenticateAndTouchAdministratorSession so
// the bearer credential and touch are checked atomically.
func (s *Store) TouchAdministratorSession(ctx context.Context, sessionID identity.ID) (AdministratorSession, error) {
	var result AdministratorSession
	if sessionID.IsZero() {
		return result, ErrSessionInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := s.now()
	result, err = administratorSessionBy(ctx, tx, "s.id=?", idBytes(sessionID))
	if err != nil {
		return result, err
	}
	if result.RevokedAt != nil {
		return result, ErrSessionInvalid
	}
	if now.Before(result.LastSeenAt) {
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
		WHERE id=? AND revoked_at IS NULL AND last_seen_at=? AND idle_expires_at>? AND absolute_expires_at>?`,
		unix(now), unix(newIdle), idBytes(sessionID), unix(result.LastSeenAt), unix(now), unix(now))
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

// RevokeAdministratorSession is a low-level compatibility/test primitive for
// trusted non-browser actors. Browser management must use the Decision-bound
// RevokeAdministratorSessionByDecision API; self-revocation uses logout.
func (s *Store) RevokeAdministratorSession(ctx context.Context, actor adminauth.Actor, sessionID identity.ID, reason string) error {
	if !actor.Valid() || sessionID.IsZero() || len(reason) < 1 || len(reason) > adminauth.MaxSessionReason {
		return fmt.Errorf("%w: invalid administrator session revocation", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	family, err := administratorSessionFamilyTx(ctx, tx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return ErrNotFound
		}
		return err
	}
	for _, member := range family {
		if member.RevokedAt != nil {
			continue
		}
		if _, err := revokeAdministratorSessionTx(ctx, tx, member.ID, actor,
			"administrator.session.revoke", reason, administratorSessionRevocationTime(now, member)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func administratorSessionRevocationTime(now time.Time, session AdministratorSession) time.Time {
	if now.Before(session.CreatedAt) {
		now = session.CreatedAt
	}
	if now.Before(session.LastSeenAt) {
		now = session.LastSeenAt
	}
	return now
}

// administratorSessionFamilyTx returns root followed by its sole successor
// chain. Migration v9's unique partial index prevents branching; the explicit
// seen set fails closed if a database has nevertheless been corrupted into a
// cycle. The caller's immediate transaction prevents a successor from being
// inserted between traversal and revocation.
func administratorSessionFamilyTx(ctx context.Context, tx *sql.Tx, rootID identity.ID) ([]AdministratorSession, error) {
	if tx == nil || rootID.IsZero() {
		return nil, ErrSessionInvalid
	}
	seen := make(map[identity.ID]struct{})
	currentID := rootID
	var result []AdministratorSession
	for {
		if _, duplicate := seen[currentID]; duplicate {
			return nil, errors.New("corrupt administrator session rotation cycle")
		}
		seen[currentID] = struct{}{}
		current, err := administratorSessionBy(ctx, tx, "s.id=?", idBytes(currentID))
		if err != nil {
			return nil, err
		}
		result = append(result, current)
		var successorRaw []byte
		err = tx.QueryRowContext(ctx, `SELECT id FROM administrator_sessions
			WHERE previous_session_id=?`, idBytes(currentID)).Scan(&successorRaw)
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		successorID, err := scanID(successorRaw)
		if err != nil {
			return nil, err
		}
		currentID = successorID
	}
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

func revokeAdministratorSessionsForPrincipalTx(ctx context.Context, tx *sql.Tx, principalID identity.ID,
	actor adminauth.Actor, action, reason string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,created_at,last_seen_at FROM administrator_sessions
		WHERE principal_id=? AND revoked_at IS NULL ORDER BY created_at,id`, idBytes(principalID))
	if err != nil {
		return err
	}
	var sessions []AdministratorSession
	for rows.Next() {
		var raw []byte
		var created, lastSeen int64
		if err := rows.Scan(&raw, &created, &lastSeen); err != nil {
			rows.Close()
			return err
		}
		sessionID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return err
		}
		sessions = append(sessions, AdministratorSession{ID: sessionID, CreatedAt: fromUnix(created), LastSeenAt: fromUnix(lastSeen)})
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, session := range sessions {
		revoked, err := revokeAdministratorSessionTx(ctx, tx, session.ID, actor, action, reason,
			administratorSessionRevocationTime(now, session))
		if err != nil {
			return err
		}
		if !revoked {
			return ErrConflict
		}
	}
	return nil
}

func administratorSessionMutationTimeTx(ctx context.Context, tx *sql.Tx, principalID identity.ID,
	base time.Time) (time.Time, error) {
	var latest sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT max(CASE WHEN last_seen_at > created_at THEN last_seen_at ELSE created_at END)
		FROM administrator_sessions WHERE principal_id=? AND revoked_at IS NULL`, idBytes(principalID)).Scan(&latest); err != nil {
		return time.Time{}, err
	}
	if latest.Valid {
		return latestTime(base, fromUnix(latest.Int64)), nil
	}
	return base.UTC(), nil
}

type rowScanner interface {
	Scan(...any) error
}

func administratorSessionBy(ctx context.Context, queryer rowQueryer, predicate string, argument any) (AdministratorSession, error) {
	row := queryer.QueryRowContext(ctx, `SELECT s.id,s.principal_id,s.credential_id,s.token_hash,s.csrf_hash,
		s.previous_session_id,s.created_at,s.last_seen_at,s.idle_lifetime_seconds,s.maximum_sessions,s.idle_expires_at,s.absolute_expires_at,s.revoked_at,s.revocation_reason
		FROM administrator_sessions s WHERE `+predicate, argument)
	return scanAdministratorSession(row)
}

func scanAdministratorSession(scanner rowScanner) (AdministratorSession, error) {
	var result AdministratorSession
	var idRaw, principalRaw, credentialRaw, tokenRaw, csrfRaw, previousRaw []byte
	var created, lastSeen, idleLifetime, maximumSessions, idleExpires, absoluteExpires int64
	var revoked sql.NullInt64
	err := scanner.Scan(&idRaw, &principalRaw, &credentialRaw, &tokenRaw, &csrfRaw, &previousRaw,
		&created, &lastSeen, &idleLifetime, &maximumSessions, &idleExpires, &absoluteExpires, &revoked, &result.RevocationReason)
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
	if maximumSessions < 1 || maximumSessions > 20 {
		return result, errors.New("corrupt administrator maximum sessions")
	}
	result.MaximumSessions = int(maximumSessions)
	result.IdleExpiresAt, result.AbsoluteExpiresAt = fromUnix(idleExpires), fromUnix(absoluteExpires)
	wantIdle := result.LastSeenAt.Add(result.IdleTimeout)
	if wantIdle.After(result.AbsoluteExpiresAt) {
		wantIdle = result.AbsoluteExpiresAt
	}
	if !result.IdleExpiresAt.Equal(wantIdle) || result.LastSeenAt.Before(result.CreatedAt) ||
		!result.LastSeenAt.Before(result.AbsoluteExpiresAt) ||
		!result.AbsoluteExpiresAt.After(result.CreatedAt) {
		return result, errors.New("corrupt administrator session lifetime")
	}
	result.RevokedAt = nullableTime(revoked)
	return result, nil
}
