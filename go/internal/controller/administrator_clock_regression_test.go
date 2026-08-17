package controller

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func TestAdministratorManagementMutationsClampRollbackClock(t *testing.T) {
	t.Run("access update", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		newer := time.Unix(2_010_000_000, 0).UTC()
		now := newer
		store.now = func() time.Time { return now }
		bootstrapAdministratorFixture(t, store)
		target := createManagementTestAdministrator(t, store, "rollback.operator", adminauth.RoleOperator, true)
		record, err := store.AdministratorPrincipal(ctx, target.ID)
		if err != nil {
			t.Fatal(err)
		}
		session, _, _, err := store.CreateAdministratorSession(ctx, target.ID, record.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = newer.Add(-time.Hour)
		enabled := false
		decision := administratorRootDecision(t, store, administratorAccessUpdatePolicy, adminauth.ObjectTarget(target.ID))
		updated, err := store.UpdateAdministrator(ctx, decision, target.ID, AdministratorUpdateSpec{Enabled: &enabled})
		if err != nil {
			t.Fatalf("rollback-clock access update: %v", err)
		}
		if updated.Enabled || updated.UpdatedAt.Before(newer) || updated.DisabledAt == nil || updated.DisabledAt.Before(newer) {
			t.Fatalf("updated administrator=%+v newer=%s", updated, newer)
		}
		assertAdministratorSessionRevokedAtOrAfter(t, store, session.ID, session.CreatedAt)
	})

	t.Run("password replacement", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		newer := time.Unix(2_020_000_000, 0).UTC()
		now := newer
		store.now = func() time.Time { return now }
		bootstrapAdministratorFixture(t, store)
		target := createManagementTestAdministrator(t, store, "rollback.owner", adminauth.RoleOwner, true)
		record, err := store.AdministratorPrincipal(ctx, target.ID)
		if err != nil {
			t.Fatal(err)
		}
		session, _, _, err := store.CreateAdministratorSession(ctx, target.ID, record.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = newer.Add(-time.Hour)
		decision := administratorRootDecision(t, store, administratorPasswordReplacePolicy, adminauth.ObjectTarget(target.ID))
		updated, err := store.ReplaceAdministratorPassword(ctx, decision, target.ID, managementTestPasswordHash(t, 31))
		if err != nil {
			t.Fatalf("rollback-clock password replacement: %v", err)
		}
		if updated.PasswordUpdatedAt.Before(newer) || updated.UpdatedAt.Before(newer) {
			t.Fatalf("replacement timestamps=%+v newer=%s", updated, newer)
		}
		var oldRevoked int64
		if err := store.db.QueryRowContext(ctx, `SELECT revoked_at FROM administrator_credentials WHERE id=?`,
			idBytes(record.Credential.ID)).Scan(&oldRevoked); err != nil {
			t.Fatal(err)
		}
		if fromUnix(oldRevoked).Before(record.Credential.CreatedAt) {
			t.Fatalf("old credential revoked_at=%s created_at=%s", fromUnix(oldRevoked), record.Credential.CreatedAt)
		}
		assertAdministratorSessionRevokedAtOrAfter(t, store, session.ID, session.CreatedAt)
	})

	t.Run("owner recovery", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		newer := time.Unix(2_030_000_000, 0).UTC()
		now := newer
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		session, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		validationNow := newer.Add(-time.Hour)
		now = validationNow
		grant, secret, err := store.IssueAdministratorRecoveryGrant(ctx,
			administratorRecoveryGrantDecision(t, store, &owner.Principal.ID), AdministratorRecoveryOwner,
			&owner.Principal.ID, validationNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		recovered, err := store.RecoverAdministratorOwner(ctx, secret, managementTestPasswordHash(t, 32))
		if err != nil {
			t.Fatalf("rollback-clock owner recovery: %v", err)
		}
		if recovered.UpdatedAt.Before(newer) || recovered.Credential.CreatedAt.Before(newer) {
			t.Fatalf("recovered administrator=%+v newer=%s", recovered, newer)
		}
		var consumed int64
		if err := store.db.QueryRowContext(ctx, `SELECT consumed_at FROM administrator_recovery_grants WHERE id=?`,
			idBytes(grant.ID)).Scan(&consumed); err != nil {
			t.Fatal(err)
		}
		if got := fromUnix(consumed); !got.Equal(validationNow) || got.After(grant.ExpiresAt) {
			t.Fatalf("grant consumed_at=%s validation_now=%s expires_at=%s", got, validationNow, grant.ExpiresAt)
		}
		assertAdministratorSessionRevokedAtOrAfter(t, store, session.ID, session.CreatedAt)
	})
}

func TestAdministratorSessionLimitEvictionClampsRollbackClock(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	newer := time.Unix(2_040_000_000, 0).UTC()
	now := newer
	store.now = func() time.Time { return now }
	owner, _ := bootstrapAdministratorFixture(t, store)
	options := AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 3 * time.Hour, MaxActive: 1}
	first, firstToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	now = newer.Add(-time.Hour)
	second, secondToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options)
	if err != nil {
		t.Fatalf("rollback-clock session replacement: %v", err)
	}
	assertAdministratorSessionRevokedAtOrAfter(t, store, first.ID, first.CreatedAt)
	if _, _, err := store.AuthenticateAdministratorSession(ctx, firstToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("evicted token error=%v", err)
	}
	if authenticated, _, err := store.AuthenticateAdministratorSession(ctx, secondToken); err != nil || authenticated.ID != second.ID {
		t.Fatalf("replacement session=%+v err=%v", authenticated, err)
	}
}

func TestAdministratorRecoveryGrantExpiryCrossingRollsBackSupersede(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(2_050_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	decision := administratorRecoveryGrantDecision(t, store, nil)
	first, _, err := store.IssueAdministratorRecoveryGrant(ctx, decision,
		AdministratorRecoveryBootstrapOwner, nil, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := base.Add(30 * time.Minute)
	reads := 0
	store.now = func() time.Time {
		reads++
		if reads == 1 {
			return base.Add(time.Minute)
		}
		return expiresAt
	}
	if _, _, err := store.IssueAdministratorRecoveryGrant(ctx, decision,
		AdministratorRecoveryBootstrapOwner, nil, expiresAt); !errors.Is(err, ErrInvalid) {
		t.Fatalf("crossed grant expiry error=%v", err)
	}
	var pending, issues, revocations int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants
		WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`, idBytes(first.ID)).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT
		sum(action='administrator.recovery.issue'),sum(action='administrator.recovery.revoke')
		FROM audit_events WHERE target_type='administrator_recovery_grant'`).Scan(&issues, &revocations); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || issues != 1 || revocations != 0 {
		t.Fatalf("pending=%d issues=%d revocations=%d", pending, issues, revocations)
	}
}

func TestAdministratorAuthorizedReadsSlideIdleOnlyOnSuccess(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_060_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	bootstrapAdministratorFixture(t, store)
	ownerSubject := administratorSessionSubject(t, store, "read.owner", adminauth.RoleOwner, true)
	ownerSessionID, _ := ownerSubject.SessionID()
	ownerDecision := administratorDecisionForSubject(t, ownerSubject, administratorListPolicy, adminauth.GlobalTarget())

	now = now.Add(10 * time.Minute)
	if _, err := store.AdministratorPrincipals(ctx, ownerDecision, 10); err != nil {
		t.Fatal(err)
	}
	assertAdministratorSessionLastSeen(t, store, ownerSessionID, now)

	now = now.Add(time.Minute)
	lookup, err := store.AdministratorPrincipalByUsername(ctx, ownerDecision, "owner")
	if err != nil || lookup.Username != "owner" {
		t.Fatalf("exact username lookup=%+v err=%v", lookup, err)
	}
	assertAdministratorSessionLastSeen(t, store, ownerSessionID, now)

	now = now.Add(time.Minute)
	if _, err := store.AdministratorPrincipalByUsername(ctx, ownerDecision, "missing.owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing exact lookup error=%v", err)
	}
	assertAdministratorSessionLastSeen(t, store, ownerSessionID, now.Add(-time.Minute))

	auditorSubject := administratorSessionSubject(t, store, "read.auditor", adminauth.RoleAuditor, true)
	auditorSessionID, _ := auditorSubject.SessionID()
	auditorCreatedAt := now
	now = now.Add(10 * time.Minute)
	auditorDecision := administratorDecisionForSubject(t, auditorSubject, administratorListPolicy, adminauth.GlobalTarget())
	if _, err := store.AdministratorPrincipals(ctx, auditorDecision, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("denied inventory error=%v", err)
	}
	assertAdministratorSessionLastSeen(t, store, auditorSessionID, auditorCreatedAt)
}

func TestAdministratorImmediateTransactionSerializesAcrossStoreOpeners(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_065_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner, rootActor := bootstrapAdministratorFixture(t, store)
	session, token, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.now = store.now

	blocker, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var finished atomic.Bool
	result := make(chan error, 1)
	go func() {
		result <- second.RevokeAdministratorSession(ctx, rootActor, session.ID, "cross-opener revoke")
		finished.Store(true)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for second.db.Stats().InUse == 0 && !finished.Load() {
		select {
		case <-ticker.C:
		case <-deadline.C:
			blocker.Rollback()
			t.Fatal("second Store opener did not queue behind immediate transaction")
		}
	}
	if finished.Load() {
		blocker.Rollback()
		t.Fatal("second Store mutation completed while first immediate transaction was open")
	}
	queuedSession, err := administratorSessionBy(ctx, blocker, "s.id=?", idBytes(session.ID))
	if err != nil || queuedSession.RevokedAt != nil {
		blocker.Rollback()
		t.Fatalf("session changed before queued mutation: session=%+v err=%v", queuedSession, err)
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("queued cross-opener revoke error=%v", err)
	}
}

func TestAdministratorLogoutByRotatedSecretsRevokesFamilyAcrossClockRollback(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(2_070_000_000, 0).UTC()
	now := base
	store.now = func() time.Time { return now }
	owner, _ := bootstrapAdministratorFixture(t, store)
	options := AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 3 * time.Hour, MaxActive: 5}
	predecessor, predecessorToken, predecessorCSRF, err := store.CreateAdministratorSession(ctx,
		owner.Principal.ID, owner.Credential.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	now = base.Add(10 * time.Minute)
	rotated, rotatedToken, _, err := store.RotateAdministratorSession(ctx,
		adminauth.SessionSubject(owner.Principal.ID, predecessor.ID))
	if err != nil {
		t.Fatal(err)
	}
	_, _, wrongCSRF, err := store.CreateAdministratorSession(ctx,
		owner.Principal.ID, owner.Credential.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LogoutAdministratorSessionBySecrets(ctx, predecessorToken, wrongCSRF); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("wrong csrf error=%v", err)
	}
	if authenticated, _, err := store.AuthenticateAdministratorSession(ctx, rotatedToken); err != nil || authenticated.ID != rotated.ID {
		t.Fatalf("wrong csrf revoked successor=%+v err=%v", authenticated, err)
	}

	now = base.Add(-time.Hour)
	if err := store.LogoutAdministratorSessionBySecrets(ctx, predecessorToken, predecessorCSRF); err != nil {
		t.Fatalf("rollback-clock logout: %v", err)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, rotatedToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("rotated successor survived logout: %v", err)
	}
	assertAdministratorSessionRevokedAtOrAfter(t, store, rotated.ID, rotated.LastSeenAt)

	now = base.Add(20 * time.Minute)
	logoutFirst, logoutToken, logoutCSRF, err := store.CreateAdministratorSession(ctx,
		owner.Principal.ID, owner.Credential.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LogoutAdministratorSessionBySecrets(ctx, logoutToken, logoutCSRF); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.RotateAdministratorSession(ctx,
		adminauth.SessionSubject(owner.Principal.ID, logoutFirst.ID)); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("rotation after logout error=%v", err)
	}
}

func TestAuthenticateAndTouchAdministratorSessionRechecksDurableState(t *testing.T) {
	t.Run("slides idle", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(2_080_000_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		_, token, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 3 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(20 * time.Minute)
		touched, principal, err := store.AuthenticateAndTouchAdministratorSession(ctx, token)
		if err != nil || principal.ID != owner.Principal.ID || !touched.LastSeenAt.Equal(now) ||
			!touched.IdleExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("touched=%+v principal=%+v err=%v", touched, principal, err)
		}
	})

	t.Run("clock rollback and expiry", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(2_081_000_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		session, token, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Minute, AbsoluteTimeout: 3 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(-time.Second)
		if _, _, err := store.AuthenticateAndTouchAdministratorSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("rollback authentication error=%v", err)
		}
		assertAdministratorSessionLastSeen(t, store, session.ID, session.LastSeenAt)
		now = session.IdleExpiresAt
		if _, _, err := store.AuthenticateAndTouchAdministratorSession(ctx, token); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("deadline authentication error=%v", err)
		}
		assertAdministratorSessionRevokedAtOrAfter(t, store, session.ID, session.CreatedAt)
	})

	t.Run("credential replacement", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(2_082_000_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		session, token, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 3 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		newCredentialID, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `UPDATE administrator_credentials
			SET revoked_at=?,revocation_reason='test replacement' WHERE id=?`, unix(now), idBytes(owner.Credential.ID)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `INSERT INTO administrator_credentials
			(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?,'password',?,?)`,
			idBytes(newCredentialID), idBytes(owner.Principal.ID), managementTestPasswordHash(t, 33), unix(now)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AuthenticateAndTouchAdministratorSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("replaced credential authentication error=%v", err)
		}
		assertAdministratorSessionRevokedAtOrAfter(t, store, session.ID, session.CreatedAt)
	})
}

func assertAdministratorSessionLastSeen(t *testing.T, store *Store, sessionID identity.ID, want time.Time) {
	t.Helper()
	var lastSeen int64
	if err := store.db.QueryRow(`SELECT last_seen_at FROM administrator_sessions WHERE id=?`, idBytes(sessionID)).Scan(&lastSeen); err != nil {
		t.Fatal(err)
	}
	if got := fromUnix(lastSeen); !got.Equal(want) {
		t.Fatalf("last_seen_at=%s want %s", got, want)
	}
}

func assertAdministratorSessionRevokedAtOrAfter(t *testing.T, store *Store, sessionID identity.ID, floor time.Time) {
	t.Helper()
	var revoked sql.NullInt64
	if err := store.db.QueryRow(`SELECT revoked_at FROM administrator_sessions WHERE id=?`, idBytes(sessionID)).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked.Valid || fromUnix(revoked.Int64).Before(floor) {
		t.Fatalf("session revoked_at=%+v floor=%s", revoked, floor)
	}
}
