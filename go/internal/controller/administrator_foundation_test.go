package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

func TestV8MigrationBackfillsAuditActorsAndAuthState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller-v7.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	schema := `CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` +
		strings.Join(migrations[:7], "\n")
	if _, err := raw.Exec(schema); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 7; version++ {
		if _, err := raw.Exec(`INSERT INTO schema_versions(version,applied_at) VALUES(?,?)`, version, version); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	networkID := identity.NetworkID{1}
	nodeID := identity.NodeID{2}
	if _, err := raw.Exec(`INSERT INTO networks
		(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at)
		VALUES(?,?,?,?,1,1,1)`, idBytes(networkID), "legacy-network", netip.MustParseAddr("192.0.2.0").AsSlice(), 24); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO nodes(id,network_id,name,enabled_capabilities,created_at)
		VALUES(?,?,?,0,1)`, idBytes(nodeID), idBytes(networkID), "legacy-node"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	auditIDs := []identity.ID{{3}, {4}, {5}}
	for _, event := range []struct {
		id     identity.ID
		actor  any
		action string
	}{
		{auditIDs[0], idBytes(nodeID), "node.renew"},
		{auditIDs[1], nil, "route.expire"},
		{auditIDs[2], nil, "network.create"},
	} {
		if _, err := raw.Exec(`INSERT INTO audit_events
			(id,network_id,actor_node_id,action,target_type,details_json,created_at)
			VALUES(?,?,?,?,?,'{}',?)`, idBytes(event.id), idBytes(networkID), event.actor, event.action, "fixture", int64(event.id[0])); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.AdministratorAuthState(ctx)
	if err != nil || state.RootServicePrincipalID.IsZero() || state.InitialOwnerPrincipalID != nil || state.BootstrapCompletedAt != nil {
		t.Fatalf("administrator auth state=%+v err=%v", state, err)
	}
	events, err := store.GlobalAuditEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	actors := make(map[string]adminauth.Actor)
	for _, event := range events {
		actors[event.Action] = event.Actor
	}
	if actor := actors["node.renew"]; actor.Kind != adminauth.ActorNode || actor.ID == nil || *actor.ID != identity.ID(nodeID) {
		t.Fatalf("node actor=%+v", actor)
	}
	if actor := actors["route.expire"]; actor.Kind != adminauth.ActorSystem || actor.ID != nil {
		t.Fatalf("expiry actor=%+v", actor)
	}
	if actor := actors["network.create"]; actor.Kind != adminauth.ActorLegacyUnknown || actor.ID != nil {
		t.Fatalf("legacy actor=%+v", actor)
	}
	rootActor := state.RootServicePrincipalID
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedState, err := reopened.AdministratorAuthState(ctx)
	if err != nil || reopenedState.RootServicePrincipalID != rootActor {
		t.Fatalf("root service actor changed across reopen: %+v err=%v", reopenedState, err)
	}
}

func TestAdministratorStoreRejectsMalformedBootstrapInputs(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateFirstOwner(ctx, adminauth.SystemActor(), "not-a-recovery-secret", "owner", "not-a-password-hash"); err == nil {
		t.Fatal("malformed bootstrap inputs accepted")
	}
	if _, err := store.AdministratorByUsername(ctx, "Owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("noncanonical username lookup error=%v", err)
	}
}

func TestFirstOwnerBootstrapAndSessionLifecycle(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootActor := adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID)
	grant, secret, err := store.IssueAdministratorRecoveryGrant(ctx, rootActor,
		AdministratorRecoveryBootstrapOwner, nil, now.Add(time.Hour))
	if err != nil || secret == "" {
		t.Fatalf("issue bootstrap grant=%+v secret-empty=%t err=%v", grant, secret == "", err)
	}
	password := []byte("a sufficiently long owner password")
	passwordHash, err := adminauth.HashPassword(password, bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.CreateFirstOwner(ctx, rootActor, secret, "owner", passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Principal.Valid() || !owner.Principal.Enabled || owner.Principal.Role != adminauth.RoleOwner ||
		owner.Credential.SecretHash != passwordHash {
		t.Fatalf("created owner=%+v", owner)
	}
	if _, err := store.CreateFirstOwner(ctx, rootActor, secret, "other-owner", passwordHash); !errors.Is(err, ErrBootstrapComplete) {
		t.Fatalf("bootstrap replay error=%v", err)
	}
	var storedGrantHash []byte
	var consumedAt sql.NullInt64
	if err := store.db.QueryRowContext(ctx, `SELECT secret_hash,consumed_at FROM administrator_recovery_grants WHERE id=?`,
		idBytes(grant.ID)).Scan(&storedGrantHash, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedGrantHash, []byte(secret)) || !consumedAt.Valid {
		t.Fatal("bootstrap secret was retained in plaintext or not consumed")
	}
	events, err := store.GlobalAuditEvents(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrapActor adminauth.Actor
	for _, event := range events {
		if event.Action == "administrator.bootstrap.complete" {
			bootstrapActor = event.Actor
		}
	}
	if bootstrapActor.Kind != adminauth.ActorServicePrincipal || bootstrapActor.ID == nil ||
		*bootstrapActor.ID != state.RootServicePrincipalID {
		t.Fatalf("bootstrap audit actor=%+v", bootstrapActor)
	}

	session, token, csrf, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Minute, AbsoluteTimeout: 10 * time.Minute, MaxActive: 2})
	if err != nil || token == "" || csrf == "" || token == csrf {
		t.Fatalf("create session=%+v token/csrf invalid err=%v", session, err)
	}
	var storedTokenHash, storedCSRFHash []byte
	if err := store.db.QueryRowContext(ctx, `SELECT token_hash,csrf_hash FROM administrator_sessions WHERE id=?`,
		idBytes(session.ID)).Scan(&storedTokenHash, &storedCSRFHash); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(storedTokenHash, []byte(token)) || bytes.Equal(storedCSRFHash, []byte(csrf)) || bytes.Equal(storedTokenHash, storedCSRFHash) {
		t.Fatal("session credentials were not independently hashed")
	}
	authenticated, principal, err := store.AuthenticateAdministratorSession(ctx, token)
	if err != nil || authenticated.ID != session.ID || principal.ID != owner.Principal.ID {
		t.Fatalf("authenticate session=%+v principal=%+v err=%v", authenticated, principal, err)
	}
	now = session.IdleExpiresAt
	if _, _, err := store.AuthenticateAdministratorSession(ctx, token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("session accepted at idle deadline: %v", err)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired session replay error=%v", err)
	}
}

func TestFirstOwnerBootstrapHasOneConcurrentWinner(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootActor := adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID)
	_, secret, err := store.IssueAdministratorRecoveryGrant(ctx, rootActor,
		AdministratorRecoveryBootstrapOwner, nil, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := adminauth.HashPassword([]byte("a sufficiently long owner password"),
		bytes.NewReader(bytes.Repeat([]byte{8}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 12
	start := make(chan struct{})
	results := make(chan error, contenders)
	var workers sync.WaitGroup
	for index := range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, createErr := store.CreateFirstOwner(ctx, rootActor, secret, "owner"+string(rune('a'+index)), passwordHash)
			results <- createErr
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result == nil {
			successes++
			continue
		}
		if !errors.Is(result, ErrBootstrapComplete) {
			t.Errorf("bootstrap contender error=%v", result)
		}
	}
	if successes != 1 {
		t.Fatalf("bootstrap winners=%d want 1", successes)
	}
	var owners, consumed int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_principals WHERE role='owner'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if owners != 1 || consumed != 1 {
		t.Fatalf("owners=%d consumed grants=%d", owners, consumed)
	}
}

func bootstrapAdministratorFixture(t *testing.T, store *Store) (AdministratorRecord, adminauth.Actor) {
	t.Helper()
	ctx := context.Background()
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootActor := adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID)
	_, secret, err := store.IssueAdministratorRecoveryGrant(ctx, rootActor,
		AdministratorRecoveryBootstrapOwner, nil, store.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := adminauth.HashPassword([]byte("a sufficiently long owner password"),
		bytes.NewReader(bytes.Repeat([]byte{9}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.CreateFirstOwner(ctx, rootActor, secret, "owner", passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	return owner, rootActor
}

func TestAdministratorSessionLimitRotationAndRevocation(t *testing.T) {
	t.Run("limit and explicit revoke", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(1_800_100_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, rootActor := bootstrapAdministratorFixture(t, store)
		options := AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 2}
		first, firstToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		second, secondToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		if _, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AuthenticateAdministratorSession(ctx, firstToken); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("evicted session authentication error=%v", err)
		}
		var firstReason string
		if err := store.db.QueryRowContext(ctx, `SELECT revocation_reason FROM administrator_sessions WHERE id=?`,
			idBytes(first.ID)).Scan(&firstReason); err != nil || firstReason != "concurrent session limit" {
			t.Fatalf("evicted session reason=%q err=%v", firstReason, err)
		}
		events, err := store.GlobalAuditEvents(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		evictionAudited := false
		for _, event := range events {
			if event.Action == "administrator.session.revoke" && event.TargetID != nil && *event.TargetID == first.ID &&
				strings.Contains(event.Details, "concurrent session limit") {
				evictionAudited = true
			}
		}
		if !evictionAudited {
			t.Fatal("session eviction was not audited")
		}
		if err := store.RevokeAdministratorSession(ctx, rootActor, second.ID, "operator request"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AuthenticateAdministratorSession(ctx, secondToken); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("revoked session authentication error=%v", err)
		}
		if err := store.RevokeAdministratorSession(ctx, rootActor, second.ID, "operator request"); err != nil {
			t.Fatalf("idempotent revoke error=%v", err)
		}
	})

	t.Run("rotation preserves absolute deadline and has one winner", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(1_800_200_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		options := AdministratorSessionOptions{IdleTimeout: 2 * time.Hour, AbsoluteTimeout: 4 * time.Hour, MaxActive: 5}
		previous, previousToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(30 * time.Minute)
		rotateOptions := options
		rotateOptions.PreviousSessionID = &previous.ID
		type rotationResult struct {
			session AdministratorSession
			token   string
			err     error
		}
		start := make(chan struct{})
		results := make(chan rotationResult, 2)
		for range 2 {
			go func() {
				<-start
				session, token, _, createErr := store.CreateAdministratorSession(ctx,
					owner.Principal.ID, owner.Credential.ID, rotateOptions)
				results <- rotationResult{session: session, token: token, err: createErr}
			}()
		}
		close(start)
		var winner rotationResult
		successes, failures := 0, 0
		for range 2 {
			result := <-results
			if result.err == nil {
				successes++
				winner = result
				continue
			}
			if !errors.Is(result.err, ErrSessionInvalid) {
				t.Fatalf("concurrent rotation error=%v", result.err)
			}
			failures++
		}
		if successes != 1 || failures != 1 {
			t.Fatalf("rotation successes=%d failures=%d", successes, failures)
		}
		if winner.session.PreviousSessionID == nil || *winner.session.PreviousSessionID != previous.ID ||
			!winner.session.AbsoluteExpiresAt.Equal(previous.AbsoluteExpiresAt) {
			t.Fatalf("rotated session=%+v previous=%+v", winner.session, previous)
		}
		if _, _, err := store.AuthenticateAdministratorSession(ctx, previousToken); !errors.Is(err, ErrSessionInvalid) {
			t.Fatalf("rotated predecessor authentication error=%v", err)
		}
		now = winner.session.AbsoluteExpiresAt
		if _, _, err := store.AuthenticateAdministratorSession(ctx, winner.token); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("rotated session accepted at absolute deadline: %v", err)
		}
	})

	t.Run("shared policy permits long idle touch", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(1_800_300_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		session, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: 12 * time.Hour, AbsoluteTimeout: 24 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
		touched, err := store.TouchAdministratorSession(ctx, session.ID)
		if err != nil || !touched.IdleExpiresAt.Equal(now.Add(12*time.Hour)) {
			t.Fatalf("touch=%+v err=%v", touched, err)
		}
	})

	t.Run("touch and rotation use persisted idle policy", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		now := time.Unix(1_800_350_000, 0).UTC()
		store.now = func() time.Time { return now }
		owner, _ := bootstrapAdministratorFixture(t, store)
		original, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: 45 * time.Minute, AbsoluteTimeout: 4 * time.Hour, MaxActive: 5})
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(5 * time.Minute)
		touched, err := store.TouchAdministratorSession(ctx, original.ID)
		if err != nil || touched.IdleTimeout != 45*time.Minute || !touched.IdleExpiresAt.Equal(now.Add(45*time.Minute)) {
			t.Fatalf("persisted-policy touch=%+v err=%v", touched, err)
		}
		rotated, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
			AdministratorSessionOptions{IdleTimeout: 2 * time.Hour, AbsoluteTimeout: 6 * time.Hour,
				MaxActive: 5, PreviousSessionID: &original.ID})
		if err != nil || rotated.IdleTimeout != 45*time.Minute || !rotated.IdleExpiresAt.Equal(now.Add(45*time.Minute)) ||
			!rotated.AbsoluteExpiresAt.Equal(original.AbsoluteExpiresAt) {
			t.Fatalf("persisted-policy rotation=%+v err=%v", rotated, err)
		}
	})

	t.Run("credential secret is immutable", func(t *testing.T) {
		store, _ := openTestStore(t)
		owner, _ := bootstrapAdministratorFixture(t, store)
		if _, err := store.db.Exec(`UPDATE administrator_credentials SET secret_hash=? WHERE id=?`,
			owner.Credential.SecretHash, idBytes(owner.Credential.ID)); err == nil ||
			!strings.Contains(err.Error(), "credential identity is immutable") {
			t.Fatalf("credential secret update error=%v", err)
		}
	})
}

func TestRestoreInvalidatesAdministratorAuthenticationState(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	owner, rootActor := bootstrapAdministratorFixture(t, store)
	stateBefore, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, sessionToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	recovery, recoverySecret, err := store.IssueAdministratorRecoveryGrant(ctx, rootActor,
		AdministratorRecoveryOwner, &owner.Principal.ID, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	recoveryHash, err := adminauth.HashSecret(adminauth.SecretRecovery, recoverySecret)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	backupPath := filepath.Join(directory, "backup.db")
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, backupPath, restoredPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	stateAfter, err := restored.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stateAfter.RootServicePrincipalID != stateBefore.RootServicePrincipalID ||
		stateAfter.InitialOwnerPrincipalID == nil || *stateAfter.InitialOwnerPrincipalID != owner.Principal.ID ||
		stateAfter.RecoveryGeneration != stateBefore.RecoveryGeneration+1 || stateAfter.LastRecoveredAt == nil {
		t.Fatalf("restored auth state before=%+v after=%+v", stateBefore, stateAfter)
	}
	restoredOwner, err := restored.AdministratorPrincipal(ctx, owner.Principal.ID)
	if err != nil || restoredOwner.Credential.ID != owner.Credential.ID ||
		restoredOwner.Credential.SecretHash != owner.Credential.SecretHash {
		t.Fatalf("restored owner=%+v err=%v", restoredOwner, err)
	}
	if _, _, err := restored.AuthenticateAdministratorSession(ctx, sessionToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("restored session authentication error=%v", err)
	}
	var restoredSessions, restoredGrant int
	if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions`).Scan(&restoredSessions); err != nil {
		t.Fatal(err)
	}
	if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants
		WHERE id=? OR secret_hash=?`, idBytes(recovery.ID), recoveryHash[:]).Scan(&restoredGrant); err != nil {
		t.Fatal(err)
	}
	if restoredSessions != 0 || restoredGrant != 0 {
		t.Fatalf("restored sessions=%d pending recovery grants=%d", restoredSessions, restoredGrant)
	}
	events, err := restored.GlobalAuditEvents(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	restoreAudited := false
	for _, event := range events {
		if event.Action == "controller.restore" && event.NetworkScope == nil && event.Actor.Kind == adminauth.ActorSystem {
			restoreAudited = true
		}
	}
	if !restoreAudited {
		t.Fatal("restore invalidation audit event is missing")
	}
	source, err := openReadOnlyDatabase(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var sourceSessions, sourceGrant int
	if err := source.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions`).Scan(&sourceSessions); err != nil {
		t.Fatal(err)
	}
	if err := source.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants WHERE id=?`,
		idBytes(recovery.ID)).Scan(&sourceGrant); err != nil {
		t.Fatal(err)
	}
	if sourceSessions != 1 || sourceGrant != 1 {
		t.Fatalf("source backup mutated: sessions=%d recovery grants=%d", sourceSessions, sourceGrant)
	}
}

func TestRestoreRejectsMalformedAdministratorSchema(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate string
	}{
		{
			name: "scope table missing critical columns",
			mutate: `DROP TABLE administrator_principal_networks;
				CREATE TABLE administrator_principal_networks(principal_id BLOB, bogus BLOB) STRICT;
				CREATE INDEX administrator_principal_networks_network
				ON administrator_principal_networks(bogus)`,
		},
		{
			name: "required index has wrong key",
			mutate: `DROP INDEX administrator_sessions_active_expiry;
				CREATE INDEX administrator_sessions_active_expiry
				ON administrator_sessions(principal_id) WHERE revoked_at IS NULL`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, _ := openTestStore(t)
			directory := t.TempDir()
			source := filepath.Join(directory, "malformed.db")
			if err := store.Backup(ctx, source); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.mutate); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), "schema is incomplete") {
				t.Fatalf("restore error=%v, want incomplete schema", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("malformed restore published destination: %v", err)
			}
		})
	}
}

func TestAdministratorSessionRotationPreservesAbsoluteDeadlineAndHasOneWinner(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actor := adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID)
	_, secret, err := store.IssueAdministratorRecoveryGrant(ctx, actor,
		AdministratorRecoveryBootstrapOwner, nil, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := adminauth.HashPassword([]byte("a sufficiently long owner password"),
		bytes.NewReader(bytes.Repeat([]byte{9}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.CreateFirstOwner(ctx, actor, secret, "owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	original, originalToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: 5 * time.Minute, AbsoluteTimeout: time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(4 * time.Minute)
	const contenders = 8
	start := make(chan struct{})
	type rotationResult struct {
		session AdministratorSession
		token   string
		err     error
	}
	results := make(chan rotationResult, contenders)
	var workers sync.WaitGroup
	for range contenders {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			session, token, _, rotateErr := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
				AdministratorSessionOptions{IdleTimeout: 5 * time.Minute, AbsoluteTimeout: 2 * time.Hour,
					MaxActive: 5, PreviousSessionID: &original.ID})
			results <- rotationResult{session: session, token: token, err: rotateErr}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	var winner rotationResult
	for result := range results {
		if result.err == nil {
			winners++
			winner = result
			continue
		}
		if !errors.Is(result.err, ErrSessionInvalid) {
			t.Errorf("rotation contender error=%v", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("rotation winners=%d want 1", winners)
	}
	if winner.session.AbsoluteExpiresAt != original.AbsoluteExpiresAt || !winner.session.IdleExpiresAt.Before(original.AbsoluteExpiresAt) {
		t.Fatalf("rotation extended deadlines: original=%+v winner=%+v", original, winner.session)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, originalToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("rotated token replay error=%v", err)
	}
	if got, _, err := store.AuthenticateAdministratorSession(ctx, winner.token); err != nil || got.ID != winner.session.ID {
		t.Fatalf("winner authentication session=%+v err=%v", got, err)
	}
	now = original.AbsoluteExpiresAt
	if _, _, err := store.AuthenticateAdministratorSession(ctx, winner.token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("rotated session accepted at original absolute deadline: %v", err)
	}
}

func TestAdministratorSessionLimitEvictsOldestAndAudits(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actor := adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID)
	_, secret, err := store.IssueAdministratorRecoveryGrant(ctx, actor,
		AdministratorRecoveryBootstrapOwner, nil, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := adminauth.HashPassword([]byte("a sufficiently long owner password"),
		bytes.NewReader(bytes.Repeat([]byte{10}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.CreateFirstOwner(ctx, actor, secret, "owner", hash)
	if err != nil {
		t.Fatal(err)
	}
	first, firstToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 2})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	second, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 2})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	third, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, firstToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("oldest session survived cap: %v", err)
	}
	var active int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions WHERE principal_id=? AND revoked_at IS NULL`,
		idBytes(owner.Principal.ID)).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 2 {
		t.Fatalf("active sessions=%d want 2 (second=%s third=%s)", active, second.ID, third.ID)
	}
	events, err := store.GlobalAuditEvents(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "administrator.session.revoke" && event.TargetID != nil && *event.TargetID == first.ID &&
			strings.Contains(event.Details, "concurrent session limit") {
			found = true
		}
	}
	if !found {
		t.Fatal("concurrent-session eviction audit missing")
	}
}

func TestAdministratorSessionRejectsSubsecondAndCorruptIdlePolicy(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_800_400_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner, _ := bootstrapAdministratorFixture(t, store)
	for _, options := range []AdministratorSessionOptions{
		{IdleTimeout: time.Minute + time.Nanosecond, AbsoluteTimeout: time.Hour, MaxActive: 5},
		{IdleTimeout: time.Minute, AbsoluteTimeout: time.Hour + time.Nanosecond, MaxActive: 5},
	} {
		if _, _, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID, options); !errors.Is(err, ErrInvalid) {
			t.Fatalf("subsecond options %+v error=%v, want ErrInvalid", options, err)
		}
	}
	session, token, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: 15 * time.Minute, AbsoluteTimeout: time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`PRAGMA ignore_check_constraints=ON;
		UPDATE administrator_sessions SET idle_expires_at=idle_expires_at+1 WHERE id=?;
		PRAGMA ignore_check_constraints=OFF`, idBytes(session.ID)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, token); err == nil ||
		!strings.Contains(err.Error(), "corrupt administrator session") {
		t.Fatalf("corrupt idle deadline authentication error=%v", err)
	}
}
