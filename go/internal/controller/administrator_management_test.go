package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func managementTestPasswordHash(t *testing.T, salt byte) string {
	t.Helper()
	hash, err := adminauth.HashPassword([]byte("a sufficiently long management password"),
		bytes.NewReader(bytes.Repeat([]byte{salt}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func createManagementTestAdministrator(t *testing.T, store *Store, username string, role adminauth.Role,
	allNetworks bool, networkIDs ...identity.NetworkID) AdministratorSummary {
	t.Helper()
	decision := administratorRootDecision(t, store, administratorCreatePolicy, adminauth.GlobalTarget())
	result, err := store.CreateAdministrator(context.Background(), decision, CreateAdministratorSpec{
		Username: username, PasswordHash: managementTestPasswordHash(t, 3),
		Access: AdministratorAccessSpec{Role: role, Enabled: true, AllNetworks: allNetworks, NetworkIDs: networkIDs},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAdministratorManagementRequiresInitialOwnerBootstrap(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	passwordHash := managementTestPasswordHash(t, 2)
	createDecision := administratorRootDecision(t, store, administratorCreatePolicy, adminauth.GlobalTarget())
	if _, err := store.CreateAdministrator(ctx, createDecision, CreateAdministratorSpec{
		Username: "prebootstrap.operator", PasswordHash: passwordHash,
		Access: AdministratorAccessSpec{Role: adminauth.RoleOperator, Enabled: true, AllNetworks: true},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-bootstrap create error=%v", err)
	}
	var principals int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_principals`).Scan(&principals); err != nil {
		t.Fatal(err)
	}
	if principals != 0 {
		t.Fatalf("pre-bootstrap principals=%d", principals)
	}

	listDecision := administratorRootDecision(t, store, administratorListPolicy, adminauth.GlobalTarget())
	listed, err := store.AdministratorPrincipals(ctx, listDecision, 10)
	if err != nil {
		t.Fatal(err)
	}
	if listed == nil || len(listed) != 0 {
		t.Fatalf("pre-bootstrap principal inventory=%+v", listed)
	}

	missingID := identity.ID{42}
	readDecision := administratorRootDecision(t, store, administratorReadPolicy, adminauth.ObjectTarget(missingID))
	if _, err := store.AdministratorPrincipalAuthorized(ctx, readDecision, missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-bootstrap read error=%v", err)
	}
	updateDecision := administratorRootDecision(t, store, administratorAccessUpdatePolicy,
		adminauth.ObjectTarget(missingID))
	if _, err := store.UpdateAdministratorAccess(ctx, updateDecision, missingID,
		AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: true, AllNetworks: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-bootstrap update error=%v", err)
	}
	passwordDecision := administratorRootDecision(t, store, administratorPasswordReplacePolicy,
		adminauth.ObjectTarget(missingID))
	if _, err := store.ReplaceAdministratorPassword(ctx, passwordDecision, missingID, passwordHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-bootstrap password replace error=%v", err)
	}
	sessionListDecision := administratorRootDecision(t, store, administratorSessionListPolicy,
		adminauth.ObjectTarget(missingID))
	sessions, err := store.AdministratorSessions(ctx, sessionListDecision, missingID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if sessions == nil || len(sessions) != 0 {
		t.Fatalf("pre-bootstrap session inventory=%+v", sessions)
	}
	revokeDecision := administratorRootDecision(t, store, administratorSessionRevokePolicy,
		adminauth.ObjectTarget(missingID))
	if err := store.RevokeAdministratorSessionByDecision(ctx, revokeDecision, missingID, "not initialized"); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-bootstrap session revoke error=%v", err)
	}
	var managementAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action LIKE 'administrator.%'`).Scan(&managementAudits); err != nil {
		t.Fatal(err)
	}
	if managementAudits != 0 {
		t.Fatalf("pre-bootstrap management audits=%d", managementAudits)
	}
}

func TestAdministratorManagementCreateListReadSafe(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	bootstrapAdministratorFixture(t, store)
	network := resourceTestNetwork(t, store, "management", "10.91.0.0/24")
	passwordHash := managementTestPasswordHash(t, 4)
	createDecision := administratorRootDecision(t, store, administratorCreatePolicy, adminauth.GlobalTarget())
	created, err := store.CreateAdministrator(ctx, createDecision, CreateAdministratorSpec{
		Username:     "network.operator",
		PasswordHash: passwordHash,
		Access: AdministratorAccessSpec{Role: adminauth.RoleOperator, Enabled: true,
			NetworkIDs: []identity.NetworkID{network.ID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Username != "network.operator" || created.Role != adminauth.RoleOperator || !created.Enabled ||
		created.AllNetworks || len(created.NetworkIDs) != 1 || created.NetworkIDs[0] != network.ID ||
		!created.CreatedAt.Equal(now) || !created.PasswordUpdatedAt.Equal(now) {
		t.Fatalf("unexpected created principal: %+v", created)
	}

	listDecision := administratorRootDecision(t, store, administratorListPolicy, adminauth.GlobalTarget())
	principals, err := store.AdministratorPrincipals(ctx, listDecision, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(principals) != 2 || !slices.ContainsFunc(principals, func(principal AdministratorSummary) bool {
		return principal.ID == created.ID
	}) {
		t.Fatalf("principals=%+v", principals)
	}
	readDecision := administratorRootDecision(t, store, administratorReadPolicy, adminauth.ObjectTarget(created.ID))
	read, err := store.AdministratorPrincipalAuthorized(ctx, readDecision, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Created AdministratorSummary
		Listed  []AdministratorSummary
		Read    AdministratorSummary
	}{created, principals, read})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{passwordHash, "PasswordHash", "SecretHash", "CredentialID"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("safe management DTO contains %q: %s", forbidden, encoded)
		}
	}

	if _, err := store.CreateAdministrator(ctx, createDecision, CreateAdministratorSpec{
		Username: "network.operator", PasswordHash: passwordHash,
		Access: AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: true, AllNetworks: true},
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username error=%v", err)
	}
	unknownNetwork := identity.NetworkID{99}
	if _, err := store.CreateAdministrator(ctx, createDecision, CreateAdministratorSpec{
		Username: "unknown.scope", PasswordHash: passwordHash,
		Access: AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: true,
			NetworkIDs: []identity.NetworkID{unknownNetwork}},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown scope error=%v", err)
	}
	var creates int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='administrator.create' AND target_id=?`, idBytes(created.ID)).Scan(&creates); err != nil {
		t.Fatal(err)
	}
	if creates != 1 {
		t.Fatalf("create audit count=%d", creates)
	}
}

func TestAdministratorManagementReauthorizesAndBindsObjects(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	bootstrapAdministratorFixture(t, store)
	target := createManagementTestAdministrator(t, store, "managed.auditor", adminauth.RoleAuditor, true)
	operatorSubject := administratorSessionSubject(t, store, "limited.operator", adminauth.RoleOperator, true)
	operatorList := administratorDecisionForSubject(t, operatorSubject, administratorListPolicy, adminauth.GlobalTarget())
	if _, err := store.AdministratorPrincipals(ctx, operatorList, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("operator list error=%v", err)
	}

	missingID := identity.ID{77}
	operatorMissing := administratorDecisionForSubject(t, operatorSubject, administratorReadPolicy,
		adminauth.ObjectTarget(missingID))
	if _, err := store.AdministratorPrincipalAuthorized(ctx, operatorMissing, missingID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unauthorized missing read error=%v", err)
	}
	rootMissing := administratorRootDecision(t, store, administratorReadPolicy, adminauth.ObjectTarget(missingID))
	if _, err := store.AdministratorPrincipalAuthorized(ctx, rootMissing, missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authorized missing read error=%v", err)
	}
	otherID := identity.ID{78}
	mismatched := administratorRootDecision(t, store, administratorReadPolicy, adminauth.ObjectTarget(otherID))
	if _, err := store.AdministratorPrincipalAuthorized(ctx, mismatched, target.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched object error=%v", err)
	}

	ownerSubject := administratorSessionSubject(t, store, "stale.owner", adminauth.RoleOwner, true)
	ownerCreate := administratorDecisionForSubject(t, ownerSubject, administratorCreatePolicy, adminauth.GlobalTarget())
	provisioned, err := store.CreateAdministrator(ctx, ownerCreate, CreateAdministratorSpec{
		Username: "owner.provisioned", PasswordHash: managementTestPasswordHash(t, 5),
		Access: AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: true, AllNetworks: true},
	})
	if err != nil {
		t.Fatalf("owner session provisioning: %v", err)
	}
	if provisioned.Role != adminauth.RoleAuditor || !provisioned.Enabled {
		t.Fatalf("owner-provisioned principal=%+v", provisioned)
	}
	staleDecision := administratorDecisionForSubject(t, ownerSubject, administratorListPolicy, adminauth.GlobalTarget())
	if _, err := store.db.ExecContext(ctx, `UPDATE administrator_principals SET role='auditor' WHERE id=?`,
		idBytes(ownerSubject.ActorID())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorPrincipals(ctx, staleDecision, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("stale owner decision error=%v", err)
	}
}

func TestAdministratorManagementAccessIsAtomicAndRevokesSessions(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_100_000, 0).UTC()
	store.now = func() time.Time { return now }
	initialOwner, _ := bootstrapAdministratorFixture(t, store)
	network := resourceTestNetwork(t, store, "access", "10.92.0.0/24")
	first := createManagementTestAdministrator(t, store, "first.owner", adminauth.RoleOwner, true)
	firstRecord, err := store.AdministratorPrincipal(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	firstSession, firstToken, _, err := store.CreateAdministratorSession(ctx, first.ID, firstRecord.Credential.ID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	updateFirst := administratorRootDecision(t, store, administratorAccessUpdatePolicy, adminauth.ObjectTarget(first.ID))
	toAuditor := AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: true,
		NetworkIDs: []identity.NetworkID{network.ID}}
	now = now.Add(time.Second)
	updated, err := store.UpdateAdministratorAccess(ctx, updateFirst, first.ID, toAuditor)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Role != adminauth.RoleAuditor || updated.AllNetworks || len(updated.NetworkIDs) != 1 ||
		updated.NetworkIDs[0] != network.ID {
		t.Fatalf("updated principal=%+v", updated)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, firstToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("access-changed session error=%v", err)
	}
	var reason string
	if err := store.db.QueryRowContext(ctx, `SELECT revocation_reason FROM administrator_sessions WHERE id=?`,
		idBytes(firstSession.ID)).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "administrator access changed" {
		t.Fatalf("session reason=%q", reason)
	}

	initialDecision := administratorRootDecision(t, store, administratorAccessUpdatePolicy,
		adminauth.ObjectTarget(initialOwner.Principal.ID))
	if _, err := store.UpdateAdministratorAccess(ctx, initialDecision, initialOwner.Principal.ID,
		AdministratorAccessSpec{Role: adminauth.RoleOwner, Enabled: false, AllNetworks: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("last enabled owner disable error=%v", err)
	}
	if _, err := store.UpdateAdministratorAccess(ctx, updateFirst, first.ID,
		AdministratorAccessSpec{Role: adminauth.RoleAuditor, Enabled: false,
			NetworkIDs: []identity.NetworkID{network.ID}}); err != nil {
		t.Fatal(err)
	}
	candidate, err := store.AdministratorPasswordCandidate(ctx, "first.owner")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Usable {
		t.Fatal("disabled principal remained usable")
	}
}

func TestAdministratorManagementConcurrentLastOwnerProtection(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	initialOwner, _ := bootstrapAdministratorFixture(t, store)
	second := createManagementTestAdministrator(t, store, "concurrent.two", adminauth.RoleOwner, true)
	decisions := []adminauth.Decision{
		administratorRootDecision(t, store, administratorAccessUpdatePolicy,
			adminauth.ObjectTarget(initialOwner.Principal.ID)),
		administratorRootDecision(t, store, administratorAccessUpdatePolicy, adminauth.ObjectTarget(second.ID)),
	}
	ids := []identity.ID{initialOwner.Principal.ID, second.ID}
	errorsByCall := make([]error, 2)
	var wait sync.WaitGroup
	for index := range ids {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, errorsByCall[index] = store.UpdateAdministratorAccess(ctx, decisions[index], ids[index],
				AdministratorAccessSpec{Role: adminauth.RoleOwner, Enabled: false, AllNetworks: true})
		}()
	}
	wait.Wait()
	var successes, conflicts int
	for _, err := range errorsByCall {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent disable error=%v", err)
		}
	}
	var enabledOwners int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_principals
		WHERE role='owner' AND enabled=1`).Scan(&enabledOwners); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || conflicts != 1 || enabledOwners != 1 {
		t.Fatalf("successes=%d conflicts=%d enabled owners=%d", successes, conflicts, enabledOwners)
	}
}

func TestAdministratorManagementPasswordAndSessionLifecycle(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_200_000, 0).UTC()
	store.now = func() time.Time { return now }
	bootstrapAdministratorFixture(t, store)
	owner := createManagementTestAdministrator(t, store, "session.owner", adminauth.RoleOwner, true)
	oldRecord, err := store.AdministratorPrincipal(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	options := AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 3 * time.Hour, MaxActive: 5}
	oldSession, oldToken, _, err := store.CreateAdministratorSession(ctx, owner.ID, oldRecord.Credential.ID, options)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, _, _, err := store.CreateAdministratorSession(ctx, owner.ID, oldRecord.Credential.ID, options); err != nil {
		t.Fatal(err)
	}
	newPasswordHash := managementTestPasswordHash(t, 8)
	now = now.Add(time.Second)
	replaceDecision := administratorRootDecision(t, store, administratorPasswordReplacePolicy,
		adminauth.ObjectTarget(owner.ID))
	replaced, err := store.ReplaceAdministratorPassword(ctx, replaceDecision, owner.ID, newPasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	if !replaced.PasswordUpdatedAt.Equal(now) || !replaced.UpdatedAt.Equal(now) {
		t.Fatalf("replacement timestamps=%+v", replaced)
	}
	if _, _, err := store.AuthenticateAdministratorSession(ctx, oldToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("old password session error=%v", err)
	}
	candidate, err := store.AdministratorPasswordCandidate(ctx, owner.Username)
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.Usable || candidate.CredentialID == oldRecord.Credential.ID || candidate.PasswordHash != newPasswordHash {
		t.Fatalf("replacement candidate=%+v", candidate)
	}
	var oldCredentialHash, oldCredentialReason string
	if err := store.db.QueryRowContext(ctx, `SELECT revocation_reason FROM administrator_credentials WHERE id=?`,
		idBytes(oldRecord.Credential.ID)).Scan(&oldCredentialReason); err != nil {
		t.Fatal(err)
	}
	if oldCredentialReason != "password replaced" {
		t.Fatalf("old credential reason=%q", oldCredentialReason)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT secret_hash FROM administrator_credentials WHERE id=?`,
		idBytes(oldRecord.Credential.ID)).Scan(&oldCredentialHash); err != nil {
		t.Fatal(err)
	}
	if oldCredentialHash != oldRecord.Credential.SecretHash {
		t.Fatal("password replacement mutated the immutable old credential")
	}
	var auditDetails string
	if err := store.db.QueryRowContext(ctx, `SELECT details_json FROM audit_events
		WHERE action='administrator.password.replace' AND target_id=?`, idBytes(owner.ID)).Scan(&auditDetails); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditDetails, newPasswordHash) {
		t.Fatal("password hash entered audit details")
	}

	now = now.Add(time.Second)
	current, _, _, err := store.CreateAdministratorSession(ctx, owner.ID, candidate.CredentialID, options)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	other, _, _, err := store.CreateAdministratorSession(ctx, owner.ID, candidate.CredentialID, options)
	if err != nil {
		t.Fatal(err)
	}
	ownerSubject := adminauth.SessionSubject(owner.ID, current.ID)
	listDecision := administratorDecisionForSubject(t, ownerSubject, administratorSessionListPolicy,
		adminauth.ObjectTarget(owner.ID))
	sessions, err := store.AdministratorSessions(ctx, listDecision, owner.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 4 {
		t.Fatalf("session count=%d want 4", len(sessions))
	}
	var sawCurrent, sawOldRevoked bool
	encoded, err := json.Marshal(sessions)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"TokenHash", "CSRFHash", "CredentialID"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("safe session DTO contains %q: %s", forbidden, encoded)
		}
	}
	for _, session := range sessions {
		sawCurrent = sawCurrent || session.ID == current.ID && session.Current && session.State == AdministratorSessionActive
		sawOldRevoked = sawOldRevoked || session.ID == oldSession.ID && session.State == AdministratorSessionRevoked
	}
	if !sawCurrent || !sawOldRevoked {
		t.Fatalf("session inventory current=%t old-revoked=%t: %+v", sawCurrent, sawOldRevoked, sessions)
	}

	revokeDecision := administratorDecisionForSubject(t, ownerSubject, administratorSessionRevokePolicy,
		adminauth.ObjectTarget(other.ID))
	if err := store.RevokeAdministratorSessionByDecision(ctx, revokeDecision, other.ID, "owner requested"); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAdministratorSessionByDecision(ctx, revokeDecision, other.ID, "owner requested"); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	var revokeAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='administrator.session.revoke' AND target_id=?`, idBytes(other.ID)).Scan(&revokeAudits); err != nil {
		t.Fatal(err)
	}
	if revokeAudits != 1 {
		t.Fatalf("explicit revoke audit count=%d", revokeAudits)
	}
	missingID := identity.ID{66}
	missingDecision := administratorDecisionForSubject(t, ownerSubject, administratorSessionRevokePolicy,
		adminauth.ObjectTarget(missingID))
	if err := store.RevokeAdministratorSessionByDecision(ctx, missingDecision, missingID, "owner requested"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session revoke error=%v", err)
	}
}
