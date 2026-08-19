package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func createServicePrincipalFixture(t *testing.T, store *Store, networkID identity.NetworkID) (
	ServicePrincipalSummary, ServiceAccessTokenSummary, string,
) {
	t.Helper()
	ctx := context.Background()
	createDecision := administratorRootDecision(t, store, servicePrincipalCreatePolicy, adminauth.GlobalTarget())
	principal, err := store.CreateServicePrincipal(ctx, createDecision, ServicePrincipalSpec{
		Name: "deployment-bot", NetworkIDs: []identity.NetworkID{networkID},
		Permissions: []adminauth.Operation{adminauth.OperationNetworkList, adminauth.OperationNetworkRead, adminauth.OperationACLManage},
	})
	if err != nil {
		t.Fatal(err)
	}
	issueDecision := administratorRootDecision(t, store, serviceTokenIssuePolicy,
		adminauth.ObjectTarget(principal.Principal.ID))
	token, bearer, err := store.IssueServiceAccessToken(ctx, issueDecision, principal.Principal.ID,
		"ci production", store.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return principal, token, bearer
}

func TestServicePrincipalTokenLifecycleScopeAndAuditAttribution(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_910_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	networkOne, err := store.CreateNetwork(ctx, "automation-one", netip.MustParsePrefix("10.110.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	networkTwo, err := store.CreateNetwork(ctx, "automation-two", netip.MustParsePrefix("10.111.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapAdministratorFixture(t, store)
	principal, token, bearer := createServicePrincipalFixture(t, store, networkOne.ID)

	var storedHash []byte
	if err := store.db.QueryRowContext(ctx, `SELECT token_hash FROM automation_service_access_tokens WHERE id=?`,
		idBytes(token.ID)).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if len(storedHash) != 32 || strings.Contains(string(storedHash), bearer) {
		t.Fatalf("stored access credential is not a digest: len=%d", len(storedHash))
	}
	authenticatedToken, authenticatedPrincipal, err := store.AuthenticateServiceAccessToken(ctx, bearer)
	if err != nil || authenticatedToken.ID != token.ID || authenticatedPrincipal.ID != principal.Principal.ID {
		t.Fatalf("authenticate token=%+v principal=%+v err=%v", authenticatedToken, authenticatedPrincipal, err)
	}
	_, proof, err := adminauth.ParseServiceAccessToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	subject := adminauth.ServicePrincipalTokenSubject(principal.Principal.ID, token.ID, proof)
	readDecision, err := adminauth.NewDecision(subject, administratorNetworkReadPolicy, adminauth.NetworkTarget(networkOne.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorNetwork(ctx, readDecision, networkOne.ID); err != nil {
		t.Fatalf("scoped network read: %v", err)
	}
	wrongNetworkDecision, err := adminauth.NewDecision(subject, administratorNetworkReadPolicy, adminauth.NetworkTarget(networkTwo.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorNetwork(ctx, wrongNetworkDecision, networkTwo.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("out-of-scope network read err=%v", err)
	}
	secondIssueDecision := administratorRootDecision(t, store, serviceTokenIssuePolicy,
		adminauth.ObjectTarget(principal.Principal.ID))
	secondToken, secondBearer, err := store.IssueServiceAccessToken(ctx, secondIssueDecision,
		principal.Principal.ID, "second token", base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, secondProof, err := adminauth.ParseServiceAccessToken(secondBearer)
	if err != nil {
		t.Fatal(err)
	}
	substitutedSubject := adminauth.ServicePrincipalTokenSubject(principal.Principal.ID, token.ID, secondProof)
	substitutedDecision, err := adminauth.NewDecision(substitutedSubject, administratorNetworkReadPolicy,
		adminauth.NetworkTarget(networkOne.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorNetwork(ctx, substitutedDecision, networkOne.ID); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("cross-token proof substitution err=%v", err)
	}
	base = base.Add(31 * time.Minute)
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, secondBearer); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expired service access token err=%v", err)
	}
	base = base.Add(-31 * time.Minute)
	createNetworkDecision, err := adminauth.NewDecision(subject, administratorNetworkCreatePolicy, adminauth.GlobalTarget())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorCreateNetworkDualStack(ctx, createNetworkDecision, "forbidden",
		netip.MustParsePrefix("10.112.0.0/24"), netip.Prefix{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("ungranted global mutation err=%v", err)
	}
	aclDecision, err := adminauth.NewDecision(subject, administratorACLCreatePolicy, adminauth.NetworkTarget(networkOne.ID))
	if err != nil {
		t.Fatal(err)
	}
	rule, _, err := store.AdministratorAddACLRule(ctx, aclDecision, networkOne.ID, 10, ACLActionAccept, `{}`, "automation audit")
	if err != nil {
		t.Fatal(err)
	}
	events, err := store.GlobalAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	foundAttributedMutation := false
	for _, event := range events {
		if event.Action == "acl_rule.create" && event.TargetID != nil && *event.TargetID == rule.ID {
			foundAttributedMutation = event.Actor.Kind == adminauth.ActorServicePrincipal && event.Actor.ID != nil &&
				*event.Actor.ID == principal.Principal.ID
		}
	}
	if !foundAttributedMutation {
		t.Fatal("automated mutation was not attributed to its service principal")
	}
	wrongObjectDecision, err := adminauth.NewDecision(subject, administratorACLUpdatePolicy,
		adminauth.ObjectTarget(secondToken.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AdministratorUpdateACLRule(ctx, wrongObjectDecision, rule.ID, 11,
		ACLActionAccept, `{}`, "substitution", true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("object-target substitution err=%v", err)
	}

	revokeDecision := administratorRootDecision(t, store, serviceTokenRevokePolicy, adminauth.ObjectTarget(token.ID))
	if err := store.RevokeServiceAccessToken(ctx, revokeDecision, token.ID, "rotation completed"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, bearer); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoked bearer authentication err=%v", err)
	}
	if _, err := store.AdministratorNetwork(ctx, readDecision, networkOne.ID); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("pre-revocation decision survived revocation: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE automation_service_access_tokens
		SET revoked_at=NULL,revocation_reason='' WHERE id=?`, idBytes(token.ID)); err == nil {
		t.Fatal("revoked service access token could be made active again")
	}
	events, err = store.GlobalAuditEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := map[string]bool{
		"service_principal.create":    false,
		"service_access_token.issue":  false,
		"service_access_token.revoke": false,
	}
	for _, event := range events {
		switch event.Action {
		case "service_principal.create":
			lifecycle[event.Action] = lifecycle[event.Action] ||
				event.TargetID != nil && *event.TargetID == principal.Principal.ID
		case "service_access_token.issue", "service_access_token.revoke":
			lifecycle[event.Action] = lifecycle[event.Action] ||
				event.TargetID != nil && *event.TargetID == token.ID
		}
	}
	for action, found := range lifecycle {
		if !found {
			t.Fatalf("missing audited automation lifecycle action %q", action)
		}
	}
}

func TestRestoreRevokesServiceAccessTokens(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network, err := store.CreateNetwork(ctx, "restore-automation", netip.MustParsePrefix("10.113.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapAdministratorFixture(t, store)
	_, token, bearer := createServicePrincipalFixture(t, store, network.ID)
	directory := t.TempDir()
	backup := filepath.Join(directory, "controller.backup")
	restoredPath := filepath.Join(directory, "controller.restored")
	if err := store.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(ctx, backup, restoredPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, bearer); err != nil {
		t.Fatalf("restore mutated the live source token: %v", err)
	}
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, _, err := restored.AuthenticateServiceAccessToken(ctx, bearer); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("restored access token remained usable: %v", err)
	}
	var reason string
	if err := restored.db.QueryRowContext(ctx, `SELECT revocation_reason FROM automation_service_access_tokens WHERE id=?`,
		idBytes(token.ID)).Scan(&reason); err != nil || reason != "controller database restored" {
		t.Fatalf("restored token reason=%q err=%v", reason, err)
	}
}

func TestRestoreRejectsWeakenedServiceAccessTokenSchema(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	source := filepath.Join(directory, "weakened.db")
	store, err := Open(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP TRIGGER automation_service_access_token_immutable`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	err = RestoreDatabase(ctx, source, filepath.Join(directory, "restored.db"))
	if err == nil || !strings.Contains(err.Error(), "administrator schema does not match") {
		t.Fatalf("weakened automation token schema restore err=%v", err)
	}
}

func TestEnabledServicePrincipalInventoryIsAuthoritativelyBounded(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	store.now = func() time.Time { return time.Unix(1_920_000_000, 0).UTC() }
	bootstrapAdministratorFixture(t, store)
	createDecision := administratorRootDecision(t, store, servicePrincipalCreatePolicy, adminauth.GlobalTarget())
	listDecision := administratorRootDecision(t, store, servicePrincipalListPolicy, adminauth.GlobalTarget())
	create := func(name string) (ServicePrincipalSummary, error) {
		return store.CreateServicePrincipal(ctx, createDecision, ServicePrincipalSpec{
			Name: name, Permissions: []adminauth.Operation{adminauth.OperationNetworkCreate},
		})
	}

	created := make([]ServicePrincipalSummary, 0, MaxEnabledServicePrincipals)
	for index := 0; index < MaxEnabledServicePrincipals; index++ {
		principal, err := create(fmt.Sprintf("inventory-%03d", index))
		if err != nil {
			t.Fatalf("create principal %d: %v", index, err)
		}
		created = append(created, principal)
	}
	if _, err := create("inventory-over-limit"); !errors.Is(err, ErrConflict) {
		t.Fatalf("create beyond enabled-principal limit err=%v", err)
	}
	principals, err := store.ServicePrincipals(ctx, listDecision, MaxEnabledServicePrincipals)
	if err != nil || len(principals) != MaxEnabledServicePrincipals {
		t.Fatalf("default-sized principal inventory count=%d err=%v", len(principals), err)
	}
	for _, principal := range principals {
		if !principal.Principal.Enabled {
			t.Fatalf("default-sized inventory included disabled principal %s", principal.Principal.ID)
		}
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE automation_service_principals SET all_networks=1 WHERE id=?`,
		idBytes(created[0].Principal.ID)); err == nil {
		t.Fatal("service principal network-scope mode could be changed directly")
	}

	disabledID := created[0].Principal.ID
	disableDecision := administratorRootDecision(t, store, servicePrincipalDisablePolicy,
		adminauth.ObjectTarget(disabledID))
	if err := store.DisableServicePrincipal(ctx, disableDecision, disabledID); err != nil {
		t.Fatal(err)
	}
	if err := store.DisableServicePrincipal(ctx, disableDecision, disabledID); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated disable err=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE automation_service_principals
		SET enabled=1,disabled_at=NULL WHERE id=?`, idBytes(disabledID)); err == nil {
		t.Fatal("disabled service principal could be re-enabled directly")
	}

	type createResult struct {
		principal ServicePrincipalSummary
		err       error
	}
	const contenders = 8
	results := make(chan createResult, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			principal, err := create(fmt.Sprintf("principal-race-%03d", index))
			results <- createResult{principal: principal, err: err}
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		if result.err == nil {
			succeeded++
			if !result.principal.Principal.Enabled {
				t.Fatal("new principal was not enabled")
			}
			continue
		}
		if !errors.Is(result.err, ErrConflict) {
			t.Fatalf("concurrent create err=%v", result.err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent create successes=%d want 1", succeeded)
	}

	var enabledCount int
	if err := store.db.QueryRowContext(ctx,
		`SELECT count(*) FROM automation_service_principals WHERE enabled=1`).Scan(&enabledCount); err != nil {
		t.Fatal(err)
	}
	if enabledCount != MaxEnabledServicePrincipals {
		t.Fatalf("enabled principal count=%d want %d", enabledCount, MaxEnabledServicePrincipals)
	}
	principals, err = store.ServicePrincipals(ctx, listDecision, MaxEnabledServicePrincipals)
	if err != nil || len(principals) != MaxEnabledServicePrincipals {
		t.Fatalf("bounded principal inventory count=%d err=%v", len(principals), err)
	}
	for _, principal := range principals {
		if !principal.Principal.Enabled {
			t.Fatalf("bounded inventory omitted enabled authority for disabled principal %s",
				principal.Principal.ID)
		}
	}
	history, err := store.ServicePrincipals(ctx, listDecision, 1000)
	if err != nil || len(history) != MaxEnabledServicePrincipals+1 {
		t.Fatalf("principal history count=%d err=%v", len(history), err)
	}
	disabledCount := 0
	for _, principal := range history {
		if !principal.Principal.Enabled {
			disabledCount++
		}
	}
	if disabledCount != 1 {
		t.Fatalf("disabled principal history count=%d want 1", disabledCount)
	}
}

func TestUnrevokedServiceTokenInventoryIsAuthoritativelyBounded(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_930_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	bootstrapAdministratorFixture(t, store)
	createDecision := administratorRootDecision(t, store, servicePrincipalCreatePolicy, adminauth.GlobalTarget())
	principal, err := store.CreateServicePrincipal(ctx, createDecision, ServicePrincipalSpec{
		Name: "bounded-token-principal", Permissions: []adminauth.Operation{adminauth.OperationNetworkCreate},
	})
	if err != nil {
		t.Fatal(err)
	}
	principalID := principal.Principal.ID
	issueDecision := administratorRootDecision(t, store, serviceTokenIssuePolicy,
		adminauth.ObjectTarget(principalID))
	listDecision := administratorRootDecision(t, store, serviceTokenListPolicy,
		adminauth.ObjectTarget(principalID))
	issue := func(label string) (ServiceAccessTokenSummary, string, error) {
		return store.IssueServiceAccessToken(ctx, issueDecision, principalID, label, base.Add(time.Hour))
	}

	liveIDs := make(map[identity.ID]struct{}, MaxUnrevokedServiceAccessTokensPerPrincipal)
	issuedBearers := make(map[identity.ID]string, MaxUnrevokedServiceAccessTokensPerPrincipal)
	for index := 0; index < MaxUnrevokedServiceAccessTokensPerPrincipal; index++ {
		token, bearer, err := issue(fmt.Sprintf("token-%03d", index))
		if err != nil {
			t.Fatalf("issue token %d: %v", index, err)
		}
		liveIDs[token.ID] = struct{}{}
		issuedBearers[token.ID] = bearer
	}
	if _, _, err := issue("token-over-limit"); !errors.Is(err, ErrConflict) {
		t.Fatalf("issue beyond unrevoked-token limit err=%v", err)
	}
	tokens, err := store.ServiceAccessTokens(ctx, listDecision, principalID,
		MaxUnrevokedServiceAccessTokensPerPrincipal)
	if err != nil || len(tokens) != MaxUnrevokedServiceAccessTokensPerPrincipal {
		t.Fatalf("default-sized token inventory count=%d err=%v", len(tokens), err)
	}
	for _, token := range tokens {
		if token.RevokedAt != nil {
			t.Fatalf("default-sized inventory included revoked token %s", token.ID)
		}
		if _, exists := liveIDs[token.ID]; !exists {
			t.Fatalf("default-sized inventory returned unknown token %s", token.ID)
		}
		delete(liveIDs, token.ID)
	}
	if len(liveIDs) != 0 {
		t.Fatalf("default-sized inventory omitted %d live tokens", len(liveIDs))
	}

	revokedID := tokens[0].ID
	revokeDecision := administratorRootDecision(t, store, serviceTokenRevokePolicy,
		adminauth.ObjectTarget(revokedID))
	for _, reason := range []string{"bad\x00reason", string([]byte{0xff})} {
		if err := store.RevokeServiceAccessToken(ctx, revokeDecision, revokedID, reason); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid revocation reason %q err=%v", reason, err)
		}
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, issuedBearers[revokedID]); err != nil {
		t.Fatalf("invalid revocation reason changed token state: %v", err)
	}
	base = base.Add(-time.Hour)
	if err := store.RevokeServiceAccessToken(ctx, revokeDecision, revokedID, "credential rotated"); err != nil {
		t.Fatalf("revoke after clock regression: %v", err)
	}
	base = base.Add(time.Hour)
	var revokedAt int64
	if err := store.db.QueryRowContext(ctx, `SELECT revoked_at FROM automation_service_access_tokens WHERE id=?`,
		idBytes(revokedID)).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt != base.Unix() {
		t.Fatalf("clock-regressed revocation time=%d want %d", revokedAt, base.Unix())
	}

	type issueResult struct {
		token  ServiceAccessTokenSummary
		bearer string
		err    error
	}
	const contenders = 8
	results := make(chan issueResult, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			token, bearer, err := issue(fmt.Sprintf("token-race-%03d", index))
			results <- issueResult{token: token, bearer: bearer, err: err}
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	var replacement ServiceAccessTokenSummary
	var replacementBearer string
	for result := range results {
		if result.err == nil {
			succeeded++
			replacement, replacementBearer = result.token, result.bearer
			continue
		}
		if !errors.Is(result.err, ErrConflict) {
			t.Fatalf("concurrent token issue err=%v", result.err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent token issue successes=%d want 1", succeeded)
	}

	var unrevokedCount int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM automation_service_access_tokens
		WHERE principal_id=? AND revoked_at IS NULL`, idBytes(principalID)).Scan(&unrevokedCount); err != nil {
		t.Fatal(err)
	}
	if unrevokedCount != MaxUnrevokedServiceAccessTokensPerPrincipal {
		t.Fatalf("unrevoked token count=%d want %d", unrevokedCount,
			MaxUnrevokedServiceAccessTokensPerPrincipal)
	}
	liveIDs = make(map[identity.ID]struct{}, MaxUnrevokedServiceAccessTokensPerPrincipal)
	for _, token := range tokens[1:] {
		liveIDs[token.ID] = struct{}{}
	}
	liveIDs[replacement.ID] = struct{}{}
	tokens, err = store.ServiceAccessTokens(ctx, listDecision, principalID,
		MaxUnrevokedServiceAccessTokensPerPrincipal)
	if err != nil || len(tokens) != MaxUnrevokedServiceAccessTokensPerPrincipal {
		t.Fatalf("bounded token inventory count=%d err=%v", len(tokens), err)
	}
	for _, token := range tokens {
		if token.RevokedAt != nil {
			t.Fatalf("bounded inventory included revoked token %s", token.ID)
		}
		if _, exists := liveIDs[token.ID]; !exists {
			t.Fatalf("bounded inventory returned unknown token %s", token.ID)
		}
		delete(liveIDs, token.ID)
	}
	if len(liveIDs) != 0 {
		t.Fatalf("bounded inventory omitted %d live tokens", len(liveIDs))
	}
	history, err := store.ServiceAccessTokens(ctx, listDecision, principalID, 1000)
	if err != nil || len(history) != MaxUnrevokedServiceAccessTokensPerPrincipal+1 {
		t.Fatalf("token history count=%d err=%v", len(history), err)
	}
	revokedCount := 0
	for _, token := range history {
		if token.RevokedAt != nil {
			revokedCount++
		}
	}
	if revokedCount != 1 {
		t.Fatalf("revoked token history count=%d want 1", revokedCount)
	}

	disableDecision := administratorRootDecision(t, store, servicePrincipalDisablePolicy,
		adminauth.ObjectTarget(principalID))
	if err := store.DisableServicePrincipal(ctx, disableDecision, principalID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, replacementBearer); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("disabled principal token authentication err=%v", err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM automation_service_access_tokens
		WHERE principal_id=? AND revoked_at IS NULL`, idBytes(principalID)).Scan(&unrevokedCount); err != nil {
		t.Fatal(err)
	}
	if unrevokedCount != 0 {
		t.Fatalf("disabled principal retained %d unrevoked tokens", unrevokedCount)
	}
	principals, err := store.ServicePrincipals(ctx,
		administratorRootDecision(t, store, servicePrincipalListPolicy, adminauth.GlobalTarget()), 1000)
	if err != nil || len(principals) != 1 || principals[0].Principal.Enabled || principals[0].DisabledAt == nil {
		t.Fatalf("disabled principal inventory=%+v err=%v", principals, err)
	}
}
