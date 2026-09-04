package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/applicationauth"
)

func applicationPKCE(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func applicationOwnerSubject(t *testing.T, store *Store) adminauth.Subject {
	t.Helper()
	owner, _ := bootstrapAdministratorFixture(t, store)
	session, _, _, err := store.CreateAdministratorSession(context.Background(), owner.Principal.ID,
		owner.Credential.ID, AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	return adminauth.SessionSubject(owner.Principal.ID, session.ID)
}

func applicationDecision(t *testing.T, subject adminauth.Subject, policy adminauth.RoutePolicy,
	target adminauth.DecisionTarget) adminauth.Decision {
	t.Helper()
	decision, err := adminauth.NewDecision(subject, policy, target)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func registerTestApplication(t *testing.T, store *Store, owner adminauth.Subject, verifier string) ApplicationRegistrationExchange {
	t.Helper()
	manifest := applicationauth.Manifest{Name: "Example deployment controller", HomepageURI: "https://client.example.com",
		SetupURI: "https://client.example.com/setup", RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:                  []string{"network.read", "node.read", "enrollment.issue", "route.read", "route.manage"},
		TokenEndpointAuthMethod: "client_secret_basic"}
	pending, err := store.CreateApplicationRegistrationRequest(context.Background(), manifest, "state-value", applicationPKCE(verifier))
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.AdministratorApproveApplicationRegistration(context.Background(), applicationDecision(t, owner,
		applicationRegistrationApprovePolicy, adminauth.ObjectTarget(pending.ID)), pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExchangeApplicationRegistration(context.Background(), approval.Code, verifier+"wrong"); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("wrong verifier error=%v", err)
	}
	exchange, err := store.ExchangeApplicationRegistration(context.Background(), approval.Code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExchangeApplicationRegistration(context.Background(), approval.Code, verifier); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("registration replay error=%v", err)
	}
	var stored []byte
	if err := store.db.QueryRow(`SELECT secret_hash FROM registered_application_credentials WHERE application_id=?`, idBytes(exchange.Application.ID)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != sha256.Size || strings.Contains(string(stored), exchange.ClientSecret) {
		t.Fatal("client secret was not stored as a digest")
	}
	return exchange
}

func authorizeTestInstallation(t *testing.T, store *Store, owner adminauth.Subject,
	application ApplicationRegistrationExchange, network Network, verifier string) ApplicationTokenGrant {
	t.Helper()
	request, err := store.CreateApplicationAuthorizationRequest(context.Background(), application.Application.ClientID,
		"https://client.example.com/callback", application.Application.Manifest.Scopes, "oauth-state", applicationPKCE(verifier))
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.AdministratorApproveApplicationAuthorization(context.Background(), applicationDecision(t, owner,
		applicationAuthorizationApprovePolicy, adminauth.NetworkTarget(network.ID)), request.ID, network.ID, request.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.ExchangeApplicationAuthorizationCode(context.Background(), application.Application.ClientID,
		application.ClientSecret, approval.Code, verifier, request.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func TestApplicationRegistrationInstallationIsolationAndRotation(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("v", 48))
	networkOne, err := store.CreateNetwork(ctx, "application-one", netip.MustParsePrefix("10.140.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	networkTwo, err := store.CreateNetwork(ctx, "application-two", netip.MustParsePrefix("10.141.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	first := authorizeTestInstallation(t, store, owner, application, networkOne, strings.Repeat("a", 48))
	second := authorizeTestInstallation(t, store, owner, application, networkTwo, strings.Repeat("b", 48))
	if first.Installation.ID == second.Installation.ID || first.Installation.ServicePrincipalID == second.Installation.ServicePrincipalID {
		t.Fatal("application installations shared an identity")
	}
	token, principal, err := store.AuthenticateServiceAccessToken(ctx, first.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	_, proof, err := adminauth.ParseServiceAccessToken(first.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	wrongDecision, err := adminauth.NewDecision(adminauth.ServicePrincipalTokenSubject(principal.ID, token.ID, proof),
		administratorNetworkReadPolicy, adminauth.NetworkTarget(networkTwo.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorNetwork(ctx, wrongDecision, networkTwo.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-network token error=%v", err)
	}
	now = now.Add(time.Minute)
	rotated, err := store.RefreshApplicationToken(ctx, application.Application.ClientID, application.ClientSecret, first.RefreshToken)
	if err != nil || rotated.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh=%+v err=%v", rotated, err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, first.AccessToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("old access token survived refresh: %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := store.RefreshApplicationToken(ctx, application.Application.ClientID, application.ClientSecret, first.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("refresh reuse error=%v", err)
	}
	if _, err := store.RefreshApplicationToken(ctx, application.Application.ClientID, application.ClientSecret, rotated.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("reused family remained active: %v", err)
	}
}

func TestApplicationReauthorizationReusesInstallationAndInstallerBindsToken(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Unix(2_010_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("r", 48))
	network, err := store.CreateNetwork(context.Background(), "reauthorize", netip.MustParsePrefix("10.142.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	first := authorizeTestInstallation(t, store, owner, application, network, strings.Repeat("x", 48))
	second := authorizeTestInstallation(t, store, owner, application, network, strings.Repeat("y", 48))
	if first.Installation.ID != second.Installation.ID {
		t.Fatal("duplicate active installation created")
	}
	request, err := store.CreateApplicationAuthorizationRequest(context.Background(), application.Application.ClientID,
		"https://client.example.com/callback", application.Application.Manifest.Scopes, "narrower-scope", applicationPKCE(strings.Repeat("z", 48)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorApproveApplicationAuthorization(context.Background(), applicationDecision(t, owner,
		applicationAuthorizationApprovePolicy, adminauth.NetworkTarget(network.ID)), request.ID, network.ID, []string{"network.read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, first.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("scope replacement left old refresh family active: %v", err)
	}
	decision := applicationDecision(t, owner, applicationNodeInstallerPolicy, adminauth.NetworkTarget(network.ID))
	installer, err := store.AdministratorIssueNodeInstallerToken(context.Background(), decision, network.ID, "private-services", now.Add(10*time.Minute), 1<<3)
	if err != nil {
		t.Fatal(err)
	}
	var requested string
	var capabilities int64
	var networkRaw []byte
	if err := store.db.QueryRow(`SELECT requested_name,enabled_capabilities,network_id FROM enrollment_tokens WHERE id=?`, idBytes(installer.ID)).Scan(&requested, &capabilities, &networkRaw); err != nil {
		t.Fatal(err)
	}
	if requested != "private-services" || capabilities != 1<<3 || !slices.Equal(networkRaw, network.ID[:]) {
		t.Fatal("installer token was not bound")
	}
}

func TestApplicationAuthorizationCodeKeepsExactRedirectBinding(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Unix(2_020_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("c", 48))
	network, err := store.CreateNetwork(context.Background(), "callback-binding", netip.MustParsePrefix("10.143.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("d", 48)
	request, err := store.CreateApplicationAuthorizationRequest(context.Background(), application.Application.ClientID,
		"https://client.example.com/callback", []string{"network.read"}, "state", applicationPKCE(verifier))
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.AdministratorApproveApplicationAuthorization(context.Background(), applicationDecision(t, owner,
		applicationAuthorizationApprovePolicy, adminauth.NetworkTarget(network.ID)), request.ID, network.ID, request.Scopes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExchangeApplicationAuthorizationCode(context.Background(), application.Application.ClientID,
		application.ClientSecret, approval.Code, verifier, "https://client.example.com/callback/"); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("near-match redirect error=%v", err)
	}
	if _, err := store.ExchangeApplicationAuthorizationCode(context.Background(), application.Application.ClientID,
		application.ClientSecret, approval.Code, verifier, request.RedirectURI); err != nil {
		t.Fatalf("correct redirect after mismatch: %v", err)
	}
}

func TestApplicationRefreshRaceKeepsOneValidFamily(t *testing.T) {
	store, _ := openTestStore(t)
	now := time.Unix(2_030_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("e", 48))
	network, err := store.CreateNetwork(context.Background(), "refresh-race", netip.MustParsePrefix("10.144.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	grant := authorizeTestInstallation(t, store, owner, application, network, strings.Repeat("f", 48))
	rotated, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, grant.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, grant.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("racing refresh replay error=%v", err)
	}
	current, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, rotated.RefreshToken)
	if err != nil || current.RefreshToken == rotated.RefreshToken {
		t.Fatalf("valid family lost after race: grant=%+v err=%v", current, err)
	}
	now = now.Add(ApplicationRefreshGrace + time.Second)
	if _, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, grant.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("late refresh reuse error=%v", err)
	}
	if _, err := store.RefreshApplicationToken(context.Background(), application.Application.ClientID, application.ClientSecret, current.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("reused family remained active: %v", err)
	}
}

func TestRevokingInstallationAndApplicationUsesExpectedBoundary(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_040_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	firstApplication := registerTestApplication(t, store, owner, strings.Repeat("g", 48))
	secondApplication := registerTestApplication(t, store, owner, strings.Repeat("h", 48))
	if firstApplication.Application.ID == secondApplication.Application.ID || firstApplication.Application.Manifest.Name != secondApplication.Application.Manifest.Name {
		t.Fatal("applications with the same display name were not independent")
	}
	networkOne, err := store.CreateNetwork(ctx, "revoke-one", netip.MustParsePrefix("10.145.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	networkTwo, err := store.CreateNetwork(ctx, "revoke-two", netip.MustParsePrefix("10.146.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	first := authorizeTestInstallation(t, store, owner, firstApplication, networkOne, strings.Repeat("i", 48))
	second := authorizeTestInstallation(t, store, owner, firstApplication, networkTwo, strings.Repeat("j", 48))
	if err := store.AdministratorDeleteApplication(ctx, applicationDecision(t, owner,
		applicationDeletePolicy, adminauth.ObjectTarget(firstApplication.Application.ID)), firstApplication.Application.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("enabled application delete error=%v", err)
	}
	if err := store.AdministratorRevokeApplicationInstallation(ctx, applicationDecision(t, owner,
		applicationInstallationDeletePolicy, adminauth.ObjectTarget(first.Installation.ID)), first.Installation.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, first.AccessToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("revoked installation token survived: %v", err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, second.AccessToken); err != nil {
		t.Fatalf("other installation token was revoked: %v", err)
	}
	if err := store.AuthenticateApplicationClient(ctx, firstApplication.Application.ClientID, firstApplication.ClientSecret); err != nil {
		t.Fatalf("removing one installation removed the application: %v", err)
	}
	if err := store.AdministratorDisableApplication(ctx, applicationDecision(t, owner,
		applicationDisablePolicy, adminauth.ObjectTarget(firstApplication.Application.ID)), firstApplication.Application.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AuthenticateServiceAccessToken(ctx, second.AccessToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("application disable left installation active: %v", err)
	}
	if err := store.AuthenticateApplicationClient(ctx, firstApplication.Application.ClientID, firstApplication.ClientSecret); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("application disable left credential active: %v", err)
	}
	if err := store.AdministratorDeleteApplication(ctx, applicationDecision(t, owner,
		applicationDeletePolicy, adminauth.ObjectTarget(firstApplication.Application.ID)), firstApplication.Application.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorApplication(ctx, applicationDecision(t, owner,
		applicationReadPolicy, adminauth.ObjectTarget(firstApplication.Application.ID)), firstApplication.Application.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted application read error=%v", err)
	}
	for table, query := range map[string]string{
		"application":  `SELECT count(*) FROM registered_applications WHERE id=?`,
		"credential":   `SELECT count(*) FROM registered_application_credentials WHERE application_id=?`,
		"installation": `SELECT count(*) FROM application_installations WHERE application_id=?`,
	} {
		var count int
		if err := store.db.QueryRowContext(ctx, query, idBytes(firstApplication.Application.ID)).Scan(&count); err != nil || count != 0 {
			t.Fatalf("deleted %s rows=%d err=%v", table, count, err)
		}
	}
	var deleteAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action='application.delete' AND target_id=?`,
		idBytes(firstApplication.Application.ID)).Scan(&deleteAudits); err != nil || deleteAudits != 1 {
		t.Fatalf("application delete audits=%d err=%v", deleteAudits, err)
	}
	if err := store.AuthenticateApplicationClient(ctx, secondApplication.Application.ClientID, secondApplication.ClientSecret); err != nil {
		t.Fatalf("deleting one application affected another: %v", err)
	}
}

func TestExpiredApplicationAccessTokenCleanupIsBounded(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_050_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("k", 48))
	network, err := store.CreateNetwork(ctx, "cleanup", netip.MustParsePrefix("10.147.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	grant := authorizeTestInstallation(t, store, owner, application, network, strings.Repeat("l", 48))
	for index := 0; index < 150; index++ {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(id[:])
		created := now.Add(time.Duration(-400+index*2) * time.Hour)
		if _, err := store.db.ExecContext(ctx, `INSERT INTO automation_service_access_tokens
			(id,principal_id,label,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)`, idBytes(id),
			idBytes(grant.Installation.ServicePrincipalID), "expired application token", digest[:], unix(created), unix(created.Add(time.Hour))); err != nil {
			t.Fatalf("insert expired token %d: %v", index, err)
		}
	}
	cleaned, err := store.CleanupApplicationCredentials(ctx, 40)
	if err != nil {
		t.Fatal(err)
	}
	if cleaned != 40 {
		t.Fatalf("bounded cleanup changed %d records", cleaned)
	}
	var remaining int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM automation_service_access_tokens WHERE principal_id=? AND revoked_at IS NULL AND expires_at<=?`,
		idBytes(grant.Installation.ServicePrincipalID), unix(now)).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 110 {
		t.Fatalf("remaining expired tokens=%d", remaining)
	}
}

func TestExpiredApplicationRefreshCleanupRemovesFamily(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_060_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	owner := applicationOwnerSubject(t, store)
	application := registerTestApplication(t, store, owner, strings.Repeat("m", 48))
	network, err := store.CreateNetwork(ctx, "refresh-cleanup", netip.MustParsePrefix("10.148.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	grant := authorizeTestInstallation(t, store, owner, application, network, strings.Repeat("n", 48))
	now = now.Add(ApplicationRefreshTokenLifetime + time.Second)
	if _, err := store.CleanupApplicationCredentials(ctx, 10); err != nil {
		t.Fatal(err)
	}
	var families, tokens int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM application_refresh_token_families WHERE installation_id=?`, idBytes(grant.Installation.ID)).Scan(&families); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM application_refresh_tokens`).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if families != 0 || tokens != 0 {
		t.Fatalf("expired refresh records remain: families=%d tokens=%d", families, tokens)
	}
	if _, err := store.RefreshApplicationToken(ctx, application.Application.ClientID, application.ClientSecret, grant.RefreshToken); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expired refresh token error=%v", err)
	}
}
