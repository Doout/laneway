package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func administratorRootDecision(t *testing.T, store *Store, policy adminauth.RoutePolicy, target adminauth.DecisionTarget) adminauth.Decision {
	t.Helper()
	state, err := store.AdministratorAuthState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := adminauth.NewDecision(adminauth.RootSubject(state.RootServicePrincipalID), policy, target)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func administratorSessionSubject(t *testing.T, store *Store, username string, role adminauth.Role,
	allNetworks bool, networks ...identity.NetworkID) adminauth.Subject {
	t.Helper()
	ctx := context.Background()
	principalID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	credentialID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := adminauth.HashPassword([]byte("a sufficiently long administrator password"),
		bytes.NewReader(bytes.Repeat([]byte{7}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	now := store.now()
	all := 0
	if allNetworks {
		all = 1
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO administrator_principals
		(id,username,role,all_networks,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`,
		idBytes(principalID), username, string(role), all, unix(now), unix(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO administrator_credentials
		(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?,'password',?,?)`,
		idBytes(credentialID), idBytes(principalID), passwordHash, unix(now)); err != nil {
		t.Fatal(err)
	}
	for _, networkID := range networks {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO administrator_principal_networks
			(principal_id,network_id,created_at) VALUES(?,?,?)`, idBytes(principalID), idBytes(networkID), unix(now)); err != nil {
			t.Fatal(err)
		}
	}
	session, _, _, err := store.CreateAdministratorSession(ctx, principalID, credentialID,
		AdministratorSessionOptions{IdleTimeout: time.Hour, AbsoluteTimeout: 2 * time.Hour, MaxActive: 5})
	if err != nil {
		t.Fatal(err)
	}
	return adminauth.SessionSubject(principalID, session.ID)
}

func administratorDecisionForSubject(t *testing.T, subject adminauth.Subject, policy adminauth.RoutePolicy,
	target adminauth.DecisionTarget) adminauth.Decision {
	t.Helper()
	decision, err := adminauth.NewDecision(subject, policy, target)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func resourceTestNetwork(t *testing.T, store *Store, name, prefix string) Network {
	t.Helper()
	result, err := store.CreateNetwork(context.Background(), name, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func resourceTestNode(t *testing.T, store *Store, networkID identity.NetworkID, name string, capabilities protocol.Capability) Node {
	t.Helper()
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), networkID, name, store.now().Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassDurable, EnabledCapabilities: uint64(capabilities)})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(context.Background(), token.Secret, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func waitForAdministratorConnectionQueue(t *testing.T, store *Store, previousWaitCount int64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			stats := store.db.Stats()
			if stats.InUse == 1 && stats.WaitCount > previousWaitCount {
				return
			}
		case <-deadline.C:
			stats := store.db.Stats()
			t.Fatalf("administrator transaction did not queue: in_use=%d waits=%d want_waits>%d",
				stats.InUse, stats.WaitCount, previousWaitCount)
		}
	}
}

func TestAdministratorExpiryChecksUseClockAfterQueuedTransactionBegins(t *testing.T) {
	t.Run("enrollment token issuance", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		base := time.Unix(1_950_000_000, 0).UTC()
		var clock atomic.Int64
		clock.Store(base.Unix())
		store.now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
		network := resourceTestNetwork(t, store, "queued-token-network", "10.94.0.0/24")
		decision := administratorRootDecision(t, store, administratorEnrollmentIssuePolicy, adminauth.NetworkTarget(network.ID))
		expiresAt := base.Add(time.Minute)

		blocker, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		previousWaitCount := store.db.Stats().WaitCount
		result := make(chan error, 1)
		go func() {
			_, issueErr := store.AdministratorIssueEnrollmentTokenWithOptions(ctx, decision, network.ID,
				"queued-token", expiresAt, EnrollmentTokenOptions{Class: EnrollmentClassDurable})
			result <- issueErr
		}()
		waitForAdministratorConnectionQueue(t, store, previousWaitCount)
		clock.Store(expiresAt.Add(time.Second).Unix())
		if err := blocker.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrInvalid) {
			t.Fatalf("queued expired token issuance error=%v want ErrInvalid", err)
		}
		var tokens int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_tokens WHERE label='queued-token'`).Scan(&tokens); err != nil {
			t.Fatal(err)
		}
		if tokens != 0 {
			t.Fatalf("queued expired token issuance persisted %d credentials", tokens)
		}
	})

	t.Run("route approval", func(t *testing.T) {
		store, _ := openTestStore(t)
		ctx := context.Background()
		base := time.Unix(1_960_000_000, 0).UTC()
		var clock atomic.Int64
		clock.Store(base.Unix())
		store.now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
		network := resourceTestNetwork(t, store, "queued-route-network", "10.95.0.0/24")
		node := resourceTestNode(t, store, network.ID, "queued-route-node", protocol.CapabilitySubnetRouterV1)
		validUntil := base.Add(time.Minute)
		route, err := store.AdvertiseRoute(ctx, node.ID, netip.MustParsePrefix("192.0.2.0/24"),
			RouteKindSubnet, RouteModeNAT, 10, &validUntil)
		if err != nil {
			t.Fatal(err)
		}
		decision := administratorRootDecision(t, store, administratorRouteApprovePolicy, adminauth.ObjectTarget(route.ID))

		blocker, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		previousWaitCount := store.db.Stats().WaitCount
		result := make(chan error, 1)
		go func() {
			_, approveErr := store.AdministratorApproveRoute(ctx, decision, route.ID)
			result <- approveErr
		}()
		waitForAdministratorConnectionQueue(t, store, previousWaitCount)
		clock.Store(validUntil.Add(time.Second).Unix())
		if err := blocker.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrConflict) {
			t.Fatalf("queued expired route approval error=%v want ErrConflict", err)
		}
		var state string
		if err := store.db.QueryRowContext(ctx, `SELECT state FROM routes WHERE id=?`, idBytes(route.ID)).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != string(RouteStateAdvertised) {
			t.Fatalf("queued expired route state=%s want %s", state, RouteStateAdvertised)
		}
	})
}

func TestEnrollmentConsumptionUsesClockAfterQueuedTransactionBegins(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_970_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	network := resourceTestNetwork(t, store, "queued-enrollment-network", "10.96.0.0/24")
	token, err := store.IssueEnrollmentToken(ctx, network.ID, "queued-enrollment", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// EnrollNode first runs the ephemeral sweeper. On its next clock read, a
	// transaction must already own the single database connection. If not, the
	// fake clock deterministically places a competing transaction in front of
	// enrollment and returns the pre-expiry value, exposing a stale clock read.
	type clockObservation struct {
		release func() error
		err     error
	}
	observation := make(chan clockObservation, 1)
	var clockReads atomic.Int32
	expired := token.ExpiresAt.Add(time.Second)
	store.now = func() time.Time {
		switch clockReads.Add(1) {
		case 1:
			return base // ExpireEphemeral.
		case 2:
			if store.db.Stats().InUse == 1 {
				observation <- clockObservation{}
				return expired
			}
			blocker, beginErr := store.db.BeginTx(ctx, nil)
			if beginErr != nil {
				observation <- clockObservation{err: beginErr}
				return expired
			}
			observation <- clockObservation{release: blocker.Rollback}
			return base
		default:
			return expired
		}
	}
	previousWaitCount := store.db.Stats().WaitCount
	result := make(chan error, 1)
	go func() {
		_, enrollErr := store.EnrollNode(ctx, token.Secret, "queued-enrollment-node", 0)
		result <- enrollErr
	}()
	var observed clockObservation
	select {
	case observed = <-observation:
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment clock was not sampled")
	}
	if observed.err != nil {
		t.Fatal(observed.err)
	}
	if observed.release != nil {
		waitForAdministratorConnectionQueue(t, store, previousWaitCount)
		if err := observed.release(); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-result; !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("queued expired enrollment error=%v want ErrTokenExpired", err)
	}
	var nodes, unconsumed int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE name='queued-enrollment-node'`).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NULL`,
		idBytes(token.ID)).Scan(&unconsumed); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || unconsumed != 1 {
		t.Fatalf("queued expired enrollment mutated nodes=%d unconsumed=%d", nodes, unconsumed)
	}
}

func TestEphemeralRenewalUsesClockAfterQueuedTransactionBegins(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_980_000_000, 0).UTC()
	var clock atomic.Int64
	clock.Store(base.Unix())
	store.now = func() time.Time { return time.Unix(clock.Load(), 0).UTC() }
	network := resourceTestNetwork(t, store, "queued-renewal-network", "10.97.0.0/24")
	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "queued-renewal", base.Add(time.Minute),
		EnrollmentTokenOptions{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime})
	if err != nil {
		t.Fatal(err)
	}
	key := WireGuardPublicKey{1}
	serial := byte(1)
	issuer := func(_ context.Context, node Node) (CertificateMaterial, error) {
		serial++
		return CertificateMaterial{Serial: []byte{serial}, DER: []byte{0x30, serial}, NotBefore: base,
			NotAfter: node.LeaseExpiresAt.Add(-time.Second)}, nil
	}
	enrollment, err := store.EnrollNodeBound(ctx, token.Secret, "queued-renewal-node", 0,
		network.ID, EnrollmentClassEphemeral, key, issuer)
	if err != nil {
		t.Fatal(err)
	}
	leaseExpiry := *enrollment.Node.LeaseExpiresAt

	blocker, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	previousWaitCount := store.db.Stats().WaitCount
	result := make(chan error, 1)
	go func() {
		_, renewErr := store.RenewNodeBound(ctx, network.ID, enrollment.Node.ID, key, issuer)
		result <- renewErr
	}()
	waitForAdministratorConnectionQueue(t, store, previousWaitCount)
	clock.Store(leaseExpiry.Unix())
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrNotFound) {
		t.Fatalf("queued expired renewal error=%v want ErrNotFound", err)
	}
	var certificates int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM certificates WHERE node_id=?`, idBytes(enrollment.Node.ID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if certificates != 1 {
		t.Fatalf("queued expired renewal persisted certificates=%d want 1", certificates)
	}
}

func TestAdministratorIssueEnrollmentTokenRechecksExpiryAfterAuthorization(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(1_990_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	network := resourceTestNetwork(t, store, "stepped-token-network", "10.98.0.0/24")
	subject := administratorSessionSubject(t, store, "stepped-token-operator", adminauth.RoleOperator, false, network.ID)
	decision := administratorDecisionForSubject(t, subject, administratorEnrollmentIssuePolicy, adminauth.NetworkTarget(network.ID))
	expiresAt := base.Add(time.Minute)

	var beforeTokens, beforeAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_tokens WHERE label='stepped-token'`).Scan(&beforeTokens); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action='enrollment_token.issue'`).Scan(&beforeAudits); err != nil {
		t.Fatal(err)
	}

	// The session authorization consumes the first clock sample. The issuance
	// boundary must be sampled again after authorization, in the same
	// transaction, before any credential or audit row is inserted.
	var clockReads atomic.Int32
	store.now = func() time.Time {
		if clockReads.Add(1) == 1 {
			return base
		}
		return expiresAt.Add(time.Second)
	}
	if _, err := store.AdministratorIssueEnrollmentTokenWithOptions(ctx, decision, network.ID, "stepped-token",
		expiresAt, EnrollmentTokenOptions{Class: EnrollmentClassDurable}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry crossed during authorization error=%v want ErrInvalid", err)
	}
	if clockReads.Load() < 2 {
		t.Fatalf("issuance clock reads=%d want at least 2", clockReads.Load())
	}

	var afterTokens, afterAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_tokens WHERE label='stepped-token'`).Scan(&afterTokens); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action='enrollment_token.issue'`).Scan(&afterAudits); err != nil {
		t.Fatal(err)
	}
	if afterTokens != beforeTokens || afterAudits != beforeAudits {
		t.Fatalf("expired issuance mutated tokens=%d want=%d audits=%d want=%d",
			afterTokens, beforeTokens, afterAudits, beforeAudits)
	}
}

func TestAdministratorAssignRouteRechecksExpiryBeforeApproval(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return base }
	network := resourceTestNetwork(t, store, "stepped-route-network", "10.99.0.0/24")
	node := resourceTestNode(t, store, network.ID, "stepped-route-node", 0)
	subject := administratorSessionSubject(t, store, "stepped-route-operator", adminauth.RoleOperator, false, network.ID)
	decision := administratorDecisionForSubject(t, subject, administratorRouteAssignPolicy, adminauth.NetworkTarget(network.ID))
	prefix := netip.MustParsePrefix("198.18.0.0/24")
	validUntil := base.Add(time.Minute)
	routeID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO routes
		(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at)
		VALUES(?,?,?,?,?,'subnet','nat',20,'advertised',?,?)`, idBytes(routeID), idBytes(network.ID), idBytes(node.ID),
		prefix.Addr().AsSlice(), prefix.Bits(), unix(validUntil), unix(base)); err != nil {
		t.Fatal(err)
	}
	beforeNetwork, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	var beforeAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action IN ('node.capabilities.set','route.advertise','route.approve')`).Scan(&beforeAudits); err != nil {
		t.Fatal(err)
	}

	// Authorization and assignment work each see the still-valid time. The
	// final approval sample crosses valid_until; every earlier capability,
	// epoch, and audit mutation must roll back with the failed approval.
	var clockReads atomic.Int32
	store.now = func() time.Time {
		if clockReads.Add(1) < 3 {
			return base
		}
		return validUntil.Add(time.Second)
	}
	if _, _, _, err := store.AdministratorAssignRoute(ctx, decision, network.ID, node.ID, prefix, RouteModeNAT, 20); !errors.Is(err, ErrConflict) {
		t.Fatalf("expiry crossed before route approval error=%v want ErrConflict", err)
	}
	if clockReads.Load() < 3 {
		t.Fatalf("assignment clock reads=%d want at least 3", clockReads.Load())
	}

	var capabilities uint64
	if err := store.db.QueryRowContext(ctx, `SELECT enabled_capabilities FROM nodes WHERE id=?`, idBytes(node.ID)).Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	var state string
	var approvedAt sql.NullInt64
	if err := store.db.QueryRowContext(ctx, `SELECT state,approved_at FROM routes WHERE id=?`, idBytes(routeID)).Scan(&state, &approvedAt); err != nil {
		t.Fatal(err)
	}
	var activeRoutes, afterAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM routes
		WHERE network_id=? AND prefix_address=? AND prefix_length=? AND state IN ('advertised','approved')`,
		idBytes(network.ID), prefix.Addr().AsSlice(), prefix.Bits()).Scan(&activeRoutes); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action IN ('node.capabilities.set','route.advertise','route.approve')`).Scan(&afterAudits); err != nil {
		t.Fatal(err)
	}
	afterNetwork, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities != 0 || state != string(RouteStateAdvertised) || approvedAt.Valid || activeRoutes != 1 ||
		afterNetwork.ConfigurationEpoch != beforeNetwork.ConfigurationEpoch || afterAudits != beforeAudits {
		t.Fatalf("expired assignment committed capabilities=%d state=%s approved=%v routes=%d epoch=%d want=%d audits=%d want=%d",
			capabilities, state, approvedAt, activeRoutes, afterNetwork.ConfigurationEpoch, beforeNetwork.ConfigurationEpoch,
			afterAudits, beforeAudits)
	}
}

func TestAdministratorResourcePoliciesMirrorManagementRegistry(t *testing.T) {
	resourcePolicies := []adminauth.RoutePolicy{
		administratorEnrollmentIssuePolicy, administratorNetworkCreatePolicy, administratorNetworkListPolicy,
		administratorNetworkReadPolicy, administratorNodeListPolicy, administratorRelayListPolicy,
		administratorEndpointStatusListPolicy,
		administratorACLListPolicy, administratorCertificateListPolicy, administratorRouteListPolicy,
		administratorAuditListPolicy, administratorAuditPageListPolicy,
		administratorGlobalAuditListPolicy, administratorGlobalAuditPageListPolicy,
		administratorRouteAssignPolicy, administratorRouteApprovePolicy,
		administratorRouteWithdrawPolicy, administratorACLCreatePolicy, administratorACLUpdatePolicy,
		administratorACLDeletePolicy, administratorNodeRevokePolicy, administratorNodeCapabilitiesPolicy,
		administratorCertificateRevokePolicy, administratorRelayCreatePolicy, administratorRelayDisablePolicy,
		administratorRelayUpdatePolicy, administratorAccessInventoryPolicy, administratorAccessUserCreatePolicy,
		administratorAccessUserUpdatePolicy, administratorAccessTeamCreatePolicy, administratorAccessMemberAddPolicy,
		administratorAccessMemberDeletePolicy, administratorAccessGrantCreatePolicy, administratorAccessGrantDeletePolicy,
		administratorAccessResourceCreatePolicy, administratorAccessResourceUpdatePolicy,
		administratorAccessServiceCreatePolicy, administratorAccessServiceUpdatePolicy,
		administratorAccessResourceGrantCreatePolicy, administratorAccessResourceGrantDeletePolicy,
	}
	if len(resourcePolicies) != 40 {
		t.Fatalf("resource policies=%d want 40 non-bootstrap routes", len(resourcePolicies))
	}
	identityPolicies := []adminauth.RoutePolicy{
		administratorCreatePolicy, administratorListPolicy, administratorReadPolicy,
		administratorAccessUpdatePolicy, administratorPasswordReplacePolicy,
		administratorSessionListPolicy, administratorSessionRevokePolicy,
		administratorBootstrapGrantPolicy, administratorOwnerRecoveryGrantPolicy,
		servicePrincipalCreatePolicy, servicePrincipalListPolicy, servicePrincipalDisablePolicy, serviceTokenIssuePolicy,
		serviceTokenListPolicy, serviceTokenRevokePolicy,
	}
	seen := make(map[string]string, len(resourcePolicies)+len(identityPolicies)+1)
	for _, policy := range resourcePolicies {
		key := policy.Method + " " + policy.Pattern
		if owner := seen[key]; owner != "" {
			t.Fatalf("duplicate resource policy %s", key)
		}
		seen[key] = "resource"
	}
	for _, policy := range identityPolicies {
		key := policy.Method + " " + policy.Pattern
		if owner := seen[key]; owner != "" {
			t.Fatalf("identity policy %s overlaps %s policy", key, owner)
		}
		seen[key] = "identity"
	}
	bootstrapKey := administratorBootstrapCreatePolicy.Method + " " + administratorBootstrapCreatePolicy.Pattern
	seen[bootstrapKey] = "bootstrap"
	// Root-token rotation is an external credential lifecycle with dedicated
	// begin/complete Store audit methods, not a durable management resource.
	for _, policy := range []adminauth.RoutePolicy{
		administratorRootTokenRotationBeginPolicy,
		administratorRootTokenRotationCompletePolicy,
	} {
		seen[policy.Method+" "+policy.Pattern] = "root-token lifecycle"
	}
	for _, registered := range adminauth.ManagementRoutes() {
		key := registered.Method + " " + registered.Pattern
		if seen[key] == "" {
			t.Errorf("registered management route has no resource policy: %s", key)
		}
		delete(seen, key)
	}
	for key, owner := range seen {
		t.Errorf("%s policy is not registered: %s", owner, key)
	}
	for _, lookup := range []struct{ method, pattern string }{
		{http.MethodGet, "/v1/admin/networks"},
		{http.MethodPost, "/v1/admin/routes/{route_id}/approve"},
	} {
		policy := mustAdministratorResourcePolicy(lookup.method, lookup.pattern)
		if policy.Method != lookup.method || policy.Pattern != lookup.pattern {
			t.Fatalf("policy lookup drifted: %+v", policy)
		}
	}
}

func TestAdministratorNetworksFiltersBeforeLimitAndRevalidatesScope(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	_ = resourceTestNetwork(t, store, "hidden-first", "10.80.0.0/24")
	now = now.Add(time.Second)
	_ = resourceTestNetwork(t, store, "hidden-second", "10.81.0.0/24")
	now = now.Add(time.Second)
	visible := resourceTestNetwork(t, store, "visible-third", "10.82.0.0/24")
	subject := administratorSessionSubject(t, store, "scoped-operator", adminauth.RoleOperator, false, visible.ID)
	decision := administratorDecisionForSubject(t, subject, administratorNetworkListPolicy, adminauth.FilteredTarget())

	networks, err := store.AdministratorNetworks(ctx, decision, 1)
	if err != nil || len(networks) != 1 || networks[0].ID != visible.ID {
		t.Fatalf("filtered-before-limit networks=%+v err=%v", networks, err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM administrator_principal_networks WHERE principal_id=?`, idBytes(subject.ActorID())); err != nil {
		t.Fatal(err)
	}
	networks, err = store.AdministratorNetworks(ctx, decision, 1)
	if err != nil || len(networks) != 0 {
		t.Fatalf("stale scope remained authoritative: networks=%+v err=%v", networks, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE administrator_principals
		SET enabled=0,disabled_at=?,updated_at=? WHERE id=?`, unix(now), unix(now), idBytes(subject.ActorID())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorNetworks(ctx, decision, 1); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("disabled principal list error=%v want ErrSessionInvalid", err)
	}
}

func TestAdministratorObjectBindingAndScopeDoNotLeakExistence(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	allowed := resourceTestNetwork(t, store, "allowed", "10.83.0.0/24")
	denied := resourceTestNetwork(t, store, "denied", "10.84.0.0/24")
	allowedNode := resourceTestNode(t, store, allowed.ID, "allowed-node", protocol.CapabilitySubnetRouterV1)
	deniedNode := resourceTestNode(t, store, denied.ID, "denied-node", protocol.CapabilitySubnetRouterV1)
	allowedRoute, err := store.AdvertiseRoute(ctx, allowedNode.ID, netip.MustParsePrefix("192.0.2.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRoute(ctx, allowedRoute.ID); err != nil {
		t.Fatal(err)
	}
	deniedRoute, err := store.AdvertiseRoute(ctx, deniedNode.ID, netip.MustParsePrefix("198.51.100.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := administratorSessionSubject(t, store, "object-operator", adminauth.RoleOperator, false, allowed.ID)

	outOfScope := administratorDecisionForSubject(t, subject, administratorRouteApprovePolicy, adminauth.ObjectTarget(deniedRoute.ID))
	if _, err := store.AdministratorApproveRoute(ctx, outOfScope, deniedRoute.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope object error=%v want ErrNotFound", err)
	}
	missingID := identity.ID{0xff}
	missing := administratorDecisionForSubject(t, subject, administratorRouteApprovePolicy, adminauth.ObjectTarget(missingID))
	if _, err := store.AdministratorApproveRoute(ctx, missing, missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object error=%v want indistinguishable ErrNotFound", err)
	}
	wrongBinding := administratorDecisionForSubject(t, subject, administratorRouteApprovePolicy, adminauth.ObjectTarget(allowedRoute.ID))
	if _, err := store.AdministratorApproveRoute(ctx, wrongBinding, deniedRoute.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong object binding error=%v want ErrInvalid", err)
	}
	if _, err := store.AdministratorWithdrawRoute(ctx, wrongBinding, allowedRoute.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same-operation route-policy substitution error=%v want ErrInvalid", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM administrator_principal_networks WHERE principal_id=?`, idBytes(subject.ActorID())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorApproveRoute(ctx, wrongBinding, allowedRoute.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unauthorized approved-route no-op leaked conflict: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `INSERT INTO administrator_principal_networks
		(principal_id,network_id,created_at) VALUES(?,?,?)`, idBytes(subject.ActorID()), idBytes(allowed.ID), unix(store.now())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorApproveRoute(ctx, wrongBinding, allowedRoute.ID); !errors.Is(err, ErrAlreadyApproved) {
		t.Fatalf("authorized approved-route no-op error=%v want ErrAlreadyApproved", err)
	}
	sessionID, _ := subject.SessionID()
	if _, err := store.db.ExecContext(ctx, `UPDATE administrator_sessions SET revoked_at=?,revocation_reason='test revoke'
		WHERE id=?`, unix(store.now()), idBytes(sessionID)); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		decision adminauth.Decision
		objectID identity.ID
	}{
		"existing": {wrongBinding, allowedRoute.ID},
		"missing":  {missing, missingID},
	} {
		t.Run("revoked session "+name, func(t *testing.T) {
			if _, err := store.AdministratorApproveRoute(ctx, test.decision, test.objectID); !errors.Is(err, ErrSessionInvalid) {
				t.Fatalf("revoked-session %s error=%v want ErrSessionInvalid", name, err)
			}
		})
	}
}

func TestAdministratorAssignRouteRollsBackEverySideEffect(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "assign-network", "10.85.0.0/24")
	node := resourceTestNode(t, store, network.ID, "assign-node", 0)
	decision := administratorRootDecision(t, store, administratorRouteAssignPolicy, adminauth.NetworkTarget(network.ID))
	before, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_route_approval_audit
		BEFORE INSERT ON audit_events WHEN NEW.action='route.approve'
		BEGIN SELECT RAISE(ABORT, 'forced route approval audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	if _, _, _, err := store.AdministratorAssignRoute(ctx, decision, network.ID, node.ID, prefix, RouteModeNAT, 20); err == nil {
		t.Fatal("forced assignment failure unexpectedly succeeded")
	}
	var capabilities, activeRoutes, partialAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT enabled_capabilities FROM nodes WHERE id=?`, idBytes(node.ID)).Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM routes WHERE node_id=? AND prefix_address=? AND prefix_length=?
		AND state IN ('advertised','approved')`, idBytes(node.ID), prefix.Addr().AsSlice(), prefix.Bits()).Scan(&activeRoutes); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action IN ('node.capabilities.set','route.advertise','route.approve')`).Scan(&partialAudits); err != nil {
		t.Fatal(err)
	}
	afterFailure, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if capabilities != 0 || activeRoutes != 0 || partialAudits != 0 || afterFailure.ConfigurationEpoch != before.ConfigurationEpoch {
		t.Fatalf("partial assignment committed capabilities=%d routes=%d audits=%d epoch=%d want=%d",
			capabilities, activeRoutes, partialAudits, afterFailure.ConfigurationEpoch, before.ConfigurationEpoch)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER fail_route_approval_audit`); err != nil {
		t.Fatal(err)
	}
	route, epoch, created, err := store.AdministratorAssignRoute(ctx, decision, network.ID, node.ID, prefix, RouteModeNAT, 20)
	if err != nil || route.State != RouteStateApproved || epoch <= before.ConfigurationEpoch || !created {
		t.Fatalf("assignment route=%+v epoch=%d created=%t err=%v", route, epoch, created, err)
	}
	noOpRoute, noOpEpoch, noOpCreated, err := store.AdministratorAssignRoute(ctx, decision, network.ID, node.ID, prefix, RouteModeNAT, 20)
	if err != nil || noOpRoute.ID != route.ID || noOpEpoch != epoch || noOpCreated {
		t.Fatalf("idempotent assignment route=%+v epoch=%d created=%t err=%v", noOpRoute, noOpEpoch, noOpCreated, err)
	}
}

func TestAdministratorCertificateRevocationIsAtomic(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "certificate-network", "10.86.0.0/24")
	node := resourceTestNode(t, store, network.ID, "certificate-node", 0)
	certificate, err := store.AddCertificate(ctx, network.ID, node.ID, []byte{1}, []byte{1, 2, 3},
		store.now().Add(-time.Hour), store.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	decision := administratorRootDecision(t, store, administratorCertificateRevokePolicy, adminauth.NetworkTarget(network.ID))
	before, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER fail_certificate_revoke_audit
		BEFORE INSERT ON audit_events WHEN NEW.action='certificate.revoke'
		BEGIN SELECT RAISE(ABORT, 'forced certificate audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorRevokeCertificateBySerial(ctx, decision, network.ID, certificate.Serial, "test rollback"); err == nil {
		t.Fatal("forced certificate revocation failure unexpectedly succeeded")
	}
	var revoked any
	if err := store.db.QueryRowContext(ctx, `SELECT revoked_at FROM certificates WHERE id=?`, idBytes(certificate.ID)).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	afterFailure, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != nil || afterFailure.ConfigurationEpoch != before.ConfigurationEpoch {
		t.Fatalf("partial certificate revocation committed revoked=%v epoch=%d want=%d", revoked, afterFailure.ConfigurationEpoch, before.ConfigurationEpoch)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER fail_certificate_revoke_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdministratorRevokeCertificateBySerial(ctx, decision, network.ID, certificate.Serial, "credential compromised"); err != nil {
		t.Fatal(err)
	}
	events, err := store.AuditEvents(ctx, network.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == "certificate.revoke" && event.TargetID != nil && *event.TargetID == certificate.ID {
			found = event.Actor.Kind == adminauth.ActorServicePrincipal && event.Actor.ID != nil &&
				*event.Actor.ID == state.RootServicePrincipalID
		}
	}
	if !found {
		t.Fatal("authorized certificate revocation omitted stable root actor audit")
	}
}

func TestAdministratorResourceDecisionRejectsRoutePolicySubstitution(t *testing.T) {
	store, _ := openTestStore(t)
	network := resourceTestNetwork(t, store, "policy-network", "10.87.0.0/24")
	decision := administratorRootDecision(t, store, administratorNodeListPolicy, adminauth.NetworkTarget(network.ID))
	if _, _, err := store.AdministratorNetworkRelays(context.Background(), decision, network.ID, 10); !errors.Is(err, ErrInvalid) {
		t.Fatalf("node-list decision used for relay-list route: %v", err)
	}
	if strings.Contains(fmt.Sprint(decision), "policy-network") {
		t.Fatal("decision unexpectedly contains mutable display data")
	}
}

func TestAdministratorInventoryReturnsEpochWithoutLegacyNetworkRead(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "epoch-network", "10.88.0.0/24")

	relayDecision := administratorRootDecision(t, store, administratorRelayListPolicy, adminauth.NetworkTarget(network.ID))
	relays, relayEpoch, err := store.AdministratorNetworkRelays(ctx, relayDecision, network.ID, 10)
	if err != nil || len(relays) != 0 || relayEpoch != network.ConfigurationEpoch {
		t.Fatalf("relay inventory values=%+v epoch=%d err=%v", relays, relayEpoch, err)
	}
	aclDecision := administratorRootDecision(t, store, administratorACLListPolicy, adminauth.NetworkTarget(network.ID))
	rules, aclEpoch, err := store.AdministratorNetworkACLRules(ctx, aclDecision, network.ID, 10)
	if err != nil || len(rules) != 0 || aclEpoch != network.ConfigurationEpoch {
		t.Fatalf("ACL inventory values=%+v epoch=%d err=%v", rules, aclEpoch, err)
	}

	missingNetwork := identity.NetworkID{0xfe}
	for name, check := range map[string]func() error{
		"nodes": func() error {
			decision := administratorRootDecision(t, store, administratorNodeListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, err := store.AdministratorNetworkNodes(ctx, decision, missingNetwork, 10)
			return err
		},
		"endpoint statuses": func() error {
			decision := administratorRootDecision(t, store, administratorEndpointStatusListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, missingNetwork, 10, store.now())
			return err
		},
		"relays": func() error {
			decision := administratorRootDecision(t, store, administratorRelayListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, _, err := store.AdministratorNetworkRelays(ctx, decision, missingNetwork, 10)
			return err
		},
		"ACL rules": func() error {
			decision := administratorRootDecision(t, store, administratorACLListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, _, err := store.AdministratorNetworkACLRules(ctx, decision, missingNetwork, 10)
			return err
		},
		"certificates": func() error {
			decision := administratorRootDecision(t, store, administratorCertificateListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, err := store.AdministratorNetworkCertificates(ctx, decision, missingNetwork, 10)
			return err
		},
		"routes": func() error {
			decision := administratorRootDecision(t, store, administratorRouteListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, err := store.AdministratorNetworkRoutes(ctx, decision, missingNetwork, 10)
			return err
		},
		"audit": func() error {
			decision := administratorRootDecision(t, store, administratorAuditListPolicy, adminauth.NetworkTarget(missingNetwork))
			_, err := store.AdministratorAuditEvents(ctx, decision, missingNetwork, 10)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing network error=%v want ErrNotFound", err)
			}
		})
	}
}

func TestAdministratorCollectionAuthenticationPrecedesParentLookup(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	existing := resourceTestNetwork(t, store, "collection-auth-network", "10.93.0.0/24")
	missing := identity.NetworkID{0xfd}
	subject := administratorSessionSubject(t, store, "collection-auth-operator", adminauth.RoleOperator, false, existing.ID)
	sessionID, _ := subject.SessionID()
	if _, err := store.db.ExecContext(ctx, `UPDATE administrator_sessions SET revoked_at=?,revocation_reason='test revoke'
		WHERE id=?`, unix(store.now()), idBytes(sessionID)); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		policy adminauth.RoutePolicy
		read   func(adminauth.Decision, identity.NetworkID) error
	}{
		{"nodes", administratorNodeListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, err := store.AdministratorNetworkNodes(ctx, decision, networkID, 10)
			return err
		}},
		{"endpoint statuses", administratorEndpointStatusListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, networkID, 10, store.now())
			return err
		}},
		{"relays", administratorRelayListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, _, err := store.AdministratorNetworkRelays(ctx, decision, networkID, 10)
			return err
		}},
		{"ACL rules", administratorACLListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, _, err := store.AdministratorNetworkACLRules(ctx, decision, networkID, 10)
			return err
		}},
		{"certificates", administratorCertificateListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, err := store.AdministratorNetworkCertificates(ctx, decision, networkID, 10)
			return err
		}},
		{"routes", administratorRouteListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, err := store.AdministratorNetworkRoutes(ctx, decision, networkID, 10)
			return err
		}},
		{"audit", administratorAuditListPolicy, func(decision adminauth.Decision, networkID identity.NetworkID) error {
			_, err := store.AdministratorAuditEvents(ctx, decision, networkID, 10)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, networkID := range []identity.NetworkID{existing.ID, missing} {
				decision := administratorDecisionForSubject(t, subject, test.policy, adminauth.NetworkTarget(networkID))
				if err := test.read(decision, networkID); !errors.Is(err, ErrSessionInvalid) {
					t.Fatalf("network=%s error=%v want ErrSessionInvalid", networkID, err)
				}
			}
		})
	}
}

func TestAdministratorBootstrapAuditRevalidatesExactDecision(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	decision := administratorRootDecision(t, store, administratorBootstrapCreatePolicy, adminauth.GlobalTarget())
	if err := store.AdministratorAuditMutation(ctx, decision, "bootstrap_bundle.create", "bootstrap_bundle",
		`{"storage":"ephemeral"}`); err != nil {
		t.Fatal(err)
	}
	events, err := store.GlobalAuditEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "bootstrap_bundle.create" ||
		events[0].Actor.Kind != adminauth.ActorServicePrincipal || events[0].Actor.ID == nil ||
		*events[0].Actor.ID != state.RootServicePrincipalID {
		t.Fatalf("bootstrap audit=%+v", events)
	}

	wrongPolicy := administratorRootDecision(t, store, administratorNetworkCreatePolicy, adminauth.GlobalTarget())
	if err := store.AdministratorAuditMutation(ctx, wrongPolicy, "bootstrap_bundle.create", "bootstrap_bundle", `{}`); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong-policy bootstrap audit error=%v want ErrInvalid", err)
	}
	if err := store.AdministratorAuditMutation(ctx, decision, "other.create", "other", `{}`); !errors.Is(err, ErrInvalid) {
		t.Fatalf("arbitrary global audit error=%v want ErrInvalid", err)
	}
}

func TestAdministratorGlobalAuditEventsRevalidatesOwnerOrRoot(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "global-audit-network", "10.91.0.0/24")
	bootstrapDecision := administratorRootDecision(t, store, administratorBootstrapCreatePolicy, adminauth.GlobalTarget())
	if err := store.AdministratorAuditMutation(ctx, bootstrapDecision, "bootstrap_bundle.create", "bootstrap_bundle", `{}`); err != nil {
		t.Fatal(err)
	}

	rootDecision := administratorRootDecision(t, store, administratorGlobalAuditListPolicy, adminauth.GlobalTarget())
	events, err := store.AdministratorGlobalAuditEvents(ctx, rootDecision, 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawGlobal, sawNetwork bool
	for _, event := range events {
		sawGlobal = sawGlobal || event.NetworkScope == nil
		sawNetwork = sawNetwork || event.NetworkScope != nil && *event.NetworkScope == network.ID
	}
	if !sawGlobal || !sawNetwork {
		t.Fatalf("global audit omitted lifecycle scopes: global=%t network=%t", sawGlobal, sawNetwork)
	}

	ownerSubject := administratorSessionSubject(t, store, "global-audit-owner", adminauth.RoleOwner, true)
	ownerDecision := administratorDecisionForSubject(t, ownerSubject, administratorGlobalAuditListPolicy, adminauth.GlobalTarget())
	if _, err := store.AdministratorGlobalAuditEvents(ctx, ownerDecision, 10); err != nil {
		t.Fatalf("owner global audit: %v", err)
	}
	operatorSubject := administratorSessionSubject(t, store, "global-audit-operator", adminauth.RoleOperator, true)
	operatorDecision := administratorDecisionForSubject(t, operatorSubject, administratorGlobalAuditListPolicy, adminauth.GlobalTarget())
	if _, err := store.AdministratorGlobalAuditEvents(ctx, operatorDecision, 10); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("operator global audit error=%v want ErrPermissionDenied", err)
	}
	wrongPolicy := administratorRootDecision(t, store, administratorNetworkListPolicy, adminauth.FilteredTarget())
	if _, err := store.AdministratorGlobalAuditEvents(ctx, wrongPolicy, 10); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong-policy global audit error=%v want ErrInvalid", err)
	}
}

func requireAdministratorRootAudit(t *testing.T, store *Store, action string, targetID identity.ID) {
	t.Helper()
	state, err := store.AdministratorAuthState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var matches int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events
		WHERE action=? AND target_id=? AND actor_kind='service_principal' AND actor_id=?`,
		action, idBytes(targetID), idBytes(state.RootServicePrincipalID)).Scan(&matches); err != nil {
		t.Fatal(err)
	}
	if matches < 1 {
		t.Fatalf("missing stable-root audit action=%s target=%s", action, targetID)
	}
}

func TestAdministratorDurableMutationRoutesAuditStableRoot(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := resourceTestNetwork(t, store, "mutation-base", "10.89.0.0/24")

	createDecision := administratorRootDecision(t, store, administratorNetworkCreatePolicy, adminauth.GlobalTarget())
	createdNetwork, err := store.AdministratorCreateNetworkDualStack(ctx, createDecision, "mutation-created",
		netip.MustParsePrefix("10.90.0.0/24"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "network.create", identity.ID(createdNetwork.ID))

	enrollmentDecision := administratorRootDecision(t, store, administratorEnrollmentIssuePolicy, adminauth.NetworkTarget(base.ID))
	token, err := store.AdministratorIssueEnrollmentTokenWithOptions(ctx, enrollmentDecision, base.ID, "mutation-token",
		store.now().Add(time.Hour), EnrollmentTokenOptions{Class: EnrollmentClassDurable})
	if err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "enrollment_token.issue", token.ID)

	assignNode := resourceTestNode(t, store, base.ID, "mutation-assign-node", 0)
	assignDecision := administratorRootDecision(t, store, administratorRouteAssignPolicy, adminauth.NetworkTarget(base.ID))
	assigned, _, created, err := store.AdministratorAssignRoute(ctx, assignDecision, base.ID, assignNode.ID,
		netip.MustParsePrefix("203.0.113.0/24"), RouteModeNAT, 10)
	if err != nil || !created {
		t.Fatalf("assign route created=%t err=%v", created, err)
	}
	requireAdministratorRootAudit(t, store, "node.capabilities.set", identity.ID(assignNode.ID))
	requireAdministratorRootAudit(t, store, "route.advertise", assigned.ID)
	requireAdministratorRootAudit(t, store, "route.approve", assigned.ID)

	routeNode := resourceTestNode(t, store, base.ID, "mutation-route-node", protocol.CapabilitySubnetRouterV1)
	route, err := store.AdvertiseRoute(ctx, routeNode.ID, netip.MustParsePrefix("198.51.100.0/24"),
		RouteKindSubnet, RouteModeRouted, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	approveDecision := administratorRootDecision(t, store, administratorRouteApprovePolicy, adminauth.ObjectTarget(route.ID))
	if _, err := store.AdministratorApproveRoute(ctx, approveDecision, route.ID); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "route.approve", route.ID)
	withdrawDecision := administratorRootDecision(t, store, administratorRouteWithdrawPolicy, adminauth.ObjectTarget(route.ID))
	if _, err := store.AdministratorWithdrawRoute(ctx, withdrawDecision, route.ID); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "route.withdraw", route.ID)

	aclCreateDecision := administratorRootDecision(t, store, administratorACLCreatePolicy, adminauth.NetworkTarget(base.ID))
	rule, _, err := store.AdministratorAddACLRule(ctx, aclCreateDecision, base.ID, 100, ACLActionAccept, `{}`, "mutation rule")
	if err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "acl_rule.create", rule.ID)
	aclUpdateDecision := administratorRootDecision(t, store, administratorACLUpdatePolicy, adminauth.ObjectTarget(rule.ID))
	if _, _, err := store.AdministratorUpdateACLRule(ctx, aclUpdateDecision, rule.ID, 110, ACLActionDeny, `{}`, "updated rule", false); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "acl_rule.update", rule.ID)
	aclDeleteDecision := administratorRootDecision(t, store, administratorACLDeletePolicy, adminauth.ObjectTarget(rule.ID))
	if _, err := store.AdministratorDeleteACLRule(ctx, aclDeleteDecision, rule.ID); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "acl_rule.delete", rule.ID)

	capabilityNode := resourceTestNode(t, store, base.ID, "mutation-capability-node", 0)
	capabilityDecision := administratorRootDecision(t, store, administratorNodeCapabilitiesPolicy,
		adminauth.ObjectTarget(identity.ID(capabilityNode.ID)))
	if _, err := store.AdministratorSetNodeCapabilities(ctx, capabilityDecision, capabilityNode.ID,
		protocol.CapabilityExitNodeV1); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "node.capabilities.set", identity.ID(capabilityNode.ID))

	revokedNode := resourceTestNode(t, store, base.ID, "mutation-revoked-node", 0)
	revokeNodeDecision := administratorRootDecision(t, store, administratorNodeRevokePolicy,
		adminauth.ObjectTarget(identity.ID(revokedNode.ID)))
	if _, err := store.AdministratorRevokeNode(ctx, revokeNodeDecision, revokedNode.ID, "mutation test"); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "node.revoke", identity.ID(revokedNode.ID))

	certificateNode := resourceTestNode(t, store, base.ID, "mutation-certificate-node", 0)
	certificate, err := store.AddCertificate(ctx, base.ID, certificateNode.ID, []byte{2}, []byte{1, 2, 3},
		store.now().Add(-time.Hour), store.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	revokeCertificateDecision := administratorRootDecision(t, store, administratorCertificateRevokePolicy,
		adminauth.NetworkTarget(base.ID))
	if _, err := store.AdministratorRevokeCertificateBySerial(ctx, revokeCertificateDecision, base.ID,
		certificate.Serial, "mutation test"); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "certificate.revoke", certificate.ID)

	serviceID := identity.ID{9}
	relayCreateDecision := administratorRootDecision(t, store, administratorRelayCreatePolicy, adminauth.NetworkTarget(base.ID))
	relay, _, err := store.AdministratorRegisterRelay(ctx, relayCreateDecision, base.ID, serviceID, nil,
		"mutation-relay", "relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "relay.register", relay.ID)
	relayUpdateDecision := administratorRootDecision(t, store, administratorRelayUpdatePolicy, adminauth.ObjectTarget(relay.ID))
	if _, _, err := store.AdministratorUpdateRelay(ctx, relayUpdateDecision, relay.ID,
		"mutation-relay-updated", "relay.example:444", true); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "relay.update", relay.ID)
	relayDisableDecision := administratorRootDecision(t, store, administratorRelayDisablePolicy, adminauth.ObjectTarget(relay.ID))
	if _, err := store.AdministratorDisableRelay(ctx, relayDisableDecision, relay.ID); err != nil {
		t.Fatal(err)
	}
	requireAdministratorRootAudit(t, store, "relay.disable", relay.ID)
}

func TestAdministratorSessionMutationAuditsCurrentPrincipal(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "session-mutation-network", "10.92.0.0/24")
	subject := administratorSessionSubject(t, store, "session-mutation-operator", adminauth.RoleOperator, false, network.ID)
	decision := administratorDecisionForSubject(t, subject, administratorACLCreatePolicy, adminauth.NetworkTarget(network.ID))
	rule, _, err := store.AdministratorAddACLRule(ctx, decision, network.ID, 100, ACLActionAccept, `{}`, "session mutation")
	if err != nil {
		t.Fatal(err)
	}
	var actorKind string
	var actorRaw []byte
	if err := store.db.QueryRowContext(ctx, `SELECT actor_kind,actor_id FROM audit_events
		WHERE action='acl_rule.create' AND target_id=?`, idBytes(rule.ID)).Scan(&actorKind, &actorRaw); err != nil {
		t.Fatal(err)
	}
	actorID, err := scanID(actorRaw)
	if err != nil {
		t.Fatal(err)
	}
	if actorKind != string(adminauth.ActorAdministrator) || actorID != subject.ActorID() {
		t.Fatalf("session audit actor kind=%s id=%s", actorKind, actorID)
	}
}
