package adminauth

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
)

func TestPermissionMatrixAndNetworkScope(t *testing.T) {
	principalID := identity.ID{1}
	networkOne, networkTwo := identity.NetworkID{2}, identity.NetworkID{3}
	tests := []struct {
		name      string
		principal Principal
		operation Operation
		network   *identity.NetworkID
		want      bool
	}{
		{"owner global mutation", Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}, OperationNetworkCreate, nil, true},
		{"operator global mutation", Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true}, OperationNetworkCreate, nil, false},
		{"owner bootstrap bundle", Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}, OperationBootstrapCreate, nil, true},
		{"operator bootstrap bundle", Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true, AllNetworks: true}, OperationBootstrapCreate, nil, false},
		{"operator scoped mutation", Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true, NetworkIDs: []identity.NetworkID{networkOne}}, OperationACLManage, &networkOne, true},
		{"operator wrong network", Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true, NetworkIDs: []identity.NetworkID{networkOne}}, OperationACLManage, &networkTwo, false},
		{"auditor scoped read", Principal{ID: principalID, Username: "auditor", Role: RoleAuditor, Enabled: true, NetworkIDs: []identity.NetworkID{networkOne}}, OperationAuditRead, &networkOne, true},
		{"auditor mutation", Principal{ID: principalID, Username: "auditor", Role: RoleAuditor, Enabled: true, AllNetworks: true}, OperationACLManage, &networkOne, false},
		{"all-network operator", Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true, AllNetworks: true}, OperationRouteManage, &networkTwo, true},
		{"disabled", Principal{ID: principalID, Username: "owner", Role: RoleOwner, AllNetworks: true}, OperationNetworkCreate, nil, false},
		{"scope omitted", Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}, OperationRouteRead, nil, false},
		{"scope on global operation", Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}, OperationNetworkList, &networkOne, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Authorize(test.principal, test.operation, test.network); got != test.want {
				t.Fatalf("Authorize()=%t want %t", got, test.want)
			}
		})
	}
}

func TestPermissionMatrixIsExhaustive(t *testing.T) {
	principalID := identity.ID{1}
	networkID := identity.NetworkID{2}
	type expectation struct {
		operation Operation
		owner     bool
		operator  bool
		auditor   bool
	}
	expectations := []expectation{
		{OperationNetworkList, true, true, true},
		{OperationNetworkRead, true, true, true},
		{OperationNetworkCreate, true, false, false},
		{OperationEnrollmentIssue, true, true, false},
		{OperationBootstrapCreate, true, false, false},
		{OperationNodeRead, true, true, true},
		{OperationNodeManage, true, true, false},
		{OperationRouteRead, true, true, true},
		{OperationRouteManage, true, true, false},
		{OperationACLRead, true, true, true},
		{OperationACLManage, true, true, false},
		{OperationRelayRead, true, true, true},
		{OperationRelayManage, true, true, false},
		{OperationCertificateRead, true, true, true},
		{OperationCertificateManage, true, true, false},
		{OperationAuditRead, true, true, true},
		{OperationAuditReadGlobal, true, false, false},
		{OperationPrincipalManage, true, false, false},
		{OperationSessionManage, true, false, false},
		{OperationRecoveryManage, false, false, false},
		{OperationRootTokenRotate, false, false, false},
	}
	if len(expectations) != len(operationPolicies) {
		t.Fatalf("permission expectations=%d policies=%d", len(expectations), len(operationPolicies))
	}
	for _, expectation := range expectations {
		for _, role := range []struct {
			name string
			role Role
			want bool
		}{
			{"owner", RoleOwner, expectation.owner},
			{"operator", RoleOperator, expectation.operator},
			{"auditor", RoleAuditor, expectation.auditor},
		} {
			scope := (*identity.NetworkID)(nil)
			principal := Principal{ID: principalID, Username: role.name, Role: role.role, Enabled: true, AllNetworks: true}
			if expectation.operation.NetworkScoped() {
				scope = &networkID
			}
			if got := Authorize(principal, expectation.operation, scope); got != role.want {
				t.Errorf("%s %s=%t want %t", role.name, expectation.operation, got, role.want)
			}
			if got := RoleAllows(role.role, expectation.operation); got != role.want {
				t.Errorf("RoleAllows(%s, %s)=%t want %t", role.role, expectation.operation, got, role.want)
			}
			if expectation.operation.NetworkScoped() && Authorize(principal, expectation.operation, nil) {
				t.Errorf("%s %s accepted a missing scope", role.name, expectation.operation)
			}
			if !expectation.operation.NetworkScoped() && Authorize(principal, expectation.operation, &networkID) {
				t.Errorf("%s %s accepted an unexpected scope", role.name, expectation.operation)
			}
		}
	}
	if RoleAllows(Role("unknown"), OperationNetworkRead) {
		t.Fatal("unknown role was allowed")
	}
	if RoleAllows(RoleOwner, Operation("unknown")) {
		t.Fatal("unknown operation was allowed")
	}
}

func TestPermissionsAreDeterministicExhaustiveAndDefensive(t *testing.T) {
	for _, role := range []Role{RoleOwner, RoleOperator, RoleAuditor} {
		first := Permissions(role)
		second := Permissions(role)
		if len(first) == 0 || len(first) != len(second) {
			t.Fatalf("Permissions(%s) lengths=%d,%d", role, len(first), len(second))
		}
		for index, operation := range first {
			if operation != second[index] || !RoleAllows(role, operation) {
				t.Fatalf("Permissions(%s)[%d]=%q", role, index, operation)
			}
		}
		first[0] = "changed"
		if Permissions(role)[0] == "changed" {
			t.Fatalf("Permissions(%s) exposed mutable storage", role)
		}
	}
	if got := Permissions(Role("unknown")); len(got) != 0 {
		t.Fatalf("unknown role permissions=%v", got)
	}
	if len(permissionOrder) != len(operationPolicies) {
		t.Fatalf("permission order=%d policies=%d", len(permissionOrder), len(operationPolicies))
	}
	seen := make(map[Operation]struct{}, len(permissionOrder))
	for _, operation := range permissionOrder {
		if !operation.Valid() {
			t.Errorf("invalid ordered permission %q", operation)
		}
		if _, exists := seen[operation]; exists {
			t.Errorf("duplicate ordered permission %q", operation)
		}
		seen[operation] = struct{}{}
	}
}

func TestVisibleNetworkIDs(t *testing.T) {
	principalID := identity.ID{1}
	networkOne, networkTwo, networkThree := identity.NetworkID{2}, identity.NetworkID{3}, identity.NetworkID{4}
	available := []identity.NetworkID{networkOne, {}, networkTwo, networkThree}
	operator := Principal{ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true, NetworkIDs: []identity.NetworkID{networkTwo}}
	got := VisibleNetworkIDs(operator, available)
	if len(got) != 1 || got[0] != networkTwo {
		t.Fatalf("scoped visible networks=%v", got)
	}
	got[0] = networkOne
	if operator.NetworkIDs[0] != networkTwo || available[2] != networkTwo {
		t.Fatal("visible-network result aliases caller state")
	}
	owner := Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}
	got = VisibleNetworkIDs(owner, available)
	if len(got) != 3 {
		t.Fatalf("owner visible networks=%v", got)
	}
	if got := VisibleNetworkIDs(Principal{ID: principalID, Username: "auditor", Role: RoleAuditor}, available); got != nil {
		t.Fatalf("disabled principal visible networks=%v", got)
	}
}

func TestManagementRoutesAreCompleteAndUnique(t *testing.T) {
	routes := ManagementRoutes()
	if len(routes) != 52 {
		t.Fatalf("management routes=%d want 52", len(routes))
	}
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if !route.Valid() {
			t.Errorf("invalid route policy: %+v", route)
		}
		key := fmt.Sprintf("%s %s", route.Method, route.Pattern)
		if _, exists := seen[key]; exists {
			t.Errorf("duplicate route policy %s", key)
		}
		seen[key] = struct{}{}
	}
	routes[0].Pattern = "changed"
	if ManagementRoutes()[0].Pattern == "changed" {
		t.Fatal("route policy registry was mutable")
	}
	invalid := ManagementRoutes()[0]
	invalid.Mutation = false
	if invalid.Valid() {
		t.Fatal("unsafe route accepted as non-mutating")
	}
	invalid.Method = "TRACE"
	invalid.Mutation = true
	if invalid.Valid() {
		t.Fatal("unsupported management method accepted")
	}
	for _, route := range ManagementRoutes() {
		if !route.Mutation {
			invalid = route
			break
		}
	}
	if invalid.Mutation {
		t.Fatal("management route registry has no safe route")
	}
	invalid.Mutation = true
	if invalid.Valid() {
		t.Fatal("safe route accepted as mutating")
	}
}

func TestSessionPolicyAndExpiry(t *testing.T) {
	policy := DefaultSessionPolicy()
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	created := time.Unix(1_800_000_000, 0).UTC()
	idle, absolute, err := SessionDeadlines(created, created.Add(7*time.Hour+45*time.Minute), policy)
	if err != nil {
		t.Fatal(err)
	}
	if idle != absolute || absolute != created.Add(8*time.Hour) {
		t.Fatalf("deadlines idle=%s absolute=%s", idle, absolute)
	}
	if err := (SessionPolicy{IdleLifetime: 0, AbsoluteLifetime: time.Hour, MaximumSessions: 1}).Validate(); err == nil {
		t.Fatal("invalid idle lifetime accepted")
	}
	principal := Principal{ID: identity.ID{1}, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}
	session := Session{
		ID: "session", Principal: principal, CSRFToken: "csrf", CreatedAt: created, LastSeenAt: created,
		IdleExpiresAt: created.Add(time.Minute), AbsoluteExpiresAt: created.Add(time.Hour),
	}
	if err := session.Validate(created); err != nil {
		t.Fatalf("session at creation: %v", err)
	}
	if err := session.Validate(created.Add(time.Minute)); err == nil {
		t.Fatal("session accepted at exact idle expiry")
	}
	if err := session.Validate(created.Add(-time.Second)); err == nil {
		t.Fatal("session accepted before creation")
	}
}

func TestOperationsAreExhaustivelyClassified(t *testing.T) {
	operations := []Operation{
		OperationNetworkList, OperationNetworkRead, OperationNetworkCreate, OperationEnrollmentIssue,
		OperationBootstrapCreate, OperationNodeRead, OperationNodeManage, OperationRouteRead,
		OperationRouteManage, OperationACLRead, OperationACLManage, OperationRelayRead,
		OperationRelayManage, OperationCertificateRead, OperationCertificateManage, OperationAuditRead,
		OperationAuditReadGlobal, OperationPrincipalManage, OperationSessionManage, OperationRecoveryManage,
		OperationRootTokenRotate,
	}
	if len(operations) != len(operationPolicies) {
		t.Fatalf("declared operations=%d policies=%d", len(operations), len(operationPolicies))
	}
	for _, operation := range operations {
		if !operation.Valid() {
			t.Errorf("operation %q has no policy", operation)
		}
	}
	if Operation("unknown").Valid() || Operation("unknown").NetworkScoped() {
		t.Fatal("unknown operation classified")
	}
}

func TestPasswordHashAndSecretValidation(t *testing.T) {
	password := []byte("a correct horse battery staple")
	hash, err := HashPassword(password, bytes.NewReader(bytes.Repeat([]byte{7}, passwordSaltSize)))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(hash, password); err != nil || !ok {
		t.Fatalf("correct password ok=%t err=%v", ok, err)
	}
	if err := ValidatePasswordHash(hash); err != nil {
		t.Fatalf("valid password hash rejected: %v", err)
	}
	if ok, err := VerifyPassword(hash, []byte("a different long password")); err != nil || ok {
		t.Fatalf("wrong password ok=%t err=%v", ok, err)
	}
	if _, err := VerifyPassword("$argon2id$v=19$m=4294967295,t=3,p=1$bad$bad", password); err == nil {
		t.Fatal("hostile hash parameters accepted")
	}
	if err := ValidatePasswordHash("$argon2id$v=19$m=4294967295,t=3,p=1$bad$bad"); err == nil {
		t.Fatal("hostile hash passed validation")
	}
	if err := ValidatePassword([]byte("too-short-pass")); err == nil {
		t.Fatal("short password accepted")
	}

	secret, digest, err := NewSecret(SecretSession, bytes.NewReader(bytes.Repeat([]byte{9}, secretBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if !SecretMatches(SecretSession, digest, secret) || SecretMatches(SecretSession, digest, secret+"x") || SecretMatches(SecretCSRF, digest, secret) {
		t.Fatal("secret comparison failed")
	}
	if _, _, err := NewSecret("unknown", nil); err == nil {
		t.Fatal("unknown secret purpose accepted")
	}
}

func TestActorValidation(t *testing.T) {
	id := identity.ID{1}
	if !SystemActor().Valid() || !IDActor(ActorAdministrator, id).Valid() {
		t.Fatal("valid actors rejected")
	}
	if (Actor{Kind: ActorAdministrator}).Valid() || (Actor{Kind: ActorSystem, ID: &id}).Valid() || (Actor{Kind: "other"}).Valid() {
		t.Fatal("invalid actor accepted")
	}
}

func TestUsernameValidation(t *testing.T) {
	for _, valid := range []string{"owner", "ops.team", "audit_reader", "admin-2"} {
		if !ValidateUsername(valid) {
			t.Errorf("valid username rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "a", "ab", "-owner", ".owner", "owner.", "owner-", "Owner", "owner name", "owner@example", " opérateur", string(bytes.Repeat([]byte{'a'}, MaxUsernameLength+1))} {
		if ValidateUsername(invalid) {
			t.Errorf("invalid username accepted: %q", invalid)
		}
	}
}

func TestPrincipalValidation(t *testing.T) {
	id := identity.ID{1}
	networkID := identity.NetworkID{2}
	if !(Principal{ID: id, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}).Valid() {
		t.Fatal("valid owner rejected")
	}
	for _, principal := range []Principal{
		{},
		{ID: id, Username: "Owner", Role: RoleOwner, AllNetworks: true},
		{ID: id, Username: "owner", Role: RoleOwner},
		{ID: id, Username: "operator", Role: RoleOperator, AllNetworks: true, NetworkIDs: []identity.NetworkID{networkID}},
		{ID: id, Username: "operator", Role: RoleOperator, NetworkIDs: []identity.NetworkID{{}}},
		{ID: id, Username: "operator", Role: RoleOperator, NetworkIDs: []identity.NetworkID{networkID, networkID}},
	} {
		if principal.Valid() {
			t.Fatalf("invalid principal accepted: %+v", principal)
		}
	}
}
