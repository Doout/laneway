package adminauth

import (
	"fmt"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func TestSubjectConstructionAndDefensiveValues(t *testing.T) {
	servicePrincipalID := identity.ID{1}
	root := RootSubject(servicePrincipalID)
	servicePrincipalID[0] = 9
	if !root.Valid() || root.Kind() != SubjectRootServicePrincipal || root.ActorID() != (identity.ID{1}) {
		t.Fatalf("invalid root subject: %+v", root)
	}
	if _, ok := root.SessionID(); ok {
		t.Fatal("root subject exposed a session ID")
	}
	rootActor := root.Actor()
	if !rootActor.Valid() || rootActor.Kind != ActorServicePrincipal || rootActor.ID == nil || *rootActor.ID != root.ActorID() {
		t.Fatalf("invalid root actor: %+v", rootActor)
	}
	rootActor.ID[0] = 8
	if root.ActorID() != (identity.ID{1}) || root.Actor().ID == nil || *root.Actor().ID != (identity.ID{1}) {
		t.Fatal("root actor aliases subject state")
	}

	principalID, sessionID := identity.ID{2}, identity.ID{3}
	session := SessionSubject(principalID, sessionID)
	principalID[0], sessionID[0] = 8, 9
	if !session.Valid() || session.Kind() != SubjectAdministratorSession || session.ActorID() != (identity.ID{2}) {
		t.Fatalf("invalid session subject: %+v", session)
	}
	gotSessionID, ok := session.SessionID()
	if !ok || gotSessionID != (identity.ID{3}) {
		t.Fatalf("session ID=(%v, %t)", gotSessionID, ok)
	}
	gotSessionID[0] = 7
	if stableSessionID, ok := session.SessionID(); !ok || stableSessionID != (identity.ID{3}) {
		t.Fatal("session ID accessor aliases subject state")
	}
	sessionActor := session.Actor()
	if !sessionActor.Valid() || sessionActor.Kind != ActorAdministrator || sessionActor.ID == nil || *sessionActor.ID != session.ActorID() {
		t.Fatalf("invalid administrator actor: %+v", sessionActor)
	}
	sessionActor.ID[0] = 6
	if session.ActorID() != (identity.ID{2}) {
		t.Fatal("administrator actor aliases subject state")
	}

	if !SubjectRootServicePrincipal.Valid() || !SubjectAdministratorSession.Valid() || SubjectKind("unknown").Valid() {
		t.Fatal("subject kinds were not classified exhaustively")
	}
	invalid := []Subject{
		{},
		RootSubject(identity.ID{}),
		SessionSubject(identity.ID{}, identity.ID{3}),
		SessionSubject(identity.ID{2}, identity.ID{}),
		{kind: SubjectRootServicePrincipal, actorID: identity.ID{1}, sessionID: identity.ID{3}},
		{kind: SubjectKind("unknown"), actorID: identity.ID{1}},
	}
	for index, subject := range invalid {
		if subject.Valid() {
			t.Errorf("invalid subject %d accepted: %+v", index, subject)
		}
		if actor := subject.Actor(); actor != (Actor{}) || actor.Valid() {
			t.Errorf("invalid subject %d produced actor %+v", index, actor)
		}
		if _, ok := subject.SessionID(); ok {
			t.Errorf("invalid subject %d exposed a session ID", index)
		}
	}
}

func TestDecisionTargetConstructionAndDefensiveValues(t *testing.T) {
	networkID, objectID := identity.NetworkID{4}, identity.ID{5}
	tests := []struct {
		name      string
		target    DecisionTarget
		kind      DecisionTargetKind
		networkID identity.NetworkID
		objectID  identity.ID
	}{
		{"global", GlobalTarget(), DecisionTargetGlobal, identity.NetworkID{}, identity.ID{}},
		{"filtered", FilteredTarget(), DecisionTargetFiltered, identity.NetworkID{}, identity.ID{}},
		{"network", NetworkTarget(networkID), DecisionTargetNetwork, networkID, identity.ID{}},
		{"object", ObjectTarget(objectID), DecisionTargetObject, identity.NetworkID{}, objectID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.target.Valid() || test.target.Kind() != test.kind {
				t.Fatalf("invalid target: %+v", test.target)
			}
			gotNetworkID, hasNetwork := test.target.NetworkID()
			if hasNetwork != !test.networkID.IsZero() || gotNetworkID != test.networkID {
				t.Errorf("NetworkID()=(%v, %t) want (%v, %t)", gotNetworkID, hasNetwork, test.networkID, !test.networkID.IsZero())
			}
			gotObjectID, hasObject := test.target.ObjectID()
			if hasObject != !test.objectID.IsZero() || gotObjectID != test.objectID {
				t.Errorf("ObjectID()=(%v, %t) want (%v, %t)", gotObjectID, hasObject, test.objectID, !test.objectID.IsZero())
			}
			gotNetworkID[0], gotObjectID[0] = 8, 9
			if stableNetworkID, _ := test.target.NetworkID(); stableNetworkID != test.networkID {
				t.Error("network target accessor aliases target state")
			}
			if stableObjectID, _ := test.target.ObjectID(); stableObjectID != test.objectID {
				t.Error("object target accessor aliases target state")
			}
		})
	}
	networkID[0], objectID[0] = 8, 9
	if got, _ := tests[2].target.NetworkID(); got != (identity.NetworkID{4}) {
		t.Fatal("network target aliases constructor input")
	}
	if got, _ := tests[3].target.ObjectID(); got != (identity.ID{5}) {
		t.Fatal("object target aliases constructor input")
	}

	if !DecisionTargetGlobal.Valid() || !DecisionTargetFiltered.Valid() || !DecisionTargetNetwork.Valid() ||
		!DecisionTargetObject.Valid() || DecisionTargetKind("unknown").Valid() {
		t.Fatal("decision target kinds were not classified exhaustively")
	}
	invalid := []DecisionTarget{
		{},
		NetworkTarget(identity.NetworkID{}),
		ObjectTarget(identity.ID{}),
		{kind: DecisionTargetGlobal, networkID: identity.NetworkID{1}},
		{kind: DecisionTargetFiltered, objectID: identity.ID{1}},
		{kind: DecisionTargetNetwork, networkID: identity.NetworkID{1}, objectID: identity.ID{2}},
		{kind: DecisionTargetObject, networkID: identity.NetworkID{1}, objectID: identity.ID{2}},
		{kind: DecisionTargetKind("unknown")},
	}
	for index, target := range invalid {
		if target.Valid() {
			t.Errorf("invalid target %d accepted: %+v", index, target)
		}
		if _, ok := target.NetworkID(); ok {
			t.Errorf("invalid target %d exposed a network ID", index)
		}
		if _, ok := target.ObjectID(); ok {
			t.Errorf("invalid target %d exposed an object ID", index)
		}
	}
}

func TestDecisionBindsEveryRouteToItsExactTargetKind(t *testing.T) {
	subject := SessionSubject(identity.ID{1}, identity.ID{2})
	networkID, objectID := identity.NetworkID{3}, identity.ID{4}
	targets := []DecisionTarget{
		GlobalTarget(),
		FilteredTarget(),
		NetworkTarget(networkID),
		ObjectTarget(objectID),
	}
	routes := ManagementRoutes()
	if len(routes) != 43 {
		t.Fatalf("management routes=%d want 43", len(routes))
	}
	for _, policy := range routes {
		policy := policy
		t.Run(fmt.Sprintf("%s %s", policy.Method, policy.Pattern), func(t *testing.T) {
			correctTarget := targetForPolicy(t, policy, networkID, objectID)
			decision, err := NewDecision(subject, policy, correctTarget)
			if err != nil {
				t.Fatalf("NewDecision(): %v", err)
			}
			if !decision.Valid() || decision.Subject() != subject || decision.Policy() != policy ||
				decision.Operation() != policy.Operation || decision.Target() != correctTarget {
				t.Fatalf("invalid decision: %+v", decision)
			}
			for _, candidate := range targets {
				want := candidate.Kind() == correctTarget.Kind()
				candidateDecision, candidateErr := NewDecision(subject, policy, candidate)
				if (candidateErr == nil) != want {
					t.Errorf("target kind %s accepted=%t want %t", candidate.Kind(), candidateErr == nil, want)
				}
				if got := decision.Matches(subject, policy, candidate); got != want {
					t.Errorf("Matches(target kind %s)=%t want %t", candidate.Kind(), got, want)
				}
				if candidateErr == nil && !candidateDecision.Valid() {
					t.Errorf("accepted target kind %s produced invalid decision", candidate.Kind())
				}
			}
		})
	}
}

func TestDecisionUsesExactRouteSubjectAndTargetValues(t *testing.T) {
	approve := managementPolicyForTest(t, "POST", "/v1/admin/routes/{route_id}/approve")
	withdraw := managementPolicyForTest(t, "POST", "/v1/admin/routes/{route_id}/withdraw")
	if approve.Operation != withdraw.Operation || approve.ScopeSource != ScopeObject || withdraw.ScopeSource != ScopeObject {
		t.Fatal("test route assumptions no longer hold")
	}
	principalID, sessionID, objectID := identity.ID{1}, identity.ID{2}, identity.ID{3}
	subject := SessionSubject(principalID, sessionID)
	target := ObjectTarget(objectID)
	decision, err := NewDecision(subject, approve, target)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Matches(subject, approve, target) {
		t.Fatal("decision did not match its inputs")
	}
	if decision.Matches(subject, withdraw, target) {
		t.Fatal("decision matched a different route with the same operation")
	}
	if decision.Matches(SessionSubject(principalID, identity.ID{9}), approve, target) {
		t.Fatal("decision matched a different session")
	}
	if decision.Matches(subject, approve, ObjectTarget(identity.ID{9})) {
		t.Fatal("decision matched a different object")
	}

	principalID[0], sessionID[0], objectID[0] = 7, 8, 9
	stablePolicy := approve
	approve.Pattern = "/changed"
	subjectCopy := decision.Subject()
	subjectCopy.actorID[0], subjectCopy.sessionID[0] = 7, 8
	policyCopy := decision.Policy()
	policyCopy.Pattern = "/also-changed"
	targetCopy := decision.Target()
	targetCopy.objectID[0] = 9
	actorCopy := decision.Subject().Actor()
	actorCopy.ID[0] = 6
	stableSubject := SessionSubject(identity.ID{1}, identity.ID{2})
	stableTarget := ObjectTarget(identity.ID{3})
	if !decision.Matches(stableSubject, stablePolicy, stableTarget) {
		t.Fatal("decision aliases constructor input or accessor state")
	}

	invalidPolicy := stablePolicy
	invalidPolicy.Pattern = ""
	for index, test := range []struct {
		subject Subject
		policy  RoutePolicy
		target  DecisionTarget
	}{
		{Subject{}, stablePolicy, stableTarget},
		{stableSubject, invalidPolicy, stableTarget},
		{stableSubject, stablePolicy, DecisionTarget{}},
		{stableSubject, stablePolicy, NetworkTarget(identity.NetworkID{3})},
	} {
		if got, err := NewDecision(test.subject, test.policy, test.target); err == nil || got != (Decision{}) {
			t.Errorf("invalid decision input %d returned (%+v, %v)", index, got, err)
		}
	}
	if (Decision{}).Valid() || (Decision{}).Matches(stableSubject, stablePolicy, stableTarget) {
		t.Fatal("zero decision was valid")
	}
}

func TestDecisionBindsGlobalObjectManagementPolicies(t *testing.T) {
	subject := SessionSubject(identity.ID{1}, identity.ID{2})
	objectID := identity.ID{3}
	owner := Principal{ID: identity.ID{1}, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}
	operator := Principal{ID: identity.ID{1}, Username: "operator", Role: RoleOperator, Enabled: true}
	for _, operation := range []Operation{
		OperationPrincipalManage, OperationSessionManage, OperationRecoveryManage, OperationRootTokenRotate,
	} {
		policy := RoutePolicy{
			Method: "DELETE", Pattern: "/v1/auth/objects/{object_id}", Operation: operation,
			ScopeSource: ScopeObject, Mutation: true,
		}
		if !policy.Valid() {
			t.Errorf("global object policy for %s was invalid", operation)
			continue
		}
		decision, err := NewDecision(subject, policy, ObjectTarget(objectID))
		if err != nil || !decision.Valid() {
			t.Errorf("global object decision for %s=(%+v, %v)", operation, decision, err)
		}
		for _, candidate := range []DecisionTarget{
			GlobalTarget(), FilteredTarget(), NetworkTarget(identity.NetworkID{3}), ObjectTarget(objectID),
		} {
			_, err := NewDecision(subject, policy, candidate)
			want := candidate.Kind() == DecisionTargetObject
			if (err == nil) != want {
				t.Errorf("global object policy for %s accepted target %s=%t want %t", operation, candidate.Kind(), err == nil, want)
			}
		}
		wantOwner := operation != OperationRecoveryManage && operation != OperationRootTokenRotate
		if got := AuthorizeEarly(subject, &owner, policy, ObjectTarget(objectID)); got != wantOwner {
			t.Errorf("owner global object operation %s=%t want %t", operation, got, wantOwner)
		}
		if AuthorizeEarly(subject, &operator, policy, ObjectTarget(objectID)) {
			t.Errorf("operator was allowed global object operation %s", operation)
		}
	}
	for _, operation := range []Operation{
		OperationNetworkList, OperationNetworkCreate, OperationBootstrapCreate,
	} {
		policy := RoutePolicy{
			Method: "DELETE", Pattern: "/v1/auth/objects/{object_id}", Operation: operation,
			ScopeSource: ScopeObject, Mutation: true,
		}
		if policy.Valid() {
			t.Errorf("non-object global operation %s accepted object scope", operation)
		}
	}
}

func TestAuthorizeEarlyAcrossEveryManagementRouteAndRole(t *testing.T) {
	principalID, sessionID := identity.ID{1}, identity.ID{2}
	networkID, objectID := identity.NetworkID{3}, identity.ID{4}
	subject := SessionSubject(principalID, sessionID)
	root := RootSubject(identity.ID{5})
	for _, policy := range ManagementRoutes() {
		policy := policy
		t.Run(fmt.Sprintf("%s %s", policy.Method, policy.Pattern), func(t *testing.T) {
			target := targetForPolicy(t, policy, networkID, objectID)
			if !AuthorizeEarly(root, nil, policy, target) {
				t.Error("root service principal was denied")
			}
			for _, test := range []struct {
				role Role
				want bool
			}{
				{RoleOwner, expectedRoleAllows(RoleOwner, policy.Operation)},
				{RoleOperator, expectedRoleAllows(RoleOperator, policy.Operation)},
				{RoleAuditor, expectedRoleAllows(RoleAuditor, policy.Operation)},
			} {
				principal := Principal{
					ID:         principalID,
					Username:   string(test.role),
					Role:       test.role,
					Enabled:    true,
					NetworkIDs: []identity.NetworkID{networkID},
				}
				if test.role == RoleOwner {
					principal.AllNetworks = true
					principal.NetworkIDs = nil
				}
				if got := AuthorizeEarly(subject, &principal, policy, target); got != test.want {
					t.Errorf("AuthorizeEarly(%s)=%t want %t", test.role, got, test.want)
				}
			}

			for _, candidate := range []DecisionTarget{
				GlobalTarget(), FilteredTarget(), NetworkTarget(networkID), ObjectTarget(objectID),
			} {
				owner := Principal{ID: principalID, Username: "owner", Role: RoleOwner, Enabled: true, AllNetworks: true}
				want := expectedRoleAllows(RoleOwner, policy.Operation) && candidate.Kind() == target.Kind()
				if got := AuthorizeEarly(subject, &owner, policy, candidate); got != want {
					t.Errorf("AuthorizeEarly(target kind %s)=%t want %t", candidate.Kind(), got, want)
				}
			}
		})
	}
}

func TestRootOnlyOperationsRejectEveryHumanRole(t *testing.T) {
	principalID, sessionID := identity.ID{1}, identity.ID{2}
	subject := SessionSubject(principalID, sessionID)
	root := RootSubject(identity.ID{9})
	for _, test := range []struct {
		policy RoutePolicy
		target DecisionTarget
	}{
		{managementPolicyForTest(t, "POST", "/v1/admin/auth/bootstrap-grants"), GlobalTarget()},
		{managementPolicyForTest(t, "POST", "/v1/admin/auth/root-token-rotations/{rotation_id}/begin"), ObjectTarget(identity.ID{4})},
		{managementPolicyForTest(t, "POST", "/v1/admin/auth/root-token-rotations/{rotation_id}/complete"), ObjectTarget(identity.ID{4})},
		{managementPolicyForTest(t, "POST", "/v1/admin/administrators/{principal_id}/recovery-grants"), ObjectTarget(identity.ID{3})},
	} {
		if !AuthorizeEarly(root, nil, test.policy, test.target) {
			t.Errorf("root subject denied %s %s", test.policy.Method, test.policy.Pattern)
		}
		for _, role := range []Role{RoleOwner, RoleOperator, RoleAuditor} {
			principal := Principal{ID: principalID, Username: string(role), Role: role, Enabled: true, AllNetworks: true}
			if AuthorizeEarly(subject, &principal, test.policy, test.target) {
				t.Errorf("%s human role allowed root-only route %s %s", role, test.policy.Method, test.policy.Pattern)
			}
		}
	}
}

func TestRootTokenRotationDecisionBindsPhaseAndRotationID(t *testing.T) {
	root := RootSubject(identity.ID{1})
	rotationID := identity.ID{2}
	begin := managementPolicyForTest(t, "POST", "/v1/admin/auth/root-token-rotations/{rotation_id}/begin")
	complete := managementPolicyForTest(t, "POST", "/v1/admin/auth/root-token-rotations/{rotation_id}/complete")
	decision, err := NewDecision(root, begin, ObjectTarget(rotationID))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Matches(root, begin, ObjectTarget(rotationID)) {
		t.Fatal("begin decision did not match its exact route and rotation ID")
	}
	if decision.Matches(root, complete, ObjectTarget(rotationID)) {
		t.Fatal("begin decision matched complete phase")
	}
	if decision.Matches(root, begin, ObjectTarget(identity.ID{3})) {
		t.Fatal("begin decision matched a different rotation ID")
	}
}

func TestAuthorizeEarlyRejectsStaleOrStructurallyInvalidInputs(t *testing.T) {
	principalID, sessionID := identity.ID{1}, identity.ID{2}
	networkID, otherNetworkID := identity.NetworkID{3}, identity.NetworkID{4}
	objectID := identity.ID{5}
	subject := SessionSubject(principalID, sessionID)
	operator := Principal{
		ID: principalID, Username: "operator", Role: RoleOperator, Enabled: true,
		NetworkIDs: []identity.NetworkID{networkID},
	}
	networkRead := managementPolicyForTest(t, "GET", "/v1/admin/networks/{network_id}")
	filteredList := managementPolicyForTest(t, "GET", "/v1/admin/networks")
	objectMutation := managementPolicyForTest(t, "POST", "/v1/admin/routes/{route_id}/approve")
	if AuthorizeEarly(subject, &operator, networkRead, NetworkTarget(otherNetworkID)) {
		t.Fatal("principal was authorized for an ungranted network")
	}
	emptyScopeOperator := operator
	emptyScopeOperator.NetworkIDs = nil
	if !AuthorizeEarly(subject, &emptyScopeOperator, filteredList, FilteredTarget()) {
		t.Fatal("filtered list was denied before Store filtering")
	}
	if !AuthorizeEarly(subject, &emptyScopeOperator, objectMutation, ObjectTarget(objectID)) {
		t.Fatal("object authorization incorrectly required an unresolved network grant")
	}
	auditor := emptyScopeOperator
	auditor.Username, auditor.Role = "auditor", RoleAuditor
	if AuthorizeEarly(subject, &auditor, objectMutation, ObjectTarget(objectID)) {
		t.Fatal("auditor was authorized for an object mutation")
	}

	disabled := operator
	disabled.Enabled = false
	invalidPrincipal := operator
	invalidPrincipal.Username = "INVALID"
	otherPrincipal := operator
	otherPrincipal.ID = identity.ID{9}
	for name, test := range map[string]struct {
		subject   Subject
		principal *Principal
		policy    RoutePolicy
		target    DecisionTarget
	}{
		"zero subject":           {Subject{}, &operator, networkRead, NetworkTarget(networkID)},
		"nil principal":          {subject, nil, networkRead, NetworkTarget(networkID)},
		"disabled principal":     {subject, &disabled, networkRead, NetworkTarget(networkID)},
		"invalid principal":      {subject, &invalidPrincipal, networkRead, NetworkTarget(networkID)},
		"different principal":    {subject, &otherPrincipal, networkRead, NetworkTarget(networkID)},
		"zero target":            {subject, &operator, networkRead, DecisionTarget{}},
		"wrong target kind":      {subject, &operator, networkRead, ObjectTarget(objectID)},
		"zero network target":    {subject, &operator, networkRead, NetworkTarget(identity.NetworkID{})},
		"invalid policy":         {subject, &operator, RoutePolicy{}, NetworkTarget(networkID)},
		"principal with root":    {RootSubject(identity.ID{8}), &operator, networkRead, NetworkTarget(networkID)},
		"invalid root principal": {RootSubject(identity.ID{}), nil, networkRead, NetworkTarget(networkID)},
	} {
		t.Run(name, func(t *testing.T) {
			if AuthorizeEarly(test.subject, test.principal, test.policy, test.target) {
				t.Fatal("invalid authorization input was allowed")
			}
		})
	}
}

func targetForPolicy(t *testing.T, policy RoutePolicy, networkID identity.NetworkID, objectID identity.ID) DecisionTarget {
	t.Helper()
	switch policy.ScopeSource {
	case ScopeGlobal:
		return GlobalTarget()
	case ScopeFiltered:
		return FilteredTarget()
	case ScopePath, ScopeBody:
		return NetworkTarget(networkID)
	case ScopeObject:
		return ObjectTarget(objectID)
	default:
		t.Fatalf("unsupported scope source %q", policy.ScopeSource)
		return DecisionTarget{}
	}
}

func managementPolicyForTest(t *testing.T, method, pattern string) RoutePolicy {
	t.Helper()
	for _, policy := range ManagementRoutes() {
		if policy.Method == method && policy.Pattern == pattern {
			return policy
		}
	}
	t.Fatalf("management policy not found: %s %s", method, pattern)
	return RoutePolicy{}
}

func expectedRoleAllows(role Role, operation Operation) bool {
	switch operation {
	case OperationNetworkList, OperationNetworkRead, OperationNodeRead, OperationRouteRead,
		OperationACLRead, OperationRelayRead, OperationCertificateRead, OperationAuditRead:
		return role == RoleOwner || role == RoleOperator || role == RoleAuditor
	case OperationEnrollmentIssue, OperationNodeManage, OperationRouteManage, OperationACLManage,
		OperationRelayManage, OperationCertificateManage:
		return role == RoleOwner || role == RoleOperator
	case OperationNetworkCreate, OperationBootstrapCreate, OperationAuditReadGlobal,
		OperationPrincipalManage, OperationSessionManage:
		return role == RoleOwner
	case OperationRecoveryManage, OperationRootTokenRotate:
		return false
	default:
		return false
	}
}
