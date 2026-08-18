package controllerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func jsonRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func decodeJSONResponse(t *testing.T, result *httptest.ResponseRecorder, value any) {
	t.Helper()
	if err := json.Unmarshal(result.Body.Bytes(), value); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", result.Code, result.Body.String(), err)
	}
}

func TestAdminNetworkManagementAuthValidationAndBodyLimit(t *testing.T) {
	f := newFixture(t, 1024, nil)
	original := f.service.access
	f.service.access = accessControllerErrorStub{err: ErrUnauthenticated}
	for _, endpoint := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/admin/enrollment-tokens"},
		{http.MethodPost, "/v1/admin/networks"},
		{http.MethodGet, "/v1/admin/networks/not-an-id"},
		{http.MethodGet, "/v1/admin/networks/not-an-id/routes"},
		{http.MethodGet, "/v1/admin/networks/not-an-id/audit"},
		{http.MethodPost, "/v1/admin/routes/not-an-id/approve"},
		{http.MethodPost, "/v1/admin/routes/not-an-id/withdraw"},
		{http.MethodPost, "/v1/admin/networks/not-an-id/acl-rules"},
		{http.MethodPut, "/v1/admin/acl-rules/not-an-id"},
		{http.MethodDelete, "/v1/admin/acl-rules/not-an-id"},
		{http.MethodPost, "/v1/admin/nodes/not-an-id/revoke"},
		{http.MethodPost, "/v1/admin/networks/not-an-id/certificates/01/revoke"},
		{http.MethodPut, "/v1/admin/nodes/not-an-id/capabilities"},
		{http.MethodPost, "/v1/admin/networks/not-an-id/relays"},
		{http.MethodPost, "/v1/admin/relays/not-an-id/disable"},
	} {
		denied := jsonRequest(t, f.service.Handler(), endpoint.method, endpoint.path, nil)
		if denied.Code != http.StatusUnauthorized {
			t.Errorf("%s %s status=%d", endpoint.method, endpoint.path, denied.Code)
		}
	}
	f.service.access = accessControllerErrorStub{err: ErrPermissionDenied}
	humanSessionActor := jsonRequest(t, f.service.Handler(), http.MethodGet, "/v1/admin/networks", nil)
	if humanSessionActor.Code != http.StatusForbidden {
		t.Fatalf("legacy management surface accepted browser administrator actor: status=%d body=%s",
			humanSessionActor.Code, humanSessionActor.Body.String())
	}
	f.service.access = original
	unauthenticatedAdvertise := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/routes", advertiseRouteRequest{Prefix: "192.0.2.0/24", Kind: "subnet", Mode: "nat"})
	if unauthenticatedAdvertise.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated advertise status=%d", unauthenticatedAdvertise.Code)
	}
	unauthenticatedWithdraw := jsonRequest(t, f.service.Handler(), http.MethodDelete, "/v1/routes/not-an-id", nil)
	if unauthenticatedWithdraw.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated withdraw status=%d", unauthenticatedWithdraw.Code)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/v1/admin/networks", strings.NewReader(`{"name":"bad","ipv4_pool":"10.55.0.0/24","unexpected":true}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResult := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(unknownResult, unknown)
	if unknownResult.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", unknownResult.Code)
	}
	noncanonical := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/networks", networkRequest{Name: "bad", IPv4Pool: "10.55.0.1/24"})
	if noncanonical.Code != http.StatusBadRequest {
		t.Fatalf("noncanonical pool status=%d", noncanonical.Code)
	}
	oversized := httptest.NewRequest(http.MethodPost, "/v1/admin/networks", strings.NewReader(strings.Repeat("x", 2048)))
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResult := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(oversizedResult, oversized)
	if oversizedResult.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized admin status=%d", oversizedResult.Code)
	}

	created := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/networks", networkRequest{Name: "managed", IPv4Pool: "10.55.0.0/24", IPv6Pool: "2001:db8:55::/120"})
	if created.Code != http.StatusCreated {
		t.Fatalf("create network status=%d body=%s", created.Code, created.Body.String())
	}
	var network networkResponse
	decodeJSONResponse(t, created, &network)
	if network.NetworkID == "" || network.ConfigurationEpoch != 1 || network.IPv4Pool != "10.55.0.0/24" || network.IPv6Pool != "2001:db8:55::/120" {
		t.Fatalf("created network=%+v", network)
	}
	read := jsonRequest(t, f.service.Handler(), http.MethodGet, "/v1/admin/networks/"+network.NetworkID, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("read network status=%d", read.Code)
	}
	var readNetwork networkResponse
	decodeJSONResponse(t, read, &readNetwork)
	if readNetwork != network {
		t.Fatalf("read network=%+v want %+v", readNetwork, network)
	}
	invalidLimit := jsonRequest(t, f.service.Handler(), http.MethodGet, "/v1/admin/networks/"+network.NetworkID+"/audit?limit=1001", nil)
	if invalidLimit.Code != http.StatusBadRequest {
		t.Fatalf("invalid audit limit status=%d", invalidLimit.Code)
	}
}

func TestAccessSubjectManagementLifecycle(t *testing.T) {
	f := newFixture(t, 0, nil)
	handler := f.service.Handler()

	createdUser := jsonRequest(t, handler, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/users", createAccessSubjectRequest{Name: "Ada"})
	if createdUser.Code != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", createdUser.Code, createdUser.Body.String())
	}
	var user accessUserResponse
	decodeJSONResponse(t, createdUser, &user)
	if user.Name != "Ada" || !user.Enabled || user.NetworkID != f.network.ID.String() {
		t.Fatalf("created user=%+v", user)
	}

	createdTeam := jsonRequest(t, handler, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/teams", createAccessSubjectRequest{Name: "Operators"})
	if createdTeam.Code != http.StatusCreated {
		t.Fatalf("create team status=%d body=%s", createdTeam.Code, createdTeam.Body.String())
	}
	var team accessTeamResponse
	decodeJSONResponse(t, createdTeam, &team)

	memberPath := "/v1/admin/teams/" + team.TeamID + "/members/" + user.UserID
	if result := jsonRequest(t, handler, http.MethodPut, memberPath, nil); result.Code != http.StatusOK {
		t.Fatalf("add team member status=%d body=%s", result.Code, result.Body.String())
	}

	createdGrant := jsonRequest(t, handler, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/access-grants", createAccessGrantRequest{
		SubjectKind: "team", SubjectID: team.TeamID, TargetKind: "network",
	})
	if createdGrant.Code != http.StatusCreated {
		t.Fatalf("create grant status=%d body=%s", createdGrant.Code, createdGrant.Body.String())
	}
	var grant accessGrantResponse
	decodeJSONResponse(t, createdGrant, &grant)
	if grant.SubjectKind != "team" || grant.SubjectID != team.TeamID || grant.TargetKind != "network" || grant.NodeID != "" {
		t.Fatalf("created grant=%+v", grant)
	}

	inventoryResult := jsonRequest(t, handler, http.MethodGet, "/v1/admin/networks/"+f.network.ID.String()+"/access-subjects", nil)
	if inventoryResult.Code != http.StatusOK {
		t.Fatalf("access inventory status=%d body=%s", inventoryResult.Code, inventoryResult.Body.String())
	}
	var inventory accessInventoryResponse
	decodeJSONResponse(t, inventoryResult, &inventory)
	if len(inventory.Users) != 1 || len(inventory.Teams) != 1 || len(inventory.Memberships) != 1 || len(inventory.Grants) != 1 {
		t.Fatalf("access inventory=%+v", inventory)
	}

	issued := jsonRequest(t, handler, http.MethodPost, "/v1/admin/enrollment-tokens", tokenRequest{
		NetworkID: f.network.ID.String(), UserID: user.UserID, Label: "Ada device", RequestedName: "Ada laptop",
		ExpiresAtUnix: time.Now().Add(time.Hour).Unix(), EnrollmentClass: "ephemeral", SessionLifetimeSeconds: 3600,
	})
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue user enrollment status=%d body=%s", issued.Code, issued.Body.String())
	}
	var token tokenResponse
	decodeJSONResponse(t, issued, &token)
	if token.UserID != user.UserID || token.EnrollmentToken == "" {
		t.Fatalf("issued user enrollment=%+v", token)
	}

	disabled := jsonRequest(t, handler, http.MethodPatch, "/v1/admin/users/"+user.UserID, updateAccessUserRequest{Enabled: boolPointer(false)})
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable user status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	if result := jsonRequest(t, handler, http.MethodDelete, "/v1/admin/access-grants/"+grant.GrantID, nil); result.Code != http.StatusOK {
		t.Fatalf("delete grant status=%d body=%s", result.Code, result.Body.String())
	}
	if result := jsonRequest(t, handler, http.MethodDelete, memberPath, nil); result.Code != http.StatusOK {
		t.Fatalf("remove team member status=%d body=%s", result.Code, result.Body.String())
	}
}

func boolPointer(value bool) *bool { return &value }

func TestAdminCreatesPreidentifiedNetworkForControllerBootstrap(t *testing.T) {
	f := newFixture(t, 0, nil)
	want := "101112131415161718191a1b1c1d1e1f"
	created := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/networks", networkRequest{
		NetworkID: want, Name: "controller-certificate-network", IPv4Pool: "10.56.0.0/24",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var response networkResponse
	decodeJSONResponse(t, created, &response)
	if response.NetworkID != want {
		t.Fatalf("network ID = %s, want %s", response.NetworkID, want)
	}
	invalid := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/networks", networkRequest{
		NetworkID: "not-an-id", Name: "bad", IPv4Pool: "10.57.0.0/24",
	})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid network ID status=%d", invalid.Code)
	}
}

func TestAdminRelayRegistrationAndDisable(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	serviceID, _ := identity.NewID()
	path := "/v1/admin/networks/" + f.network.ID.String() + "/relays"
	bad := jsonRequest(t, f.service.Handler(), http.MethodPost, path, registerRelayRequest{
		ServiceID: "bad", Name: "relay-one", Endpoint: "relay.example:443",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid service ID status=%d body=%s", bad.Code, bad.Body.String())
	}
	created := jsonRequest(t, f.service.Handler(), http.MethodPost, path, registerRelayRequest{
		ServiceID: serviceID.String(), Name: "relay-one", Endpoint: "relay.example:443",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("register relay status=%d body=%s", created.Code, created.Body.String())
	}
	var relay relayResponse
	decodeJSONResponse(t, created, &relay)
	if relay.RelayID == "" || relay.NetworkID != f.network.ID.String() || relay.ServiceID != serviceID.String() || !relay.Enabled || relay.ConfigurationEpoch != 2 {
		t.Fatalf("relay response=%+v", relay)
	}
	disabled := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/relays/"+relay.RelayID+"/disable", nil)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable relay status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	var epoch epochResponse
	decodeJSONResponse(t, disabled, &epoch)
	if epoch.ConfigurationEpoch != 3 {
		t.Fatalf("disable epoch=%d", epoch.ConfigurationEpoch)
	}
	second := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/relays/"+relay.RelayID+"/disable", nil)
	if second.Code != http.StatusConflict {
		t.Fatalf("second disable status=%d body=%s", second.Code, second.Body.String())
	}
}

func TestAdminCertificateRevocationByNetworkSerial(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	enrollment, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "certificate-admin")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
	}
	leaf := parseLeaf(t, enrollment.GetCertificateChain())
	path := "/v1/admin/networks/" + f.network.ID.String() + "/certificates/" + hex.EncodeToString(leaf.SerialNumber.Bytes()) + "/revoke"
	revoked := jsonRequest(t, f.service.Handler(), http.MethodPost, path, revocationRequest{Reason: "credential compromised"})
	if revoked.Code != http.StatusOK {
		t.Fatalf("certificate revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	var epoch epochResponse
	decodeJSONResponse(t, revoked, &epoch)
	if epoch.ConfigurationEpoch != 3 {
		t.Fatalf("certificate revoke epoch=%d", epoch.ConfigurationEpoch)
	}
	second := jsonRequest(t, f.service.Handler(), http.MethodPost, path, revocationRequest{Reason: "again"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second certificate revoke status=%d body=%s", second.Code, second.Body.String())
	}
}

func TestNodeRouteLifecycleOwnershipAdminApprovalAndReads(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	tokenOne := issueToken(t, f, time.Now().Add(time.Hour))
	responseOne, enrolled := enroll(t, f, tokenOne, csrDER(t, ""), "route-one")
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("first enroll status=%d", enrolled.Code)
	}
	var nodeOne identity.NodeIdentity
	copy(nodeOne.NetworkID[:], responseOne.NetworkId)
	copy(nodeOne.NodeID[:], responseOne.NodeId)
	tokenTwo := issueToken(t, f, time.Now().Add(time.Hour))
	responseTwo, enrolled := enroll(t, f, tokenTwo, csrDER(t, ""), "route-two")
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("second enroll status=%d", enrolled.Code)
	}
	var nodeTwo identity.NodeIdentity
	copy(nodeTwo.NetworkID[:], responseTwo.NetworkId)
	copy(nodeTwo.NodeID[:], responseTwo.NodeId)
	authenticated = nodeOne
	capabilities := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/admin/nodes/"+nodeOne.NodeID.String()+"/capabilities", nodeCapabilitiesRequest{
		EnabledCapabilities: uint64(protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1),
	})
	if capabilities.Code != http.StatusOK {
		t.Fatalf("capability grant status=%d body=%s", capabilities.Code, capabilities.Body.String())
	}

	spoof := httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{"prefix":"192.0.2.0/24","kind":"subnet","mode":"nat","metric":5,"node_id":"`+nodeTwo.NodeID.String()+`"}`))
	spoof.Header.Set("Content-Type", "application/json")
	spoofResult := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(spoofResult, spoof)
	if spoofResult.Code != http.StatusBadRequest {
		t.Fatalf("spoof field status=%d", spoofResult.Code)
	}
	badKind := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/routes", advertiseRouteRequest{Prefix: "192.0.2.1/24", Kind: "overlay", Mode: "nat"})
	if badKind.Code != http.StatusBadRequest {
		t.Fatalf("bad route status=%d", badKind.Code)
	}
	advertised := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/routes", advertiseRouteRequest{Prefix: "192.0.2.0/24", Kind: "subnet", Mode: "nat", Metric: 5})
	if advertised.Code != http.StatusCreated {
		t.Fatalf("advertise status=%d body=%s", advertised.Code, advertised.Body.String())
	}
	var route routeResponse
	decodeJSONResponse(t, advertised, &route)
	if route.NodeID != nodeOne.NodeID.String() || route.State != "advertised" {
		t.Fatalf("advertised route=%+v", route)
	}
	approved := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/routes/"+route.RouteID+"/approve", nil)
	if approved.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approved.Code, approved.Body.String())
	}
	var approvedEpoch epochResponse
	decodeJSONResponse(t, approved, &approvedEpoch)
	if approvedEpoch.ConfigurationEpoch != 5 {
		t.Fatalf("approval epoch=%d", approvedEpoch.ConfigurationEpoch)
	}
	reapprove := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/routes/"+route.RouteID+"/approve", nil)
	if reapprove.Code != http.StatusConflict {
		t.Fatalf("reapprove status=%d", reapprove.Code)
	}

	authenticated = nodeTwo
	wrongOwner := jsonRequest(t, f.service.Handler(), http.MethodDelete, "/v1/routes/"+route.RouteID, nil)
	if wrongOwner.Code != http.StatusForbidden {
		t.Fatalf("wrong-owner withdrawal status=%d", wrongOwner.Code)
	}
	authenticated = nodeOne
	withdrawn := jsonRequest(t, f.service.Handler(), http.MethodDelete, "/v1/routes/"+route.RouteID, nil)
	if withdrawn.Code != http.StatusOK {
		t.Fatalf("withdraw status=%d", withdrawn.Code)
	}
	var withdrawnEpoch epochResponse
	decodeJSONResponse(t, withdrawn, &withdrawnEpoch)
	if withdrawnEpoch.ConfigurationEpoch != 6 {
		t.Fatalf("withdraw epoch=%d", withdrawnEpoch.ConfigurationEpoch)
	}

	exit := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/routes", advertiseRouteRequest{Prefix: "0.0.0.0/0", Kind: "exit", Mode: "routed", Metric: 50})
	if exit.Code != http.StatusCreated {
		t.Fatalf("exit advertise status=%d body=%s", exit.Code, exit.Body.String())
	}
	var exitRoute routeResponse
	decodeJSONResponse(t, exit, &exitRoute)
	adminWithdrawn := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/routes/"+exitRoute.RouteID+"/withdraw", nil)
	if adminWithdrawn.Code != http.StatusOK {
		t.Fatalf("admin withdraw status=%d body=%s", adminWithdrawn.Code, adminWithdrawn.Body.String())
	}
	allRoutes := jsonRequest(t, f.service.Handler(), http.MethodGet, "/v1/admin/networks/"+f.network.ID.String()+"/routes?limit=10", nil)
	if allRoutes.Code != http.StatusOK {
		t.Fatalf("route read status=%d body=%s", allRoutes.Code, allRoutes.Body.String())
	}
	var routeList struct {
		Routes []routeResponse `json:"routes"`
	}
	decodeJSONResponse(t, allRoutes, &routeList)
	if len(routeList.Routes) != 2 {
		t.Fatalf("routes=%+v", routeList.Routes)
	}
	audit := jsonRequest(t, f.service.Handler(), http.MethodGet, "/v1/admin/networks/"+f.network.ID.String()+"/audit?limit=100", nil)
	if audit.Code != http.StatusOK {
		t.Fatalf("audit read status=%d body=%s", audit.Code, audit.Body.String())
	}
	var auditList struct {
		Events []auditResponse `json:"events"`
	}
	decodeJSONResponse(t, audit, &auditList)
	if len(auditList.Events) < 8 {
		t.Fatalf("too few audit events: %d", len(auditList.Events))
	}
	state, err := f.store.AdministratorAuthState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rootID := state.RootServicePrincipalID.String()
	wantedRootMutations := map[string]string{
		"route.approve":         route.RouteID,
		"route.withdraw":        exitRoute.RouteID,
		"node.capabilities.set": nodeOne.NodeID.String(),
	}
	foundRootMutations := make(map[string]bool, len(wantedRootMutations))
	for _, event := range auditList.Events {
		if event.ActorKind == "" {
			t.Fatalf("audit event omitted actor kind: %+v", event)
		}
		if event.ActorNodeID != nil && (event.ActorID == nil || *event.ActorID != *event.ActorNodeID) {
			t.Fatalf("node actor compatibility fields disagree: %+v", event)
		}
		wantedTarget, isRootMutation := wantedRootMutations[event.Action]
		if !isRootMutation || event.TargetID == nil || *event.TargetID != wantedTarget {
			continue
		}
		if event.ActorKind != string(adminauth.ActorServicePrincipal) || event.ActorID == nil || *event.ActorID != rootID {
			t.Fatalf("administrator mutation actor=%+v want stable root service principal", event)
		}
		foundRootMutations[event.Action] = true
	}
	for action := range wantedRootMutations {
		if !foundRootMutations[action] {
			t.Fatalf("missing root-attributed %s audit event", action)
		}
	}
}

func TestManagementRejectsNonRootServicePrincipalAndRollsBack(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	wrongID := identity.ID{99}
	f.service.access = accessControllerStub{rootID: wrongID}
	response := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/networks",
		networkRequest{Name: "must-not-exist", IPv4Pool: "10.55.0.0/24"})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched service-principal status=%d body=%s", response.Code, response.Body.String())
	}
	networks, err := f.store.Networks(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range networks {
		if network.Name == "must-not-exist" {
			t.Fatal("mismatched service principal committed management mutation")
		}
	}
}

func TestAdministratorMutationHandlersAuditStableRootServicePrincipal(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) {
		return authenticated, nil
	})
	state, err := f.store.AdministratorAuthState(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	type auditExpectation struct {
		networkID identity.NetworkID
		action    string
		targetID  identity.ID
	}
	requireStatus := func(t *testing.T, method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		result := jsonRequest(t, f.service.Handler(), method, path, body)
		if result.Code != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, result.Code, want, result.Body.String())
		}
		return result
	}
	parseID := func(t *testing.T, value string) identity.ID {
		t.Helper()
		id, err := identity.ParseID(value)
		if err != nil {
			t.Fatalf("parse response ID %q: %v", value, err)
		}
		return id
	}
	prepareNode := func(t *testing.T, name string) (identity.NodeIdentity, identity.ID, []byte) {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(context.Background(), f.network.ID, name, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		response, result := enroll(t, f, token.Secret, csrDER(t, ""), name)
		if result.Code != http.StatusCreated {
			t.Fatalf("prepare node status=%d body=%s", result.Code, result.Body.String())
		}
		var node identity.NodeIdentity
		copy(node.NetworkID[:], response.GetNetworkId())
		copy(node.NodeID[:], response.GetNodeId())
		certificates, err := f.store.NetworkCertificates(context.Background(), node.NetworkID, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, certificate := range certificates {
			if certificate.NodeID == node.NodeID {
				return node, certificate.ID, append([]byte(nil), certificate.Serial...)
			}
		}
		t.Fatalf("prepared node %s has no certificate", node.NodeID)
		return identity.NodeIdentity{}, identity.ID{}, nil
	}
	prepareAdvertisedRoute := func(t *testing.T, name, prefix string) identity.ID {
		t.Helper()
		node, _, _ := prepareNode(t, name)
		if _, err := f.store.SetNodeCapabilities(context.Background(), node.NodeID, protocol.CapabilitySubnetRouterV1); err != nil {
			t.Fatal(err)
		}
		authenticated = node
		result := requireStatus(t, http.MethodPost, "/v1/routes", advertiseRouteRequest{
			Prefix: prefix, Kind: "subnet", Mode: "nat", Metric: 10,
		}, http.StatusCreated)
		var route routeResponse
		decodeJSONResponse(t, result, &route)
		if route.State != "advertised" {
			t.Fatalf("prepared route state=%q", route.State)
		}
		return parseID(t, route.RouteID)
	}
	validSelector := json.RawMessage(`{"source_prefixes":[{"address":"wAACAA==","prefix_length":24}],"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":443,"last":443}]}`)

	tests := []struct {
		name   string
		invoke func(*testing.T) []auditExpectation
	}{
		{
			name: "enrollment token issue",
			invoke: func(t *testing.T) []auditExpectation {
				result := requireStatus(t, http.MethodPost, "/v1/admin/enrollment-tokens", tokenRequest{
					NetworkID: f.network.ID.String(), Label: "root actor audit", ExpiresAtUnix: time.Now().Add(time.Hour).Unix(),
				}, http.StatusCreated)
				var response tokenResponse
				decodeJSONResponse(t, result, &response)
				if response.EnrollmentToken == "" {
					t.Fatal("issued enrollment token omitted its secret")
				}
				return []auditExpectation{{f.network.ID, "enrollment_token.issue", parseID(t, response.TokenID)}}
			},
		},
		{
			name: "network create",
			invoke: func(t *testing.T) []auditExpectation {
				result := requireStatus(t, http.MethodPost, "/v1/admin/networks", networkRequest{
					Name: "root-actor-audit", IPv4Pool: "10.55.0.0/24",
				}, http.StatusCreated)
				var response networkResponse
				decodeJSONResponse(t, result, &response)
				networkID, err := identity.ParseNetworkID(response.NetworkID)
				if err != nil {
					t.Fatalf("parse created network ID: %v", err)
				}
				if _, err := f.store.Network(context.Background(), networkID); err != nil {
					t.Fatalf("read created network: %v", err)
				}
				return []auditExpectation{{networkID, "network.create", identity.ID(networkID)}}
			},
		},
		{
			name: "route assign",
			invoke: func(t *testing.T) []auditExpectation {
				node, _, _ := prepareNode(t, "root-actor-route-assign")
				result := requireStatus(t, http.MethodPost, "/v1/admin/routes/assign", assignRouteRequest{
					NetworkID: f.network.ID.String(), NodeID: node.NodeID.String(), Prefix: "192.0.2.0/24", Mode: "nat", Metric: 20,
				}, http.StatusCreated)
				var response routeResponse
				decodeJSONResponse(t, result, &response)
				if response.State != "approved" {
					t.Fatalf("assigned route state=%q", response.State)
				}
				routeID := parseID(t, response.RouteID)
				return []auditExpectation{
					{f.network.ID, "node.capabilities.set", identity.ID(node.NodeID)},
					{f.network.ID, "route.advertise", routeID},
					{f.network.ID, "route.approve", routeID},
				}
			},
		},
		{
			name: "route approve",
			invoke: func(t *testing.T) []auditExpectation {
				routeID := prepareAdvertisedRoute(t, "root-actor-route-approve", "198.51.100.0/24")
				requireStatus(t, http.MethodPost, "/v1/admin/routes/"+routeID.String()+"/approve", nil, http.StatusOK)
				return []auditExpectation{{f.network.ID, "route.approve", routeID}}
			},
		},
		{
			name: "route withdraw",
			invoke: func(t *testing.T) []auditExpectation {
				routeID := prepareAdvertisedRoute(t, "root-actor-route-withdraw", "203.0.113.0/24")
				requireStatus(t, http.MethodPost, "/v1/admin/routes/"+routeID.String()+"/withdraw", nil, http.StatusOK)
				return []auditExpectation{{f.network.ID, "route.withdraw", routeID}}
			},
		},
		{
			name: "ACL create",
			invoke: func(t *testing.T) []auditExpectation {
				result := requireStatus(t, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/acl-rules", aclRuleRequest{
					Priority: 10, Action: "accept", Selector: validSelector, Description: "root actor audit create",
				}, http.StatusCreated)
				var response aclRuleResponse
				decodeJSONResponse(t, result, &response)
				return []auditExpectation{{f.network.ID, "acl_rule.create", parseID(t, response.RuleID)}}
			},
		},
		{
			name: "ACL update",
			invoke: func(t *testing.T) []auditExpectation {
				created := requireStatus(t, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/acl-rules", aclRuleRequest{
					Priority: 20, Action: "accept", Selector: validSelector, Description: "root actor audit update setup",
				}, http.StatusCreated)
				var rule aclRuleResponse
				decodeJSONResponse(t, created, &rule)
				result := requireStatus(t, http.MethodPut, "/v1/admin/acl-rules/"+rule.RuleID, updateACLRuleRequest{
					Priority: 21, Action: "deny", Selector: validSelector, Description: "root actor audit updated", Enabled: false,
				}, http.StatusOK)
				var response aclRuleResponse
				decodeJSONResponse(t, result, &response)
				if response.Enabled || response.Action != "deny" || response.Priority != 21 {
					t.Fatalf("updated ACL rule=%+v", response)
				}
				return []auditExpectation{{f.network.ID, "acl_rule.update", parseID(t, rule.RuleID)}}
			},
		},
		{
			name: "ACL delete",
			invoke: func(t *testing.T) []auditExpectation {
				created := requireStatus(t, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/acl-rules", aclRuleRequest{
					Priority: 30, Action: "accept", Selector: validSelector, Description: "root actor audit delete setup",
				}, http.StatusCreated)
				var rule aclRuleResponse
				decodeJSONResponse(t, created, &rule)
				requireStatus(t, http.MethodDelete, "/v1/admin/acl-rules/"+rule.RuleID, nil, http.StatusOK)
				return []auditExpectation{{f.network.ID, "acl_rule.delete", parseID(t, rule.RuleID)}}
			},
		},
		{
			name: "node revoke",
			invoke: func(t *testing.T) []auditExpectation {
				node, _, _ := prepareNode(t, "root-actor-node-revoke")
				requireStatus(t, http.MethodPost, "/v1/admin/nodes/"+node.NodeID.String()+"/revoke", revocationRequest{
					Reason: "root actor audit",
				}, http.StatusOK)
				stored, err := f.store.Node(context.Background(), node.NodeID)
				if err != nil || stored.RevokedAt == nil {
					t.Fatalf("revoked node=%+v err=%v", stored, err)
				}
				return []auditExpectation{{f.network.ID, "node.revoke", identity.ID(node.NodeID)}}
			},
		},
		{
			name: "certificate revoke",
			invoke: func(t *testing.T) []auditExpectation {
				_, certificateID, serial := prepareNode(t, "root-actor-certificate-revoke")
				requireStatus(t, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/certificates/"+hex.EncodeToString(serial)+"/revoke", revocationRequest{
					Reason: "root actor audit",
				}, http.StatusOK)
				return []auditExpectation{{f.network.ID, "certificate.revoke", certificateID}}
			},
		},
		{
			name: "node capabilities set",
			invoke: func(t *testing.T) []auditExpectation {
				node, _, _ := prepareNode(t, "root-actor-node-capabilities")
				requireStatus(t, http.MethodPut, "/v1/admin/nodes/"+node.NodeID.String()+"/capabilities", nodeCapabilitiesRequest{
					EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1),
				}, http.StatusOK)
				stored, err := f.store.Node(context.Background(), node.NodeID)
				if err != nil || stored.EnabledCapabilities != uint64(protocol.CapabilityExitNodeV1) {
					t.Fatalf("capability-updated node=%+v err=%v", stored, err)
				}
				return []auditExpectation{{f.network.ID, "node.capabilities.set", identity.ID(node.NodeID)}}
			},
		},
		{
			name: "relay register",
			invoke: func(t *testing.T) []auditExpectation {
				serviceID, err := identity.NewID()
				if err != nil {
					t.Fatal(err)
				}
				result := requireStatus(t, http.MethodPost, "/v1/admin/networks/"+f.network.ID.String()+"/relays", registerRelayRequest{
					ServiceID: serviceID.String(), Name: "root-actor-relay-register", Endpoint: "relay-register.example:443",
				}, http.StatusCreated)
				var response relayResponse
				decodeJSONResponse(t, result, &response)
				if !response.Enabled {
					t.Fatal("registered relay is disabled")
				}
				return []auditExpectation{{f.network.ID, "relay.register", parseID(t, response.RelayID)}}
			},
		},
		{
			name: "relay disable",
			invoke: func(t *testing.T) []auditExpectation {
				serviceID, err := identity.NewID()
				if err != nil {
					t.Fatal(err)
				}
				relay, _, err := f.store.RegisterRelay(context.Background(), f.network.ID, serviceID, nil,
					"root-actor-relay-disable", "relay-disable.example:443")
				if err != nil {
					t.Fatal(err)
				}
				requireStatus(t, http.MethodPost, "/v1/admin/relays/"+relay.ID.String()+"/disable", nil, http.StatusOK)
				return []auditExpectation{{f.network.ID, "relay.disable", relay.ID}}
			},
		},
		{
			name: "relay update",
			invoke: func(t *testing.T) []auditExpectation {
				serviceID, err := identity.NewID()
				if err != nil {
					t.Fatal(err)
				}
				relay, _, err := f.store.RegisterRelay(context.Background(), f.network.ID, serviceID, nil,
					"root-actor-relay-update", "relay-update.example:443")
				if err != nil {
					t.Fatal(err)
				}
				result := requireStatus(t, http.MethodPut, "/v1/admin/relays/"+relay.ID.String(), updateRelayRequest{
					Name: "root-actor-relay-updated", Endpoint: "relay-updated.example:8443", Enabled: false,
				}, http.StatusOK)
				var response relayResponse
				decodeJSONResponse(t, result, &response)
				if response.Enabled || response.Name != "root-actor-relay-updated" || response.Endpoint != "relay-updated.example:8443" {
					t.Fatalf("updated relay=%+v", response)
				}
				return []auditExpectation{{f.network.ID, "relay.update", relay.ID}}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectations := test.invoke(t)
			events, err := f.store.GlobalAuditEvents(context.Background(), 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, expectation := range expectations {
				matches := 0
				for _, event := range events {
					if event.Action != expectation.action || event.TargetID == nil || *event.TargetID != expectation.targetID {
						continue
					}
					matches++
					if event.NetworkScope == nil || *event.NetworkScope != expectation.networkID {
						t.Fatalf("%s audit network=%v want=%s", expectation.action, event.NetworkScope, expectation.networkID)
					}
					if event.Actor.Kind != adminauth.ActorServicePrincipal || event.Actor.ID == nil || *event.Actor.ID != state.RootServicePrincipalID {
						t.Fatalf("%s audit actor=%+v want service principal %s", expectation.action, event.Actor, state.RootServicePrincipalID)
					}
				}
				if matches != 1 {
					t.Fatalf("%s audit events for target %s=%d want=1", expectation.action, expectation.targetID, matches)
				}
			}
		})
	}
}

func TestAdminAssignRouteIsIdempotentAndPreservesCapabilities(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	response, enrolled := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "ibmcloud")
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", enrolled.Code, enrolled.Body.String())
	}
	var nodeID identity.NodeID
	copy(nodeID[:], response.NodeId)
	if _, err := f.store.SetNodeCapabilities(context.Background(), nodeID, protocol.CapabilityExitNodeV1); err != nil {
		t.Fatal(err)
	}
	request := assignRouteRequest{NetworkID: f.network.ID.String(), NodeID: nodeID.String(), Prefix: "10.240.64.6/32", Mode: "nat"}
	assigned := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/routes/assign", request)
	if assigned.Code != http.StatusCreated {
		t.Fatalf("assign status=%d body=%s", assigned.Code, assigned.Body.String())
	}
	var route routeResponse
	decodeJSONResponse(t, assigned, &route)
	if route.Prefix != request.Prefix || route.NodeID != request.NodeID || route.State != "approved" {
		t.Fatalf("assigned route=%+v", route)
	}
	node, err := f.store.Node(context.Background(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	want := uint64(protocol.CapabilityExitNodeV1 | protocol.CapabilitySubnetRouterV1)
	if node.EnabledCapabilities != want {
		t.Fatalf("capabilities=%d want=%d", node.EnabledCapabilities, want)
	}
	again := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/routes/assign", request)
	if again.Code != http.StatusOK {
		t.Fatalf("repeat assign status=%d body=%s", again.Code, again.Body.String())
	}
	routes, err := f.store.NetworkRoutes(context.Background(), f.network.ID, 1000)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes=%v err=%v", routes, err)
	}
}

func TestACLStrictProtoJSONEpochAndDelete(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	path := "/v1/admin/networks/" + f.network.ID.String() + "/acl-rules"
	for name, selector := range map[string]json.RawMessage{
		"unknown":     json.RawMessage(`{"unknown":true}`),
		"unspecified": json.RawMessage(`{}`),
		"short ID":    json.RawMessage(`{"source_node_ids":["AQ=="],"ip_protocol":"IP_PROTOCOL_TCP"}`),
		"host bits":   json.RawMessage(`{"source_prefixes":[{"address":"wAACAw==","prefix_length":24}],"ip_protocol":"IP_PROTOCOL_TCP"}`),
		"ICMP ports":  json.RawMessage(`{"ip_protocol":"IP_PROTOCOL_ICMP","destination_ports":[{"first":80,"last":80}]}`),
		"zero port":   json.RawMessage(`{"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":0,"last":80}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			result := jsonRequest(t, f.service.Handler(), http.MethodPost, path, aclRuleRequest{Priority: 10, Action: "accept", Selector: selector})
			if result.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
			}
		})
	}
	validSelector := json.RawMessage(`{"source_prefixes":[{"address":"wAACAA==","prefix_length":24}],"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":443,"last":443}]}`)
	created := jsonRequest(t, f.service.Handler(), http.MethodPost, path, aclRuleRequest{Priority: 10, Action: "accept", Selector: validSelector, Description: "HTTPS"})
	if created.Code != http.StatusCreated {
		t.Fatalf("ACL create status=%d body=%s", created.Code, created.Body.String())
	}
	var rule aclRuleResponse
	decodeJSONResponse(t, created, &rule)
	if rule.ConfigurationEpoch != 2 || rule.RuleID == "" {
		t.Fatalf("ACL response=%+v", rule)
	}
	updated := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/admin/acl-rules/"+rule.RuleID, updateACLRuleRequest{Priority: 20, Action: "deny", Selector: validSelector, Description: "blocked HTTPS", Enabled: false})
	if updated.Code != http.StatusOK {
		t.Fatalf("ACL update status=%d body=%s", updated.Code, updated.Body.String())
	}
	var updatedRule aclRuleResponse
	decodeJSONResponse(t, updated, &updatedRule)
	if updatedRule.ConfigurationEpoch != 3 || updatedRule.Enabled || updatedRule.Action != "deny" || updatedRule.Priority != 20 {
		t.Fatalf("ACL update=%+v", updatedRule)
	}
	deleted := jsonRequest(t, f.service.Handler(), http.MethodDelete, "/v1/admin/acl-rules/"+rule.RuleID, nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("ACL delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	var epoch epochResponse
	decodeJSONResponse(t, deleted, &epoch)
	if epoch.ConfigurationEpoch != 4 {
		t.Fatalf("delete epoch=%d", epoch.ConfigurationEpoch)
	}
}

func TestAdminNodeRevocationAdvancesEpochAndBlocksNode(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	token := issueToken(t, f, time.Now().Add(time.Hour))
	response, enrolled := enroll(t, f, token, csrDER(t, ""), "revoked-by-admin")
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d", enrolled.Code)
	}
	copy(authenticated.NetworkID[:], response.NetworkId)
	copy(authenticated.NodeID[:], response.NodeId)
	invalidReason := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/nodes/"+authenticated.NodeID.String()+"/revoke", revocationRequest{})
	if invalidReason.Code != http.StatusBadRequest {
		t.Fatalf("invalid reason status=%d", invalidReason.Code)
	}
	revoked := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/admin/nodes/"+authenticated.NodeID.String()+"/revoke", revocationRequest{Reason: "compromised"})
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	var epoch epochResponse
	decodeJSONResponse(t, revoked, &epoch)
	if epoch.ConfigurationEpoch != 3 {
		t.Fatalf("revoke epoch=%d", epoch.ConfigurationEpoch)
	}
	blocked := jsonRequest(t, f.service.Handler(), http.MethodPost, "/v1/routes", advertiseRouteRequest{Prefix: "198.51.100.0/24", Kind: "subnet", Mode: "nat"})
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("revoked node status=%d", blocked.Code)
	}
}
