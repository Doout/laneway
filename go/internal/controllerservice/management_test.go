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

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
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
	original := f.service.authorizeAdm
	f.service.authorizeAdm = func(*http.Request) error { return ErrUnauthenticated }
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
		{http.MethodPost, "/v1/admin/networks/not-an-id/acl-rules"},
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
	f.service.authorizeAdm = original
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
	deleted := jsonRequest(t, f.service.Handler(), http.MethodDelete, "/v1/admin/acl-rules/"+rule.RuleID, nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("ACL delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	var epoch epochResponse
	decodeJSONResponse(t, deleted, &epoch)
	if epoch.ConfigurationEpoch != 3 {
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
