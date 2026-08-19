package controllerservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func bearerJSONRequest(method, target string, body any, bearer string) *http.Request {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestServicePrincipalHTTPTokenIsScopedAuditedAndImmediatelyRevocable(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	useProductionRootAccess(t, fixture)
	_, _, _, _ = bootstrapAdministratorSessionForHTTPTest(t, fixture, "owner", "a sufficiently long owner password")

	create := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(create, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-principals", []byte(`{
			"name":"ci-bot",
			"all_networks":false,
			"network_ids":["`+fixture.network.ID.String()+`"],
			"permissions":["network.list","network.read","acl.manage"]
		}`)))
	var principal servicePrincipalResponse
	if create.Code != http.StatusCreated || json.Unmarshal(create.Body.Bytes(), &principal) != nil || principal.PrincipalID == "" {
		t.Fatalf("create service principal status=%d body=%s", create.Code, create.Body.String())
	}

	issue := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(issue, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-principals/"+principal.PrincipalID+"/tokens", []byte(`{
			"label":"integration test",
			"expires_at_unix_seconds":`+strconv.FormatInt(time.Now().UTC().Add(time.Hour).Unix(), 10)+`
		}`)))
	var issued struct {
		AccessToken string                     `json:"access_token"`
		Token       serviceAccessTokenResponse `json:"token"`
	}
	if issue.Code != http.StatusCreated || json.Unmarshal(issue.Body.Bytes(), &issued) != nil ||
		issued.AccessToken == "" || issued.Token.TokenID == "" || issue.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("issue access token status=%d headers=%v body=%s", issue.Code, issue.Header(), issue.Body.String())
	}

	login := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(login, bearerJSONRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/login",
		map[string]any{"username": "owner", "password": "a sufficiently long owner password"}, issued.AccessToken))
	if login.Code != http.StatusUnauthorized {
		t.Fatalf("service token was accepted as a login credential: status=%d", login.Code)
	}
	rootProbe := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(rootProbe, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/auth/root", nil, issued.AccessToken))
	if rootProbe.Code != http.StatusUnauthorized {
		t.Fatalf("service token was accepted as the root credential: status=%d", rootProbe.Code)
	}
	credentialManagement := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(credentialManagement, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/service-principals", nil, issued.AccessToken))
	if credentialManagement.Code != http.StatusForbidden {
		t.Fatalf("service token administered service principals: status=%d", credentialManagement.Code)
	}

	list := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(list, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/networks", nil, issued.AccessToken))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), fixture.network.ID.String()) {
		t.Fatalf("service token network list status=%d body=%s", list.Code, list.Body.String())
	}
	forbidden := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(forbidden, bearerJSONRequest(http.MethodPost,
		"https://controller.example/v1/admin/networks", map[string]any{
			"name": "forbidden", "ipv4_pool": "10.250.0.0/24",
		}, issued.AccessToken))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("ungranted operation status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}
	browser := bearerJSONRequest(http.MethodGet, "https://controller.example/v1/admin/networks", nil, issued.AccessToken)
	browser.Header.Set("Origin", "https://controller.example")
	browserResponse := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(browserResponse, browser)
	if browserResponse.Code != http.StatusUnauthorized {
		t.Fatalf("browser-context service token status=%d", browserResponse.Code)
	}

	mutation := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(mutation, bearerJSONRequest(http.MethodPost,
		"https://controller.example/v1/admin/networks/"+fixture.network.ID.String()+"/users",
		map[string]any{"name": "Automation User"}, issued.AccessToken))
	if mutation.Code != http.StatusCreated {
		t.Fatalf("service token mutation status=%d body=%s", mutation.Code, mutation.Body.String())
	}
	audit := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(audit, rootHTTPRequest(http.MethodGet,
		"https://controller.example/v1/admin/audit?limit=100", nil))
	if audit.Code != http.StatusOK || !strings.Contains(audit.Body.String(), `"actor_kind":"service_principal"`) ||
		!strings.Contains(audit.Body.String(), `"actor_id":"`+principal.PrincipalID+`"`) {
		t.Fatalf("service mutation audit status=%d body=%s", audit.Code, audit.Body.String())
	}

	nulReason := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(nulReason, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-access-tokens/"+issued.Token.TokenID+"/revoke",
		[]byte(`{"reason":"bad\u0000reason"}`)))
	if nulReason.Code != http.StatusBadRequest {
		t.Fatalf("NUL revocation reason status=%d body=%s", nulReason.Code, nulReason.Body.String())
	}
	invalidUTF8Payload := []byte(`{"reason":"bad`)
	invalidUTF8Payload = append(invalidUTF8Payload, 0xff)
	invalidUTF8Payload = append(invalidUTF8Payload, []byte(`"}`)...)
	invalidUTF8 := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(invalidUTF8, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-access-tokens/"+issued.Token.TokenID+"/revoke",
		invalidUTF8Payload))
	if invalidUTF8.Code != http.StatusBadRequest {
		t.Fatalf("invalid UTF-8 revocation reason status=%d body=%s", invalidUTF8.Code, invalidUTF8.Body.String())
	}
	stillActive := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(stillActive, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/networks", nil, issued.AccessToken))
	if stillActive.Code != http.StatusOK {
		t.Fatalf("invalid revocation request changed token state: status=%d body=%s",
			stillActive.Code, stillActive.Body.String())
	}

	revoke := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(revoke, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-access-tokens/"+issued.Token.TokenID+"/revoke",
		[]byte(`{"reason":"rotated"}`)))
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke token status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	after := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(after, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/networks", nil, issued.AccessToken))
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d body=%s", after.Code, after.Body.String())
	}

	replacementIssue := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(replacementIssue, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-principals/"+principal.PrincipalID+"/tokens", []byte(`{
			"label":"disable test",
			"expires_at_unix_seconds":`+strconv.FormatInt(time.Now().UTC().Add(time.Hour).Unix(), 10)+`
		}`)))
	var replacement struct {
		AccessToken string `json:"access_token"`
	}
	if replacementIssue.Code != http.StatusCreated || json.Unmarshal(replacementIssue.Body.Bytes(), &replacement) != nil ||
		replacement.AccessToken == "" {
		t.Fatalf("issue replacement status=%d body=%s", replacementIssue.Code, replacementIssue.Body.String())
	}
	disable := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(disable, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/service-principals/"+principal.PrincipalID+"/disable", nil))
	if disable.Code != http.StatusNoContent {
		t.Fatalf("disable principal status=%d body=%s", disable.Code, disable.Body.String())
	}
	disabledToken := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(disabledToken, bearerJSONRequest(http.MethodGet,
		"https://controller.example/v1/admin/networks", nil, replacement.AccessToken))
	if disabledToken.Code != http.StatusUnauthorized {
		t.Fatalf("disabled principal token status=%d body=%s", disabledToken.Code, disabledToken.Body.String())
	}
}
