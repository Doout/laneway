//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/applicationauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

type publicApplicationHTTP func(method, path string, body io.Reader, headers http.Header, want int) *http.Response

type dispatchClientProbe struct{ binary, address, authority, caPEM string }

func (p dispatchClientProbe) run(t *testing.T, step string, fields map[string]string, result any) {
	t.Helper()
	fields["Step"], fields["Address"], fields["Authority"], fields["CAPEM"] = step, p.address, p.authority, p.caPEM
	input, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), p.binary)
	cmd.Stdin, cmd.Stderr = bytes.NewReader(input), os.Stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Dispatch client %s failed: %v", step, err)
	}
	if result != nil {
		if err := json.Unmarshal(output, result); err != nil {
			t.Fatalf("Dispatch client %s returned invalid JSON", step)
		}
	}
}

func testRustPublicApplication(t *testing.T, f fixture, foreign identity.NetworkID, public publicApplicationHTTP,
	direct *http.Client, directURL string, browser http.Header, root string, probe dispatchClientProbe,
) {
	t.Helper()
	const dispatch = "https://dispatch.example.test"
	const setup = dispatch + "/api/v1/laneway-applications/setup"
	const callback = dispatch + "/api/v1/laneway-networks/callback"
	const setupVerifier = "public-dispatch-registration-pkce-verifier-123456"
	const verifier = "public-dispatch-authorization-pkce-verifier-12345"
	const setupState = "registration + test/~"
	const state = "installation + test/~"
	scopes := []string{"network.read", "node.read", "enrollment.issue", "route.read", "route.manage"}
	network := "/v1/admin/networks/" + f.network.ID.String()
	other := "/v1/admin/networks/" + foreign.String()
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	pkce := func(proof string) string {
		hash := sha256.Sum256([]byte(proof))
		return base64.RawURLEncoding.EncodeToString(hash[:])
	}
	jsonBody := func(value any) io.Reader {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return strings.NewReader(string(encoded))
	}
	read := func(resp *http.Response, into any) {
		t.Helper()
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			t.Fatalf("invalid application JSON response: %v", err)
		}
	}
	requestID := func(resp *http.Response, route string) string {
		t.Helper()
		defer resp.Body.Close()
		location, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || location.IsAbs() || location.Host != "" || location.Path != route ||
			location.Query().Get("request") == "" {
			t.Fatal("application flow did not link to the same-origin consent screen")
		}
		return location.Query().Get("request")
	}
	readCode := func(resp *http.Response, expectedURI, expectedState string) string {
		t.Helper()
		var reply struct {
			Redirect string `json:"redirect_uri"`
		}
		read(resp, &reply)
		u, err := url.Parse(reply.Redirect)
		if err != nil || !strings.HasPrefix(reply.Redirect, expectedURI+"?") ||
			u.Query().Get("state") != expectedState || u.Query().Get("code") == "" {
			t.Fatal("approval returned a callback outside the reviewed URI or lost state")
		}
		return u.Query().Get("code")
	}

	manifest, err := json.Marshal(applicationauth.Manifest{
		Name: "Dispatch", HomepageURI: dispatch, SetupURI: setup, RedirectURIs: []string{callback},
		Scopes: scopes, TokenEndpointAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := url.Values{
		"manifest": {string(manifest)}, "state": {setupState},
		"code_challenge_method": {"S256"}, "code_challenge": {pkce(setupVerifier)},
	}
	registration := requestID(public("POST", "/applications/new", strings.NewReader(reg.Encode()), form, 303), "/applications/consent")
	regPath := "/v1/admin/application-registration-requests/" + registration
	public("GET", regPath, nil, browser, 200).Body.Close()
	regCode := readCode(public("POST", regPath+"/approve", nil, browser, 200), setup, setupState)
	regExchange := func(proof string, want int) *http.Response {
		return public("POST", "/v1/application-registrations/exchange",
			jsonBody(map[string]string{"code": regCode, "code_verifier": proof}), jsonHeader, want)
	}
	var app struct {
		ApplicationID string `json:"application_id"`
		ClientID      string `json:"client_id"`
		ClientSecret  string `json:"client_secret"`
	}
	regExchange(verifier, 400).Body.Close()
	if probe.binary == "" {
		read(regExchange(setupVerifier, 200), &app)
	} else {
		probe.run(t, "register", map[string]string{"Code": regCode, "Verifier": setupVerifier}, &app)
	}
	regExchange(setupVerifier, 400).Body.Close()
	if app.ApplicationID == "" || app.ClientID == "" || app.ClientSecret == "" {
		t.Fatal("registration returned an incomplete Dispatch client")
	}
	grants := url.Values{
		"response_type": {"code"}, "client_id": {app.ClientID}, "redirect_uri": {callback},
		"state": {state}, "scope": {strings.Join(scopes, " ")}, "code_challenge": {pkce(verifier)},
		"code_challenge_method": {"S256"},
	}
	install := requestID(public("GET", "/oauth/authorize?"+grants.Encode(), nil, nil, 303), "/applications/install")
	public("GET", "/oauth/authorization-requests/"+install, nil, nil, 200).Body.Close()
	approve := network + "/application-authorization-requests/" + install + "/approve"
	code := readCode(public("POST", approve, jsonBody(map[string][]string{"scopes": scopes}), browser, 200), callback, state)

	basic := form.Clone()
	basic.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(app.ClientID+":"+app.ClientSecret)))
	codeFields := func(proof string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {proof}, "redirect_uri": {callback}}
	}
	oauth := func(path string, fields url.Values, want int) *http.Response {
		t.Helper()
		resp := public("POST", path, strings.NewReader(fields.Encode()), basic, want)
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatal("public OAuth response lost its cache protection")
		}
		return resp
	}
	type tokens struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Scope   string `json:"scope"`
		Kind    string `json:"token_type"`
		Install struct {
			ID      string `json:"installation_id"`
			App     string `json:"application_id"`
			Network struct {
				ID string `json:"network_id"`
			} `json:"network"`
		} `json:"installation"`
	}
	var token tokens
	oauth("/oauth/token", codeFields(setupVerifier), 400).Body.Close()
	if probe.binary == "" {
		read(oauth("/oauth/token", codeFields(verifier), 200), &token)
	} else {
		probe.run(t, "exchange", map[string]string{"Code": code, "Verifier": verifier, "Redirect": callback,
			"ClientID": app.ClientID, "ClientKey": app.ClientSecret}, &token)
	}
	oauth("/oauth/token", codeFields(verifier), 400).Body.Close()
	wantScopes := append([]string(nil), scopes...)
	actual := strings.Fields(token.Scope)
	sort.Strings(wantScopes)
	sort.Strings(actual)
	if token.Access == "" || token.Refresh == "" || token.Kind != "Bearer" || token.Install.ID == "" ||
		token.Install.App != app.ApplicationID || token.Install.Network.ID != f.network.ID.String() ||
		strings.Join(actual, " ") != strings.Join(wantScopes, " ") {
		t.Fatal("public token grant is not bound to the approved application, network and five scopes")
	}

	bearer := func(value string) http.Header { return http.Header{"Authorization": {"Bearer " + value}} }
	active := bearer(token.Access)
	makeRouter := func(net identity.NetworkID, name string) identity.NodeID {
		t.Helper()
		grant, err := f.store.IssueEnrollmentToken(t.Context(), net, name, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		router, err := f.store.EnrollNode(t.Context(), grant.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.SetNodeCapabilities(t.Context(), router.ID, protocol.CapabilitySubnetRouterV1); err != nil {
			t.Fatal(err)
		}
		return router.ID
	}
	router := makeRouter(f.network.ID, "dispatch-router")
	foreignRouter := makeRouter(foreign, "other-router")
	for _, suffix := range []string{"", "/nodes?limit=500", "/endpoint-statuses?limit=500", "/routes?limit=500"} {
		public("GET", network+suffix, nil, active, 200).Body.Close()
		public("GET", other+suffix, nil, active, 403).Body.Close()
	}
	installer := map[string]string{"name": "dispatch-connector", "kind": "connector", "install_mode": "systemd"}
	appJSON := active.Clone()
	appJSON.Set("Content-Type", "application/json")
	var installed struct {
		ID      string `json:"installation_id"`
		Command string `json:"command"`
	}
	result := public("POST", network+"/node-installers", jsonBody(installer), appJSON, 201)
	read(result, &installed)
	if installed.ID == "" || installed.Command == "" || result.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("public application did not receive a private installer")
	}
	public("POST", other+"/node-installers", jsonBody(installer), appJSON, 403).Body.Close()
	assign := func(net identity.NetworkID, node identity.NodeID, prefix string) io.Reader {
		return jsonBody(map[string]any{"network_id": net, "node_id": node, "prefix": prefix, "mode": "nat", "metric": 22})
	}
	public("POST", "/v1/admin/routes/assign", assign(foreign, foreignRouter, "198.51.100.0/24"), appJSON, 403).Body.Close()
	public("POST", "/v1/admin/routes/assign", assign(f.network.ID, foreignRouter, "198.51.100.0/24"), appJSON, 404).Body.Close()
	var route struct {
		ID     string `json:"route_id"`
		NodeID string `json:"node_id"`
	}
	read(public("POST", "/v1/admin/routes/assign", assign(f.network.ID, router, "198.51.100.0/24"), appJSON, 201), &route)
	if route.ID == "" || route.NodeID != router.String() {
		t.Fatal("route assignment did not select the approved network's node")
	}
	if probe.binary != "" {
		probe.run(t, "inventory-write", map[string]string{
			"Network": f.network.ID.String(), "Node": router.String(), "Access": token.Access,
		}, nil)
	}
	public("GET", network+"/application-installations", nil, active, 401).Body.Close()
	public("GET", network, nil, http.Header{"X-Laneway-Relay-Application-Access": {"Bearer " + token.Access}}, 401).Body.Close()
	mixed := active.Clone()
	mixed.Set("Origin", dispatch)
	public("GET", network, nil, mixed, 401).Body.Close()

	private := labManagementHTTP(t, direct)
	rootAuth := labCredentials{bearer: root}
	private(directURL, "GET", network, "", rootAuth, 200)
	public("GET", network, nil, bearer(root), 401).Body.Close()
	principal := private(directURL, "POST", "/v1/admin/service-principals",
		fmt.Sprintf(`{"name":"private-network-reader","permissions":["network.read"],"network_ids":[%q]}`, f.network.ID), rootAuth, 201)["principal_id"].(string)
	automation := private(directURL, "POST", "/v1/admin/service-principals/"+principal+"/tokens",
		fmt.Sprintf(`{"label":"private only","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), rootAuth, 201)["access_token"].(string)
	private(directURL, "GET", network, "", labCredentials{bearer: automation}, 200)
	public("GET", network, nil, bearer(automation), 401).Body.Close()
	for _, header := range []http.Header{
		{"Authorization": {"LanewayPublicApplication " + token.Access}},
		{"X-Laneway-Relay-Application-Access": {"Bearer " + token.Access}, "X-Laneway-Public-Client-Ip": {"192.0.2.9"}},
	} {
		req, err := http.NewRequestWithContext(t.Context(), "GET", directURL+network, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = header
		resp, err := direct.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatal("direct request forged the public relay's credential context")
		}
	}

	var rotated tokens
	if probe.binary == "" {
		read(oauth("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token.Refresh}}, 200), &rotated)
	} else {
		probe.run(t, "refresh", map[string]string{"ClientID": app.ClientID, "ClientKey": app.ClientSecret,
			"Refresh": token.Refresh}, &rotated)
	}
	if rotated.Access == "" || rotated.Access == token.Access || rotated.Install.ID != token.Install.ID {
		t.Fatal("refresh did not rotate the access token in place")
	}
	public("GET", network, nil, active, 401).Body.Close()
	public("GET", network, nil, bearer(rotated.Access), 200).Body.Close()
	if probe.binary == "" {
		oauth("/oauth/revoke", url.Values{"token": {rotated.Refresh}, "token_type_hint": {"refresh_token"}}, 200).Body.Close()
	} else {
		probe.run(t, "revoke", map[string]string{"ClientID": app.ClientID, "ClientKey": app.ClientSecret,
			"Refresh": rotated.Refresh}, nil)
		t.Log("real Dispatch client passed registration, token exchange, inventory, installer and route writes, refresh, and revocation")
	}
	public("GET", network, nil, bearer(rotated.Access), 401).Body.Close()
}
