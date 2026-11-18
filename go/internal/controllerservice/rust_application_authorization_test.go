//go:build rustinterop

package controllerservice

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func testRustApplicationAuthorization(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, web labCredentials, registered map[string]any) {
	t.Helper()
	root := labCredentials{bearer: testRootBearer}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	send := labManagementHTTP(t, &copy)
	clientID := registered["client_id"].(string)
	clientSecret := registered["client_secret"].(string)
	const callbackURI = "https://dispatch.example/callback-a"
	const verifier = "integration-authorization-request-verifier-for-pkce"
	const state = "network request + lab"
	hash := sha256.Sum256([]byte(verifier))
	operatorToken, operatorCSRF := rustScopedBrowserFixture(t, f, "operator")
	operator := labCredentials{session: operatorToken, csrf: operatorCSRF}
	unrelated, err := f.store.CreateNetwork(t.Context(), "authorization-other", netip.MustParsePrefix("10.99.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/networks/" + f.network.ID.String()
	other := "/v1/admin/networks/" + unrelated.ID.String()
	snapshot := func() map[string]any {
		route := path + "/application-installations"
		goResult := send(goURL, "GET", route, "", root, 200)
		rustResult := send(rustURL, "GET", route, "", operator, 200)
		if !reflect.DeepEqual(goResult, rustResult) {
			t.Fatal("Go and Rust returned different installation inventories")
		}
		rows := rustResult["application_installations"].([]any)
		if len(rows) != 1 {
			t.Fatalf("unexpected installation count: %d", len(rows))
		}
		return rows[0].(map[string]any)
	}
	authorize := func(base, redirect, scope string, want int) string {
		t.Helper()
		query := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "scope": {scope},
			"state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])},
			"code_challenge_method": {"S256"},
		}
		req, err := http.NewRequestWithContext(t.Context(), "GET", base+"/oauth/authorize?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := copy.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("authorize got %d, wanted %d", resp.StatusCode, want)
		}
		if want != 303 {
			if resp.Header.Get("Location") != "" {
				t.Fatal("rejected authorization redirected to an unreviewed callback")
			}
			return ""
		}
		location, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || location.IsAbs() || location.Path != "/applications/install" || location.Query().Get("request") == "" {
			t.Fatal("invalid installation consent location")
		}
		return location.Query().Get("request")
	}
	publicReview := func(base, requestID string, want int) map[string]any {
		return send(base, "GET", "/oauth/authorization-requests/"+requestID, "", labCredentials{}, want)
	}
	approval := func(networkPath, requestID string) string {
		return networkPath + "/application-authorization-requests/" + requestID
	}
	callback := func(base, path, selection string, creds labCredentials) url.Values {
		t.Helper()
		reply := send(base, "POST", path, selection, creds, 200)
		location, err := url.Parse(reply["redirect_uri"].(string))
		if err != nil || !strings.HasPrefix(reply["redirect_uri"].(string), callbackURI+"?") ||
			location.Query().Get("state") != state {
			t.Fatal("callback did not bind the authorization to the registered redirect and state")
		}
		return location.Query()
	}
	exchange := func(code string, want int) labCredentials {
		t.Helper()
		values := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {callbackURI}, "code_verifier": {verifier},
		}
		req, err := http.NewRequestWithContext(t.Context(), "POST", goURL+"/oauth/token", strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := copy.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("Go exchange of Rust authorization code got %d, wanted %d", resp.StatusCode, want)
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if want == 200 {
			if result["refresh_token"] == "" || result["access_token"] == "" {
				t.Fatal("exchange did not produce access and refresh credentials")
			}
			return labCredentials{bearer: result["access_token"].(string)}
		}
		if result["error"] != "invalid_grant" {
			t.Fatal("retired code did not return invalid_grant")
		}
		return labCredentials{}
	}
	const broad = `{"scopes":["route.manage","network.read"]}`
	const narrow = `{"scopes":["network.read"]}`
	authorize(rustURL, "https://dispatch.example/unreviewed", "network.read", 400)
	authorize(rustURL, callbackURI, "enrollment.issue", 400)
	first := authorize(goURL, callbackURI, "route.manage network.read", 303)
	if !reflect.DeepEqual(publicReview(goURL, first, 200), publicReview(rustURL, first, 200)) {
		t.Fatal("authorization request views differ")
	}
	send(rustURL, "POST", approval(other, first)+"/approve", broad, operator, 403)
	send(rustURL, "POST", approval(path, first)+"/approve", broad, root, 403)
	send(rustURL, "POST", approval(path, first)+"/approve", `{"scopes":["enrollment.issue"]}`, web, 404)
	send(rustURL, "POST", approval(path, first)+"/approve", broad, labCredentials{session: web.session, csrf: "wrong"}, 403)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlRun := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	sqlRun(`CREATE TRIGGER lab_installation_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='application_installation.authorize' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "POST", approval(path, first)+"/approve", broad, operator, 500)
	publicReview(goURL, first, 200)
	sqlRun("DROP TRIGGER lab_installation_abort")
	code := callback(rustURL, approval(path, first)+"/approve", broad, operator).Get("code")
	original := snapshot()
	publicReview(rustURL, first, 404)
	old := exchange(code, 200)
	send(rustURL, "GET", path, "", old, 200)
	send(rustURL, "GET", other, "", old, 403)

	same := authorize(rustURL, callbackURI, "route.manage network.read", 303)
	retiredCode := callback(goURL, approval(path, same)+"/approve", broad, web).Get("code")
	if !reflect.DeepEqual(snapshot(), original) {
		t.Fatal("same-scope reauthorization should keep the installation identity")
	}
	second := authorize(rustURL, callbackURI, "network.read", 303)
	nextCode := callback(rustURL, approval(path, second)+"/approve", narrow, web).Get("code")
	updated := snapshot()
	if updated["installation_id"] != original["installation_id"] || updated["service_principal_id"] == original["service_principal_id"] {
		t.Fatal("scope change did not replace the service identity in place")
	}
	exchange(retiredCode, 400)
	send(goURL, "GET", path, "", old, 401)
	send(rustURL, "GET", path, "", old, 401)
	now := exchange(nextCode, 200)
	send(rustURL, "GET", path, "", now, 200)
	send(rustURL, "GET", path+"/application-installations", "", now, 403)

	declined := authorize(rustURL, callbackURI, "network.read", 303)
	if result := callback(rustURL, approval(path, declined)+"/cancel", "", operator); result.Get("error") != "access_denied" || result.Get("code") != "" {
		t.Fatal("cancellation did not return a denial")
	}
	publicReview(rustURL, declined, 404)
	revoke := "/v1/admin/application-installations/" + original["installation_id"].(string)
	send(rustURL, "DELETE", revoke, "", operator, 204)
	if snapshot()["enabled"] != false {
		t.Fatal("revoked installation remained enabled")
	}
	send(goURL, "GET", path, "", now, 401)
	send(rustURL, "GET", path, "", now, 401)
	send(rustURL, "DELETE", revoke, "", root, 404)
}
