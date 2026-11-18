//go:build rustinterop

package controllerservice

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/applicationauth"
)

func testRustApplicationTokenLifecycle(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, web labCredentials, registered map[string]any) {
	t.Helper()
	const callback = "https://dispatch.example/callback-a"
	const verifier = "token-lifecycle-pkce-verifier-for-interoperability"
	appID := registered["application_id"].(string)
	clientID := registered["client_id"].(string)
	clientKey := registered["client_secret"].(string)
	networkPath := "/v1/admin/networks/" + f.network.ID.String()
	send := labManagementHTTP(t, client)
	issueCode := func() string {
		t.Helper()
		digest := sha256.Sum256([]byte(verifier))
		request, err := f.store.CreateApplicationAuthorizationRequest(t.Context(), clientID, callback,
			[]string{"network.read"}, "token-test", base64.RawURLEncoding.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		approval := send(rustURL, "POST", networkPath+"/application-authorization-requests/"+request.ID.String()+"/approve",
			`{"scopes":["network.read"]}`, web, 200)
		redirect, err := url.Parse(approval["redirect_uri"].(string))
		if err != nil || redirect.Query().Get("code") == "" {
			t.Fatal("approval did not produce an authorization code")
		}
		return redirect.Query().Get("code")
	}
	request := func(path string, fields url.Values, key string, wantStatus int, wantError string) map[string]any {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rustURL+path, strings.NewReader(fields.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(clientID, key)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != wantStatus || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("%s got status %d or unexpected cache headers, wanted %d", path, resp.StatusCode, wantStatus)
		}
		if wantStatus == 401 && resp.Header.Get("WWW-Authenticate") != `Basic realm="Laneway OAuth"` {
			t.Fatal("authentication failure did not advertise Basic authentication")
		}
		if path == "/oauth/revoke" && wantStatus == 200 {
			buf, err := io.ReadAll(resp.Body)
			if err != nil || len(buf) != 0 {
				t.Fatal("revocation revealed information about the token")
			}
			return nil
		}
		var result map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if wantError != "" && result["error"] != wantError {
			t.Fatalf("unexpected OAuth error at %s", path)
		}
		return result
	}
	codeForm := func(code, redirect, proof string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {redirect}, "code_verifier": {proof},
		}
	}
	refreshForm := func(token string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	}
	checkAccess := func(token string, want int) {
		t.Helper()
		for _, base := range []string{goURL, rustURL} {
			send(base, "GET", networkPath, "", labCredentials{bearer: token}, want)
		}
	}
	fields := func(value map[string]any) (string, string) {
		t.Helper()
		inst := value["installation"].(map[string]any)
		network := inst["network"].(map[string]any)
		if value["scope"] != "network.read" || value["token_type"] != "Bearer" || value["expires_in"] != float64(3600) ||
			inst["application_id"] != appID || network["network_id"] != f.network.ID.String() {
			t.Fatal("OAuth grant returned the wrong scope, network, or application")
		}
		return value["access_token"].(string), value["refresh_token"].(string)
	}
	code := issueCode()
	request("/oauth/token", codeForm(code, callback, verifier), "invalid-client", 401, "invalid_client")
	request("/oauth/token", codeForm(code, callback+"?different=1", verifier), clientKey, 400, "invalid_grant")
	request("/oauth/token", codeForm(code, callback, strings.Repeat("x", 50)), clientKey, 400, "invalid_grant")
	access, refresh := fields(request("/oauth/token", codeForm(code, callback, verifier), clientKey, 200, ""))
	request("/oauth/token", codeForm(code, callback, verifier), clientKey, 400, "invalid_grant")
	checkAccess(access, 200)

	goRotated, err := f.store.RefreshApplicationToken(t.Context(), clientID, clientKey, refresh)
	if err != nil {
		t.Fatalf("Go could not refresh the Rust grant: %v", err)
	}
	checkAccess(access, 401)
	rustAccess, rustRefresh := fields(request("/oauth/token", refreshForm(goRotated.RefreshToken), clientKey, 200, ""))
	checkAccess(goRotated.AccessToken, 401)
	request("/oauth/token", refreshForm(goRotated.RefreshToken), clientKey, 400, "invalid_grant")
	checkAccess(rustAccess, 200)

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	retired, _, err := applicationauth.ParseSecret(applicationauth.PurposeRefreshToken, goRotated.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	// Advance the fixture past the grace window without a real-time delay.
	if _, err := db.ExecContext(t.Context(), `UPDATE application_refresh_tokens
		SET created_at=unixepoch()-12,consumed_at=unixepoch()-6 WHERE id=?`, retired[:]); err != nil {
		t.Fatal(err)
	}
	request("/oauth/token", refreshForm(goRotated.RefreshToken), clientKey, 400, "invalid_grant")
	checkAccess(rustAccess, 401)
	if _, err := f.store.RefreshApplicationToken(t.Context(), clientID, clientKey, rustRefresh); err == nil {
		t.Fatal("Go still accepted a refresh token from the retired family")
	}
	nextAccess, nextRefresh := fields(request("/oauth/token", codeForm(issueCode(), callback, verifier), clientKey, 200, ""))
	request("/oauth/revoke", url.Values{"token": {nextRefresh}, "token_type_hint": {"refresh_token"}}, clientKey, 200, "")
	checkAccess(nextAccess, 401)
	if _, err := f.store.RefreshApplicationToken(t.Context(), clientID, clientKey, nextRefresh); err == nil {
		t.Fatal("Go still accepted an explicitly revoked refresh token")
	}
	for _, event := range []string{"application_refresh.reuse", "application_refresh.revoke"} {
		var count int
		if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_events
			WHERE action=? AND actor_kind='service_principal' AND target_type='application_refresh_family' AND lower(hex(network_id))=?`,
			event, f.network.ID.String()).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expected one %s audit event, got %d (%v)", event, count, err)
		}
	}
}
