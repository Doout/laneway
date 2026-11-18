//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/adminauth"
)

func testRustAdministratorChanges(t *testing.T, f fixture, client *http.Client, goURL, rustURL, owner string, web, automation labCredentials) {
	t.Helper()
	const administrators = "/v1/admin/administrators"
	const auth = "/v1/admin/auth/"
	const username = "managed-operator"
	const oldPassword = "initial managed operator password"
	const newPassword = "replacement managed operator password"
	const finalPassword = "self-service managed owner password"
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	jsonBody := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	request := func(base, method, path, body string, caller labCredentials, want int) (http.Header, labCredentials, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if caller.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+caller.bearer)
		} else {
			req.Header.Set("Origin", base)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if caller.session != "" {
			req.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: caller.session})
			req.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: caller.csrf})
			req.Header.Set(adminauth.CSRFHeaderName, caller.csrf)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: got %d, want %d", method, path, resp.StatusCode, want)
		}
		var result map[string]any
		var session labCredentials
		if want != 204 {
			if err := json.Unmarshal(bodyBytes, &result); err != nil {
				t.Fatal(err)
			}
		}
		for _, cookie := range resp.Cookies() {
			switch cookie.Name {
			case adminauth.SessionCookieName:
				session.session = cookie.Value
			case adminauth.CSRFCookieName:
				session.csrf = cookie.Value
			}
		}
		return resp.Header, session, result
	}
	login := func(base, password string, want int) (labCredentials, string) {
		t.Helper()
		header, creds, record := request(base, "POST", auth+"login",
			jsonBody(map[string]string{"username": username, "password": password}), labCredentials{}, want)
		if want == 200 && (creds.session == "" || creds.csrf == "" || header.Get(administratorSessionIDHeader) == "") {
			t.Fatal("login did not produce a session")
		}
		id, _ := record["session_id"].(string)
		return creds, id
	}

	send(rustURL, "PATCH", administrators+"/"+owner, `{"enabled":false}`, root, 409)
	send(rustURL, "PATCH", administrators+"/"+owner,
		`{"access":{"role":"auditor","all_networks":true,"network_ids":[]}}`, web, 409)
	newAccount := jsonBody(map[string]any{
		"username": username, "password": oldPassword, "role": "operator", "network_ids": []string{f.network.ID.String()},
	})
	send(rustURL, "POST", administrators, newAccount, automation, 403)
	send(rustURL, "POST", administrators, newAccount, labCredentials{session: web.session, csrf: "invalid"}, 403)
	headers, _, created := request(rustURL, "POST", administrators, newAccount, web, 201)
	target := administrators + "/" + created["principal_id"].(string)
	if headers.Get("Location") != target || headers.Get(administratorSessionIDHeader) == "" {
		t.Fatal("create did not return its resource location and browser metadata")
	}
	if !reflect.DeepEqual(created, send(goURL, "GET", target, "", root, 200)) {
		t.Fatal("Go cannot read the Rust-created administrator")
	}
	send(rustURL, "POST", administrators, newAccount, root, 409)

	managed, _ := login(goURL, oldPassword, 200)
	access := func(role string, enabled bool) string {
		return jsonBody(map[string]any{"enabled": enabled, "access": map[string]any{
			"role": role, "all_networks": false, "network_ids": []string{f.network.ID.String()},
		}})
	}
	if current := send(rustURL, "PATCH", target, access("operator", true), root, 200); !reflect.DeepEqual(current, created) {
		t.Fatal("no-op update changed the principal")
	}
	send(rustURL, "GET", auth+"session", "", managed, 200)
	updated := send(rustURL, "PATCH", target, access("auditor", false), web, 200)
	if updated["enabled"] != false || updated["role"] != "auditor" ||
		!reflect.DeepEqual(updated, send(goURL, "GET", target, "", root, 200)) {
		t.Fatal("access patch did not atomically update role and enabled state")
	}
	send(goURL, "GET", auth+"session", "", managed, 401)
	enabled := send(rustURL, "PATCH", target, `{"enabled":true}`, root, 200)
	if enabled["enabled"] != true || enabled["role"] != "auditor" || enabled["disabled_at_unix_seconds"] != nil {
		t.Fatal("enabled-only patch changed access or retained the disabled timestamp")
	}
	managed, _ = login(goURL, oldPassword, 200)

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execSQL := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	password := func(value string) string { return jsonBody(map[string]string{"password": value}) }
	execSQL(`CREATE TRIGGER lab_password_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='administrator.password.replace' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	request(rustURL, "POST", target+"/password", password(newPassword), web, 500)
	execSQL("DROP TRIGGER lab_password_abort")
	send(goURL, "GET", auth+"session", "", managed, 200)
	send(rustURL, "POST", target+"/password", password(newPassword), root, 204)
	send(goURL, "GET", auth+"session", "", managed, 401)
	login(goURL, oldPassword, 401)
	managed, predecessor := login(goURL, newPassword, 200)
	_, successor, _ := request(rustURL, "POST", auth+"session/rotate", "", managed, 200)
	other, _ := login(rustURL, newPassword, 200)
	revocation := "/v1/admin/sessions/" + predecessor + "/revoke"
	send(rustURL, "POST", revocation, `{"reason":"retired by lab operator"}`, web, 204)
	send(rustURL, "POST", revocation, `{"reason":"idempotent retry"}`, root, 204)
	send(goURL, "GET", auth+"session", "", successor, 401)
	send(rustURL, "GET", auth+"session", "", other, 200)

	send(rustURL, "PATCH", target, `{"access":{"role":"owner","all_networks":true,"network_ids":[]}}`, root, 200)
	self, _ := login(rustURL, newPassword, 200)
	cleared := func(headers http.Header) {
		t.Helper()
		response := &http.Response{Header: headers}
		cookies := response.Cookies()
		if headers.Get(administratorSessionIDHeader) != "" || len(cookies) != 2 {
			t.Fatal("self-termination must clear both cookies and omit session metadata")
		}
		for _, cookie := range cookies {
			if cookie.Value != "" || cookie.MaxAge >= 0 || !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("incorrect cookie expiration")
			}
		}
	}
	headers, _, _ = request(rustURL, "POST", target+"/password", password(finalPassword), self, 204)
	cleared(headers)
	send(goURL, "GET", auth+"session", "", self, 401)
	self, sessionID := login(rustURL, finalPassword, 200)
	headers, _, _ = request(rustURL, "POST", "/v1/admin/sessions/"+sessionID+"/revoke",
		`{"reason":"self-sign-out"}`, self, 204)
	cleared(headers)
	send(goURL, "GET", auth+"session", "", self, 401)

	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_events
		WHERE actor_kind='administrator' AND action='administrator.session.revoke'
		  AND json_extract(details_json,'$.reason')='retired by lab operator'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("session family revocation audit count = %d: %v", count, err)
	}
}
