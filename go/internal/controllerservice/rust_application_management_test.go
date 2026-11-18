//go:build rustinterop

package controllerservice

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"testing"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

func testRustApplicationManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, web labCredentials, registered map[string]any) {
	t.Helper()
	const callback = "https://dispatch.example/callback-a"
	const verifier = "application-management-lab-verifier-for-pkce"
	const networkPath = "/v1/admin/networks/"
	const appPath = "/v1/admin/applications/"
	app := registered["application_id"].(string)
	clientID := registered["client_id"].(string)
	oldSecret := registered["client_secret"].(string)
	target := appPath + app
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)

	second, err := f.store.CreateNetwork(t.Context(), "lifecycle-other", netip.MustParsePrefix("10.104.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	issued := func(network identity.NetworkID) controller.ApplicationTokenGrant {
		t.Helper()
		challenge := sha256.Sum256([]byte(verifier))
		pending, err := f.store.CreateApplicationAuthorizationRequest(t.Context(), clientID, callback,
			[]string{"network.read"}, "management", base64.RawURLEncoding.EncodeToString(challenge[:]))
		if err != nil {
			t.Fatal(err)
		}
		out := send(rustURL, "POST", networkPath+network.String()+"/application-authorization-requests/"+pending.ID.String()+"/approve",
			`{"scopes":["network.read"]}`, web, 200)
		redirect, err := url.Parse(out["redirect_uri"].(string))
		if err != nil {
			t.Fatal(err)
		}
		grant, err := f.store.ExchangeApplicationAuthorizationCode(t.Context(), clientID, oldSecret, redirect.Query().Get("code"), verifier, callback)
		if err != nil {
			t.Fatalf("Go could not exchange the Rust-issued code: %v", err)
		}
		return grant
	}
	a, b := issued(f.network.ID), issued(second.ID)
	active := func(network identity.NetworkID, access string, want int) {
		t.Helper()
		for _, base := range []string{goURL, rustURL} {
			send(base, "GET", networkPath+network.String(), "", labCredentials{bearer: access}, want)
		}
	}
	active(f.network.ID, a.AccessToken, 200)
	active(second.ID, b.AccessToken, 200)
	send(rustURL, "DELETE", target, "", root, 409)
	send(rustURL, "POST", target+"/client-secrets", "", labCredentials{bearer: a.AccessToken}, 403)
	send(rustURL, "POST", target+"/disable", "", labCredentials{session: web.session, csrf: "wrong"}, 403)
	send(rustURL, "POST", target+"/client-secrets", `{"unknown":true}`, root, 400)

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	count := func(want int, query string, args ...any) {
		t.Helper()
		var result int
		if err := db.QueryRowContext(t.Context(), query, args...).Scan(&result); err != nil || result != want {
			t.Fatalf("wanted %d, got %d (%v): %s", want, result, err, query)
		}
	}
	exec(`CREATE TRIGGER lab_rotate_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='application.client_secret_rotate' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "POST", target+"/client-secrets", "", web, 500)
	if err := f.store.AuthenticateApplicationClient(t.Context(), clientID, oldSecret); err != nil {
		t.Fatal("failed rotation retired the working secret")
	}
	exec("DROP TRIGGER lab_rotate_abort")
	rotated := send(rustURL, "POST", target+"/client-secrets", "{}", web, 201)
	newSecret := rotated["client_secret"].(string)
	if newSecret == "" || newSecret == oldSecret || rotated["application_id"] != app {
		t.Fatal("rotation did not issue a new credential for the application")
	}
	if err := f.store.AuthenticateApplicationClient(t.Context(), clientID, oldSecret); err == nil {
		t.Fatal("Go still accepted the replaced secret")
	}
	if err := f.store.AuthenticateApplicationClient(t.Context(), clientID, newSecret); err != nil {
		t.Fatalf("Go could not authenticate the replacement secret: %v", err)
	}
	active(f.network.ID, a.AccessToken, 200)
	active(second.ID, b.AccessToken, 200)
	if _, err := f.store.RefreshApplicationToken(t.Context(), clientID, oldSecret, a.RefreshToken); err == nil {
		t.Fatal("the previous secret could still refresh the installation")
	}
	next, err := f.store.RefreshApplicationToken(t.Context(), clientID, newSecret, a.RefreshToken)
	if err != nil {
		t.Fatalf("the existing refresh family could not use the replacement client secret: %v", err)
	}
	active(f.network.ID, next.AccessToken, 200)

	exec(`CREATE TRIGGER lab_disable_app_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='application.disable' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "POST", target+"/disable", "", root, 500)
	active(f.network.ID, next.AccessToken, 200)
	active(second.ID, b.AccessToken, 200)
	exec("DROP TRIGGER lab_disable_app_abort")
	send(rustURL, "POST", target+"/disable", "", web, 204)
	send(rustURL, "POST", target+"/disable", "", root, 404)
	send(rustURL, "POST", target+"/client-secrets", "", root, 404)
	goApp := send(goURL, "GET", target, "", root, 200)
	rustApp := send(rustURL, "GET", target, "", web, 200)
	if goApp["enabled"] != false || !reflect.DeepEqual(goApp, rustApp) {
		t.Fatal("controllers disagree about the disabled application")
	}
	active(f.network.ID, next.AccessToken, 401)
	active(second.ID, b.AccessToken, 401)
	if err := f.store.AuthenticateApplicationClient(t.Context(), clientID, newSecret); err == nil {
		t.Fatal("disabled application still authenticates")
	}
	count(0, "SELECT count(*) FROM application_installations WHERE lower(hex(application_id))=? AND enabled=1", app)
	count(2, `SELECT count(*) FROM application_refresh_token_families
		WHERE lower(hex(application_id))=? AND revocation_reason='registered application disabled'`, app)
	count(0, "SELECT count(*) FROM registered_application_credentials WHERE lower(hex(application_id))=? AND revoked_at IS NULL", app)

	exec(`CREATE TRIGGER lab_delete_app_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='application.delete' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "DELETE", target, "", root, 500)
	send(goURL, "GET", target, "", root, 200)
	count(3, "SELECT count(*) FROM application_installations WHERE lower(hex(application_id))=?", app)
	exec("DROP TRIGGER lab_delete_app_abort")
	send(rustURL, "DELETE", target, "", root, 204)
	for _, base := range []string{goURL, rustURL} {
		send(base, "GET", target, "", root, 404)
	}
	count(0, "SELECT count(*) FROM application_installations WHERE lower(hex(application_id))=?", app)
	count(0, "SELECT count(*) FROM registered_application_credentials WHERE lower(hex(application_id))=?", app)
	count(0, "SELECT count(*) FROM application_refresh_token_families WHERE lower(hex(application_id))=?", app)
	count(2, "SELECT count(*) FROM automation_service_principals WHERE enabled=0 AND id IN (?,?)",
		a.Installation.ServicePrincipalID[:], b.Installation.ServicePrincipalID[:])
	count(3, `SELECT count(*) FROM audit_events WHERE lower(hex(target_id))=?
		AND action IN ('application.client_secret_rotate','application.disable','application.delete')`, app)
	count(0, "SELECT count(*) FROM audit_events WHERE instr(details_json,?)>0", newSecret)
}
