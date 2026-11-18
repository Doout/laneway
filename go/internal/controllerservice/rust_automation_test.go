//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
)

func testRustAutomationCredentials(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, web, unprivileged labCredentials) {
	t.Helper()
	const principals = "/v1/admin/service-principals"
	const tokens = "/v1/admin/service-access-tokens"
	const networks = "/v1/admin/networks"
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	body := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	same := func(path string, caller labCredentials, code int) map[string]any {
		t.Helper()
		goResult := send(goURL, "GET", path, "", caller, code)
		rustResult := send(rustURL, "GET", path, "", caller, code)
		if !reflect.DeepEqual(goResult, rustResult) {
			t.Fatalf("Go and Rust returned different representations for %s", path)
		}
		return rustResult
	}
	scoped := body(map[string]any{
		"name": "rust-scoped-reader", "network_ids": []string{f.network.ID.String()},
		"permissions": []string{"network.read", "network.list", "audit.read_global"},
	})
	same(principals, unprivileged, 403)
	same(principals+"?limit=0", root, 400)
	send(rustURL, "POST", principals, scoped, unprivileged, 403)
	send(rustURL, "POST", principals, scoped, labCredentials{session: web.session, csrf: "invalid"}, 403)
	for _, invalid := range []string{
		`{"name":"invalid-scope","permissions":["network.list"]}`,
		`{"name":"global-only","all_networks":true,"permissions":["audit.read_global"]}`,
		`{"name":"cannot-delegate","permissions":["service_principal.manage","root_token.rotate"]}`,
		`{"name":"duplicate-permissions","permissions":["audit.read_global","audit.read_global"]}`,
		`{"name":"no-such-network","network_ids":["abcabcabcabcabcabcabcabcabcabcab"],"permissions":["network.list"]}`,
	} {
		send(rustURL, "POST", principals, invalid, root, 400)
	}
	principal := send(rustURL, "POST", principals, scoped, web, 201)
	id := principal["principal_id"].(string)
	send(rustURL, "POST", principals, scoped, root, 409)
	same(principals, web, 200)
	same(principals+"/"+id+"/tokens", web, 200)
	otherNetwork, err := f.store.CreateNetwork(t.Context(), "automation-other", netip.MustParsePrefix("10.97.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := principals + "/" + id + "/tokens"
	expires := time.Now().Add(time.Hour).Unix()
	issueBody := func(label string, expiry int64) string {
		return body(map[string]any{"label": label, "expires_at_unix_seconds": expiry})
	}
	send(rustURL, "POST", tokenPath, issueBody("expired", time.Now().Add(-time.Minute).Unix()), root, 400)
	send(rustURL, "POST", tokenPath, issueBody("bad\x00label", expires), root, 400)
	send(rustURL, "POST", tokenPath, issueBody("too long-lived", time.Now().AddDate(2, 0, 0).Unix()), root, 400)
	issue := func(base, label string, caller labCredentials) (labCredentials, string) {
		t.Helper()
		result := send(base, "POST", tokenPath, issueBody(label, expires), caller, 201)
		id := result["token"].(map[string]any)["token_id"].(string)
		return labCredentials{bearer: result["access_token"].(string)}, id
	}
	minted, tokenID := issue(rustURL, "native token", web)
	fromGo, _ := issue(goURL, "reference token", root)
	second, _ := issue(rustURL, "native retained", root)
	for _, credential := range []labCredentials{minted, fromGo, second} {
		visible := same(networks, credential, 200)["networks"].([]any)
		if len(visible) != 1 || visible[0].(map[string]any)["network_id"] != f.network.ID.String() {
			t.Fatal("automation token escaped its network list scope")
		}
		same(networks+"/"+f.network.ID.String(), credential, 200)
		same(networks+"/"+otherNetwork.ID.String(), credential, 403)
		send(rustURL, "GET", principals, "", credential, 403)
	}
	same(tokenPath, web, 200)

	revoke := tokens + "/" + tokenID + "/revoke"
	send(rustURL, "POST", revoke, `{"reason":" bad whitespace "}`, root, 400)
	send(rustURL, "POST", revoke, `{"reason":"planned replacement"}`, web, 204)
	send(rustURL, "POST", revoke, `{"reason":"duplicate"}`, root, 409)
	same(networks, minted, 401)

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execSQL := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	resolved, digest, err := adminauth.ParseServiceAccessToken(minted.bearer)
	if err != nil || resolved.String() != tokenID {
		t.Fatal("Rust produced a token that Go could not validate")
	}
	var count int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM automation_service_access_tokens WHERE id=? AND token_hash=?",
		resolved[:], digest[:]).Scan(&count); err != nil || count != 1 {
		t.Fatalf("persisted digest does not match the Go format: %v", err)
	}
	// An expired credential stays in the list and is retired on disable,
	// but must not consume a slot in the active-token cap.
	execSQL(`INSERT INTO automation_service_access_tokens(id,principal_id,label,token_hash,created_at,expires_at)
		SELECT randomblob(16), id, 'expired lab token', randomblob(32), unixepoch()-2, unixepoch()-1
		FROM automation_service_principals WHERE lower(hex(id))=?`, id)
	execSQL(`WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM seq WHERE i<97)
		INSERT INTO automation_service_access_tokens(id,principal_id,label,token_hash,created_at,expires_at)
		SELECT randomblob(16), p.id, 'cap fixture', randomblob(32), unixepoch(), unixepoch()+600
		FROM automation_service_principals p, seq WHERE lower(hex(p.id))=?`, id)
	issue(rustURL, "last active slot", root)
	send(rustURL, "POST", tokenPath, issueBody("over active cap", expires), root, 409)
	same(tokenPath+"?limit=1", root, 200)
	if listed := same(tokenPath+"?limit=1000", root, 200)["tokens"].([]any); len(listed) != 102 ||
		listed[99].(map[string]any)["state"] != "active" ||
		listed[100].(map[string]any)["state"] != "expired" ||
		listed[101].(map[string]any)["state"] != "revoked" {
		t.Fatal("token history order or active-cap accounting does not match")
	}

	disable := principals + "/" + id + "/disable"
	execSQL(`CREATE TRIGGER lab_disable_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='service_principal.disable' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "POST", disable, "", web, 500)
	same(networks, fromGo, 200)
	execSQL("DROP TRIGGER lab_disable_abort")
	send(rustURL, "POST", disable, "", root, 204)
	send(rustURL, "POST", disable, "", root, 409)
	same(networks, fromGo, 401)
	same(networks, second, 401)
	send(rustURL, "POST", tokenPath, issueBody("disabled", expires), root, 404)
	same(principals, root, 200)
	same(tokenPath+"?limit=1000", root, 200)
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='service_principal.disable' AND lower(hex(target_id))=? AND json_extract(details_json,'$.revoked_tokens')=101`,
		id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("disable didn't audit revocation of the outstanding token set: %d (%v)", count, err)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_events WHERE instr(details_json,?)>0", minted.bearer).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit included a plaintext token or could not be checked: %v", err)
	}
}
