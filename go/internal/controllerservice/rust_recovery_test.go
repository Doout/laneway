//go:build rustinterop

package controllerservice

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

func startRustAdministratorLab(t *testing.T, database, cert, key, rootFile string) (string, func()) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", database, "127.0.0.1:0", cert, key, "--root-token-file", rootFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	t.Cleanup(stop)
	announce := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); announce <- strings.TrimSpace(line) }()
	select {
	case line := <-announce:
		if !strings.HasPrefix(line, "listening https://127.0.0.1:") {
			t.Fatalf("administrator listener did not start: %q", line)
		}
		return strings.TrimPrefix(line, "listening "), stop
	case <-time.After(10 * time.Second):
		t.Fatal("administrator listener startup timed out")
		return "", nil
	}
}

func testRustAdministratorRecovery(t *testing.T, client *http.Client, pair tls.Certificate, cert, key, rootFile string) {
	t.Helper()
	f := newFixture(t, 0, nil)
	useProductionRootAccess(t, f)
	goServer := httptest.NewUnstartedServer(f.service.Handler())
	goServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	goServer.StartTLS()
	t.Cleanup(goServer.Close)
	rustURL, stop := startRustAdministratorLab(t, f.dbPath, cert, key, rootFile)

	const auth = "/v1/admin/auth/"
	const username = "recovery-owner"
	const oldPassword = "lab owner initial fixture password"
	const newPassword = "lab owner replacement fixture password"
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	for _, base := range []string{rustURL, goServer.URL} {
		rows := send(base, "GET", "/v1/admin/administrators", "", root, 200)["administrators"]
		if values, ok := rows.([]any); !ok || len(values) != 0 {
			t.Fatal("unconfigured controller must return an empty administrator list")
		}
	}
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
	count := func(want int, query string, args ...any) {
		t.Helper()
		var got int
		if err := db.QueryRowContext(t.Context(), query, args...).Scan(&got); err != nil || got != want {
			t.Fatalf("state check: got %d, want %d: %v (%s)", got, want, err, query)
		}
	}
	browserPost := func(base, path, origin string, body map[string]string, want int) (http.Header, []*http.Cookie) {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("POST %s: got %d, want %d", path, resp.StatusCode, want)
		}
		if want == http.StatusNoContent && (len(payload) != 0 || len(resp.Cookies()) != 0) {
			t.Fatal("grant redemption must not create a session")
		}
		return resp.Header, resp.Cookies()
	}
	bootstrap := func(secret string) map[string]string {
		return map[string]string{"grant": secret, "username": username, "password": oldPassword}
	}
	grant := func(base, path string) string {
		t.Helper()
		result := send(base, "POST", path, "", root, 201)
		secret, ok := result["grant"].(string)
		expires, expiryOK := result["expires_at_unix_seconds"].(float64)
		if !ok || len(secret) != 43 || !expiryOK || time.Until(time.Unix(int64(expires), 0)) < 9*time.Minute {
			t.Fatal("invalid grant envelope")
		}
		return secret
	}

	send(rustURL, "POST", auth+"bootstrap-grants", "", labCredentials{}, 401)
	rustGrant := grant(rustURL, auth+"bootstrap-grants")
	candidate, err := f.store.AdministratorRecoveryCandidate(t.Context(), rustGrant, controller.AdministratorRecoveryBootstrapOwner)
	if err != nil || !candidate.Usable {
		t.Fatalf("Go cannot validate Rust-issued bootstrap grant: %v", err)
	}
	goGrant := grant(goServer.URL, auth+"bootstrap-grants")
	browserPost(rustURL, auth+"bootstrap", "https://untrusted.example", bootstrap(goGrant), 403)
	browserPost(rustURL, auth+"bootstrap", rustURL, bootstrap(rustGrant), 401)
	browserPost(rustURL, auth+"bootstrap", rustURL, bootstrap(goGrant), 204)
	browserPost(rustURL, auth+"bootstrap", rustURL, bootstrap(goGrant), 401)
	send(rustURL, "POST", auth+"bootstrap-grants", "", root, 409)
	authState, err := f.store.AdministratorAuthState(t.Context())
	if err != nil || authState.InitialOwnerPrincipalID == nil {
		t.Fatalf("Go cannot read Rust-bootstrapped administrator: %v", err)
	}
	owner := authState.InitialOwnerPrincipalID.String()
	recoveryPath := "/v1/admin/administrators/" + owner + "/recovery-grants"
	login := func(base, password string, want int) labCredentials {
		t.Helper()
		_, cookies := browserPost(base, auth+"login", base, map[string]string{"username": username, "password": password}, want)
		var session labCredentials
		for _, c := range cookies {
			switch c.Name {
			case adminauth.SessionCookieName:
				session.session = c.Value
			case adminauth.CSRFCookieName:
				session.csrf = c.Value
			}
		}
		if want == 200 && (session.session == "" || session.csrf == "") {
			t.Fatal("login did not create a session")
		}
		return session
	}
	oldSession := login(goServer.URL, oldPassword, 200)
	send(rustURL, "POST", recoveryPath, "", oldSession, 403)
	send(rustURL, "POST", "/v1/admin/administrators/abcabcabcabcabcabcabcabcabcabcab/recovery-grants", "", root, 404)
	automationID := send(goServer.URL, "POST", "/v1/admin/service-principals",
		`{"name":"recovery-reader","permissions":["audit.read_global"]}`, root, 201)["principal_id"].(string)
	tokenRequest, _ := json.Marshal(map[string]any{"label": "lab", "expires_at_unix_seconds": time.Now().Add(time.Hour).Unix()})
	automation := send(goServer.URL, "POST", "/v1/admin/service-principals/"+automationID+"/tokens",
		string(tokenRequest), root, 201)["access_token"].(string)
	send(rustURL, "POST", recoveryPath, "", labCredentials{bearer: automation}, 403)

	expired := grant(rustURL, recoveryPath)
	execSQL("UPDATE administrator_recovery_grants SET created_at=unixepoch()-2,expires_at=unixepoch()-1 WHERE purpose='owner_recovery'")
	recoverBody := func(secret string) map[string]string {
		return map[string]string{"grant": secret, "password": newPassword}
	}
	browserPost(rustURL, auth+"recover", rustURL, recoverBody(expired), 401)
	recovery := grant(rustURL, recoveryPath)
	hash, err := adminauth.HashSecret(adminauth.SecretRecovery, recovery)
	if err != nil {
		t.Fatal(err)
	}
	count(1, "SELECT count(*) FROM administrator_recovery_grants WHERE secret_hash=? AND consumed_at IS NULL", hash[:])
	count(1, "SELECT count(*) FROM administrator_recovery_grants WHERE revocation_reason='expired'")
	execSQL(`CREATE TRIGGER lab_recovery_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='administrator.recovery.complete' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	browserPost(rustURL, auth+"recover", rustURL, recoverBody(recovery), 500)
	count(1, "SELECT count(*) FROM administrator_recovery_grants WHERE secret_hash=? AND consumed_at IS NULL", hash[:])
	count(1, "SELECT count(*) FROM administrator_auth_state WHERE recovery_generation=0 AND last_recovered_at IS NULL")
	count(0, "SELECT count(*) FROM administrator_credentials WHERE revoked_at IS NOT NULL")
	send(rustURL, "GET", auth+"session", "", oldSession, 200)
	execSQL("DROP TRIGGER lab_recovery_abort")

	browserPost(rustURL, auth+"recover", rustURL, recoverBody(recovery), 204)
	browserPost(rustURL, auth+"recover", rustURL, recoverBody(recovery), 401)
	var ownerSession labCredentials
	for _, base := range []string{rustURL, goServer.URL} {
		send(base, "GET", auth+"session", "", oldSession, 401)
		login(base, oldPassword, 401)
		ownerSession = login(base, newPassword, 200)
	}
	count(1, "SELECT count(*) FROM administrator_auth_state WHERE recovery_generation=1 AND last_recovered_at IS NOT NULL")
	count(1, "SELECT count(*) FROM administrator_credentials WHERE revocation_reason='owner recovery'")
	count(1, "SELECT count(*) FROM administrator_sessions WHERE revocation_reason='owner recovery'")
	count(1, `SELECT count(*) FROM audit_events a JOIN administrator_recovery_grants g ON g.id=a.actor_id
		WHERE a.action='administrator.recovery.complete' AND a.actor_kind='recovery_grant'
		AND g.secret_hash=? AND g.consumed_at IS NOT NULL AND lower(hex(a.target_id))=?`, hash[:], owner)
	count(4, "SELECT count(*) FROM audit_events WHERE action='administrator.recovery.failure' AND details_json=?", `{"reason":"recovery_rejected"}`)
	count(0, "SELECT count(*) FROM audit_events WHERE instr(details_json,?)>0 OR instr(details_json,?)>0", recovery, newPassword)
	t.Run("inventory", func(t *testing.T) {
		testRustAdministratorInventory(t, f, client, goServer.URL, rustURL, username, owner, ownerSession, labCredentials{bearer: automation})
	})
	t.Run("changes", func(t *testing.T) {
		testRustAdministratorChanges(t, f, client, goServer.URL, rustURL, owner, ownerSession, labCredentials{bearer: automation})
	})
	t.Run("automation", func(t *testing.T) {
		testRustAutomationCredentials(t, f, client, goServer.URL, rustURL, ownerSession, labCredentials{bearer: automation})
	})
	t.Run("root-rotation", func(t *testing.T) {
		testRustRootRotation(t, f, client, goServer.URL, rustURL, stop, cert, key, ownerSession, labCredentials{bearer: automation})
	})
}

func testRustAdministratorInventory(t *testing.T, f fixture, client *http.Client, goURL, rustURL, username, owner string, web, automation labCredentials) {
	t.Helper()
	const path = "/v1/admin/administrators"
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	auditor, csrf := rustScopedBrowserFixture(t, f, "auditor")
	for _, check := range []struct {
		path string
		auth labCredentials
		code int
	}{
		{path, root, 200},
		{path + "?limit=1", web, 200},
		{path + "?username=" + username, root, 200},
		{path + "?username=does-not-exist", root, 200},
		{path + "?username=" + username + "&limit=2", root, 400},
		{path + "?username=" + username + "&username=", root, 400},
		{path + "?username=UPPERCASE", root, 400},
		{path + "?limit=1001", root, 400},
		{path + "?username=" + username, web, 403},
		{path, labCredentials{session: auditor, csrf: csrf}, 403},
		{path, automation, 403},
		{path + "/" + owner, web, 200},
		{path + "/invalid", root, 400},
		{path + "/abcabcabcabcabcabcabcabcabcabcab", root, 404},
		{path + "/" + owner + "/sessions", web, 200},
		{path + "/" + owner + "/sessions?limit=1", root, 200},
	} {
		goResult := send(goURL, "GET", check.path, "", check.auth, check.code)
		rustResult := send(rustURL, "GET", check.path, "", check.auth, check.code)
		if !reflect.DeepEqual(goResult, rustResult) {
			t.Fatalf("administrator inventory differs at %s", check.path)
		}
	}
	sessions := send(rustURL, "GET", path+"/"+owner+"/sessions", "", web, 200)["sessions"].([]any)
	current, revoked := 0, 0
	for _, value := range sessions {
		s := value.(map[string]any)
		if s["current"] == true && s["state"] == "active" {
			current++
		}
		if s["state"] == "revoked" && s["revocation_reason"] == "owner recovery" {
			revoked++
		}
	}
	if current != 1 || revoked != 1 {
		t.Fatalf("incorrect current/revoked session totals: %d/%d", current, revoked)
	}
}

func testRustRootRotation(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, stop func(), cert, key string, web, automation labCredentials) {
	t.Helper()
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	rotationID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/auth/root-token-rotations/" + rotationID.String()
	send(rustURL, "POST", path+"/complete", "", root, 409)
	send(rustURL, "POST", path+"/begin", "", web, 403)
	send(rustURL, "POST", path+"/begin", "", automation, 403)
	send(rustURL, "POST", "/v1/admin/auth/root-token-rotations/invalid/begin", "", root, 400)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(), `CREATE TRIGGER lab_rotation_abort BEFORE INSERT ON administrator_root_token_rotations
		BEGIN SELECT RAISE(ABORT,'lab rotation rollback'); END`); err != nil {
		t.Fatal(err)
	}
	send(rustURL, "POST", path+"/begin", "", root, 500)
	var orphan int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_events WHERE target_id=?", rotationID[:]).Scan(&orphan); err != nil || orphan != 0 {
		t.Fatalf("failed begin left an audit event without its marker: %d (%v)", orphan, err)
	}
	if _, err := db.ExecContext(t.Context(), "DROP TRIGGER lab_rotation_abort"); err != nil {
		t.Fatal(err)
	}
	send(rustURL, "POST", path+"/begin", "", root, 204)
	send(goURL, "POST", path+"/begin", "", root, 204)
	stop()

	const nextToken = "replacement-root-secret-for-local-fixtures"
	next := filepath.Join(t.TempDir(), "next.token")
	if err := os.WriteFile(next, []byte(nextToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rustURL, _ = startRustAdministratorLab(t, f.dbPath, cert, key, next)
	send(rustURL, "POST", path+"/complete", "", root, 401)
	newRoot := labCredentials{bearer: nextToken}
	for range 2 {
		send(rustURL, "POST", path+"/complete", "", newRoot, 204)
	}
	var markers, events int
	err = db.QueryRowContext(t.Context(), `SELECT
	  (SELECT count(*) FROM administrator_root_token_rotations r
	   JOIN audit_events a ON a.id=r.begin_audit_event_id
	   JOIN audit_events b ON b.id=r.complete_audit_event_id
	   JOIN administrator_auth_state s ON s.singleton=1
	   WHERE r.rotation_id=?1 AND r.begun_at=a.created_at AND r.completed_at=b.created_at
	     AND r.completed_at>=r.begun_at AND a.actor_id=s.root_service_principal_id
	     AND a.actor_id=b.actor_id AND a.actor_kind='service_principal' AND a.actor_kind=b.actor_kind
	     AND a.details_json=b.details_json AND json_extract(a.details_json,'$.rotation_id')=?2),
	  (SELECT count(*) FROM audit_events WHERE target_id=?1
	   AND action IN ('administrator.root_token.rotate.begin','administrator.root_token.rotate.complete'))`,
		rotationID[:], rotationID.String()).Scan(&markers, &events)
	if err != nil || markers != 1 || events != 2 {
		t.Fatalf("rotation must commit exactly one marker and two linked audit events: %d/%d (%v)", markers, events, err)
	}
}
