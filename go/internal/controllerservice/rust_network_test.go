//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

type labCredentials struct{ bearer, session, csrf string }

func labManagementHTTP(t *testing.T, client *http.Client) func(string, string, string, string, labCredentials, int) map[string]any {
	return func(base, method, route, body string, c labCredentials, want int) map[string]any {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, base+route, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if c.bearer != "" {
			r.Header.Set("Authorization", "Bearer "+c.bearer)
		}
		if c.session != "" {
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: c.session})
			r.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: c.csrf})
			r.Header.Set(adminauth.CSRFHeaderName, c.csrf)
			r.Header.Set("Origin", base)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var value map[string]any
		if res.StatusCode != http.StatusNoContent {
			if err = json.NewDecoder(res.Body).Decode(&value); err != nil {
				t.Fatal(err)
			}
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: got %d (%v), want %d", method, route, res.StatusCode, value["detail"], want)
		}
		if (res.Header.Get(administratorSessionIDHeader) != "") != (want < 400 && c.session != "") {
			t.Fatal("unexpected browser metadata")
		}
		delete(value, "request_id")
		return value
	}
}

func testRustNetworkManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL, token, csrf string) {
	t.Helper()
	const path = "/v1/admin/networks"
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	type credentials = labCredentials
	owner := credentials{session: token, csrf: csrf}
	root := credentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	create := func(name, id string) string {
		data, err := json.Marshal(networkRequest{NetworkID: id, Name: name, IPv4Pool: "10.186.0.0/24", IPv6Pool: "fd86:1::/64"})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	// Go issues a global-only credential. It may create, but not read,
	// networks. The Rust audit actor must be the principal, never its token.
	principal := send(goURL, "POST", "/v1/admin/service-principals", `{"name":"network-creator","permissions":["network.create"]}`, root, 201)["principal_id"].(string)
	args, _ := json.Marshal(map[string]any{"label": "lab", "expires_at_unix_seconds": time.Now().Add(time.Hour).Unix()})
	issued := send(goURL, "POST", "/v1/admin/service-principals/"+principal+"/tokens", string(args), root, 201)
	automation := credentials{bearer: issued["access_token"].(string)}
	authState, err := f.store.AdministratorAuthState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, base, actor, kind, id string
		c                           credentials
	}{
		{"rust-owner", rustURL, authState.InitialOwnerPrincipalID.String(), "administrator", "", owner},
		{"rust-root", rustURL, authState.RootServicePrincipalID.String(), "service_principal", "abcabcabcabcabcabcabcabcabcabcab", root},
		{"rust-automation", rustURL, principal, "service_principal", "", automation},
		{"go-reference", goURL, authState.RootServicePrincipalID.String(), "service_principal", "", root},
	} {
		created := send(tc.base, "POST", path, create(tc.name, tc.id), tc.c, 201)
		id := created["network_id"].(string)
		if (tc.id != "" && tc.id != id) || created["configuration_epoch"] != float64(1) {
			t.Fatal("incorrect created identity or epoch")
		}
		for _, base := range []string{goURL, rustURL} {
			if !reflect.DeepEqual(created, send(base, "GET", path+"/"+id, "", root, 200)) {
				t.Fatal("network details differ")
			}
		}
		var count int
		err = db.QueryRow(`SELECT count(*) FROM audit_events a JOIN networks n ON n.id=a.network_id WHERE lower(hex(n.id))=? AND a.target_id=n.id AND a.action='network.create' AND a.target_type='network' AND a.details_json='{}' AND a.actor_kind=? AND lower(hex(a.actor_id))=? AND a.created_at=n.created_at AND n.next_ipv4=1 AND n.next_ipv6=1`, id, tc.kind, tc.actor).Scan(&count)
		if err != nil || count != 1 {
			t.Fatalf("network %s: audit or initial allocation state mismatch (%d, %v)", tc.name, count, err)
		}
		networkID, err := identity.ParseNetworkID(id)
		if err != nil {
			t.Fatal(err)
		}
		enroll, err := f.store.IssueEnrollmentToken(t.Context(), networkID, "interop", time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("Go could not use created network: %v", err)
		}
		node, err := f.store.EnrollNode(t.Context(), enroll.Secret, "first-node", 0)
		if err != nil || node.IPv4Address.String() != "10.186.0.1" || node.IPv6Address.String() != "fd86:1::1" {
			t.Fatalf("Go could not allocate first dual-stack addresses: %v", err)
		}
		if send(rustURL, "GET", path+"/"+id, "", root, 200)["configuration_epoch"] != float64(2) {
			t.Fatal("Rust did not see the Go enrollment epoch")
		}
		nodes := send(rustURL, "GET", path+"/"+id+"/nodes", "", root, 200)["nodes"].([]any)
		if len(nodes) != 1 {
			t.Fatal("Rust did not see the enrolled node")
		}
		row := nodes[0].(map[string]any)
		if row["ipv4_address"] != node.IPv4Address.String() || row["ipv6_address"] != node.IPv6Address.String() {
			t.Fatal("Rust and Go disagree on assigned addresses")
		}
		send(rustURL, "GET", path+"/"+id, "", automation, 403)
		send(rustURL, "POST", path, create(tc.name, ""), root, 409)
	}
	for _, s := range []string{"operator", "auditor"} {
		candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-"+s)
		if err != nil {
			t.Fatal(err)
		}
		_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		c := credentials{session: token, csrf: csrf}
		for _, base := range []string{goURL, rustURL} {
			send(base, "POST", path, create("forbidden", ""), c, 403)
			send(base, "GET", path+"/"+f.network.ID.String(), "", c, 200)
			send(base, "GET", path+"/abcabcabcabcabcabcabcabcabcabcab", "", c, 403)
		}
	}
	// Create-only authorization is not implied by even an all-networks
	// reader, and revocation by Go must take effect on the next Rust write.
	readerID := send(goURL, "POST", "/v1/admin/service-principals", `{"name":"net-read","all_networks":true,"permissions":["network.read"]}`, root, 201)["principal_id"].(string)
	reader := credentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+readerID+"/tokens", string(args), root, 201)["access_token"].(string)}
	tokenID := issued["token"].(map[string]any)["token_id"].(string)
	revoke := bearerJSONRequest("POST", goURL+"/v1/admin/service-access-tokens/"+tokenID+"/revoke", map[string]any{"reason": "fixture complete"}, testRootBearer)
	w := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(w, revoke)
	if w.Code != 204 {
		t.Fatalf("revoke fixture token: HTTP %d", w.Code)
	}
	for _, base := range []string{goURL, rustURL} {
		send(base, "POST", path, create("denied", ""), reader, 403)
		send(base, "POST", path, `{"unknown":1}`, reader, 400)
		send(base, "POST", path, create("denied", ""), automation, 401)
	}
	v4 := send(rustURL, "POST", path, `{"Name":"ignored","NAME":"v4-only","name":null,"IPv4_Pool":"10.150.0.0/20"}`, root, 201)
	if v4["name"] != "v4-only" || v4["ipv6_pool"] != nil || !reflect.DeepEqual(v4, send(goURL, "GET", path+"/"+v4["network_id"].(string), "", root, 200)) {
		t.Fatal("IPv4-only network mismatch")
	}
	for _, tc := range []struct {
		body   string
		c      credentials
		status int
	}{
		{create("denied", ""), credentials{}, 401},
		{create("denied", ""), credentials{session: token, csrf: "wrong"}, 403},
		{create("denied", ""), credentials{session: token, csrf: csrf, bearer: testRootBearer}, 401},
		{create("bad-id", "NOT-AN-ID"), owner, 400},
		{create(" white", ""), root, 400},
		{create("not-duplicate-name", "abcabcabcabcabcabcabcabcabcabcab"), root, 409},
		{`{"name":"bad","ipv4_pool":"169.0.0.0/8"}`, root, 400},
		{`{"name":"bad","ipv4_pool":"10.0.0.1/24"}`, root, 400},
		{`{"name":"bad","ipv4_pool":"10.0.0.0/24","ipv6_pool":"fe80::/64"}`, root, 400},
		{`{"name":"bad","ipv4_pool":"10.0.0.0/24","ipv6_pool":"FD86::/64"}`, root, 400},
		{`{"unknown":1}`, root, 400},
		{strings.Repeat(" ", 131073), root, 413},
	} {
		a := send(goURL, "POST", path, tc.body, tc.c, tc.status)
		b := send(rustURL, "POST", path, tc.body, tc.c, tc.status)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("network error mismatch: Go %v Rust %v", a, b)
		}
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_network_audit BEFORE INSERT ON audit_events WHEN NEW.action='network.create' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	send(rustURL, "POST", path, create("must-roll-back", ""), owner, 500)
	var n int
	if err = db.QueryRow("SELECT count(*) FROM networks WHERE name IN ('must-roll-back','forbidden','denied')").Scan(&n); err != nil || n != 0 {
		t.Fatalf("failed write survived: %d, %v", n, err)
	}
	if _, err = db.Exec("DROP TRIGGER reject_network_audit"); err != nil {
		t.Fatal(err)
	}
	// Both implementations contend for the same immutable ID in WAL mode.
	const raceID = "abcdabcdabcdabcdabcdabcdabcdabcd"
	start := make(chan struct{})
	status := make(chan int, 2)
	for _, base := range []string{rustURL, goURL} {
		r, err := http.NewRequestWithContext(t.Context(), "POST", base+path, strings.NewReader(create("single-winner", raceID)))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+testRootBearer)
		r.Header.Set("Content-Type", "application/json")
		go func() {
			<-start
			resp, err := client.Do(r)
			if err != nil {
				status <- 0
				return
			}
			resp.Body.Close()
			status <- resp.StatusCode
		}()
	}
	close(start)
	a, b := <-status, <-status
	if !((a == 201 && b == 409) || (a == 409 && b == 201)) {
		t.Fatalf("expected exactly one successful create, got %d and %d", a, b)
	}
	if err = db.QueryRow(`SELECT count(*) FROM audit_events WHERE lower(hex(target_id))=? AND action='network.create'`, raceID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("raced creation audit count %d: %v", n, err)
	}
}
