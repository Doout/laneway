//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func testRustBearerInventory(t *testing.T, f fixture, cookie string, check func(string, string, http.Header, int, ...string) map[string]any) {
	t.Helper()
	const networks = "/v1/admin/networks"
	// Issue credentials and change grants on Go while both servers remain running.
	other, err := f.store.CreateNetwork(t.Context(), "scoped", netip.MustParsePrefix("10.198.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string, body any, status int, out any) {
		t.Helper()
		r := bearerJSONRequest("POST", "https://controller.example/v1/admin/"+path, body, testRootBearer)
		w := httptest.NewRecorder()
		f.service.Handler().ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("fixture setup %s: HTTP %d", path, w.Code)
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	issue := func(name string, all bool, ops []string) (string, string, string) {
		t.Helper()
		principal := map[string]any{"name": name, "all_networks": all, "permissions": ops}
		if !all {
			principal["network_ids"] = []string{other.ID.String()}
		}
		var p servicePrincipalResponse
		post("service-principals", principal, 201, &p)
		var tok struct {
			AccessToken string                     `json:"access_token"`
			Token       serviceAccessTokenResponse `json:"token"`
		}
		post("service-principals/"+p.PrincipalID+"/tokens", map[string]any{"label": "fixture", "expires_at_unix_seconds": time.Now().Add(time.Hour).Unix()}, 201, &tok)
		if tok.AccessToken == "" {
			t.Fatal("no fixture token")
		}
		return tok.AccessToken, tok.Token.TokenID, p.PrincipalID
	}
	scoped, tid, _ := issue("scoped-inventory", false, []string{"network.list", "network.read", "node.read"})
	all, _, pid := issue("all-inventory", true, []string{"network.list"})
	bearerHeader := func(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }
	l := check("scoped list", networks+"?limit=1", bearerHeader(scoped), 200)
	rows := l["networks"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["network_id"] != other.ID.String() {
		t.Fatal("scope must filter before limit")
	}
	check("allowed nodes", networks+"/"+other.ID.String()+"/nodes", bearerHeader(scoped), 200)
	check("allowed network", networks+"/"+other.ID.String(), bearerHeader(scoped), 200)
	check("network outside scope", networks+"/"+f.network.ID.String(), bearerHeader(scoped), 403)
	check("list permission does not imply detail", networks+"/"+other.ID.String(), bearerHeader(all), 403)
	check("denied network", networks+"/"+f.network.ID.String()+"/nodes", bearerHeader(scoped), 403)
	check("denied permission", networks+"/"+other.ID.String()+"/nodes", bearerHeader(all), 403)
	check("all networks", networks, bearerHeader(all), 200)
	check("root", networks, bearerHeader(testRootBearer), 200)
	check("root credential probe", "/v1/admin/auth/root", bearerHeader(testRootBearer), 204)
	check("automation is not root", "/v1/admin/auth/root", bearerHeader(all), 401)
	check("browser session is not root", "/v1/admin/auth/root", nil, 401, cookie)
	check("root nodes", networks+"/"+f.network.ID.String()+"/nodes", bearerHeader(testRootBearer), 200)
	check("wrong root scheme", networks, http.Header{"Authorization": {"bearer " + testRootBearer}}, 401)
	check("automation scheme", networks, http.Header{"Authorization": {"bearer " + scoped}}, 200)
	for _, auth := range []string{testRootBearer, scoped} {
		for _, k := range []string{"Origin", "Sec-Fetch-Site"} {
			h := bearerHeader(auth)
			h.Set(k, "")
			check("browser "+k, networks, h, 401)
		}
		check("mixed credentials", networks, bearerHeader(auth), 401, cookie)
		check("duplicate authorization", networks, http.Header{"Authorization": {"Bearer " + auth, "Bearer " + auth}}, 401)
	}
	// Valid token ID and encoding, but the secret belongs to a different token.
	check("wrong secret", networks, bearerHeader(scoped[:strings.LastIndex(scoped, ".")+1]+all[strings.LastIndex(all, ".")+1:]), 401)
	// Seed time-bound tokens directly: the management API correctly refuses
	// to issue an already-expired credential. No sleeping or clock changes.
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	principal, err := identity.ParseID(pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, hours := range []int64{-2, 1} {
		id, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		token, digest, err := adminauth.NewServiceAccessToken(id, nil)
		if err != nil {
			t.Fatal(err)
		}
		created := time.Now().Unix() + 3600*hours
		if _, err = db.ExecContext(t.Context(), "INSERT INTO automation_service_access_tokens(id,principal_id,label,token_hash,created_at,expires_at) VALUES(?,?,'time-window',?,?,?)", id[:], principal[:], digest[:], created, created+3600); err != nil {
			t.Fatal(err)
		}
		check("outside validity interval", networks, bearerHeader(token), 401)
	}
	post("service-access-tokens/"+tid+"/revoke", map[string]any{"reason": "test complete"}, 204, nil)
	check("revoked", networks, bearerHeader(scoped), 401)
	post("service-principals/"+pid+"/disable", nil, 204, nil)
	check("disabled", networks, bearerHeader(all), 401)
}
