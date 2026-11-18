//go:build rustinterop

package controllerservice

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/applicationauth"
)

func testRustApplicationRegistration(t *testing.T, f fixture, client *http.Client, goURL, rustURL string, web, automation labCredentials) {
	t.Helper()
	const reviewPath = "/v1/admin/application-registration-requests/"
	const applications = "/v1/admin/applications"
	const exchange = "/v1/application-registrations/exchange"
	const proof = "this-is-a-long-verifier-for-the-lab-fixture-registration"
	const state = "state +/~ fixture"
	challenge := sha256.Sum256([]byte(proof))
	root := labCredentials{bearer: testRootBearer}
	noFollow := *client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	send := labManagementHTTP(t, &noFollow)
	jsonBody := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	manifest := applicationauth.Manifest{
		Name: "Router lab", HomepageURI: "https://dispatch.example",
		SetupURI:     "https://dispatch.example/setup?keep=%7E&state=prior",
		RedirectURIs: []string{"https://dispatch.example/callback-b", "https://dispatch.example/callback-a"},
		Scopes:       []string{"route.manage", "network.read"}, TokenEndpointAuthMethod: "client_secret_basic",
	}
	form := func(value applicationauth.Manifest) string {
		return url.Values{
			"manifest": {jsonBody(value)}, "state": {state},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"},
		}.Encode()
	}
	start := func(base, encoded string, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "POST", base+"/applications/new", strings.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("registration start returned %d, want %d", resp.StatusCode, want)
		}
		if want != 303 {
			return ""
		}
		location, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || location.IsAbs() || location.Path != "/applications/consent" || location.Query().Get("request") == "" {
			t.Fatal("registration did not link to the consent screen")
		}
		return location.Query().Get("request")
	}
	for _, invalid := range []string{
		"http://dispatch.example/setup",
		"https://dispatch.example@another.example/setup",
		"https://*.dispatch.example/setup",
		"https://dispatch.example/setup#fragment",
	} {
		value := manifest
		value.SetupURI = invalid
		start(rustURL, form(value), 400)
	}
	start(rustURL, form(manifest)+"&state=duplicate", 400)
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
	callback := func(base, id, action string) url.Values {
		t.Helper()
		reply := send(base, "POST", reviewPath+id+"/"+action, "", web, 200)
		loc, err := url.Parse(reply["redirect_uri"].(string))
		if err != nil || loc.Host != "dispatch.example" || loc.Path != "/setup" {
			t.Fatal("consent result did not preserve the reviewed setup URL")
		}
		values := loc.Query()
		if values.Get("keep") != "~" || values.Get("state") != state {
			t.Fatal("consent callback discarded existing query parameters or state")
		}
		return values
	}
	exchangeBody := func(code, verifier string) string {
		return jsonBody(map[string]string{"code": code, "code_verifier": verifier})
	}
	for i, direction := range []struct{ start, approve, redeem string }{
		{goURL, rustURL, goURL},
		{rustURL, goURL, rustURL},
	} {
		id := start(direction.start, form(manifest), 303)
		goManifest := send(goURL, "GET", reviewPath+id, "", web, 200)
		if !reflect.DeepEqual(goManifest, send(rustURL, "GET", reviewPath+id, "", root, 200)) {
			t.Fatal("Go and Rust disagreed on the manifest awaiting consent")
		}
		send(rustURL, "GET", reviewPath+id, "", automation, 403)
		send(rustURL, "POST", reviewPath+id+"/approve", "", root, 403)
		send(rustURL, "POST", reviewPath+id+"/approve", "", labCredentials{session: web.session, csrf: "wrong"}, 403)
		if i == 0 {
			sqlRun(`CREATE TRIGGER lab_application_abort BEFORE INSERT ON audit_events
				WHEN NEW.action='application.create' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
			send(rustURL, "POST", reviewPath+id+"/approve", "", web, 500)
			send(goURL, "GET", reviewPath+id, "", web, 200)
			sqlRun("DROP TRIGGER lab_application_abort")
		}
		code := callback(direction.approve, id, "approve").Get("code")
		if code == "" {
			t.Fatal("consent returned no registration code")
		}
		send(rustURL, "POST", reviewPath+id+"/approve", "", web, 404)
		// Check rejection before the good exchange so it must not spend the code.
		wrong := send(direction.redeem, "POST", exchange, exchangeBody(code, strings.Repeat("x", 64)), labCredentials{}, 400)
		if wrong["error"] != "invalid_grant" {
			t.Fatal("bad verifier did not return invalid_grant")
		}
		issued := send(direction.redeem, "POST", exchange, exchangeBody(code, proof), labCredentials{}, 200)
		for _, base := range []string{goURL, rustURL} {
			replay := send(base, "POST", exchange, exchangeBody(code, proof), labCredentials{}, 400)
			if replay["error"] != "invalid_grant" {
				t.Fatal("registration exchange was not single-use")
			}
		}
		if err := f.store.AuthenticateApplicationClient(t.Context(), issued["client_id"].(string), issued["client_secret"].(string)); err != nil {
			t.Fatalf("Go did not recognize the exchanged client credential: %v", err)
		}
		path := applications + "/" + issued["application_id"].(string)
		if !reflect.DeepEqual(send(goURL, "GET", path, "", root, 200), send(rustURL, "GET", path, "", web, 200)) {
			t.Fatal("registered application inventories differ")
		}
	}
	cancelID := start(goURL, form(manifest), 303)
	if result := callback(rustURL, cancelID, "cancel"); result.Get("error") != "access_denied" || result.Get("code") != "" {
		t.Fatal("cancel did not return the denial to the reviewed application")
	}
	send(goURL, "GET", reviewPath+cancelID, "", root, 404)
	apps := send(rustURL, "GET", applications, "", web, 200)
	if !reflect.DeepEqual(apps, send(goURL, "GET", applications, "", root, 200)) || len(apps["applications"].([]any)) != 2 {
		t.Fatal("approval, denial or rollback changed the application inventory")
	}
	var installs int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM application_installations").Scan(&installs); err != nil || installs != 0 {
		t.Fatalf("application registration must not grant network access: %d (%v)", installs, err)
	}
}
