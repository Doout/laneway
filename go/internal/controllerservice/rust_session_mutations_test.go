//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
)

// Keep each Go/Rust pair on the same live database. Each side must accept
// the other's cookies and invalidate its successors, not just emit similar JSON.
func testRustSessionMutations(t *testing.T, f fixture, goURL, rustURL string, post func(string, string, string, http.Header) (int, map[string]any, http.Header)) {
	t.Helper()
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-owner")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const logout = "/v1/admin/auth/logout"
	const rotate = "/v1/admin/auth/session/rotate"
	headers := func(base, csrf string) http.Header {
		return http.Header{"Origin": {base}, "Sec-Fetch-Site": {"same-origin"}, "Cookie": {adminauth.CSRFCookieName + "=" + csrf}, adminauth.CSRFHeaderName: {csrf}}
	}
	for _, pair := range []struct{ name, rotate, logout string }{{"rust-rotate", rustURL, goURL}, {"rust-logout", goURL, rustURL}} {
		t.Run(pair.name, func(t *testing.T) {
			old, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
			if err != nil {
				t.Fatal(err)
			}
			// Structurally untrusted requests must never clear or replace cookies.
			for _, path := range []string{rotate, logout} {
				for _, mode := range []string{"cross-origin", "no-origin", "wrong-fetch", "duplicate-origin", "wrong-proof"} {
					h := headers(rustURL, csrf)
					want := 403
					switch mode {
					case "cross-origin":
						h.Set("Origin", "https://other.invalid")
					case "no-origin":
						h.Del("Origin")
					case "wrong-fetch":
						h.Set("Sec-Fetch-Site", "cross-site")
					case "duplicate-origin":
						h.Add("Origin", rustURL)
					case "wrong-proof":
						h.Set(adminauth.CSRFHeaderName, token)
						if path == logout {
							want = 401
						}
					}
					status, _, res := post(rustURL, path, token, h)
					if status != want || len(res.Values("Set-Cookie")) != 0 {
						t.Fatalf("%s %s: HTTP %d; want %d, no cookies", path, mode, status, want)
					}
				}
			}
			if pair.rotate == rustURL {
				// The insert and predecessor revocation must both roll back
				// if recording the rotation's audit event fails.
				_, err = db.Exec(`CREATE TRIGGER reject_test_rotate BEFORE INSERT ON audit_events WHEN NEW.action='administrator.session.rotate' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
				status, _, h := post(rustURL, rotate, token, headers(rustURL, csrf))
				if status != 500 || len(h.Values("Set-Cookie")) != 0 {
					t.Fatal("failed rotation returned credentials")
				}
				if _, _, err := f.store.AuthenticateAdministratorSession(t.Context(), token); err != nil {
					t.Fatal("audit failure consumed original session")
				}
				if _, err = db.Exec("DROP TRIGGER reject_test_rotate"); err != nil {
					t.Fatal(err)
				}
			}
			status, body, h := post(pair.rotate, rotate, token, headers(pair.rotate, csrf))
			if status != 200 || body["session_id"] == old.ID.String() || body["absolute_expires_at_unix_seconds"] != json.Number(h.Get(administratorSessionAbsoluteHeader)) {
				t.Fatalf("rotation did not issue valid metadata: HTTP %d", status)
			}
			var next, proof string
			cookies := (&http.Response{Header: h}).Cookies()
			if len(cookies) != 2 {
				t.Fatal("expected two rotated cookies")
			}
			for _, c := range cookies {
				if c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteStrictMode || !c.Secure || !c.HttpOnly || c.MaxAge <= 0 || !c.Expires.Equal(old.AbsoluteExpiresAt) {
					t.Fatal("cookie attributes or absolute session deadline changed")
				}
				switch c.Name {
				case adminauth.SessionCookieName:
					next = c.Value
				case adminauth.CSRFCookieName:
					proof = c.Value
				}
			}
			if next == "" || proof == "" || token == next || csrf == proof || proof != body["csrf_token"] {
				t.Fatal("rotation did not replace both secrets")
			}
			if _, _, err := f.store.AuthenticateAdministratorSession(t.Context(), token); err == nil {
				t.Fatal("superseded session still live")
			}
			active, _, err := f.store.AuthenticateAdministratorSession(t.Context(), next)
			if err != nil || active.ID.String() != h.Get(administratorSessionIDHeader) || !active.AbsoluteExpiresAt.Equal(old.AbsoluteExpiresAt) {
				t.Fatal("Go rejected rotated session or absolute expiry was extended")
			}
			if pair.logout == rustURL {
				_, err = db.Exec(`CREATE TRIGGER reject_test_logout BEFORE INSERT ON audit_events WHEN NEW.action='administrator.logout' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
				status, _, _ = post(rustURL, logout, token, headers(rustURL, csrf))
				if status != 500 {
					t.Fatal("failed logout reported success")
				}
				if _, _, err := f.store.AuthenticateAdministratorSession(t.Context(), next); err != nil {
					t.Fatal("failed logout was not rolled back")
				}
				if _, err = db.Exec("DROP TRIGGER reject_test_logout"); err != nil {
					t.Fatal(err)
				}
			}
			// A matching cookie and header are insufficient without the
			// corresponding stored secret. The structurally valid request clears its own cookies.
			status, _, h = post(pair.logout, logout, token, headers(pair.logout, proof))
			if status != 401 || len(h.Values("Set-Cookie")) != 2 {
				t.Fatal("incorrect stored proof response")
			}
			status, _, h = post(pair.logout, logout, token, headers(pair.logout, csrf))
			if status != 204 {
				t.Fatalf("logout via predecessor returned HTTP %d", status)
			}
			cleared := (&http.Response{Header: h}).Cookies()
			if len(cleared) != 2 {
				t.Fatal("missing cleared cookies")
			}
			for _, c := range cleared {
				if c.Value != "" || c.Expires.Unix() != 1 || c.MaxAge >= 0 || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteStrictMode {
					t.Fatal("invalid cookie removal")
				}
			}
			if _, _, err := f.store.AuthenticateAdministratorSession(t.Context(), next); err == nil {
				t.Fatal("successor survived predecessor logout")
			}
			var count int
			if err = db.QueryRow("SELECT count(*) FROM audit_events WHERE action='administrator.logout' AND target_id=? AND actor_id=? AND actor_kind='administrator'", active.ID[:], old.PrincipalID[:]).Scan(&count); err != nil || count != 1 {
				t.Fatal("missing durable attributed logout")
			}
		})
	}
}

func testRustLogoutRotationRace(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-owner")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{goURL, rustURL}, {rustURL, goURL}} {
		_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		type outcome struct {
			status int
			next   string
			err    error
		}
		start := make(chan struct{})
		call := func(base, path string) <-chan outcome {
			done := make(chan outcome, 1)
			req, err := http.NewRequestWithContext(t.Context(), "POST", base+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Origin", base)
			req.Header.Set(adminauth.CSRFHeaderName, csrf)
			req.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: token})
			req.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrf})
			go func() {
				<-start
				resp, err := client.Do(req)
				if err != nil {
					done <- outcome{err: err}
					return
				}
				out := outcome{status: resp.StatusCode}
				for _, c := range resp.Cookies() {
					if c.Name == adminauth.SessionCookieName {
						out.next = c.Value
					}
				}
				_, out.err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				done <- out
			}()
			return done
		}
		r, l := call(pair[0], "/v1/admin/auth/session/rotate"), call(pair[1], "/v1/admin/auth/logout")
		close(start)
		rotation, logout := <-r, <-l
		if rotation.err != nil || logout.err != nil || logout.status != 204 || (rotation.status != 200 && rotation.status != 401) {
			t.Fatalf("concurrent rotation/logout: HTTP %d/%d", rotation.status, logout.status)
		}
		if rotation.status == 200 && rotation.next == "" {
			t.Fatal("successful rotation omitted successor")
		}
		for _, s := range []string{token, rotation.next} {
			if s != "" {
				if _, _, err := f.store.AuthenticateAdministratorSession(t.Context(), s); err == nil {
					t.Fatal("session survived completed concurrent logout")
				}
			}
		}
	}
}
