//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
)

func testRustBrowserLogin(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	const correct = `{"username":"web-owner","password":"local browser fixture password"}`
	const wrong = `{"username":"web-owner","password":"wrong browser fixture password"}`
	post := func(base, body, origin, contentType, token string, want int) (http.Header, map[string]any) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), "POST", base+"/v1/admin/auth/login", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: token})
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var obj map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("login HTTP %d, want %d", resp.StatusCode, want)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("login is cacheable")
		}
		if want >= 400 && (len(resp.Cookies()) != 0 || obj["request_id"] != resp.Header.Get(AdministratorRequestIDHeader)) {
			t.Fatal("login failure included cookies or lacked a correlated error")
		}
		return resp.Header, obj
	}
	for _, base := range []string{goURL, rustURL} {
		post(base, correct, "https://other.invalid", "application/json", "", 403)
		post(base, correct, base, "text/plain", "", 415)
		post(base, `{"unknown":1}`, base, "application/json", "", 400)
		post(base, correct+" {}", base, "application/json", "", 400)
		post(base, strings.Repeat(" ", 131073), base, "application/json", "", 413)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-owner")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, _, _, err = f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{MaxActive: 20}); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{rustURL, goURL}, {goURL, rustURL}} {
		base, other := pair[0], pair[1]
		h, obj := post(base, correct, base, "application/json; charset=utf-8", "stale-cookie", 200)
		var n int
		if err := db.QueryRow("SELECT count(*) FROM administrator_sessions WHERE principal_id=? AND revoked_at IS NULL AND idle_expires_at>unixepoch() AND absolute_expires_at>unixepoch()", candidate.PrincipalID[:]).Scan(&n); err != nil || n != 5 {
			t.Fatal("login did not enforce the administrator session cap")
		}
		cookies := (&http.Response{Header: h}).Cookies()
		if len(cookies) != 2 || obj["role"] != "owner" {
			t.Fatal("missing authenticated identity or cookie pair")
		}
		next, err := http.NewRequestWithContext(t.Context(), "GET", other+"/v1/admin/auth/session", nil)
		if err != nil {
			t.Fatal(err)
		}
		var token string
		for _, c := range cookies {
			if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteStrictMode || c.MaxAge <= 0 {
				t.Fatal("incorrect cookie policy")
			}
			next.AddCookie(c)
			if c.Name == adminauth.SessionCookieName {
				token = c.Value
			}
		}
		resp, err := client.Do(next)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != 200 || resp.Header.Get(administratorSessionIDHeader) != h.Get(administratorSessionIDHeader) {
			t.Fatal("other controller did not restore issued session")
		}
		s, _, err := f.store.AuthenticateAdministratorSession(t.Context(), token)
		if err != nil || s.IdleTimeout != 30*time.Minute || s.AbsoluteExpiresAt.Sub(s.CreatedAt) != 8*time.Hour {
			t.Fatal("incorrect durable login policy")
		}
		post(base, correct, base, "application/json", token, 401)
		post(base, wrong, base, "application/json", "", 401)
	}
	count := func(query string) int {
		t.Helper()
		var n int
		if err := db.QueryRowContext(t.Context(), query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count("SELECT count(*) FROM administrator_sessions")
	if _, err = db.Exec(`CREATE TRIGGER reject_test_login BEFORE INSERT ON audit_events WHEN NEW.action='administrator.login' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	post(rustURL, correct, rustURL, "application/json", "", 500)
	if _, err = db.Exec("DROP TRIGGER reject_test_login"); err != nil {
		t.Fatal(err)
	}
	if before != count("SELECT count(*) FROM administrator_sessions") {
		t.Fatal("failed login audit created a session")
	}
	// An unknown username shares its five-attempt bucket with case variants.
	for _, name := range []string{"unknown", "UNKNOWN", "unknown", "Unknown", "unknown"} {
		post(rustURL, fmt.Sprintf(`{"username":%q,"password":"local browser fixture password"}`, name), rustURL, "application/json", "", 401)
	}
	audit := count("SELECT count(*) FROM audit_events WHERE action='administrator.login.failure'")
	h, _ := post(rustURL, `{"username":"unknown","password":"local browser fixture password"}`, rustURL, "application/json", "", 429)
	if h.Get("Retry-After") == "" || count("SELECT count(*) FROM audit_events WHERE action='administrator.login.failure'") != audit {
		t.Fatal("rate-limited login lacks retry deadline or grows audit log")
	}
}
