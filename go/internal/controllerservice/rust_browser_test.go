//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
)

func rustScopedBrowserFixture(t *testing.T, f fixture, role string) (string, string) {
	t.Helper()
	username := "web-" + role
	r := bearerJSONRequest("POST", "https://controller.example/v1/admin/administrators", map[string]any{"username": username, "password": "local browser fixture password", "role": role, "network_ids": []string{f.network.ID.String()}}, testRootBearer)
	w := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("create %s: HTTP %d", role, w.Code)
	}
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), username)
	if err != nil {
		t.Fatal(err)
	}
	_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return token, csrf
}

func testRustSessionRejection(t *testing.T, f fixture, rejected func(token, csrf string)) {
	t.Helper()
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-owner")
	if err != nil {
		t.Fatal(err)
	}
	s, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	age := func(last int64) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), `UPDATE administrator_sessions SET created_at=?,last_seen_at=?,idle_expires_at=min(?+idle_lifetime_seconds,absolute_expires_at) WHERE id=?`, last, last, last, s.ID[:]); err != nil {
			t.Fatal(err)
		}
	}
	last := time.Now().Add(-time.Minute).Unix()
	age(last)
	rejected(token, token)
	var actual int64
	if err := db.QueryRowContext(t.Context(), "SELECT last_seen_at FROM administrator_sessions WHERE id=? AND revoked_at IS NULL", s.ID[:]).Scan(&actual); err != nil || actual != last {
		t.Fatal("bad CSRF changed the session")
	}
	age(time.Now().Add(-2 * s.IdleTimeout).Unix())
	rejected(token, csrf)
	rejected(token, csrf)
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_events WHERE action='administrator.session.expire' AND target_id=?`, s.ID[:]).Scan(&actual); err != nil || actual != 1 {
		t.Fatal("expected exactly one durable expiration event")
	}
}
