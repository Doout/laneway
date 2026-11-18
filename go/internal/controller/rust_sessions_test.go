//go:build rustinterop

package controller

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
)

func TestRustControllerSessions(t *testing.T) {
	bin := os.Getenv("LANEWAY_RUST_CONTROLLER")
	if bin == "" {
		t.Fatal("missing Rust controller binary")
	}
	store, path := openTestStore(t)
	ctx := t.Context()
	inventory := func(t *testing.T, token, wantError string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, append([]string{"session-inventory", args[0], path}, args[1:]...)...)
		cmd.Stdin = strings.NewReader(token + "\n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if wantError == "" {
			if err != nil {
				t.Fatalf("inventory failed: %v (%s)", err, stderr.String())
			}
		} else if err == nil || len(out) != 0 || !strings.Contains(stderr.String(), wantError) {
			t.Fatalf("expected %s without inventory data; err=%v", wantError, err)
		}
		return out
	}
	run := func(token, wantError string, args ...string) []byte {
		t.Helper()
		return inventory(t, token, wantError, args...)
	}
	past := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Second)
	store.now = func() time.Time { return past }
	hidden := resourceTestNetwork(t, store, "hidden", "10.80.0.0/24")
	past = past.Add(time.Second)
	visible := resourceTestNetwork(t, store, "visible", "10.81.0.0/24")
	subject, token := administratorSessionFixture(t, store, "scoped-auditor", adminauth.RoleAuditor, false, visible.ID)
	sessionID, _ := subject.SessionID()
	run(token, "network access denied", "nodes", hidden.ID.String())
	before, err := administratorSessionBy(ctx, store.db, "s.id=?", idBytes(sessionID))
	if err != nil || !before.LastSeenAt.Equal(past) {
		t.Fatalf("denied request changed last-seen: %v", err)
	}
	assertList := func(token string, limit string, want ...string) {
		t.Helper()
		var result struct {
			Networks []struct {
				ID string `json:"network_id"`
			} `json:"networks"`
		}
		if err := json.Unmarshal(run(token, "", "networks", limit), &result); err != nil {
			t.Fatal(err)
		}
		if result.Networks == nil || len(result.Networks) != len(want) {
			t.Fatalf("network count=%d want=%d", len(result.Networks), len(want))
		}
		for i, id := range want {
			if result.Networks[i].ID != id {
				t.Fatal("wrong network or order")
			}
		}
	}
	assertList(token, "1", visible.ID.String())
	s, err := administratorSessionBy(ctx, store.db, "s.id=?", idBytes(sessionID))
	if err != nil || !s.LastSeenAt.After(past) || !s.IdleExpiresAt.Equal(s.LastSeenAt.Add(time.Hour)) {
		t.Fatalf("Rust did not slide Go session deadline: %v", err)
	}
	store.now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	decision := administratorDecisionForSubject(t, subject, administratorNetworkListPolicy, adminauth.FilteredTarget())
	got, err := store.AdministratorNetworks(ctx, decision, 1)
	if err != nil || len(got) != 1 || got[0].ID != visible.ID {
		t.Fatalf("Go no longer accepts touched session: %v", err)
	}
	run(token, "", "nodes", visible.ID.String())
	run(token, "network access denied", "nodes", hidden.ID.String())
	run(token, "network access denied", "nodes", "ffffffffffffffffffffffffffffffff")
	if _, err = store.db.Exec("DELETE FROM administrator_principal_networks WHERE principal_id=?", idBytes(subject.ActorID())); err != nil {
		t.Fatal(err)
	}
	assertList(token, "100")
	run(token, "network access denied", "nodes", visible.ID.String())
	if err = store.LogoutAdministratorSession(ctx, subject); err != nil {
		t.Fatal(err)
	}
	run(token, "invalid administrator session", "networks")
	run("not-a-secret", "invalid administrator session", "networks")

	_, ownerToken := administratorSessionFixture(t, store, "global-owner", adminauth.RoleOwner, true)
	assertList(ownerToken, "100", hidden.ID.String(), visible.ID.String())
	// Mint separate sessions against known clock boundaries without external
	// time overrides on the Rust binary. Check what a Go controller sees next.
	for _, tc := range []struct {
		name         string
		offset       time.Duration
		invalidation string
		firstError   string
		audit        string
	}{
		{"idle-expired", -70 * time.Minute, "", "administrator session expired", "administrator.session.expire"},
		{"absolute-expired", -3 * time.Hour, "", "administrator session expired", "administrator.session.expire"},
		{"disabled", 0, "disable", "invalid administrator session", "administrator.session.revoke"},
		{"credential-revoked", 0, "credential", "invalid administrator session", "administrator.session.revoke"},
		{"clock-rollback", time.Hour, "", "invalid administrator session", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store.now = func() time.Time { return time.Now().UTC().Add(tc.offset).Truncate(time.Second) }
			subject, token := administratorSessionFixture(t, store, tc.name, adminauth.RoleOperator, true)
			id, _ := subject.SessionID()
			var err error
			switch tc.invalidation {
			case "disable":
				_, err = store.db.Exec("UPDATE administrator_principals SET enabled=0,disabled_at=updated_at WHERE id=?", idBytes(subject.ActorID()))
			case "credential":
				_, err = store.db.Exec("UPDATE administrator_credentials SET revoked_at=created_at,revocation_reason='replaced' WHERE principal_id=?", idBytes(subject.ActorID()))
			}
			if err != nil {
				t.Fatal(err)
			}
			inventory(t, token, tc.firstError, "networks")
			inventory(t, token, "invalid administrator session", "networks")
			record, err := administratorSessionBy(ctx, store.db, "s.id=?", idBytes(id))
			if err != nil || (record.RevokedAt != nil) != (tc.audit != "") {
				t.Fatalf("wrong durable session state: %v", err)
			}
			if tc.audit != "" {
				var count int
				if err := store.db.QueryRow("SELECT count(*) FROM audit_events WHERE actor_kind='system' AND action=? AND target_id=? AND target_type='administrator_session'", tc.audit, idBytes(id)).Scan(&count); err != nil || count != 1 {
					t.Fatalf("audit count=%d err=%v", count, err)
				}
			}
		})
	}

	t.Run("expiry requires durable audit", func(t *testing.T) {
		store.now = func() time.Time { return time.Now().UTC().Add(-70 * time.Minute).Truncate(time.Second) }
		subject, token := administratorSessionFixture(t, store, "expiry-atomic", adminauth.RoleOperator, true)
		id, _ := subject.SessionID()
		if _, err := store.db.Exec(`CREATE TRIGGER test_refuse_expiry BEFORE INSERT ON audit_events
			WHEN NEW.action='administrator.session.expire' BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END`); err != nil {
			t.Fatal(err)
		}
		inventory(t, token, "test audit unavailable", "networks")
		record, err := administratorSessionBy(ctx, store.db, "s.id=?", idBytes(id))
		if err != nil || record.RevokedAt != nil {
			t.Fatalf("failed audit left a partial revocation: %v", err)
		}
		if _, err := store.db.Exec("DROP TRIGGER test_refuse_expiry"); err != nil {
			t.Fatal(err)
		}
		inventory(t, token, "administrator session expired", "networks")
	})
}
