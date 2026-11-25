//go:build linux

package controller

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sysunix "golang.org/x/sys/unix"
)

// Set LANEWAY_CONTROLLER_RESTORE_BIN to the absolute path of a maintenance
// candidate. The fixture and all compatibility assertions come from Go.
func TestRestoreBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("LANEWAY_CONTROLLER_RESTORE_BIN")
	if binary == "" {
		t.Skip("set LANEWAY_CONTROLLER_RESTORE_BIN to an absolute candidate path")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("LANEWAY_CONTROLLER_RESTORE_BIN must be an absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.db")
	backup := filepath.Join(dir, "backup.db")
	destination := filepath.Join(dir, "restored.db")
	createExactV8AdministratorFixture(t, source)
	if err := BackupDatabase(ctx, source, backup); err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	original, err := openReadOnlyDatabase(backup)
	if err != nil {
		t.Fatal(err)
	}
	var originalPrincipal, sessionHash, grantHash []byte
	for _, field := range []struct {
		query string
		value *[]byte
	}{
		{"SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1", &originalPrincipal},
		{"SELECT token_hash FROM administrator_sessions WHERE revoked_at IS NULL LIMIT 1", &sessionHash},
		{"SELECT secret_hash FROM administrator_recovery_grants WHERE consumed_at IS NULL LIMIT 1", &grantHash},
	} {
		if err := original.QueryRowContext(ctx, field.query).Scan(field.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "controller.toml")
	settings := []byte(`mode = "controller"
[tls]
certificate = "unused.crt"
private_key = "unused.key"
ca = "unused-ca.crt"
[controller]
database = "` + destination + `"
quic_listen = "127.0.0.1:0"
ca_private_key = "unused-ca.key"
admin_token_file = "unused-token"
`)
	if err := os.WriteFile(config, settings, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(wantError string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, binary, "-config", config, "-restore", backup).CombinedOutput()
		if wantError == "" {
			if err != nil {
				t.Fatalf("restore failed: %v\n%s", err, out)
			}
		} else if err == nil || !strings.Contains(string(out), wantError) {
			t.Fatalf("expected %q, got %v\n%s", wantError, err, out)
		}
	}

	t.Run("rejects Go lifecycle lock", func(t *testing.T) {
		lock, err := os.OpenFile(destination+".lock", os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := sysunix.Flock(int(lock.Fd()), sysunix.LOCK_EX|sysunix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		run("restore requires a stopped controller")
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatalf("locked restore created a destination: %v", err)
		}
	})

	run("")
	if err := validateDatabase(ctx, destination, currentSchemaVersion); err != nil {
		t.Fatalf("Go rejected restored SQLite database: %v", err)
	}
	restored, err := openReadOnlyDatabase(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var version, generation, sessions, grants, audits int
	var restoredPrincipal []byte
	if err := restored.QueryRowContext(ctx, `SELECT
		(SELECT max(version) FROM schema_versions), recovery_generation, root_service_principal_id,
		(SELECT count(*) FROM administrator_sessions),
		(SELECT count(*) FROM administrator_recovery_grants WHERE consumed_at IS NULL),
		(SELECT count(*) FROM audit_events WHERE action='controller.restore' AND actor_kind='system' AND network_id IS NULL)
		FROM administrator_auth_state WHERE singleton=1 AND last_recovered_at IS NOT NULL`).
		Scan(&version, &generation, &restoredPrincipal, &sessions, &grants, &audits); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion || generation != 2 || !bytes.Equal(restoredPrincipal, originalPrincipal) ||
		sessions != 0 || grants != 0 || audits != 1 {
		t.Fatalf("restored version=%d generation=%d principal-preserved=%t sessions=%d grants=%d audits=%d",
			version, generation, bytes.Equal(restoredPrincipal, originalPrincipal), sessions, grants, audits)
	}
	restoredBytes, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range [][]byte{sessionHash, grantHash} {
		if !bytes.Contains(backupBytes, hash) || bytes.Contains(restoredBytes, hash) {
			t.Fatal("restored SQLite bytes failed secret redaction check")
		}
	}
	run("destination already exists")
	for path, want := range map[string][]byte{backup: backupBytes, destination: restoredBytes} {
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restore modified %s: %v", path, err)
		}
	}
}
