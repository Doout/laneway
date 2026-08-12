package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"laneway.dev/laneway/internal/adminauth"
)

func TestBackupAndFreshRestore(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "controller.db")
	store, err := Open(ctx, sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	network, err := store.CreateNetwork(ctx, "backup-test", netip.MustParsePrefix("100.96.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}

	backupPath := filepath.Join(directory, "backups", "controller.db")
	if err := os.Mkdir(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	assertNoTemporaryDatabaseFiles(t, filepath.Dir(backupPath))
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("backup permissions = %o, want 600", got)
	}

	// A record committed after the snapshot must not appear in the backup.
	if _, err := store.CreateNetwork(ctx, "after-backup", netip.MustParsePrefix("100.97.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restoredPath := filepath.Join(directory, "restored", "controller.db")
	if err := os.Mkdir(filepath.Dir(restoredPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(ctx, backupPath, restoredPath); err != nil {
		t.Fatal(err)
	}
	assertNoTemporaryDatabaseFiles(t, filepath.Dir(restoredPath))
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got, err := restored.Network(ctx, network.ID); err != nil || got.Name != network.Name {
		t.Fatalf("restored network = %+v, %v", got, err)
	}
	var afterCount int
	if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM networks WHERE name = 'after-backup'`).Scan(&afterCount); err != nil {
		t.Fatal(err)
	}
	if afterCount != 0 {
		t.Fatalf("post-backup record count = %d, want 0", afterCount)
	}
}

func assertNoTemporaryDatabaseFiles(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".laneway-database-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		return
	}
	var details []string
	for _, match := range matches {
		info, statErr := os.Lstat(match)
		if statErr != nil {
			details = append(details, match+": "+statErr.Error())
			continue
		}
		details = append(details, fmt.Sprintf("%s (%d bytes, %s)", match, info.Size(), info.Mode()))
	}
	t.Fatalf("temporary SQLite files remain: %s", strings.Join(details, ", "))
}

func TestBackupNeverOverwritesDestination(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	destination := filepath.Join(t.TempDir(), "existing.db")
	const sentinel = "operator-owned"
	if err := os.WriteFile(destination, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(ctx, destination); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Backup error = %v, want already exists", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("existing destination changed to %q", got)
	}
}

func TestBackupNeverFollowsDestinationSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges")
	}
	store, _ := openTestStore(t)
	directory := t.TempDir()
	target := filepath.Join(directory, "foreign")
	const sentinel = "do-not-touch"
	if err := os.WriteFile(target, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "backup.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(context.Background(), link); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Backup error = %v, want already exists", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Fatalf("symlink target changed to %q", got)
	}
}

func TestRestoreRejectsExistingAndCorruptDestinations(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	corrupt := filepath.Join(directory, "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("not SQLite"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(directory, "missing.db")
	if err := RestoreDatabase(ctx, corrupt, missing); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("corrupt restore error = %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt restore created destination: %v", err)
	}

	store, _ := openTestStore(t)
	backup := filepath.Join(directory, "valid.db")
	if err := store.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(directory, "existing.db")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(ctx, backup, existing); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing restore error = %v", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("existing destination changed: %q, %v", contents, err)
	}
}

func TestBackupHonorsCanceledContext(t *testing.T) {
	store, _ := openTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	directory := t.TempDir()
	destination := filepath.Join(directory, "canceled.db")
	if err := store.Backup(ctx, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("Backup error = %v, want context canceled", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled backup published destination: %v", err)
	}
	assertNoTemporaryDatabaseFiles(t, directory)
}

func TestRestoreRejectsFutureSchema(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "future.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_versions VALUES(999, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(context.Background(), source, filepath.Join(directory, "restored.db")); err == nil || !strings.Contains(err.Error(), "unsupported backup schema") {
		t.Fatalf("RestoreDatabase error = %v", err)
	}
}

func TestRestoreRejectsIncompleteSchema(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "incomplete.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_versions VALUES(1, 0)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDatabase(context.Background(), source, filepath.Join(directory, "restored.db")); err == nil || !strings.Contains(err.Error(), "schema is incomplete") {
		t.Fatalf("RestoreDatabase error = %v", err)
	}
}

func TestBackupDatabaseDoesNotMigrateSource(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	source := filepath.Join(directory, "schema-five.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` + strings.Join(migrations[:5], "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_versions(version, applied_at) VALUES(1,1),(2,2),(3,3),(4,4),(5,5)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "backup.db")
	if err := BackupDatabase(ctx, source, destination); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var version int
	if err := raw.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("source schema version = %d, want unchanged 5", version)
	}
	var wireGuardColumns int
	if err := raw.QueryRow(`SELECT count(*) FROM pragma_table_info('nodes') WHERE name='wireguard_public_key'`).Scan(&wireGuardColumns); err != nil {
		t.Fatal(err)
	}
	if wireGuardColumns != 0 {
		t.Fatal("read-only backup migrated the source nodes table")
	}
}

func TestExactV8BackupAndRestoreUpgradePrivateCopy(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	source := filepath.Join(directory, "source-v8.db")
	createExactV8AdministratorFixture(t, source)
	backup := filepath.Join(directory, "backup-v8.db")
	if err := BackupDatabase(ctx, source, backup); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"source": source, "backup": backup} {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		var version, active, pending int
		if err := db.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM administrator_sessions WHERE revoked_at IS NULL`).Scan(&active); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM administrator_recovery_grants
			WHERE consumed_at IS NULL AND revoked_at IS NULL`).Scan(&pending); err != nil {
			db.Close()
			t.Fatal(err)
		}
		db.Close()
		if version != 8 || active != 6 || pending != 1 {
			t.Fatalf("%s mutated: version=%d active=%d pending=%d", name, version, active, pending)
		}
	}
	restored := filepath.Join(directory, "restored-v9.db")
	if err := RestoreDatabase(ctx, backup, restored); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var version, sessions, pending int
	if err := store.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants
		WHERE consumed_at IS NULL AND revoked_at IS NULL`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version != 9 || sessions != 0 || pending != 0 || state.RecoveryGeneration != 2 {
		t.Fatalf("restored version=%d sessions=%d pending=%d state=%+v", version, sessions, pending, state)
	}
}

func TestRestoreInvalidatesAdministratorSecrets(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := Open(ctx, filepath.Join(directory, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	state, err := store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrapSecret, err := store.IssueAdministratorRecoveryGrant(ctx, administratorRecoveryGrantDecision(t, store, nil),
		AdministratorRecoveryBootstrapOwner, nil, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := adminauth.HashPassword([]byte("a sufficiently long owner password"),
		bytes.NewReader(bytes.Repeat([]byte{4}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	owner, err := store.BootstrapFirstAdministrator(ctx, bootstrapSecret, "owner", passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	_, sessionToken, _, err := store.CreateAdministratorSession(ctx, owner.Principal.ID, owner.Credential.ID,
		AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	grant, recoverySecret, err := store.IssueAdministratorRecoveryGrant(ctx,
		administratorRecoveryGrantDecision(t, store, &owner.Principal.ID),
		AdministratorRecoveryOwner, &owner.Principal.ID, now.Add(time.Hour))
	if err != nil || recoverySecret == "" {
		t.Fatalf("issue recovery grant=%+v err=%v", grant, err)
	}
	backupPath := filepath.Join(directory, "backup.db")
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, backupPath, restoredPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if _, _, err := restored.AuthenticateAdministratorSession(ctx, sessionToken); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("pre-restore session survived: %v", err)
	}
	var sessions, pendingGrants int
	if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_recovery_grants WHERE consumed_at IS NULL`).Scan(&pendingGrants); err != nil {
		t.Fatal(err)
	}
	restoredState, err := restored.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || pendingGrants != 0 || restoredState.RecoveryGeneration != state.RecoveryGeneration+1 ||
		restoredState.LastRecoveredAt == nil || restoredState.RootServicePrincipalID != state.RootServicePrincipalID {
		t.Fatalf("restored auth state=%+v sessions=%d pending=%d", restoredState, sessions, pendingGrants)
	}
	events, err := restored.GlobalAuditEvents(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundRestore := false
	for _, event := range events {
		if event.Action == "controller.restore" && event.Actor.Kind == adminauth.ActorSystem && event.NetworkScope == nil {
			foundRestore = true
		}
	}
	if !foundRestore {
		t.Fatal("restore system audit event missing")
	}
}

func TestRestoreRejectsMalformedCurrentAdministratorScopeTable(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, source := openTestStore(t)
	validBackup := filepath.Join(directory, "valid.db")
	if err := store.Backup(ctx, validBackup); err != nil {
		t.Fatal(err)
	}
	_ = source
	db, err := sql.Open("sqlite", "file:"+validBackup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=OFF;
		DROP INDEX administrator_principal_networks_network;
		ALTER TABLE administrator_principal_networks RENAME TO administrator_principal_networks_old;
		CREATE TABLE administrator_principal_networks(principal_id BLOB PRIMARY KEY) STRICT;
		DROP TABLE administrator_principal_networks_old;
		CREATE INDEX administrator_principal_networks_network ON administrator_principal_networks(principal_id);`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, validBackup, destination); err == nil || !strings.Contains(err.Error(), "canonical v9 definition") {
		t.Fatalf("malformed current-schema restore error=%v, want canonical-schema rejection", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed restore published destination: %v", err)
	}
}

func TestRestoreRejectsWeakenedCurrentAdministratorDDL(t *testing.T) {
	for _, test := range []struct {
		name       string
		old, newer string
	}{
		{
			name:  "partial password uniqueness predicate",
			old:   `WHERE credential_type = 'password' AND revoked_at IS NULL`,
			newer: `WHERE credential_type = 'password'`,
		},
		{
			name:  "administrator role constraint",
			old:   `role TEXT NOT NULL CHECK(role IN ('owner','operator','auditor'))`,
			newer: `role TEXT NOT NULL`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			store, _ := openTestStore(t)
			source := filepath.Join(directory, "weakened.db")
			if err := store.Backup(ctx, source); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			var definition string
			objectType, objectName := "table", "administrator_principals"
			if strings.Contains(test.name, "predicate") {
				objectType, objectName = "index", "one_active_administrator_password"
			}
			if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE type=? AND name=?`, objectType, objectName).Scan(&definition); err != nil {
				db.Close()
				t.Fatal(err)
			}
			weakened := strings.Replace(definition, test.old, test.newer, 1)
			if weakened == definition {
				db.Close()
				t.Fatalf("fixture did not find canonical fragment %q", test.old)
			}
			if _, err := db.Exec(`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=? WHERE type=? AND name=?; PRAGMA writable_schema=OFF`,
				weakened, objectType, objectName); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), "canonical v9 definition") {
				t.Fatalf("weakened restore error=%v, want canonical-schema rejection", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("weakened restore published destination: %v", err)
			}
		})
	}
}

func TestRestoreRejectsUnexpectedTriggerThatMutatesAdministratorState(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, _ := openTestStore(t)
	source := filepath.Join(directory, "trigger.db")
	if err := store.Backup(ctx, source); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER unexpected_auth_mutation AFTER INSERT ON networks
		BEGIN DELETE FROM administrator_sessions; END`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), "canonical v9 definition") {
		t.Fatalf("unexpected-trigger restore error=%v, want canonical-schema rejection", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected-trigger restore published destination: %v", err)
	}
}
