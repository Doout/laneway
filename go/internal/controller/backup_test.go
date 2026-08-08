package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
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
	destination := filepath.Join(t.TempDir(), "canceled.db")
	if err := store.Backup(ctx, destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("Backup error = %v, want context canceled", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled backup published destination: %v", err)
	}
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
