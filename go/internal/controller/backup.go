package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Doout/laneway/go/internal/adminauth"
	sqlite "modernc.org/sqlite"
)

const backupStepPages int32 = 256

type sqliteBackuper interface {
	NewBackup(string) (*sqlite.Backup, error)
}

// Backup writes a transactionally consistent snapshot of the live controller
// database. The destination is published atomically and is never overwritten.
func (s *Store) Backup(ctx context.Context, destination string) error {
	if s == nil || s.db == nil {
		return errors.New("backup controller database: store is closed")
	}
	return backupDatabase(ctx, s.db, destination, currentSchemaVersion, false)
}

// BackupDatabase snapshots an existing controller database through a read-only
// source connection. It is suitable for maintenance tooling because it cannot
// apply migrations or otherwise mutate the live source database.
func BackupDatabase(ctx context.Context, source, destination string) error {
	if err := validateDatabase(ctx, source, currentSchemaVersion); err != nil {
		return fmt.Errorf("validate controller database: %w", err)
	}
	db, err := openReadOnlyDatabase(source)
	if err != nil {
		return fmt.Errorf("open controller database read-only: %w", err)
	}
	defer db.Close()
	if err := backupDatabase(ctx, db, destination, currentSchemaVersion, false); err != nil {
		return fmt.Errorf("backup controller database: %w", err)
	}
	return nil
}

// RestoreDatabase creates destination from a validated controller backup. It
// deliberately refuses to replace an existing path: restoring an active or
// unknown database must never happen as a side effect of a maintenance command.
func RestoreDatabase(ctx context.Context, source, destination string) error {
	if err := validateDatabase(ctx, source, currentSchemaVersion); err != nil {
		return fmt.Errorf("validate controller backup: %w", err)
	}
	db, err := openReadOnlyDatabase(source)
	if err != nil {
		return fmt.Errorf("open controller backup: %w", err)
	}
	defer db.Close()
	if err := backupDatabase(ctx, db, destination, currentSchemaVersion, true); err != nil {
		return fmt.Errorf("restore controller database: %w", err)
	}
	return nil
}

func backupDatabase(ctx context.Context, source *sql.DB, destination string, maximumSchema int, prepareRestore bool) (retErr error) {
	destination, err := validateNewDatabasePath(destination)
	if err != nil {
		return err
	}
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".laneway-database-*")
	if err != nil {
		return fmt.Errorf("create private backup file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if removeErr := removeTemporaryDatabaseFiles(temporaryPath); removeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary backup: %w", removeErr))
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("restrict backup permissions: %w", err), temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close empty backup file: %w", err)
	}

	connection, err := source.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire source database connection: %w", err)
	}
	defer connection.Close()
	if err := connection.Raw(func(driverConnection any) error {
		backuper, ok := driverConnection.(sqliteBackuper)
		if !ok {
			return errors.New("SQLite driver does not support online backup")
		}
		backup, err := backuper.NewBackup(temporaryPath)
		if err != nil {
			return fmt.Errorf("start SQLite online backup: %w", err)
		}
		finished := false
		defer func() {
			if !finished {
				_ = backup.Finish()
			}
		}()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, stepErr := backup.Step(backupStepPages)
			if stepErr != nil {
				return fmt.Errorf("copy SQLite pages: %w", stepErr)
			}
			if !more {
				break
			}
		}
		if err := backup.Finish(); err != nil {
			return fmt.Errorf("finish SQLite online backup: %w", err)
		}
		finished = true
		return nil
	}); err != nil {
		return err
	}
	if prepareRestore {
		if err := prepareRestoredDatabase(ctx, temporaryPath); err != nil {
			return fmt.Errorf("prepare restored controller database: %w", err)
		}
	}
	if err := validateDatabase(ctx, temporaryPath, maximumSchema); err != nil {
		return fmt.Errorf("validate completed backup: %w", err)
	}
	if err := syncFile(temporaryPath); err != nil {
		return err
	}
	// Link is an atomic no-replace publication because the temporary file is
	// created in the destination directory. It also closes the Lstat race that
	// would exist with os.Rename, which overwrites existing files on Unix.
	if err := os.Link(temporaryPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("destination already exists: %s", destination)
		}
		return fmt.Errorf("publish backup without overwrite: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		_ = os.Remove(destination)
		return err
	}
	return nil
}

// prepareRestoredDatabase upgrades the private restore candidate and invalidates
// replayable authentication state before the database is atomically published.
func prepareRestoredDatabase(ctx context.Context, path string) error {
	store, err := Open(ctx, path)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	now := store.now()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM administrator_sessions`); err != nil {
		return fmt.Errorf("invalidate restored administrator sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM administrator_recovery_grants WHERE consumed_at IS NULL`); err != nil {
		return fmt.Errorf("invalidate restored administrator recovery grants: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE administrator_auth_state
		SET recovery_generation=recovery_generation+1,last_recovered_at=? WHERE singleton=1`, unix(now))
	if err != nil {
		return fmt.Errorf("advance restored authentication generation: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return errors.New("restored administrator auth state is missing")
	}
	if err := auditActorTx(ctx, tx, nil, adminauth.SystemActor(), "controller.restore", "controller_database", nil, `{}`, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit restored authentication invalidation: %w", err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint restored controller database: %w", err)
	}
	if err := store.Close(); err != nil {
		return fmt.Errorf("close restored controller database: %w", err)
	}
	closed = true
	return nil
}

func removeTemporaryDatabaseFiles(path string) error {
	var result error
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		candidate := path + suffix
		if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove %s: %w", filepath.Base(candidate), err))
		}
	}
	return result
}

func validateNewDatabasePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("database destination is empty")
	}
	clean := filepath.Clean(path)
	if info, err := os.Lstat(clean); err == nil {
		return "", fmt.Errorf("destination already exists (%s): %s", info.Mode().Type(), clean)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect destination: %w", err)
	}
	info, err := os.Stat(filepath.Dir(clean))
	if err != nil {
		return "", fmt.Errorf("inspect destination directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("database destination parent is not a directory")
	}
	return clean, nil
}

func validateDatabase(ctx context.Context, path string, maximumSchema int) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("database path is empty")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("database is not a regular file: %s", path)
	}
	db, err := openReadOnlyDatabase(path)
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fmt.Errorf("run SQLite integrity check: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("SQLite integrity check failed: %s", integrity)
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_versions`).Scan(&version); err != nil {
		return fmt.Errorf("read backup schema version: %w", err)
	}
	if version < 1 || version > maximumSchema {
		return fmt.Errorf("unsupported backup schema version %d (maximum %d)", version, maximumSchema)
	}
	var versionRows, minimumVersion int
	if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(MIN(version), 0) FROM schema_versions`).Scan(&versionRows, &minimumVersion); err != nil {
		return fmt.Errorf("validate backup schema history: %w", err)
	}
	if minimumVersion != 1 || versionRows != version {
		return errors.New("backup schema history is incomplete")
	}
	requiredTables := []string{"networks", "nodes", "certificates", "overlay_addresses", "routes", "acl_rules", "relays", "enrollment_tokens", "audit_events", "schema_versions"}
	if version >= 11 {
		requiredTables = append(requiredTables, "access_users", "access_teams", "access_team_members", "access_grants")
	}
	if version >= 12 {
		requiredTables = append(requiredTables, "controller_identity_state")
	}
	if version >= endpointStatusSchemaVersion {
		requiredTables = append(requiredTables, "endpoint_status_latest")
	}
	if version >= 8 {
		requiredTables = append(requiredTables, "administrator_principals", "administrator_principal_networks",
			"administrator_credentials", "administrator_sessions", "administrator_recovery_grants", "administrator_auth_state")
	}
	if version >= 9 {
		requiredTables = append(requiredTables, "administrator_root_token_rotations")
	}
	if version >= 10 {
		requiredTables = append(requiredTables, "ephemeral_exit_sessions")
	}
	for _, table := range requiredTables {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			return fmt.Errorf("validate backup table %s: %w", table, err)
		}
		if count != 1 {
			return fmt.Errorf("backup schema is incomplete: required table %s is missing", table)
		}
	}
	if version >= endpointStatusSchemaVersion {
		var invalidTTLRows int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM endpoint_status_latest
			WHERE valid_for_seconds NOT BETWEEN 10 AND 300
			OR expires_at != observed_at + valid_for_seconds`).Scan(&invalidTTLRows); err != nil {
			return fmt.Errorf("validate endpoint status TTL: %w", err)
		}
		if invalidTTLRows != 0 {
			return errors.New("backup endpoint status TTL is corrupt")
		}
	}
	if version >= 8 {
		if err := validateAdministratorBackupSchema(ctx, db, version); err != nil {
			return err
		}
	}
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("run SQLite foreign-key check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("SQLite foreign-key check failed")
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read SQLite foreign-key check: %w", err)
	}
	return nil
}

func validateAdministratorBackupSchema(ctx context.Context, db *sql.DB, version int) error {
	want, wantObjects, err := expectedAdministratorSchemaFingerprint(ctx, version)
	if err != nil {
		return fmt.Errorf("build canonical administrator schema: %w", err)
	}
	got, gotObjects, err := administratorSchemaFingerprint(ctx, db)
	if err != nil {
		return fmt.Errorf("fingerprint backup administrator schema: %w", err)
	}
	if gotObjects != wantObjects || got != want {
		return fmt.Errorf("backup schema is incomplete: administrator schema does not match the canonical v%d definition", version)
	}
	var singletonCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM administrator_auth_state
		WHERE singleton=1 AND length(root_service_principal_id)=16 AND root_service_principal_id<>zeroblob(16)`).Scan(&singletonCount); err != nil {
		return fmt.Errorf("validate administrator auth state: %w", err)
	}
	if singletonCount != 1 {
		return errors.New("backup administrator auth state is missing or corrupt")
	}
	if version >= 12 {
		if err := validateControllerIdentityBackupState(ctx, db); err != nil {
			return err
		}
	}
	return nil
}

func validateControllerIdentityBackupState(ctx context.Context, db *sql.DB) error {
	var count, totalBindingAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM controller_identity_state`).Scan(&count); err != nil {
		return fmt.Errorf("validate controller identity state: %w", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='controller.identity.bind'`).Scan(&totalBindingAudits); err != nil {
		return fmt.Errorf("validate controller identity binding audit history: %w", err)
	}
	if count == 0 {
		if totalBindingAudits != 0 {
			return errors.New("backup controller identity binding audit exists without durable state")
		}
		return nil
	}
	if count != 1 {
		return errors.New("backup controller identity state is corrupt")
	}
	if totalBindingAudits != 1 {
		return errors.New("backup controller identity binding audit history is ambiguous")
	}
	var networkRaw, serviceRaw []byte
	var bindingCreated, networkCreated int64
	if err := db.QueryRowContext(ctx, `SELECT c.network_id,c.controller_service_id,c.created_at,n.created_at
		FROM controller_identity_state c JOIN networks n ON n.id=c.network_id WHERE c.singleton=1`).
		Scan(&networkRaw, &serviceRaw, &bindingCreated, &networkCreated); err != nil {
		return fmt.Errorf("validate controller identity binding: %w", err)
	}
	if _, err := scanID(networkRaw); err != nil {
		return errors.New("backup controller network binding is corrupt")
	}
	if _, err := scanID(serviceRaw); err != nil {
		return errors.New("backup controller service binding is corrupt")
	}
	if bindingCreated < networkCreated {
		return errors.New("backup controller identity binding predates its network")
	}
	var bindingAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE network_id=? AND actor_kind='system' AND actor_id IS NULL
		AND action='controller.identity.bind' AND target_type='controller_service'
		AND target_id=? AND created_at=?`, networkRaw, serviceRaw, bindingCreated).Scan(&bindingAudits); err != nil {
		return fmt.Errorf("validate controller identity binding audit: %w", err)
	}
	if bindingAudits != 1 {
		return errors.New("backup controller identity binding audit is missing or corrupt")
	}
	return nil
}

var administratorSchemaTables = map[string]struct{}{
	"administrator_principals":           {},
	"administrator_principal_networks":   {},
	"administrator_credentials":          {},
	"administrator_sessions":             {},
	"administrator_recovery_grants":      {},
	"administrator_auth_state":           {},
	"administrator_root_token_rotations": {},
	"ephemeral_exit_sessions":            {},
	"controller_identity_state":          {},
	"endpoint_status_latest":             {},
	"audit_events":                       {},
}

// administratorSchemaFingerprint covers the exact sqlite_schema text and
// complete object set for every security-critical administrator or runtime
// truth table. This includes implicit/explicit indexes and triggers, so altered
// CHECK/FK clauses, partial-index predicates, STRICT declarations, or
// unexpected triggers all change the fingerprint.
func administratorSchemaFingerprint(ctx context.Context, db *sql.DB) ([sha256.Size]byte, int, error) {
	rows, err := db.QueryContext(ctx, `SELECT type,name,tbl_name,sql
		FROM sqlite_schema WHERE type IN ('table','index','trigger')
		ORDER BY type,name,tbl_name`)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	defer rows.Close()
	hash := sha256.New()
	objects := 0
	for rows.Next() {
		var objectType, name, table string
		var definition sql.NullString
		if err := rows.Scan(&objectType, &name, &table, &definition); err != nil {
			return [sha256.Size]byte{}, 0, err
		}
		_, criticalTable := administratorSchemaTables[table]
		if !criticalTable && objectType != "trigger" {
			continue
		}
		objects++
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%t\x00%s\x00",
			objectType, name, table, definition.Valid, definition.String)
	}
	if err := rows.Err(); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, objects, nil
}

func expectedAdministratorSchemaFingerprint(ctx context.Context, version int) ([sha256.Size]byte, int, error) {
	if version < 8 || version > currentSchemaVersion {
		return [sha256.Size]byte{}, 0, fmt.Errorf("unsupported administrator schema version %d", version)
	}
	reference, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	reference.SetMaxOpenConns(1)
	defer reference.Close()
	if _, err := reference.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	for migrationIndex, migration := range migrations[:version] {
		if _, err := reference.ExecContext(ctx, migration); err != nil {
			return [sha256.Size]byte{}, 0, fmt.Errorf("apply reference migration %d: %w", migrationIndex+1, err)
		}
	}
	return administratorSchemaFingerprint(ctx, reference)
}

func openReadOnlyDatabase(path string) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	values := url.Values{}
	values.Set("mode", "ro")
	values.Add("_pragma", "foreign_keys(1)")
	values.Add("_pragma", "query_only(1)")
	uri := url.URL{Scheme: "file", Path: absolute, RawQuery: values.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open completed backup for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync completed backup: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open backup directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync backup directory: %w", err)
	}
	return nil
}
