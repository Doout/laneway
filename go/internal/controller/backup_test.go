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

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
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
	token, err := store.IssueEnrollmentToken(ctx, network.ID, "backup status", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(ctx, token.Secret, "reported-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID},
		testEndpointStatusReport(), time.Now()); err != nil {
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
	var restoredVersion string
	if err := restored.db.QueryRowContext(ctx, `SELECT product_version FROM endpoint_status_latest WHERE node_id=?`,
		idBytes(node.ID)).Scan(&restoredVersion); err != nil || restoredVersion != "1.2.3" {
		t.Fatalf("restored endpoint status version=%q err=%v", restoredVersion, err)
	}
}

func testEndpointStatusReport() EndpointStatusReport {
	return EndpointStatusReport{
		ValidForSeconds: 60, ProductVersion: "1.2.3", Platform: EndpointPlatformLinux,
		CertificateState: CertificateStatusHealthy, ConfigurationState: ConfigurationStatusCurrent,
		CarrierState: CarrierStatusDirect, RouteState: RouteStatusReady,
		SelectedExitState: SelectedExitStatusNotSelected, ConfigurationEpoch: 1,
	}
}

func TestBackupRestorePreservesControllerIdentityBinding(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := Open(ctx, filepath.Join(directory, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
		store.Close()
		t.Fatal(err)
	}
	backup := filepath.Join(directory, "backup.db")
	if err := store.Backup(ctx, backup); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, backup, restoredPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	network, created, err := restored.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, authenticated)
	if err != nil || created || !initialNetworkMatches(network, configured) {
		t.Fatalf("restored binding network=%+v created=%t err=%v", network, created, err)
	}
	drift := authenticated
	drift.SubjectID = identity.ID{9}
	if _, _, err := restored.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, drift); !errors.Is(err, ErrConflict) {
		t.Fatalf("restored service drift error=%v", err)
	}
}

func TestRestoreRejectsTamperedControllerIdentityState(t *testing.T) {
	for _, test := range []struct {
		name                  string
		tamper                string
		preservesSchemaAndFKs bool
	}{
		{
			name: "weakened schema",
			tamper: `PRAGMA writable_schema=ON;
				UPDATE sqlite_schema SET sql=replace(sql,'BEFORE DELETE','AFTER DELETE')
				WHERE type='trigger' AND name='controller_identity_state_undeletable';
				PRAGMA writable_schema=OFF`,
		},
		{name: "missing binding audit", tamper: `DELETE FROM audit_events WHERE action='controller.identity.bind'`},
		{
			name: "additional conflicting binding audit",
			tamper: `INSERT INTO audit_events
				(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
				SELECT x'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',network_id,actor_kind,actor_id,action,target_type,
				x'09000000000000000000000000000000',details_json,created_at+1
				FROM audit_events WHERE action='controller.identity.bind' LIMIT 1`,
			preservesSchemaAndFKs: true,
		},
		{
			name: "binding audit without durable state",
			tamper: "DROP TRIGGER controller_identity_state_undeletable;" +
				"\nDELETE FROM controller_identity_state;" +
				"\nCREATE TRIGGER controller_identity_state_undeletable\n" +
				"    BEFORE DELETE ON controller_identity_state\n" +
				"BEGIN\n" +
				"    SELECT RAISE(ABORT, 'controller identity binding cannot be deleted');\n" +
				"END",
			preservesSchemaAndFKs: true,
		},
		{
			name: "binding predates network",
			tamper: `DROP TRIGGER controller_identity_state_immutable;
				UPDATE controller_identity_state SET created_at=0;
				CREATE TRIGGER controller_identity_state_immutable BEFORE UPDATE ON controller_identity_state
				BEGIN SELECT RAISE(ABORT, 'controller identity binding is immutable'); END`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			directory := t.TempDir()
			store, err := Open(ctx, filepath.Join(directory, "source.db"))
			if err != nil {
				t.Fatal(err)
			}
			configured, authenticated := initialNetworkFixture()
			if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
				store.Close()
				t.Fatal(err)
			}
			source := filepath.Join(directory, "tampered.db")
			if err := store.Backup(ctx, source); err != nil {
				store.Close()
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.tamper); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if test.preservesSchemaAndFKs {
				wantFingerprint, wantObjects, err := expectedAdministratorSchemaFingerprint(ctx, currentSchemaVersion)
				if err != nil {
					db.Close()
					t.Fatal(err)
				}
				gotFingerprint, gotObjects, err := administratorSchemaFingerprint(ctx, db)
				if err != nil {
					db.Close()
					t.Fatal(err)
				}
				if gotObjects != wantObjects || gotFingerprint != wantFingerprint {
					db.Close()
					t.Fatal("durable-state deletion changed the canonical schema fingerprint")
				}
				rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
				if err != nil {
					db.Close()
					t.Fatal(err)
				}
				if rows.Next() {
					rows.Close()
					db.Close()
					t.Fatal("durable-state deletion introduced a foreign-key violation")
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					db.Close()
					t.Fatal(err)
				}
				if err := rows.Close(); err != nil {
					db.Close()
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil {
				t.Fatal("tampered controller identity backup restored")
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tampered restore published destination: %v", err)
			}
		})
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

func TestRestoreRejectsCurrentBackupWithoutEndpointStatusTable(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, _ := openTestStore(t)
	source := filepath.Join(directory, "missing-status.db")
	if err := store.Backup(ctx, source); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE endpoint_status_latest`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, source, destination); err == nil ||
		!strings.Contains(err.Error(), "required table endpoint_status_latest is missing") {
		t.Fatalf("restore missing endpoint status table error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete restore published destination: %v", err)
	}
}

func TestRestoreRejectsEndpointStatusTTLViolation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, _ := openTestStore(t)
	network := resourceTestNetwork(t, store, "tampered-backup-status", "10.118.0.0/24")
	node := resourceTestNode(t, store, network.ID, "tampered-backup-node", 0)
	current, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := testEndpointStatusReport()
	report.ConfigurationEpoch = current.ConfigurationEpoch
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID},
		report, time.Now()); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "tampered-status-ttl.db")
	if err := store.Backup(ctx, source); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA ignore_check_constraints=ON;
		UPDATE endpoint_status_latest SET expires_at=observed_at+10000;
		PRAGMA ignore_check_constraints=OFF`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), "endpoint status TTL is corrupt") {
		t.Fatalf("tampered endpoint TTL restore error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered endpoint TTL restore published destination: %v", err)
	}
}

func TestRestoreRejectsMissingNamedAccessPolicyTables(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	for _, table := range []string{"access_resources", "access_services", "access_service_ports", "access_resource_grants"} {
		t.Run(table, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "missing.db")
			if err := store.Backup(ctx, source); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`PRAGMA foreign_keys=OFF; DROP TABLE ` + table); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), "required table "+table+" is missing") {
				t.Fatalf("missing %s restore error=%v", table, err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing-table restore published destination: %v", err)
			}
		})
	}
}

func TestRestoreRejectsWeakenedNamedAccessPolicySchema(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, _ := openTestStore(t)
	source := filepath.Join(directory, "weakened-access.db")
	if err := store.Backup(ctx, source); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	var definition string
	if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name='access_resources'`).Scan(&definition); err != nil {
		db.Close()
		t.Fatal(err)
	}
	weakened := strings.Replace(definition, "target_kind TEXT NOT NULL CHECK(target_kind IN ('node','prefix'))", "target_kind TEXT NOT NULL", 1)
	if weakened == definition {
		db.Close()
		t.Fatal("fixture did not find resource target constraint")
	}
	if _, err := db.Exec(`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='access_resources'; PRAGMA writable_schema=OFF`, weakened); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "restored.db")
	if err := RestoreDatabase(ctx, source, destination); err == nil ||
		!strings.Contains(err.Error(), fmt.Sprintf("access policy schema does not match the canonical v%d definition", currentSchemaVersion)) {
		t.Fatalf("weakened access restore error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("weakened access restore published destination: %v", err)
	}
}

func TestRestoreRejectsMissingNamedAccessPolicyGuardTriggers(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	for _, trigger := range []string{
		"routes_identity_immutable",
		"access_services_staged_insert",
		"access_services_seal",
		"access_service_ports_staged_insert",
		"access_service_ports_immutable_update",
		"access_service_ports_immutable_delete",
	} {
		t.Run(trigger, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "missing-trigger.db")
			if err := store.Backup(ctx, source); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`DROP TRIGGER ` + trigger); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil ||
				!strings.Contains(err.Error(), fmt.Sprintf("access policy schema does not match the canonical v%d definition", currentSchemaVersion)) {
				t.Fatalf("missing trigger %s restore error=%v", trigger, err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing-trigger restore published destination: %v", err)
			}
		})
	}
}

func TestRestoreRejectsNamedAccessPolicyDataTamperingWithRestoredGuards(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	network := resourceTestNetwork(t, store, "backup-named-access", "10.92.0.0/24")
	firstConnector := resourceTestNode(t, store, network.ID, "backup-first-connector", protocol.CapabilitySubnetRouterV1)
	secondConnector := resourceTestNode(t, store, network.ID, "backup-second-connector", protocol.CapabilitySubnetRouterV1)
	route, err := store.AdvertiseRoute(ctx, firstConnector.ID, netip.MustParsePrefix("10.242.0.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRoute(ctx, route.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AdministratorCreateAccessResource(ctx,
		administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Backup database", AccessResourceTargetPrefix, nil, &route.ID, netip.MustParsePrefix("10.242.0.9/32")); err != nil {
		t.Fatal(err)
	}
	service, _, err := store.AdministratorCreateAccessService(ctx,
		administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Backup HTTPS", AccessServiceTCP, []AccessPortRange{{First: 443, Last: 443}})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		trigger  string
		mutation string
		args     []any
		want     string
	}{
		{name: "missing service ports", trigger: "access_service_ports_immutable_delete",
			mutation: `DELETE FROM access_service_ports WHERE service_id=?`, args: []any{idBytes(service.ID)}, want: "service ports are missing or non-canonical"},
		{name: "retargeted route", trigger: "routes_identity_immutable",
			mutation: `UPDATE routes SET node_id=? WHERE id=?`, args: []any{idBytes(secondConnector.ID), idBytes(route.ID)}, want: "pinned route target changed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "tampered.db")
			if err := store.Backup(ctx, source); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", source)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				db.Close()
				t.Fatal(err)
			}
			var definition string
			if err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?`, test.trigger).Scan(&definition); err != nil {
				tx.Rollback()
				db.Close()
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, `DROP TRIGGER `+test.trigger); err != nil {
				tx.Rollback()
				db.Close()
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, test.mutation, test.args...); err != nil {
				tx.Rollback()
				db.Close()
				t.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, definition); err != nil {
				tx.Rollback()
				db.Close()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("tampered restore error=%v want %q", err, test.want)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("tampered restore published destination: %v", err)
			}
		})
	}
}

func TestBackupAndRestoreRejectAutomationLimitTamperingWithRestoredGuards(t *testing.T) {
	tests := []struct {
		name, trigger, want string
		mutate              func(context.Context, *sql.Tx, identity.NetworkID) error
	}{
		{
			name:    "enabled service principals",
			trigger: "automation_service_principals_enabled_limit",
			want:    "enabled service principal limit exceeded",
			mutate: func(ctx context.Context, tx *sql.Tx, _ identity.NetworkID) error {
				if _, err := tx.ExecContext(ctx, `WITH RECURSIVE sequence(value) AS (
					VALUES(1) UNION ALL SELECT value+1 FROM sequence WHERE value<101
				) INSERT INTO automation_service_principals
					(id,name,enabled,all_networks,created_at,updated_at)
					SELECT randomblob(16),printf('backup-bot-%03d',value),1,0,1,1 FROM sequence`); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_permissions
					(principal_id,operation,created_at)
					SELECT id,'network.create',1 FROM automation_service_principals
					WHERE name LIKE 'backup-bot-%'`)
				return err
			},
		},
		{
			name:    "unrevoked service access tokens",
			trigger: "automation_service_access_token_unrevoked_limit",
			want:    "unrevoked service access token limit exceeded",
			mutate: func(ctx context.Context, tx *sql.Tx, _ identity.NetworkID) error {
				if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
					(id,name,enabled,all_networks,created_at,updated_at)
					VALUES(x'01000000000000000000000000000001','token-cap-bot',1,0,1,1);
					INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at)
					VALUES(x'01000000000000000000000000000001','network.create',1)`); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `WITH RECURSIVE sequence(value) AS (
					VALUES(1) UNION ALL SELECT value+1 FROM sequence WHERE value<101
				) INSERT INTO automation_service_access_tokens
					(id,principal_id,label,token_hash,created_at,expires_at)
					SELECT randomblob(16),x'01000000000000000000000000000001',
					printf('token-%03d',value),randomblob(32),1,3601 FROM sequence`)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAutomationBackupAndRestoreRejectTamper(t, test.trigger, test.want, test.mutate)
		})
	}
}

func TestBackupAndRestoreRejectInvalidServicePrincipalShape(t *testing.T) {
	tests := []struct {
		name, trigger string
		mutate        func(context.Context, *sql.Tx, identity.NetworkID) error
	}{
		{
			name: "zero permissions",
			mutate: func(ctx context.Context, tx *sql.Tx, _ identity.NetworkID) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
					(id,name,enabled,all_networks,created_at,updated_at)
					VALUES(x'02000000000000000000000000000001','empty-permissions',1,0,1,1)`)
				return err
			},
		},
		{
			name: "network permission without scope",
			mutate: func(ctx context.Context, tx *sql.Tx, _ identity.NetworkID) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
					(id,name,enabled,all_networks,created_at,updated_at)
					VALUES(x'02000000000000000000000000000002','unscoped-reader',1,0,1,1);
					INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at)
					VALUES(x'02000000000000000000000000000002','network.read',1)`)
				return err
			},
		},
		{
			name:    "all networks with explicit scope",
			trigger: "automation_service_principal_scope_requires_scoped",
			mutate: func(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID) error {
				if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
					(id,name,enabled,all_networks,created_at,updated_at)
					VALUES(x'02000000000000000000000000000003','ambiguous-reader',1,1,1,1);
					INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at)
					VALUES(x'02000000000000000000000000000003','network.read',1)`); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_networks
					(principal_id,network_id,created_at)
					VALUES(x'02000000000000000000000000000003',?,1)`, idBytes(networkID))
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAutomationBackupAndRestoreRejectTamper(t, test.trigger,
				"service principal is invalid", test.mutate)
		})
	}
}

func assertAutomationBackupAndRestoreRejectTamper(t *testing.T, trigger, want string,
	mutate func(context.Context, *sql.Tx, identity.NetworkID) error,
) {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	store, _ := openTestStore(t)
	network, err := store.CreateNetwork(ctx, "automation-backup", netip.MustParsePrefix("10.119.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	restoreSource := filepath.Join(directory, "restore-source.db")
	if err := store.Backup(ctx, restoreSource); err != nil {
		t.Fatal(err)
	}
	applyAutomationBackupTamper(t, ctx, store.db, network.ID, trigger, mutate)
	restoreDB, err := sql.Open("sqlite", restoreSource)
	if err != nil {
		t.Fatal(err)
	}
	applyAutomationBackupTamper(t, ctx, restoreDB, network.ID, trigger, mutate)
	if err := restoreDB.Close(); err != nil {
		t.Fatal(err)
	}

	backupDestination := filepath.Join(directory, "rejected-backup.db")
	if err := store.Backup(ctx, backupDestination); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("tampered backup error=%v want %q", err, want)
	}
	if _, err := os.Stat(backupDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered backup published destination: %v", err)
	}
	restoreDestination := filepath.Join(directory, "rejected-restore.db")
	if err := RestoreDatabase(ctx, restoreSource, restoreDestination); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("tampered restore error=%v want %q", err, want)
	}
	if _, err := os.Stat(restoreDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered restore published destination: %v", err)
	}
	assertNoTemporaryDatabaseFiles(t, directory)
}

func applyAutomationBackupTamper(t *testing.T, ctx context.Context, db *sql.DB,
	networkID identity.NetworkID, trigger string,
	mutate func(context.Context, *sql.Tx, identity.NetworkID) error,
) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var definition string
	if trigger != "" {
		if err := tx.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema
			WHERE type='trigger' AND name=?`, trigger).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `DROP TRIGGER `+trigger); err != nil {
			t.Fatal(err)
		}
	}
	if err := mutate(ctx, tx, networkID); err != nil {
		t.Fatal(err)
	}
	if definition != "" {
		if _, err := tx.ExecContext(ctx, definition); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	wantFingerprint, wantObjects, err := expectedAdministratorSchemaFingerprint(ctx, currentSchemaVersion)
	if err != nil {
		t.Fatal(err)
	}
	gotFingerprint, gotObjects, err := administratorSchemaFingerprint(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if gotObjects != wantObjects || gotFingerprint != wantFingerprint {
		t.Fatal("automation data tamper did not restore the canonical schema exactly")
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
	if version != currentSchemaVersion || sessions != 0 || pending != 0 || state.RecoveryGeneration != 2 {
		t.Fatalf("restored version=%d sessions=%d pending=%d state=%+v", version, sessions, pending, state)
	}
}

func TestExactV11BackupRestoreAndInitialNetworkAdoption(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	source := filepath.Join(directory, "source-v11.db")
	raw, err := sql.Open("sqlite", "file:"+source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE schema_versions(
		version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` +
		strings.Join(migrations[:11], "\n")); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 11; version++ {
		if _, err := raw.Exec(`INSERT INTO schema_versions(version,applied_at) VALUES(?,?)`, version, version); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	configured, authenticated := initialNetworkFixture()
	if _, err := raw.Exec(`INSERT INTO networks
		(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length,next_ipv6)
		VALUES(?,?,?,?,1,7,100,?,?,1)`, idBytes(configured.NetworkID), configured.Name,
		configured.IPv4Pool.Addr().AsSlice(), configured.IPv4Pool.Bits(),
		configured.IPv6Pool.Addr().AsSlice(), configured.IPv6Pool.Bits()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(directory, "backup-v11.db")
	if err := BackupDatabase(ctx, source, backup); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"source": source, "backup": backup} {
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		var version, identityTables int
		if err := db.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='controller_identity_state'`).Scan(&identityTables); err != nil {
			db.Close()
			t.Fatal(err)
		}
		db.Close()
		if version != 11 || identityTables != 0 {
			t.Fatalf("%s mutated: version=%d identity tables=%d", name, version, identityTables)
		}
	}

	restoredPath := filepath.Join(directory, "restored-v12.db")
	if err := RestoreDatabase(ctx, backup, restoredPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(ctx, restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if version, err := restored.SchemaVersion(ctx); err != nil || version != currentSchemaVersion {
		t.Fatalf("restored schema version=%d err=%v", version, err)
	}
	network, created, err := restored.EnsureControllerInitialNetwork(ctx, configured, authenticated)
	if err != nil || created || network.ConfigurationEpoch != 7 || !initialNetworkMatches(network, configured) {
		t.Fatalf("restored v11 adoption network=%+v created=%t err=%v", network, created, err)
	}
	for _, table := range []string{"access_users", "access_teams", "access_team_members", "access_grants"} {
		var count int
		if err := restored.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("restored access table %s count=%d", table, count)
		}
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
	if err := RestoreDatabase(ctx, validBackup, destination); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("canonical v%d definition", currentSchemaVersion)) {
		t.Fatalf("malformed current-schema restore error=%v, want canonical-schema rejection", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("malformed restore published destination: %v", err)
	}
}

func TestRestoreRejectsWeakenedCurrentAdministratorDDL(t *testing.T) {
	for _, test := range []struct {
		name                   string
		objectType, objectName string
		old, newer             string
	}{
		{
			name: "partial password uniqueness predicate", objectType: "index",
			objectName: "one_active_administrator_password",
			old:        `WHERE credential_type = 'password' AND revoked_at IS NULL`,
			newer:      `WHERE credential_type = 'password'`,
		},
		{
			name: "administrator role constraint", objectType: "table", objectName: "administrator_principals",
			old: `role TEXT NOT NULL CHECK(role IN ('owner','operator','auditor'))`, newer: `role TEXT NOT NULL`,
		},
		{
			name: "endpoint status TTL constraint", objectType: "table", objectName: "endpoint_status_latest",
			old:   `valid_for_seconds INTEGER NOT NULL CHECK(valid_for_seconds BETWEEN 10 AND 300)`,
			newer: `valid_for_seconds INTEGER NOT NULL`,
		},
		{
			name: "endpoint status expiry relation", objectType: "table", objectName: "endpoint_status_latest",
			old:   `expires_at INTEGER NOT NULL CHECK(expires_at = observed_at + valid_for_seconds)`,
			newer: `expires_at INTEGER NOT NULL`,
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
			if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE type=? AND name=?`, test.objectType, test.objectName).Scan(&definition); err != nil {
				db.Close()
				t.Fatal(err)
			}
			weakened := strings.Replace(definition, test.old, test.newer, 1)
			if weakened == definition {
				db.Close()
				t.Fatalf("fixture did not find canonical fragment %q", test.old)
			}
			if _, err := db.Exec(`PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=? WHERE type=? AND name=?; PRAGMA writable_schema=OFF`,
				weakened, test.objectType, test.objectName); err != nil {
				db.Close()
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(directory, "restored.db")
			if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("canonical v%d definition", currentSchemaVersion)) {
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
	if err := RestoreDatabase(ctx, source, destination); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("canonical v%d definition", currentSchemaVersion)) {
		t.Fatalf("unexpected-trigger restore error=%v, want canonical-schema rejection", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected-trigger restore published destination: %v", err)
	}
}
