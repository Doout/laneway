//go:build rustinterop && unix

package controllerservice

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"golang.org/x/sys/unix"
)

func testRustBackupRestore(t *testing.T, client *http.Client, cert, key, rootFile string) {
	f := newFixture(t, 0, nil)
	ctx := t.Context()
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	_, token, csrf, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "backup-owner", "backup fixture owner password")
	original, err := f.store.AdministratorAuthState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	configured := controller.ControllerInitialNetwork{NetworkID: f.network.ID, Name: f.network.Name, IPv4Pool: f.network.IPv4Pool, IPv6Pool: f.network.IPv6Pool}
	authenticated := identity.AuthenticatedIdentity{NetworkID: f.network.ID, Role: identity.IdentityRoleController, SubjectID: serviceID}
	if _, created, err := f.store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil || created {
		t.Fatalf("bind existing controller identity: created=%t err=%v", created, err)
	}
	nodeToken, err := f.store.IssueEnrollmentToken(ctx, f.network.ID, "backup node", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	node, err := f.store.EnrollNodeWithCertificate(ctx, nodeToken.Secret, "backup node", 0, func(_ context.Context, subject controller.Node) (controller.CertificateMaterial, error) {
		_, leaf, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: f.network.ID, NodeID: subject.ID}, time.Now(), time.Hour)
		if err != nil {
			return controller.CertificateMaterial{}, err
		}
		return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	live, stop := startRustAdministratorLab(t, f.dbPath, cert, key, rootFile)
	const sessionPath = "/v1/admin/auth/session"
	browser := labCredentials{session: token, csrf: csrf}
	base := "/v1/admin/networks/" + f.network.ID.String()
	send(live, "GET", sessionPath, "", browser, 200)
	send(live, "POST", "/v1/admin/administrators/"+original.InitialOwnerPrincipalID.String()+"/recovery-grants", "", root, 201)
	bot := send(live, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"backup-reader","permissions":["network.read"],"network_ids":[%q]}`, f.network.ID.String()), root, 201)["principal_id"].(string)
	access := send(live, "POST", "/v1/admin/service-principals/"+bot+"/tokens", fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)
	automation := labCredentials{bearer: access}
	send(live, "GET", base, "", automation, 200)
	send(live, "POST", base+"/services", `{"name":"backup service","protocol":"tcp","ports":[{"first":443,"last":443}]}`, root, 201)
	checkpoint, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var busy, pages, written int
	err = checkpoint.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &written)
	checkpoint.Close()
	if err != nil || busy != 0 {
		t.Fatalf("checkpoint fixture before WAL-only write: %d %v", busy, err)
	}
	rule, beforeEpoch, err := f.store.AddACLRule(ctx, f.network.ID, 17, controller.ACLActionDeny, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "committed in WAL")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(f.dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("expected active source WAL: %v", err)
	}
	mainOnly, err := sql.Open("sqlite", "file:"+f.dbPath+"?immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	var premature int
	err = mainOnly.QueryRow("SELECT count(*) FROM acl_rules WHERE id=?", rule.ID[:]).Scan(&premature)
	mainOnly.Close()
	if err != nil || premature != 0 {
		t.Fatalf("fixture ACL must exist only in WAL before backup: %d %v", premature, err)
	}
	run := func(failure string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), args...)
		out, err := cmd.CombinedOutput()
		if (failure == "" && err != nil) || (failure != "" && (err == nil || !strings.Contains(string(out), failure))) {
			t.Fatalf("%s: %v; wanted failure %q; output %s", args[0], err, failure, out)
		}
	}
	dir := t.TempDir()
	rustBackup := filepath.Join(dir, "rust-backup.db")
	goBackup := filepath.Join(dir, "go-backup.db")
	restored := filepath.Join(dir, "rust-restored.db")
	run("already in use", "migrate-fleet", f.dbPath)
	run("", "backup", f.dbPath, rustBackup)
	if err := f.store.Backup(ctx, goBackup); err != nil {
		t.Fatal(err)
	}
	run("already exists", "backup", f.dbPath, rustBackup)
	if info, err := os.Stat(rustBackup); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions not private: %v %v", info, err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(rustBackup + suffix); !os.IsNotExist(err) {
			t.Fatalf("backup is not standalone: %s: %v", suffix, err)
		}
	}
	lock, err := os.OpenFile(restored+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		t.Fatal(err)
	}
	run("already in use", "restore", goBackup, restored)
	lock.Close()
	run("", "restore", goBackup, restored)
	run("already exists", "restore", goBackup, restored)
	newEndpoint, stopRestored := startRustAdministratorLab(t, restored, cert, key, rootFile)
	send(newEndpoint, "GET", sessionPath, "", browser, 401)
	send(newEndpoint, "GET", base, "", automation, 401)
	if result := send(newEndpoint, "GET", base, "", root, 200); result["configuration_epoch"] != float64(beforeEpoch) {
		t.Fatalf("restored wrong epoch: %#v", result)
	}
	rules := send(newEndpoint, "GET", base+"/acl-rules", "", root, 200)["acl_rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["rule_id"] != rule.ID.String() {
		t.Fatalf("restored wrong ACL: %#v", rules)
	}
	stopRestored()
	send(live, "GET", sessionPath, "", browser, 200)
	send(live, "GET", base, "", automation, 200)
	stop()

	count := func(db *sql.DB, query string, want int, args ...any) {
		t.Helper()
		var got int
		if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil || got != want {
			t.Fatalf("state check got %d want %d: %v (%s)", got, want, err, query)
		}
	}
	checkPublic := func(path string) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		count(db, "SELECT count(*) FROM administrator_sessions", 0)
		count(db, "SELECT count(*) FROM administrator_recovery_grants WHERE consumed_at IS NULL", 0)
		count(db, "SELECT count(*) FROM administrator_recovery_grants WHERE consumed_at IS NOT NULL", 1)
		count(db, "SELECT count(*) FROM administrator_auth_state WHERE recovery_generation=? AND root_service_principal_id=? AND last_recovered_at IS NOT NULL", 1, original.RecoveryGeneration+1, original.RootServicePrincipalID[:])
		count(db, "SELECT count(*) FROM automation_service_access_tokens WHERE revoked_at IS NOT NULL AND revocation_reason='controller database restored'", 1)
		count(db, "SELECT count(*) FROM audit_events WHERE action='controller.restore' AND actor_kind='system' AND network_id IS NULL", 1)
		count(db, "SELECT count(*) FROM acl_rules WHERE id=?", 1, rule.ID[:])
		count(db, "SELECT count(*) FROM controller_identity_state WHERE network_id=? AND controller_service_id=?", 1, f.network.ID[:], serviceID[:])
	}
	checkPublic(restored)
	goRestored := filepath.Join(dir, "go-restored.db")
	if err := controller.RestoreDatabase(ctx, rustBackup, goRestored); err != nil {
		t.Fatalf("Go could not restore Rust backup: %v", err)
	}
	checkPublic(goRestored)

	fleet := filepath.Join(dir, "fleet.db")
	fleetBackup := filepath.Join(dir, "fleet-backup.db")
	fleetRestored := filepath.Join(dir, "fleet-restored.db")
	run("", "backup", rustBackup, fleet)
	run("", "migrate-fleet", fleet)
	fleetDB, err := sql.Open("sqlite", fleet)
	if err != nil {
		t.Fatal(err)
	}
	defer fleetDB.Close()
	execSQL := func(db *sql.DB, sql string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	const nodeBytes = 16
	var update [nodeBytes]byte
	update[0] = 1
	execSQL(fleetDB, `INSERT INTO fleet_updates(id,network_id,version,component,channel,target_count,canary_count,state,created_at,updated_at)
		VALUES(?,?,'v1.2.3','node','stable',1,1,'rollout',unixepoch(),unixepoch())`, update[:], f.network.ID[:])
	execSQL(fleetDB, "INSERT INTO fleet_update_targets(update_id,network_id,node_id,canary,state,updated_at) VALUES(?,?,?,1,'running',unixepoch())", update[:], f.network.ID[:], node.Node.ID[:])
	execSQL(fleetDB, "INSERT INTO fleet_update_agents VALUES(?,'node','stable','v1.2.2',unixepoch())", node.Node.ID[:])
	execSQL(fleetDB, "INSERT INTO node_topology VALUES(?,unixepoch(),unixepoch()+300,'[]')", node.Node.ID[:])
	execSQL(fleetDB, `INSERT INTO node_credential_recovery_grants
		SELECT randomblob(32),network_id,node_id,id,unixepoch()+300,NULL,unixepoch() FROM certificates WHERE node_id=?`, node.Node.ID[:])
	execSQL(fleetDB, "INSERT INTO policy_revisions VALUES(?,1,?,'[]',unixepoch())", f.network.ID[:], beforeEpoch)
	run("", "backup", fleet, fleetBackup)
	run("", "restore", fleetBackup, fleetRestored)
	checkPublic(fleetRestored)
	checkFleet := func(path, state string, ephemeral int) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		count(db, "SELECT count(*) FROM fleet_updates WHERE state=?", 1, state)
		count(db, "SELECT count(*) FROM fleet_update_targets WHERE state='running'", 1)
		count(db, "SELECT count(*) FROM fleet_update_agents", ephemeral)
		count(db, "SELECT count(*) FROM node_topology", ephemeral)
		count(db, "SELECT count(*) FROM node_credential_recovery_grants", ephemeral)
		count(db, "SELECT count(*) FROM policy_revisions", 1)
	}
	checkFleet(fleetBackup, "rollout", 1)
	checkFleet(fleetRestored, "paused", 0)

	tampered := filepath.Join(dir, "tampered.db")
	run("", "backup", rustBackup, tampered)
	tamperedDB, err := sql.Open("sqlite", tampered)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(tamperedDB, "CREATE TRIGGER unexpected_restore_trigger AFTER DELETE ON administrator_sessions BEGIN SELECT 1; END")
	tamperedDB.Close()
	rejected := filepath.Join(dir, "rejected.db")
	run("schema does not match", "restore", tampered, rejected)
	if _, err := os.Lstat(rejected); !os.IsNotExist(err) {
		t.Fatalf("failed restore published database: %v", err)
	}
	fault := filepath.Join(dir, "fault.db")
	run("", "backup", rustBackup, fault)
	faultDB, err := sql.Open("sqlite", fault)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(faultDB, "UPDATE administrator_auth_state SET recovery_generation=9223372036854775807")
	run("advance restored authentication generation", "restore", fault, rejected)
	if _, err := os.Lstat(rejected); !os.IsNotExist(err) {
		t.Fatalf("partially restored database was published: %v", err)
	}
	count(faultDB, "SELECT count(*) FROM administrator_sessions", 1)
	count(faultDB, "SELECT count(*) FROM automation_service_access_tokens WHERE revoked_at IS NULL", 1)
	faultDB.Close()
	if staging, err := filepath.Glob(filepath.Join(dir, ".laneway-database-*")); err != nil || len(staging) != 0 {
		t.Fatalf("restore left private staging files: %v %v", staging, err)
	}
	linked := filepath.Join(dir, "symlink.db")
	if err := os.Symlink(rustBackup, linked); err != nil {
		t.Fatal(err)
	}
	run("not a symlink", "backup", linked, rejected)
	run("already exists", "backup", rustBackup, linked)
	stale := filepath.Join(dir, "stale.db")
	if err := os.WriteFile(stale+"-wal", []byte("existing sidecar"), 0600); err != nil {
		t.Fatal(err)
	}
	run("sidecar already exists", "restore", rustBackup, stale)
	if content, err := os.ReadFile(stale + "-wal"); err != nil || string(content) != "existing sidecar" {
		t.Fatalf("restore replaced an unrelated sidecar: %v", err)
	}
}
