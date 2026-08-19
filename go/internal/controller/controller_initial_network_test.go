package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Doout/laneway/go/internal/identity"
)

func TestEnsureControllerInitialNetworkFreshAndIdempotent(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_100_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	configured, authenticated := initialNetworkFixture()

	legacy, created, err := store.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, authenticated)
	if err != nil || created || !legacy.ID.IsZero() {
		t.Fatalf("unconfigured ensure network=%+v created=%t err=%v", legacy, created, err)
	}
	for _, table := range []string{"networks", "controller_identity_state", "audit_events"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("unconfigured ensure wrote %d %s rows", count, table)
		}
	}

	network, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
	if err != nil || !created || !initialNetworkMatches(network, configured) || !network.CreatedAt.Equal(now) {
		t.Fatalf("fresh ensure network=%+v created=%t err=%v", network, created, err)
	}
	assertControllerIdentityState(t, store, configured.NetworkID, authenticated.SubjectID, now)
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 1)

	restarted, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
	if err != nil || created || restarted != network {
		t.Fatalf("restart ensure network=%+v created=%t err=%v", restarted, created, err)
	}
	withoutConfig, created, err := store.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, authenticated)
	if err != nil || created || withoutConfig != network {
		t.Fatalf("restart without config network=%+v created=%t err=%v", withoutConfig, created, err)
	}
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 1)
}

func TestEnsureControllerInitialNetworkAdoptsExactLegacyNetwork(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	configured, authenticated := initialNetworkFixture()
	createdAt := time.Unix(2_200_000_000, 0).UTC()
	store.now = func() time.Time { return createdAt }
	legacy, err := store.CreateNetworkDualStackWithID(ctx, configured.NetworkID, configured.Name, configured.IPv4Pool, configured.IPv6Pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateNetwork(ctx, "other", netip.MustParsePrefix("100.98.0.0/16")); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return createdAt.Add(-24 * time.Hour) }

	adopted, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
	if err != nil || created || adopted != legacy {
		t.Fatalf("legacy adoption network=%+v created=%t err=%v", adopted, created, err)
	}
	assertControllerIdentityState(t, store, configured.NetworkID, authenticated.SubjectID, createdAt)
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 1)
}

func TestEnsureControllerInitialNetworkRejectsDriftAndNonemptyFreshState(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	configured, authenticated := initialNetworkFixture()
	if _, err := store.CreateNetwork(ctx, "existing", netip.MustParsePrefix("100.99.0.0/16")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); !errors.Is(err, ErrConflict) {
		t.Fatalf("absent configured network in nonempty store error=%v", err)
	}
	var bindings int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM controller_identity_state`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 {
		t.Fatalf("failed ensure left %d identity bindings", bindings)
	}

	boundStore, _ := openTestStore(t)
	if _, _, err := boundStore.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]identity.AuthenticatedIdentity{
		"network": {NetworkID: identity.NetworkID{9}, Role: identity.IdentityRoleController, SubjectID: authenticated.SubjectID},
		"service": {NetworkID: authenticated.NetworkID, Role: identity.IdentityRoleController, SubjectID: identity.ID{9}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := boundStore.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, candidate); !errors.Is(err, ErrConflict) {
				t.Fatalf("identity drift error=%v", err)
			}
		})
	}
	drift := configured
	drift.Name = "different"
	if _, _, err := boundStore.EnsureControllerInitialNetwork(ctx, drift, authenticated); !errors.Is(err, ErrConflict) {
		t.Fatalf("configuration drift error=%v", err)
	}
	nonController := authenticated
	nonController.Role = identity.IdentityRoleRelay
	if _, _, err := boundStore.EnsureControllerInitialNetwork(ctx, configured, nonController); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-controller identity error=%v", err)
	}
}

func TestEnsureControllerInitialNetworkRollsBackFreshAndAdoptBindingFailures(t *testing.T) {
	for _, adopt := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "adopt"}[adopt], func(t *testing.T) {
			store, _ := openTestStore(t)
			ctx := context.Background()
			configured, authenticated := initialNetworkFixture()
			if adopt {
				if _, err := store.CreateNetworkDualStackWithID(ctx, configured.NetworkID, configured.Name, configured.IPv4Pool, configured.IPv6Pool); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_controller_identity_audit
				BEFORE INSERT ON audit_events WHEN NEW.action='controller.identity.bind'
				BEGIN SELECT RAISE(ABORT, 'fixture rejects binding audit'); END`); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err == nil {
				t.Fatal("ensure unexpectedly survived binding audit failure")
			}
			var networks, bindings, bindingAudits int
			_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM networks`).Scan(&networks)
			_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM controller_identity_state`).Scan(&bindings)
			_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action='controller.identity.bind'`).Scan(&bindingAudits)
			wantNetworks := 0
			if adopt {
				wantNetworks = 1
			}
			if networks != wantNetworks || bindings != 0 || bindingAudits != 0 {
				t.Fatalf("rollback networks=%d want=%d bindings=%d audits=%d", networks, wantNetworks, bindings, bindingAudits)
			}
		})
	}
}

func TestEnsureControllerInitialNetworkConcurrentStores(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	configured, authenticated := initialNetworkFixture()
	type result struct {
		network Network
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wait.Add(1)
		go func(store *Store) {
			defer wait.Done()
			<-start
			network, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
			results <- result{network: network, created: created, err: err}
		}(store)
	}
	close(start)
	wait.Wait()
	close(results)
	created := 0
	for result := range results {
		if result.err != nil || !initialNetworkMatches(result.network, configured) {
			t.Fatalf("concurrent ensure network=%+v error=%v", result.network, result.err)
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("concurrent created results=%d, want 1", created)
	}
	assertInitialNetworkAuditCounts(t, first, configured.NetworkID, 1, 1)
}

func TestV12MigrationPreservesV11AccessSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller-v11.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	schema := `CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` +
		strings.Join(migrations[:11], "\n")
	if _, err := raw.Exec(schema); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	for version := 1; version <= 11; version++ {
		if _, err := raw.Exec(`INSERT INTO schema_versions(version,applied_at) VALUES(?,?)`, version, version); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	networkID := identity.NetworkID{1}
	userID, teamID, grantID := identity.ID{2}, identity.ID{3}, identity.ID{4}
	pool := netip.MustParsePrefix("100.96.0.0/24")
	if _, err := raw.Exec(`INSERT INTO networks
		(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at)
		VALUES(?,?,?,?,1,1,100)`, idBytes(networkID), "production", pool.Addr().AsSlice(), pool.Bits()); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO access_users(id,network_id,name,enabled,created_at,updated_at)
		VALUES(?,?,?,1,100,100)`, idBytes(userID), idBytes(networkID), "operator"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO access_teams(id,network_id,name,created_at,updated_at)
		VALUES(?,?,?,100,100)`, idBytes(teamID), idBytes(networkID), "platform"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO access_team_members(network_id,team_id,user_id,created_at)
		VALUES(?,?,?,100)`, idBytes(networkID), idBytes(teamID), idBytes(userID)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO access_grants
		(id,network_id,subject_kind,user_id,team_id,target_kind,node_id,created_at)
		VALUES(?,?,'team',NULL,?,'network',NULL,100)`, idBytes(grantID), idBytes(networkID), idBytes(teamID)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if version, err := store.SchemaVersion(ctx); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d error=%v", version, err)
	}
	for _, object := range []string{"access_users", "access_teams", "access_team_members", "access_grants", "controller_identity_state"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, object).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s count=%d", object, count)
		}
	}
	for _, table := range []string{"access_users", "access_teams", "access_team_members", "access_grants"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("preserved %s rows=%d", table, count)
		}
	}
}

func TestControllerIdentityBindingIsImmutable(t *testing.T) {
	store, _ := openTestStore(t)
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(context.Background(), configured, authenticated); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE controller_identity_state SET controller_service_id=? WHERE singleton=1`, idBytes(identity.ID{9})); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("binding update error=%v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM controller_identity_state WHERE singleton=1`); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("binding delete error=%v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM networks WHERE id=?`, idBytes(configured.NetworkID)); err == nil {
		t.Fatal("bound network was deleted")
	}
}

func initialNetworkFixture() (ControllerInitialNetwork, identity.AuthenticatedIdentity) {
	networkID := identity.NetworkID{1}
	return ControllerInitialNetwork{
			NetworkID: networkID,
			Name:      "production",
			IPv4Pool:  netip.MustParsePrefix("100.96.0.0/16"),
			IPv6Pool:  netip.MustParsePrefix("fd00:96::/64"),
		}, identity.AuthenticatedIdentity{
			NetworkID: networkID,
			Role:      identity.IdentityRoleController,
			SubjectID: identity.ID{2},
		}
}

func assertControllerIdentityState(t *testing.T, store *Store, networkID identity.NetworkID, serviceID identity.ID, createdAt time.Time) {
	t.Helper()
	var networkRaw, serviceRaw []byte
	var created int64
	if err := store.db.QueryRow(`SELECT network_id,controller_service_id,created_at FROM controller_identity_state WHERE singleton=1`).Scan(&networkRaw, &serviceRaw, &created); err != nil {
		t.Fatal(err)
	}
	if string(networkRaw) != string(idBytes(networkID)) || string(serviceRaw) != string(idBytes(serviceID)) || created != unix(createdAt) {
		t.Fatalf("binding network=%x service=%x created=%d", networkRaw, serviceRaw, created)
	}
}

func assertInitialNetworkAuditCounts(t *testing.T, store *Store, networkID identity.NetworkID, networkCreates, identityBinds int) {
	t.Helper()
	var creates, binds int
	if err := store.db.QueryRow(`SELECT COALESCE(sum(action='network.create'),0),COALESCE(sum(action='controller.identity.bind'),0)
		FROM audit_events WHERE network_id=?`, idBytes(networkID)).Scan(&creates, &binds); err != nil {
		t.Fatal(err)
	}
	if creates != networkCreates || binds != identityBinds {
		t.Fatalf("network.create audits=%d want=%d, controller.identity.bind audits=%d want=%d", creates, networkCreates, binds, identityBinds)
	}
}
