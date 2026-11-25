package controller

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"laneway.dev/laneway/internal/identity"
)

func TestEnsureControllerInitialNetworkFreshAndIdempotent(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(2_100_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	configured, authenticated := initialNetworkFixture()
	legacy, created, err := store.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, authenticated)
	if err != nil || created || !legacy.ID.IsZero() {
		t.Fatalf("unconfigured legacy ensure network=%+v created=%t err=%v", legacy, created, err)
	}
	for _, table := range []string{"networks", "controller_identity_state", "audit_events"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("unconfigured legacy ensure wrote %d %s rows", count, table)
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
		t.Fatalf("unconfigured restart network=%+v created=%t err=%v", withoutConfig, created, err)
	}
	assertControllerIdentityState(t, store, configured.NetworkID, authenticated.SubjectID, now)
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 1)
}

func TestEnsureControllerInitialNetworkFailsClosedOnDrift(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
		t.Fatal(err)
	}

	differentNetwork := authenticated
	differentNetwork.NetworkID = identity.NetworkID{9}
	differentService := authenticated
	differentService.SubjectID = identity.ID{9}
	for name, candidate := range map[string]identity.AuthenticatedIdentity{
		"certificate network without config": differentNetwork,
		"certificate service without config": differentService,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := store.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, candidate); !errors.Is(err, ErrConflict) {
				t.Fatalf("error=%v, want ErrConflict", err)
			}
		})
	}

	for name, mutate := range map[string]func(*ControllerInitialNetwork){
		"name": func(value *ControllerInitialNetwork) { value.Name = "different" },
		"IPv4 pool": func(value *ControllerInitialNetwork) {
			value.IPv4Pool = netip.MustParsePrefix("100.97.0.0/16")
		},
		"IPv6 pool": func(value *ControllerInitialNetwork) {
			value.IPv6Pool = netip.MustParsePrefix("fd00:97::/64")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := configured
			mutate(&candidate)
			if _, _, err := store.EnsureControllerInitialNetwork(ctx, candidate, authenticated); !errors.Is(err, ErrConflict) {
				t.Fatalf("error=%v, want ErrConflict", err)
			}
		})
	}

	mismatchedID := configured
	mismatchedID.NetworkID = identity.NetworkID{8}
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, mismatchedID, authenticated); !errors.Is(err, ErrConflict) {
		t.Fatalf("configured/certificate network mismatch error=%v", err)
	}
	partial := ControllerInitialNetwork{Name: "partial"}
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, partial, authenticated); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial configuration error=%v", err)
	}
	nonController := authenticated
	nonController.Role = identity.IdentityRoleRelay
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, nonController); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-controller identity error=%v", err)
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
	var actorKind string
	if err := store.db.QueryRowContext(ctx, `SELECT actor_kind FROM audit_events
		WHERE network_id=? AND action='controller.identity.bind'`, idBytes(configured.NetworkID)).Scan(&actorKind); err != nil {
		t.Fatal(err)
	}
	if actorKind != "system" {
		t.Fatalf("binding audit actor=%q, want system", actorKind)
	}
}

func TestEnsureControllerInitialNetworkFreshCreationClampsGlobalAuditClock(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	future := time.Unix(2_300_000_000, 0).UTC()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO audit_events
		(id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
		VALUES(?,NULL,'system',NULL,'fixture.future','fixture',NULL,'{}',?)`,
		idBytes(identity.ID{9}), unix(future)); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return future.Add(-24 * time.Hour) }
	configured, authenticated := initialNetworkFixture()
	network, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
	if err != nil || !created || !network.CreatedAt.Equal(future) {
		t.Fatalf("rollback-clock fresh network=%+v created=%t err=%v", network, created, err)
	}
	assertControllerIdentityState(t, store, configured.NetworkID, authenticated.SubjectID, future)
	rows, err := store.db.QueryContext(ctx, `SELECT action,created_at FROM audit_events
		WHERE action IN ('network.create','controller.identity.bind') ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var action string
		var createdAt int64
		if err := rows.Scan(&action, &createdAt); err != nil {
			t.Fatal(err)
		}
		if createdAt != unix(future) {
			t.Fatalf("%s created_at=%d want=%d", action, createdAt, unix(future))
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("lifecycle audit count=%d, want 2", count)
	}
}

func TestEnsureControllerInitialNetworkRejectsAbsentIDInNonemptyStore(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateNetwork(ctx, "existing", netip.MustParsePrefix("100.99.0.0/16")); err != nil {
		t.Fatal(err)
	}
	configured, authenticated := initialNetworkFixture()
	var networksBefore, auditsBefore int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM networks`).Scan(&networksBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); !errors.Is(err, ErrConflict) {
		t.Fatalf("absent configured ID error=%v, want ErrConflict", err)
	}
	var networksAfter, auditsAfter, bindings int
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM networks`).Scan(&networksAfter)
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&auditsAfter)
	_ = store.db.QueryRowContext(ctx, `SELECT count(*) FROM controller_identity_state`).Scan(&bindings)
	if networksAfter != networksBefore || auditsAfter != auditsBefore || bindings != 0 {
		t.Fatalf("failed ensure mutated networks=%d/%d audits=%d/%d bindings=%d",
			networksBefore, networksAfter, auditsBefore, auditsAfter, bindings)
	}
}

func TestEnsureControllerInitialNetworkConcurrentFreshCalls(t *testing.T) {
	store, _ := openTestStore(t)
	configured, authenticated := initialNetworkFixture()
	const callers = 12
	var created atomic.Int32
	errorsByCaller := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasCreated, err := store.EnsureControllerInitialNetwork(context.Background(), configured, authenticated)
			if wasCreated {
				created.Add(1)
			}
			errorsByCaller <- err
		}()
	}
	wait.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatalf("concurrent ensure: %v", err)
		}
	}
	if created.Load() != 1 {
		t.Fatalf("created results=%d, want 1", created.Load())
	}
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 1)
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
	for _, store := range []*Store{first, second} {
		go func(store *Store) {
			<-start
			network, created, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated)
			results <- result{network: network, created: created, err: err}
		}(store)
	}
	close(start)
	var created int
	var stable Network
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("racing store ensure: %v", result.err)
		}
		if !initialNetworkMatches(result.network, configured) {
			t.Fatalf("racing store network=%+v", result.network)
		}
		if stable.ID.IsZero() {
			stable = result.network
		} else if result.network != stable {
			t.Fatalf("racing stores returned differing networks: %+v and %+v", stable, result.network)
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("racing store created results=%d, want 1", created)
	}
	assertInitialNetworkAuditCounts(t, first, configured.NetworkID, 1, 1)
}

func TestEnsureControllerInitialNetworkRollsBackAuditFailure(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_controller_identity_audit
		BEFORE INSERT ON audit_events WHEN NEW.action='controller.identity.bind'
		BEGIN SELECT RAISE(ABORT, 'fixture rejects binding audit'); END`); err != nil {
		t.Fatal(err)
	}
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err == nil {
		t.Fatal("ensure unexpectedly survived binding audit failure")
	}
	for _, table := range []string{"networks", "controller_identity_state", "audit_events"} {
		var count int
		if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s rows=%d after rollback", table, count)
		}
	}
}

func TestEnsureControllerInitialNetworkAdoptionRollsBackAuditFailure(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	configured, authenticated := initialNetworkFixture()
	legacy, err := store.CreateNetworkDualStackWithID(ctx, configured.NetworkID, configured.Name,
		configured.IPv4Pool, configured.IPv6Pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_controller_identity_adoption_audit
		BEFORE INSERT ON audit_events WHEN NEW.action='controller.identity.bind'
		BEGIN SELECT RAISE(ABORT, 'fixture rejects adoption audit'); END`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err == nil {
		t.Fatal("legacy adoption unexpectedly survived binding audit failure")
	}
	got, err := store.Network(ctx, configured.NetworkID)
	if err != nil || got != legacy {
		t.Fatalf("legacy network after rollback=%+v err=%v", got, err)
	}
	var bindings, bindingAudits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM controller_identity_state`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='controller.identity.bind'`).Scan(&bindingAudits); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || bindingAudits != 0 {
		t.Fatalf("failed adoption left bindings=%d binding audits=%d", bindings, bindingAudits)
	}
	assertInitialNetworkAuditCounts(t, store, configured.NetworkID, 1, 0)
}

func TestControllerIdentityBindingIsImmutable(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE controller_identity_state SET controller_service_id=? WHERE singleton=1`,
		idBytes(identity.ID{9})); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("binding update error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM controller_identity_state WHERE singleton=1`); err == nil || !strings.Contains(err.Error(), "cannot be deleted") {
		t.Fatalf("binding delete error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM networks WHERE id=?`, idBytes(configured.NetworkID)); err == nil {
		t.Fatal("bound network was deleted")
	}
}

func TestEnsureControllerInitialNetworkRejectsCorruptMissingBoundNetwork(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	configured, authenticated := initialNetworkFixture()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, configured, authenticated); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA foreign_keys=OFF; DELETE FROM networks WHERE id=?`, idBytes(configured.NetworkID)); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.EnsureControllerInitialNetwork(ctx, ControllerInitialNetwork{}, authenticated); err == nil || !strings.Contains(err.Error(), "missing network") {
		t.Fatalf("missing bound network error=%v", err)
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
	if err := store.db.QueryRow(`SELECT network_id,controller_service_id,created_at
		FROM controller_identity_state WHERE singleton=1`).Scan(&networkRaw, &serviceRaw, &created); err != nil {
		t.Fatal(err)
	}
	if string(networkRaw) != string(idBytes(networkID)) || string(serviceRaw) != string(idBytes(serviceID)) || created != unix(createdAt) {
		t.Fatalf("binding network=%x service=%x created=%d", networkRaw, serviceRaw, created)
	}
}

func assertInitialNetworkAuditCounts(t *testing.T, store *Store, networkID identity.NetworkID, networkCreates, identityBinds int) {
	t.Helper()
	var creates, binds int
	if err := store.db.QueryRow(`SELECT
		COALESCE(sum(action='network.create'),0),COALESCE(sum(action='controller.identity.bind'),0)
		FROM audit_events WHERE network_id=?`, idBytes(networkID)).Scan(&creates, &binds); err != nil {
		t.Fatal(err)
	}
	if creates != networkCreates || binds != identityBinds {
		t.Fatalf("network.create audits=%d want=%d, controller.identity.bind audits=%d want=%d",
			creates, networkCreates, binds, identityBinds)
	}
}
