package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/netvalidate"
	"github.com/Doout/laneway/go/internal/protocol"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func createTestNetwork(t *testing.T, s *Store, cidr string) Network {
	t.Helper()
	n, err := s.CreateNetwork(context.Background(), "test-network", netip.MustParsePrefix(cidr))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func issueToken(t *testing.T, s *Store, networkID identity.NetworkID, label string) EnrollmentToken {
	t.Helper()
	tok, err := s.IssueEnrollmentToken(context.Background(), networkID, label, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestOpenMigratesAndConfiguresSQLite(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	version, err := s.SchemaVersion(ctx)
	if err != nil || version != currentSchemaVersion {
		t.Fatalf("version=%d err=%v", version, err)
	}
	var foreignKeys, busy int
	var journal string
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 || busy != busyTimeoutMS || journal != "wal" {
		t.Fatalf("pragmas foreign_keys=%d busy_timeout=%d journal=%q", foreignKeys, busy, journal)
	}
	for _, table := range []string{"networks", "nodes", "certificates", "overlay_addresses", "routes", "acl_rules", "relays", "enrollment_tokens", "audit_events", "access_users", "access_teams", "access_team_members", "access_grants", "schema_versions"} {
		var found string
		if err := s.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&found); err != nil {
			t.Errorf("table %s: %v", table, err)
		}
	}
}

func TestMigrationRollbackAndNewerVersionRefusal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "broken.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE networks(unrelated TEXT)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("migration unexpectedly succeeded")
	}
	raw, err = sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var count int
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_versions'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migration was not rolled back")
	}

	newer := filepath.Join(t.TempDir(), "newer.db")
	raw2, err := sql.Open("sqlite", "file:"+newer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw2.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_versions VALUES(999,0)`); err != nil {
		t.Fatal(err)
	}
	raw2.Close()
	if _, err := Open(ctx, newer); !errors.Is(err, ErrUnsupportedDB) {
		t.Fatalf("got %v, want ErrUnsupportedDB", err)
	}
}

func TestMigrationFromIPv4SchemaPreservesNetwork(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` + migrations[0]); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	if _, err := raw.Exec(`INSERT INTO schema_versions(version, applied_at) VALUES(1, 1)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at) VALUES(?,?,?,?,?,?,?)`,
		idBytes(networkID), "legacy", netip.MustParseAddr("10.47.0.0").AsSlice(), 24, 1, 7, 1); err != nil {
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
		t.Fatalf("version=%d err=%v", version, err)
	}
	network, err := store.Network(ctx, networkID)
	if err != nil {
		t.Fatal(err)
	}
	if network.Name != "legacy" || network.IPv4Pool != netip.MustParsePrefix("10.47.0.0/24") || network.IPv6Pool.IsValid() || network.ConfigurationEpoch != 7 {
		t.Fatalf("migrated network = %+v", network)
	}
}

func TestMigrationFromV2LeavesLegacyRelaysUnauthorized(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v2.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;` + migrations[0] + migrations[1]); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	relayID := identity.ID{2}
	if _, err := raw.Exec(`INSERT INTO schema_versions(version,applied_at) VALUES(1,1),(2,2)`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at) VALUES(?,?,?,?,?,?,?)`,
		idBytes(networkID), "legacy-v2", netip.MustParseAddr("10.48.0.0").AsSlice(), 24, 1, 4, 1); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO relays(id,network_id,node_id,name,endpoint,enabled,created_at) VALUES(?,?,NULL,?,?,1,?)`,
		idBytes(relayID), idBytes(networkID), "legacy-relay", "relay.example:443", 1); err != nil {
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
		t.Fatalf("version=%d err=%v", version, err)
	}
	var serviceID []byte
	if err := store.db.QueryRowContext(ctx, `SELECT service_id FROM relays WHERE id=?`, idBytes(relayID)).Scan(&serviceID); err != nil {
		t.Fatal(err)
	}
	if serviceID != nil {
		t.Fatalf("legacy service_id=%x, want NULL", serviceID)
	}
	unknownService, _ := identity.NewID()
	if err := store.AuthorizeRelay(ctx, networkID, unknownService); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy relay authorized: %v", err)
	}
}

func TestRelayIdentityAuthorizationLifecycle(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.97.0.0/24")
	serviceID, _ := identity.NewID()
	relay, epoch, err := s.RegisterRelay(context.Background(), network.ID, serviceID, nil, "relay-one", "relay.example:443")
	if err != nil || epoch != 2 || relay.ServiceID != serviceID || !relay.Enabled {
		t.Fatalf("register relay=%+v epoch=%d err=%v", relay, epoch, err)
	}
	if err := s.AuthorizeRelay(context.Background(), network.ID, serviceID); err != nil {
		t.Fatalf("known relay denied: %v", err)
	}
	otherService, _ := identity.NewID()
	if err := s.AuthorizeRelay(context.Background(), network.ID, otherService); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown relay authorization=%v", err)
	}
	if _, _, err := s.RegisterRelay(context.Background(), network.ID, serviceID, nil, "relay-two", "relay2.example:443"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate relay service identity error=%v", err)
	}
	epoch, err = s.DisableRelay(context.Background(), relay.ID)
	if err != nil || epoch != 3 {
		t.Fatalf("disable epoch=%d err=%v", epoch, err)
	}
	if err := s.AuthorizeRelay(context.Background(), network.ID, serviceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled relay authorized: %v", err)
	}
	if _, err := s.DisableRelay(context.Background(), relay.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("second disable error=%v", err)
	}
	events, err := s.AuditEvents(context.Background(), network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var registered, disabled bool
	for _, event := range events {
		registered = registered || event.Action == "relay.register"
		disabled = disabled || event.Action == "relay.disable"
	}
	if !registered || !disabled {
		t.Fatalf("relay audit events missing: %+v", events)
	}
}

func TestRelayEndpointsAreCanonicalAndEnabledSetIsBounded(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.119.0.0/24")
	ctx := context.Background()
	for _, endpoint := range []string{"https://relay.example:443", "bad host:443", "relay.example:0"} {
		service, _ := identity.NewID()
		if _, _, err := s.RegisterRelay(ctx, network.ID, service, nil, "invalid-"+service.String(), endpoint); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid endpoint %q error = %v", endpoint, err)
		}
	}
	var first Relay
	for index := 0; index < netvalidate.MaxRelayEndpoints; index++ {
		service := identity.ID{15: byte(index + 1)}
		relay, _, err := s.RegisterRelay(ctx, network.ID, service, nil,
			fmt.Sprintf("relay-%02d", index), fmt.Sprintf("Relay-%02d.Example.:%d", index, 4400+index))
		if err != nil {
			t.Fatalf("register relay %d: %v", index, err)
		}
		if relay.Endpoint != fmt.Sprintf("relay-%02d.example:%d", index, 4400+index) {
			t.Fatalf("canonical endpoint %d = %q", index, relay.Endpoint)
		}
		if index == 0 {
			first = relay
		}
	}
	extraService, _ := identity.NewID()
	if _, _, err := s.RegisterRelay(ctx, network.ID, extraService, nil, "relay-extra", "relay-extra.example:443"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("33rd enabled relay error = %v", err)
	}
	if _, err := s.DisableRelay(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RegisterRelay(ctx, network.ID, extraService, nil, "relay-extra", "relay-extra.example:443"); err != nil {
		t.Fatalf("replacement relay: %v", err)
	}
	if _, _, err := s.UpdateRelay(ctx, first.ID, first.Name, first.Endpoint, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("re-enable beyond relay cap error = %v", err)
	}
	relays, err := s.ActiveRelays(ctx, network.ID)
	if err != nil || len(relays) != netvalidate.MaxRelayEndpoints {
		t.Fatalf("active relays = %d, %v", len(relays), err)
	}
}

func TestCertificateRevocationByNetworkSerialAndSnapshot(t *testing.T) {
	s, _ := openTestStore(t)
	first := createTestNetwork(t, s, "100.98.0.0/24")
	second, err := s.CreateNetwork(context.Background(), "second-network", netip.MustParsePrefix("100.99.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	firstNode, err := s.EnrollNode(context.Background(), issueToken(t, s, first.ID, "first").Secret, "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	secondNode, err := s.EnrollNode(context.Background(), issueToken(t, s, second.ID, "second").Secret, "second", 0)
	if err != nil {
		t.Fatal(err)
	}
	serial := []byte{0x12, 0x34}
	now := time.Now().UTC()
	if _, err := s.AddCertificate(context.Background(), first.ID, firstNode.ID, serial, []byte{0x30, 1}, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCertificate(context.Background(), second.ID, secondNode.ID, serial, []byte{0x30, 2}, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.RevokeCertificateBySerial(context.Background(), first.ID, serial, "credential retired")
	if err != nil || epoch != 3 {
		t.Fatalf("revoke epoch=%d err=%v", epoch, err)
	}
	revoked, err := s.RevokedCertificateSerials(context.Background(), first.ID, now)
	if err != nil || len(revoked) != 1 || string(revoked[0]) != string(serial) {
		t.Fatalf("first revocations=%x err=%v", revoked, err)
	}
	other, err := s.RevokedCertificateSerials(context.Background(), second.ID, now)
	if err != nil || len(other) != 0 {
		t.Fatalf("second revocations=%x err=%v", other, err)
	}
	if _, err := s.RevokeCertificateBySerial(context.Background(), second.ID, []byte{0x99}, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown serial error=%v", err)
	}
}

func TestEnrollmentStoresHashAndConsumesExactlyOnceConcurrently(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.96.0.0/24")
	token := issueToken(t, s, network.ID, "build host")
	var stored []byte
	if err := s.db.QueryRow(`SELECT token_hash FROM enrollment_tokens WHERE id=?`, idBytes(token.ID)).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == token.Secret || len(stored) != 32 {
		t.Fatalf("token was not stored only as SHA-256 digest")
	}

	const contenders = 12
	type result struct {
		node Node
		err  error
	}
	results := make(chan result, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, err := s.EnrollNode(context.Background(), token.Secret, fmt.Sprintf("node-%d", i), 0)
			results <- result{n, err}
		}(i)
	}
	wg.Wait()
	close(results)
	var success int
	var enrolled Node
	for r := range results {
		if r.err == nil {
			success++
			enrolled = r.node
		} else if !errors.Is(r.err, ErrTokenConsumed) {
			t.Errorf("unexpected enrollment error: %v", r.err)
		}
	}
	if success != 1 {
		t.Fatalf("successful enrollments=%d, want 1", success)
	}
	if !network.IPv4Pool.Contains(enrolled.IPv4Address) {
		t.Fatalf("address %s outside pool", enrolled.IPv4Address)
	}
	var nodes, consumed int
	if err := s.db.QueryRow(`SELECT count(*) FROM nodes WHERE network_id=?`, idBytes(network.ID)).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE consumed_at IS NOT NULL`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || consumed != 1 {
		t.Fatalf("nodes=%d consumed=%d", nodes, consumed)
	}
}

func TestConcurrentEnrollmentAllocatesUniqueIPv4Addresses(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.97.0.0/24")
	const count = 40
	tokens := make([]EnrollmentToken, count)
	for i := range tokens {
		tokens[i] = issueToken(t, s, network.ID, fmt.Sprintf("token-%d", i))
	}
	addresses := make(chan netip.Addr, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n, err := s.EnrollNode(context.Background(), tokens[i].Secret, fmt.Sprintf("concurrent-%d", i), 0)
			if err != nil {
				errs <- err
				return
			}
			addresses <- n.IPv4Address
		}(i)
	}
	wg.Wait()
	close(errs)
	close(addresses)
	for err := range errs {
		t.Errorf("enroll: %v", err)
	}
	seen := make(map[netip.Addr]bool)
	for addr := range addresses {
		if seen[addr] {
			t.Errorf("duplicate address %s", addr)
		}
		seen[addr] = true
	}
	if len(seen) != count {
		t.Fatalf("allocated=%d want=%d", len(seen), count)
	}
}

func TestDualStackEnrollmentAllocatesHostRoutes(t *testing.T) {
	s, _ := openTestStore(t)
	network, err := s.CreateNetworkDualStack(context.Background(), "dual-stack",
		netip.MustParsePrefix("100.99.0.0/24"), netip.MustParsePrefix("2001:db8:99::/120"))
	if err != nil {
		t.Fatal(err)
	}
	token := issueToken(t, s, network.ID, "dual")
	node, err := s.EnrollNode(context.Background(), token.Secret, "dual-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !network.IPv4Pool.Contains(node.IPv4Address) || !network.IPv6Pool.Contains(node.IPv6Address) {
		t.Fatalf("dual addresses IPv4=%s IPv6=%s pools=%s,%s", node.IPv4Address, node.IPv6Address, network.IPv4Pool, network.IPv6Pool)
	}
	routes, err := s.OverlayRoutes(context.Background(), network.ID)
	if err != nil || len(routes) != 2 || routes[0].Prefix.Addr().BitLen() == routes[1].Prefix.Addr().BitLen() {
		t.Fatalf("dual overlay routes = %+v, %v", routes, err)
	}
	stored, err := s.Node(context.Background(), node.ID)
	if err != nil || stored.IPv6Address != node.IPv6Address {
		t.Fatalf("stored dual node = %+v, %v", stored, err)
	}
}

func TestEnrollmentRollsBackWhenPoolExhausted(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.98.0.0/30")
	for i := 0; i < 2; i++ {
		tok := issueToken(t, s, network.ID, fmt.Sprintf("ok-%d", i))
		if _, err := s.EnrollNode(context.Background(), tok.Secret, fmt.Sprintf("ok-%d", i), 0); err != nil {
			t.Fatal(err)
		}
	}
	tok := issueToken(t, s, network.ID, "rollback")
	if _, err := s.EnrollNode(context.Background(), tok.Secret, "must-rollback", 0); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("got %v", err)
	}
	var nodeCount, unconsumed int
	if err := s.db.QueryRow(`SELECT count(*) FROM nodes WHERE name='must-rollback'`).Scan(&nodeCount); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NULL`, idBytes(tok.ID)).Scan(&unconsumed); err != nil {
		t.Fatal(err)
	}
	if nodeCount != 0 || unconsumed != 1 {
		t.Fatalf("nodeCount=%d unconsumed=%d", nodeCount, unconsumed)
	}
}

func TestAtomicEnrollmentRollsBackIssuerFailureAndAllowsRetry(t *testing.T) {
	s, _ := openTestStore(t)
	network, err := s.CreateNetworkDualStack(context.Background(), "atomic-dual",
		netip.MustParsePrefix("100.111.0.0/24"), netip.MustParsePrefix("2001:db8:111::/120"))
	if err != nil {
		t.Fatal(err)
	}
	token := issueToken(t, s, network.ID, "issuer-failure")
	injected := errors.New("injected signer failure")
	if _, err := s.EnrollNodeWithCertificate(context.Background(), token.Secret, "atomic-node", 0,
		func(context.Context, Node) (CertificateMaterial, error) {
			return CertificateMaterial{}, injected
		}); !errors.Is(err, injected) {
		t.Fatalf("enrollment error = %v, want injected signer failure", err)
	}
	assertEnrollmentRolledBack(t, s, network.ID, token.ID, "atomic-node", 0)

	base := time.Now().UTC().Truncate(time.Second)
	enrollment, err := s.EnrollNodeWithCertificate(context.Background(), token.Secret, "atomic-node", 0,
		func(_ context.Context, node Node) (CertificateMaterial, error) {
			if !network.IPv4Pool.Contains(node.IPv4Address) || !network.IPv6Pool.Contains(node.IPv6Address) {
				t.Fatalf("issuer received node without allocated dual-stack addresses: %+v", node)
			}
			return CertificateMaterial{Serial: []byte{1}, DER: []byte{0x30, 0x00}, NotBefore: base, NotAfter: base.Add(time.Hour)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Certificate.NodeID != enrollment.Node.ID || len(enrollment.Certificate.DER) == 0 {
		t.Fatalf("incomplete atomic enrollment: %+v", enrollment)
	}
	var nodes, addresses, certificates, consumed int
	if err := s.db.QueryRow(`SELECT count(*) FROM nodes WHERE network_id=?`, idBytes(network.ID)).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM overlay_addresses WHERE network_id=?`, idBytes(network.ID)).Scan(&addresses); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM certificates WHERE network_id=?`, idBytes(network.ID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NOT NULL`, idBytes(token.ID)).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if nodes != 1 || addresses != 2 || certificates != 1 || consumed != 1 {
		t.Fatalf("nodes=%d addresses=%d certificates=%d consumed=%d", nodes, addresses, certificates, consumed)
	}
}

func TestNetworkBoundEnrollmentRejectsMismatchBeforeTokenConsumption(t *testing.T) {
	s, _ := openTestStore(t)
	intended := createTestNetwork(t, s, "100.115.0.0/24")
	other, err := s.CreateNetwork(context.Background(), "other-network", netip.MustParsePrefix("100.116.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	token := issueToken(t, s, intended.ID, "network-bound")
	base := time.Now().UTC().Truncate(time.Second)
	issuer := func(context.Context, Node) (CertificateMaterial, error) {
		return CertificateMaterial{Serial: []byte{42}, DER: []byte{0x30, 0x00}, NotBefore: base, NotAfter: base.Add(time.Hour)}, nil
	}
	if _, err := s.EnrollNodeWithCertificateForNetwork(context.Background(), token.Secret, "wrong-network", 0, other.ID, issuer); !errors.Is(err, ErrTokenNetwork) {
		t.Fatalf("network mismatch error = %v", err)
	}
	if _, err := s.EnrollNodeWithCertificateForNetwork(context.Background(), token.Secret, "right-network", 0, intended.ID, issuer); err != nil {
		t.Fatalf("mismatched request consumed token: %v", err)
	}
}

func TestNameBoundEnrollmentResolvesOmittedNameAndRejectsSubstitution(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.117.0.0/24")
	token, err := s.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "invited-laptop", time.Now().Add(time.Hour), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime, RequestedName: "invited-laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollNode(context.Background(), token.Secret, "substituted-name", 0); !errors.Is(err, ErrTokenName) {
		t.Fatalf("name substitution error = %v", err)
	}
	node, err := s.EnrollNode(context.Background(), token.Secret, "", 0)
	if err != nil {
		t.Fatalf("name mismatch consumed invite: %v", err)
	}
	if node.Name != "invited-laptop" || node.EnrollmentClass != EnrollmentClassEphemeral {
		t.Fatalf("resolved enrollment = %+v", node)
	}
}

func TestClassBoundEnrollmentRejectsMismatchBeforeTokenConsumption(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.118.0.0/24")
	token, err := s.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "remembered-user", time.Now().Add(time.Hour), EnrollmentTokenOptions{
		Class: EnrollmentClassRemembered, RequestedName: "remembered-user",
	})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	issuer := func(context.Context, Node) (CertificateMaterial, error) {
		return CertificateMaterial{Serial: []byte{43}, DER: []byte{0x30, 0x00}, NotBefore: base, NotAfter: base.Add(time.Hour)}, nil
	}
	if _, err := s.EnrollNodeWithCertificateForNetworkAndClass(context.Background(), token.Secret, "", 0, network.ID, EnrollmentClassEphemeral, issuer); !errors.Is(err, ErrTokenClass) {
		t.Fatalf("class mismatch error = %v", err)
	}
	if _, err := s.EnrollNodeWithCertificateForNetworkAndClass(context.Background(), token.Secret, "", 0, network.ID, EnrollmentClassRemembered, issuer); err != nil {
		t.Fatalf("class mismatch consumed invite: %v", err)
	}
}

func TestCreateNetworkWithAdministratorGeneratedID(t *testing.T) {
	s, _ := openTestStore(t)
	want, err := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	network, err := s.CreateNetworkDualStackWithID(context.Background(), want, "preidentified",
		netip.MustParsePrefix("100.112.0.0/24"), netip.MustParsePrefix("2001:db8:112::/120"))
	if err != nil {
		t.Fatal(err)
	}
	if network.ID != want {
		t.Fatalf("network ID = %s, want %s", network.ID, want)
	}
	if _, err := s.CreateNetworkDualStackWithID(context.Background(), want, "duplicate-id",
		netip.MustParsePrefix("100.113.0.0/24"), netip.Prefix{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate ID error = %v", err)
	}
	if _, err := s.CreateNetworkDualStackWithID(context.Background(), identity.NetworkID{}, "zero-id",
		netip.MustParsePrefix("100.114.0.0/24"), netip.Prefix{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero ID error = %v", err)
	}
}

func TestAtomicEnrollmentRollsBackCertificatePersistenceFailure(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.112.0.0/24")
	seedToken := issueToken(t, s, network.ID, "seed")
	seed, err := s.EnrollNode(context.Background(), seedToken.Secret, "seed-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	if _, err := s.AddCertificate(context.Background(), network.ID, seed.ID, []byte{9}, []byte{0x30, 0x00}, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	token := issueToken(t, s, network.ID, "persist-failure")
	material := func(serial byte) EnrollmentCertificateIssuer {
		return func(context.Context, Node) (CertificateMaterial, error) {
			return CertificateMaterial{Serial: []byte{serial}, DER: []byte{0x30, 0x00}, NotBefore: base, NotAfter: base.Add(time.Hour)}, nil
		}
	}
	if _, err := s.EnrollNodeWithCertificate(context.Background(), token.Secret, "persist-node", 0, material(9)); !errors.Is(err, ErrConflict) {
		t.Fatalf("enrollment error = %v, want duplicate serial conflict", err)
	}
	assertEnrollmentRolledBack(t, s, network.ID, token.ID, "persist-node", 1)
	if _, err := s.EnrollNodeWithCertificate(context.Background(), token.Secret, "persist-node", 0, material(10)); err != nil {
		t.Fatalf("token was not reusable after persistence rollback: %v", err)
	}
}

func assertEnrollmentRolledBack(t *testing.T, s *Store, networkID identity.NetworkID, tokenID identity.ID, nodeName string, existingCertificates int) {
	t.Helper()
	var nodes, addresses, certificates, unconsumed int
	if err := s.db.QueryRow(`SELECT count(*) FROM nodes WHERE network_id=? AND name=?`, idBytes(networkID), nodeName).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM overlay_addresses WHERE node_id IN (SELECT id FROM nodes WHERE network_id=? AND name=?)`, idBytes(networkID), nodeName).Scan(&addresses); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM certificates WHERE network_id=?`, idBytes(networkID)).Scan(&certificates); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NULL`, idBytes(tokenID)).Scan(&unconsumed); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || addresses != 0 || certificates != existingCertificates || unconsumed != 1 {
		t.Fatalf("rollback nodes=%d addresses=%d certificates=%d unconsumed=%d", nodes, addresses, certificates, unconsumed)
	}
}

func TestExpiredTokenDoesNotMutateState(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.101.0.0/24")
	base := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return base }
	token, err := s.IssueEnrollmentToken(context.Background(), network.ID, "short-lived", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(time.Minute) }
	if _, err := s.EnrollNode(context.Background(), token.Secret, "too-late", 0); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("got %v, want ErrTokenExpired", err)
	}
	var nodes, unconsumed int
	if err := s.db.QueryRow(`SELECT count(*) FROM nodes WHERE network_id=?`, idBytes(network.ID)).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NULL`, idBytes(token.ID)).Scan(&unconsumed); err != nil {
		t.Fatal(err)
	}
	if nodes != 0 || unconsumed != 1 {
		t.Fatalf("nodes=%d unconsumed=%d", nodes, unconsumed)
	}
}

func TestPersistenceRoutesEpochRevocationAndAudit(t *testing.T) {
	s, path := openTestStore(t)
	network := createTestNetwork(t, s, "100.99.0.0/24")
	tok := issueToken(t, s, network.ID, "persistent")
	node, err := s.EnrollNode(context.Background(), tok.Secret, "gateway", uint64(protocol.CapabilitySubnetRouterV1))
	if err != nil {
		t.Fatal(err)
	}
	route, err := s.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("192.168.50.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := s.ApproveRoute(context.Background(), route.ID)
	if err != nil || epoch != 3 {
		t.Fatalf("approve epoch=%d err=%v", epoch, err)
	}
	cert, err := s.AddCertificate(context.Background(), network.ID, node.ID, []byte{1, 2, 3}, []byte{0x30, 1}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	epoch, err = s.RevokeCertificate(context.Background(), cert.ID, "key retired")
	if err != nil || epoch != 4 {
		t.Fatalf("revoke epoch=%d err=%v", epoch, err)
	}
	rule, epoch, err := s.AddACLRule(context.Background(), network.ID, 10, ACLActionAccept, `{}`, "allow test")
	if err != nil || epoch != 5 || rule.ID.IsZero() {
		t.Fatalf("ACL epoch=%d err=%v", epoch, err)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	_, epoch, err = s.RegisterRelay(context.Background(), network.ID, serviceID, &node.ID, "relay-1", "relay.example:443")
	if err != nil || epoch != 6 {
		t.Fatalf("relay epoch=%d err=%v", epoch, err)
	}
	events, err := s.AuditEvents(context.Background(), network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 8 {
		t.Fatalf("audit events=%d", len(events))
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	gotNetwork, err := reopened.Network(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotNetwork.ConfigurationEpoch != 6 || gotNetwork.IPv4Pool != network.IPv4Pool {
		t.Fatalf("reopened network=%+v", gotNetwork)
	}
	gotNode, err := reopened.Node(context.Background(), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotNode.Name != node.Name || gotNode.IPv4Address != node.IPv4Address {
		t.Fatalf("reopened node=%+v", gotNode)
	}
}

func TestNodeRevocationWithdrawsStateAtomically(t *testing.T) {
	s, _ := openTestStore(t)
	network := createTestNetwork(t, s, "100.102.0.0/24")
	tok := issueToken(t, s, network.ID, "revoke")
	node, err := s.EnrollNode(context.Background(), tok.Secret, "router", uint64(protocol.CapabilitySubnetRouterV1))
	if err != nil {
		t.Fatal(err)
	}
	route, err := s.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("10.20.0.0/16"), RouteKindSubnet, RouteModeRouted, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRoute(context.Background(), route.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCertificate(context.Background(), network.ID, node.ID, []byte{9}, []byte{0x30}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	epoch, err := s.RevokeNode(context.Background(), node.ID, "host decommissioned")
	if err != nil || epoch != 4 {
		t.Fatalf("epoch=%d err=%v", epoch, err)
	}
	got, err := s.Node(context.Background(), node.ID)
	if err != nil || got.RevokedAt == nil || got.IPv4Address != node.IPv4Address {
		t.Fatalf("revoked node=%+v err=%v", got, err)
	}
	var activeAddresses, activeRoutes, activeCertificates int
	if err := s.db.QueryRow(`SELECT count(*) FROM overlay_addresses WHERE node_id=? AND released_at IS NULL`, idBytes(node.ID)).Scan(&activeAddresses); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM routes WHERE node_id=? AND state='approved'`, idBytes(node.ID)).Scan(&activeRoutes); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM certificates WHERE node_id=? AND revoked_at IS NULL`, idBytes(node.ID)).Scan(&activeCertificates); err != nil {
		t.Fatal(err)
	}
	if activeAddresses != 0 || activeRoutes != 0 || activeCertificates != 0 {
		t.Fatalf("active addresses=%d routes=%d certificates=%d", activeAddresses, activeRoutes, activeCertificates)
	}
}

func TestApprovedRouteExpiryWithdrawsBatchAndAdvancesEpochOnce(t *testing.T) {
	s, _ := openTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return base }
	network := createTestNetwork(t, s, "100.103.0.0/24")
	token, err := s.IssueEnrollmentToken(context.Background(), network.ID, "expiring-router", base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.EnrollNode(context.Background(), token.Secret, "expiring-router", uint64(protocol.CapabilitySubnetRouterV1))
	if err != nil {
		t.Fatal(err)
	}
	validUntil := base.Add(time.Minute)
	route, err := s.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("10.30.0.0/16"), RouteKindSubnet, RouteModeRouted, 7, &validUntil)
	if err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.ApproveRoute(context.Background(), route.ID); err != nil || epoch != 3 {
		t.Fatalf("approve epoch=%d err=%v", epoch, err)
	}
	second, err := s.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("10.31.0.0/16"), RouteKindSubnet, RouteModeRouted, 8, &validUntil)
	if err != nil {
		t.Fatal(err)
	}
	if epoch, err := s.ApproveRoute(context.Background(), second.ID); err != nil || epoch != 4 {
		t.Fatalf("second approve epoch=%d err=%v", epoch, err)
	}
	if epoch, count, err := s.ExpireApprovedRoutes(context.Background(), network.ID, validUntil.Add(-time.Second)); err != nil || epoch != 4 || count != 0 {
		t.Fatalf("early expiry epoch=%d count=%d err=%v", epoch, count, err)
	}
	epoch, count, err := s.ExpireApprovedRoutes(context.Background(), network.ID, validUntil)
	if err != nil || epoch != 5 || count != 2 {
		t.Fatalf("expiry epoch=%d count=%d err=%v", epoch, count, err)
	}
	routes, err := s.NetworkRoutes(context.Background(), network.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("expired routes=%+v", routes)
	}
	for _, expired := range routes {
		if expired.State != RouteStateWithdrawn || expired.WithdrawnAt == nil || !expired.WithdrawnAt.Equal(validUntil) {
			t.Fatalf("expired route=%+v", expired)
		}
	}
	epoch, count, err = s.ExpireApprovedRoutes(context.Background(), network.ID, validUntil.Add(time.Hour))
	if err != nil || epoch != 5 || count != 0 {
		t.Fatalf("idempotent expiry epoch=%d count=%d err=%v", epoch, count, err)
	}
	events, err := s.AuditEvents(context.Background(), network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	expiredTargets := map[identity.ID]bool{route.ID: true, second.ID: true}
	var expirations int
	for _, event := range events {
		if event.Action == "route.expire" {
			expirations++
			if event.TargetID == nil || !expiredTargets[*event.TargetID] || event.Details != `{"reason":"expired"}` {
				t.Fatalf("expiry audit=%+v", event)
			}
			delete(expiredTargets, *event.TargetID)
		}
	}
	if expirations != 2 || len(expiredTargets) != 0 {
		t.Fatalf("route expiry audits=%d", expirations)
	}
}

func TestApprovedRouteExpiryRollsBackWhenEpochCannotAdvance(t *testing.T) {
	s, _ := openTestStore(t)
	base := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return base }
	network := createTestNetwork(t, s, "100.104.0.0/24")
	token, err := s.IssueEnrollmentToken(context.Background(), network.ID, "rollback-router", base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.EnrollNode(context.Background(), token.Secret, "rollback-router", uint64(protocol.CapabilitySubnetRouterV1))
	if err != nil {
		t.Fatal(err)
	}
	validUntil := base.Add(time.Minute)
	route, err := s.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("10.40.0.0/16"), RouteKindSubnet, RouteModeNAT, 1, &validUntil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRoute(context.Background(), route.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE networks SET configuration_epoch=9223372036854775807 WHERE id=?`, idBytes(network.ID)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ExpireApprovedRoutes(context.Background(), network.ID, validUntil); !errors.Is(err, ErrConflict) {
		t.Fatalf("expiry error=%v, want ErrConflict", err)
	}
	var state string
	var withdrawn sql.NullInt64
	if err := s.db.QueryRow(`SELECT state,withdrawn_at FROM routes WHERE id=?`, idBytes(route.ID)).Scan(&state, &withdrawn); err != nil {
		t.Fatal(err)
	}
	if state != string(RouteStateApproved) || withdrawn.Valid {
		t.Fatalf("route state=%s withdrawn=%v after rollback", state, withdrawn)
	}
}

func TestStrictInputBounds(t *testing.T) {
	s, _ := openTestStore(t)
	if _, err := s.CreateNetwork(context.Background(), "", netip.MustParsePrefix("100.64.0.0/10")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	if _, err := s.CreateNetwork(context.Background(), "bad-pool", netip.MustParsePrefix("10.0.0.0/7")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pool: %v", err)
	}
	n := createTestNetwork(t, s, "100.100.0.0/24")
	if _, err := s.IssueEnrollmentToken(context.Background(), n.ID, "", time.Now().Add(MaxTokenLifetime+time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry: %v", err)
	}
	if _, err := s.EnrollNode(context.Background(), "not-a-token", "node", 0); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("token: %v", err)
	}
	if _, _, err := s.AddACLRule(context.Background(), n.ID, 1, ACLActionAccept, `{broken`, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("JSON: %v", err)
	}
	if _, err := s.AuditEvents(context.Background(), n.ID, 1001); !errors.Is(err, ErrInvalid) {
		t.Fatalf("audit limit: %v", err)
	}
}
