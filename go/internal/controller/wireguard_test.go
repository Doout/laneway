package controller

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
)

func generatedWireGuardPublicKey(t *testing.T) WireGuardPublicKey {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ParseWireGuardPublicKey(privateKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func TestWireGuardPublicKeyValidation(t *testing.T) {
	if _, err := ParseWireGuardPublicKey(make([]byte, WireGuardKeySize-1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short key error = %v", err)
	}
	if _, err := ParseWireGuardPublicKey(make([]byte, WireGuardKeySize)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("low-order key error = %v", err)
	}
	key := generatedWireGuardPublicKey(t)
	if key.IsZero() || len(key.Bytes()) != WireGuardKeySize {
		t.Fatalf("valid key = %x", key)
	}
}

func TestBoundEnrollmentUniquenessAndTransactionalRenewal(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.122.0.0/24")
	base := time.Now().UTC().Truncate(time.Second)
	serial := byte(1)
	issuer := func(context.Context, Node) (CertificateMaterial, error) {
		value := CertificateMaterial{Serial: []byte{serial}, DER: []byte{0x30, serial}, NotBefore: base, NotAfter: base.Add(time.Hour)}
		serial++
		return value, nil
	}
	keyOne := generatedWireGuardPublicKey(t)
	tokenOne := issueToken(t, store, network.ID, "bound-one")
	one, err := store.EnrollNodeBound(context.Background(), tokenOne.Secret, "bound-one", 0, network.ID, EnrollmentClassDurable, keyOne, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if one.Node.WireGuardPublicKey != keyOne {
		t.Fatalf("enrolled key = %x want %x", one.Node.WireGuardPublicKey, keyOne)
	}

	tokenTwo := issueToken(t, store, network.ID, "bound-two")
	if _, err := store.EnrollNodeBound(context.Background(), tokenTwo.Secret, "bound-two", 0, network.ID, EnrollmentClassDurable, keyOne, issuer); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key enrollment error = %v", err)
	}
	var reusable int
	if err := store.db.QueryRow(`SELECT count(*) FROM enrollment_tokens WHERE id=? AND consumed_at IS NULL`, idBytes(tokenTwo.ID)).Scan(&reusable); err != nil || reusable != 1 {
		t.Fatalf("duplicate key consumed invite: reusable=%d error=%v", reusable, err)
	}
	keyTwo := generatedWireGuardPublicKey(t)
	two, err := store.EnrollNodeBound(context.Background(), tokenTwo.Secret, "bound-two", 0, network.ID, EnrollmentClassDurable, keyTwo, issuer)
	if err != nil {
		t.Fatal(err)
	}

	before, err := store.Network(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	var certificatesBefore int
	if err := store.db.QueryRow(`SELECT count(*) FROM certificates WHERE node_id=?`, idBytes(one.Node.ID)).Scan(&certificatesBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RenewNodeBound(context.Background(), network.ID, one.Node.ID, keyTwo, issuer); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate rotation error = %v", err)
	}
	afterConflict, _ := store.Network(context.Background(), network.ID)
	stored, _ := store.Node(context.Background(), one.Node.ID)
	var certificatesAfterConflict int
	_ = store.db.QueryRow(`SELECT count(*) FROM certificates WHERE node_id=?`, idBytes(one.Node.ID)).Scan(&certificatesAfterConflict)
	if afterConflict.ConfigurationEpoch != before.ConfigurationEpoch || stored.WireGuardPublicKey != keyOne || certificatesAfterConflict != certificatesBefore {
		t.Fatalf("failed rotation mutated state: epoch=%d key=%x certificates=%d", afterConflict.ConfigurationEpoch, stored.WireGuardPublicKey, certificatesAfterConflict)
	}

	keyThree := generatedWireGuardPublicKey(t)
	renewed, err := store.RenewNodeBound(context.Background(), network.ID, one.Node.ID, keyThree, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Epoch != before.ConfigurationEpoch+1 || renewed.Node.WireGuardPublicKey != keyThree {
		t.Fatalf("renewal = %+v", renewed)
	}
	stored, err = store.Node(context.Background(), one.Node.ID)
	if err != nil || stored.WireGuardPublicKey != keyThree {
		t.Fatalf("stored renewed node = %+v error=%v", stored, err)
	}
	peers, err := store.ActiveNodes(context.Background(), network.ID)
	if err != nil || len(peers) != 2 || peers[0].WireGuardPublicKey.IsZero() || peers[1].WireGuardPublicKey.IsZero() {
		t.Fatalf("active peer key directory = %+v error=%v", peers, err)
	}
	_ = two
}

func TestMigrationFromV5PreservesUnboundNodeForFailClosedUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v5.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	schema := `CREATE TABLE schema_versions(version INTEGER PRIMARY KEY CHECK(version > 0), applied_at INTEGER NOT NULL) STRICT;`
	for i := 0; i < 5; i++ {
		schema += migrations[i]
	}
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO schema_versions(version,applied_at) VALUES(1,1),(2,2),(3,3),(4,4),(5,5)`); err != nil {
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	nodeID := identity.NodeID{2}
	addressID := identity.ID{3}
	if _, err := raw.Exec(`INSERT INTO networks(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at) VALUES(?,?,?,?,?,?,?)`, idBytes(networkID), "legacy-v5", netip.MustParseAddr("100.123.0.0").AsSlice(), 24, 2, 7, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO nodes(id,network_id,name,enabled_capabilities,created_at,enrollment_class) VALUES(?,?,?,?,?,?)`, idBytes(nodeID), idBytes(networkID), "legacy-node", 0, 1, string(EnrollmentClassDurable)); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO overlay_addresses(id,network_id,node_id,address,prefix_length,created_at) VALUES(?,?,?,?,?,?)`, idBytes(addressID), idBytes(networkID), idBytes(nodeID), netip.MustParseAddr("100.123.0.1").AsSlice(), 32, 1); err != nil {
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
	node, err := store.Node(ctx, nodeID)
	if err != nil || !node.WireGuardPublicKey.IsZero() {
		t.Fatalf("migrated legacy node = %+v error=%v", node, err)
	}
	key := generatedWireGuardPublicKey(t)
	base := time.Now().UTC().Truncate(time.Second)
	if _, err := store.RenewNodeBound(ctx, networkID, nodeID, key, func(context.Context, Node) (CertificateMaterial, error) {
		return CertificateMaterial{Serial: []byte{1}, DER: []byte{0x30}, NotBefore: base, NotAfter: base.Add(time.Hour)}, nil
	}); err != nil {
		t.Fatalf("bind legacy node during authenticated renewal: %v", err)
	}
}
