package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEphemeralEnrollmentExpiryAndSafeAddressReuse(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.111.0.0/30")
	base := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "temporary-user", base.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(context.Background(), token.Secret, "temporary-user", 0)
	if err != nil {
		t.Fatal(err)
	}
	wantLease := base.Add(MinEphemeralLifetime)
	if node.EnrollmentClass != EnrollmentClassEphemeral || node.LeaseExpiresAt == nil || !node.LeaseExpiresAt.Equal(wantLease) {
		t.Fatalf("ephemeral node lease = %+v", node)
	}
	if next, err := store.NextEphemeralExpiry(context.Background(), network.ID); err != nil || next == nil || !next.Equal(wantLease) {
		t.Fatalf("next network expiry=%v err=%v", next, err)
	}
	if _, err := store.AddCertificate(context.Background(), network.ID, node.ID, []byte{1}, []byte{0x30}, base.Add(-time.Minute), wantLease.Add(time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("certificate beyond lease error = %v", err)
	}
	certificate, err := store.AddCertificate(context.Background(), network.ID, node.ID, []byte{2}, []byte{0x30}, base.Add(-time.Minute), wantLease)
	if err != nil {
		t.Fatal(err)
	}

	store.now = func() time.Time { return wantLease }
	if next, err := store.NextEphemeralExpiry(context.Background(), network.ID); err != nil || next != nil {
		t.Fatalf("next expiry at boundary=%v err=%v", next, err)
	}
	if active, err := store.ActiveNodes(context.Background(), network.ID); err != nil || len(active) != 0 {
		t.Fatalf("active nodes at exact lease boundary = %d, %v", len(active), err)
	}
	if count, err := store.ExpireEphemeral(context.Background(), 1); err != nil || count != 1 {
		t.Fatalf("expire count=%d err=%v", count, err)
	}
	expired, err := store.Node(context.Background(), node.ID)
	if err != nil || expired.RevokedAt == nil {
		t.Fatalf("expired node=%+v err=%v", expired, err)
	}
	storedCertificate, err := store.CertificateBySerial(context.Background(), certificate.Serial)
	if err != nil || storedCertificate.RevokedAt == nil || storedCertificate.RevocationReason != "ephemeral lease expired" {
		t.Fatalf("expired certificate=%+v err=%v", storedCertificate, err)
	}
	var released int
	if err := store.db.QueryRow(`SELECT count(*) FROM overlay_addresses WHERE node_id=? AND released_at IS NOT NULL`, idBytes(node.ID)).Scan(&released); err != nil || released != 1 {
		t.Fatalf("released addresses=%d err=%v", released, err)
	}

	// Consume the other /30 address, forcing the next enrollment to reuse the
	// released address. Revocation above guarantees the old credential cannot
	// overlap the new assignment.
	durable, err := store.IssueEnrollmentToken(context.Background(), network.ID, "durable", wantLease.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnrollNode(context.Background(), durable.Secret, "durable", 0); err != nil {
		t.Fatal(err)
	}
	nextToken, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "next-user", wantLease.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.EnrollNode(context.Background(), nextToken.Secret, "temporary-user", 0)
	if err != nil {
		t.Fatal(err)
	}
	if next.IPv4Address != node.IPv4Address {
		t.Fatalf("reused address=%s want %s", next.IPv4Address, node.IPv4Address)
	}
	if tombstone, err := store.Node(context.Background(), node.ID); err != nil || tombstone.RevokedAt == nil || tombstone.IPv4Address.IsValid() {
		t.Fatalf("reused-address tombstone=%+v err=%v", tombstone, err)
	}
}

func TestEnrollmentClassesAndLifetimeValidation(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.112.0.0/24")
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	for _, options := range []EnrollmentTokenOptions{
		{Class: EnrollmentClassEphemeral},
		{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime - time.Second},
		{Class: EnrollmentClassEphemeral, SessionLifetime: MaxEphemeralLifetime + time.Second},
		{Class: EnrollmentClassRemembered, SessionLifetime: time.Hour},
		{Class: "administrator"},
	} {
		if _, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "invalid", now.Add(time.Minute), options); !errors.Is(err, ErrInvalid) {
			t.Fatalf("options %+v error=%v", options, err)
		}
	}
	remembered, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "remembered", now.Add(time.Minute), EnrollmentTokenOptions{Class: EnrollmentClassRemembered})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(context.Background(), remembered.Secret, "remembered", 0)
	if err != nil || node.EnrollmentClass != EnrollmentClassRemembered || node.LeaseExpiresAt != nil {
		t.Fatalf("remembered node=%+v err=%v", node, err)
	}
	store.now = func() time.Time { return now.Add(365 * 24 * time.Hour) }
	if count, err := store.ExpireEphemeral(context.Background(), MaxExpireBatch); err != nil || count != 0 {
		t.Fatalf("remembered expiry count=%d err=%v", count, err)
	}
}

func TestEphemeralReconnectExpiresPredecessorBeforeNameCheck(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.114.0.0/24")
	base := time.Date(2026, 8, 7, 11, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	firstToken, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "first", base.Add(time.Minute), EnrollmentTokenOptions{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime})
	if err != nil {
		t.Fatal(err)
	}
	secondToken, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "second", base.Add(10*time.Minute), EnrollmentTokenOptions{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.EnrollNode(context.Background(), firstToken.Secret, "same-device", 0)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(MinEphemeralLifetime) }
	second, err := store.EnrollNode(context.Background(), secondToken.Secret, "same-device", 0)
	if err != nil || second.ID == first.ID {
		t.Fatalf("ephemeral reconnect=%+v err=%v", second, err)
	}
	predecessor, err := store.Node(context.Background(), first.ID)
	if err != nil || predecessor.RevokedAt == nil {
		t.Fatalf("predecessor=%+v err=%v", predecessor, err)
	}
}

func TestEphemeralLeaseSurvivesControllerRestart(t *testing.T) {
	store, path := openTestStore(t)
	network := createTestNetwork(t, store, "100.113.0.0/24")
	base := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "restart-user", base.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(context.Background(), token.Secret, "restart-user", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return base.Add(MinEphemeralLifetime) }
	if count, err := reopened.ExpireEphemeral(context.Background(), MaxExpireBatch); err != nil || count != 1 {
		t.Fatalf("expiry after restart count=%d err=%v", count, err)
	}
	got, err := reopened.Node(context.Background(), node.ID)
	if err != nil || got.RevokedAt == nil || got.LeaseExpiresAt == nil || !got.LeaseExpiresAt.Equal(base.Add(MinEphemeralLifetime)) {
		t.Fatalf("persisted ephemeral node=%+v err=%v", got, err)
	}
	reopened.now = func() time.Time { return base.Add(MinEphemeralLifetime + ExpiredEphemeralRetention + time.Second) }
	if count, err := reopened.ExpireEphemeral(context.Background(), MaxExpireBatch); err != nil || count != 0 {
		t.Fatalf("retention cleanup count=%d err=%v", count, err)
	}
	if _, err := reopened.Node(context.Background(), node.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retained ephemeral node was not pruned: %v", err)
	}
	events, err := reopened.AuditEvents(context.Background(), network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawExpiry bool
	for _, event := range events {
		sawExpiry = sawExpiry || event.Action == "ephemeral.expire"
	}
	if !sawExpiry {
		t.Fatal("ephemeral audit event was not retained after record pruning")
	}
}
