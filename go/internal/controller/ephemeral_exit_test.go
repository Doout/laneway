package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/protocol"
)

func TestEphemeralExitHeartbeatAndTerminalRevocation(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.119.0.0/24")
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	name := strings.Repeat("e", 253)
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "shared-exit", base.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: time.Hour, RequestedName: name,
		EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1),
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := store.enrollNode(context.Background(), token.Secret, name, 0, network.ID,
		EnrollmentClassEphemeral, WireGuardPublicKey{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	session := enrollment.EphemeralExitSession
	if session == nil || session.Generation == 0 || !session.SuspectAt.Equal(base.Add(20*time.Second)) || !session.RevokeAt.Equal(base.Add(time.Minute)) {
		t.Fatalf("initial session=%+v", session)
	}
	if _, err := store.HeartbeatEphemeralExit(context.Background(), enrollment.Node.ID, session.Generation+1); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("wrong generation heartbeat error=%v", err)
	}
	store.now = func() time.Time { return base.Add(10 * time.Second) }
	renewed, err := store.HeartbeatEphemeralExit(context.Background(), enrollment.Node.ID, session.Generation)
	if err != nil || !renewed.SuspectAt.Equal(base.Add(30*time.Second)) || !renewed.RevokeAt.Equal(base.Add(70*time.Second)) {
		t.Fatalf("renewed session=%+v err=%v", renewed, err)
	}
	store.now = func() time.Time { return base.Add(69 * time.Second) }
	if count, err := store.ExpireDisconnectedEphemeralExits(context.Background(), MaxExpireBatch); err != nil || count != 0 {
		t.Fatalf("early expiry count=%d err=%v", count, err)
	}
	store.now = func() time.Time { return base.Add(70 * time.Second) }
	if count, err := store.ExpireDisconnectedEphemeralExits(context.Background(), MaxExpireBatch); err != nil || count != 1 {
		t.Fatalf("terminal expiry count=%d err=%v", count, err)
	}
	if _, err := store.HeartbeatEphemeralExit(context.Background(), enrollment.Node.ID, session.Generation); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("late heartbeat reactivated terminal lease: %v", err)
	}
	node, err := store.Node(context.Background(), enrollment.Node.ID)
	if err != nil || node.RevokedAt == nil {
		t.Fatalf("terminal node=%+v err=%v", node, err)
	}
	var released int
	if err := store.db.QueryRow(`SELECT count(*) FROM overlay_addresses WHERE node_id=? AND released_at IS NOT NULL`, idBytes(node.ID)).Scan(&released); err != nil || released != 1 {
		t.Fatalf("released addresses=%d err=%v", released, err)
	}
	routes, err := store.NetworkRoutes(context.Background(), network.ID, 100)
	if err != nil || len(routes) != 1 || routes[0].State != RouteStateWithdrawn {
		t.Fatalf("terminal routes=%+v err=%v", routes, err)
	}
	events, err := store.AuditEvents(context.Background(), network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	var start, revoke bool
	for _, event := range events {
		start = start || event.Action == "ephemeral_exit.session.start"
		revoke = revoke || event.Action == "ephemeral_exit.lease.revoke"
	}
	if !start || !revoke {
		t.Fatalf("lifecycle audits start=%t revoke=%t", start, revoke)
	}
}

func TestEphemeralExitCannotUpgradeItsCapabilityClass(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.120.0.0/24")
	now := time.Now().UTC().Truncate(time.Second)
	store.now = func() time.Time { return now }
	_, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "overbroad", now.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: time.Hour,
		EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1 | protocol.CapabilitySubnetRouterV1),
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("overbroad ephemeral Exit capability error=%v", err)
	}
}

func TestEphemeralExitAbsoluteLifetimeTerminatesHeartbeatSessionAtomically(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.121.0.0/24")
	base := time.Date(2026, 8, 17, 13, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "bounded-exit", base.Add(time.Minute), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime, RequestedName: "bounded-exit",
		EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1),
	})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := store.enrollNode(context.Background(), token.Secret, "bounded-exit", 0, network.ID,
		EnrollmentClassEphemeral, WireGuardPublicKey{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(MinEphemeralLifetime) }
	if count, err := store.ExpireEphemeral(context.Background(), MaxExpireBatch); err != nil || count != 1 {
		t.Fatalf("absolute expiry count=%d err=%v", count, err)
	}
	if _, err := store.EphemeralExitSession(context.Background(), enrollment.Node.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absolute expiry left live heartbeat session: %v", err)
	}
}
