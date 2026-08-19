package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func TestAuditEventsReturnsNewestFirstBeforeLimit(t *testing.T) {
	s, _ := openTestStore(t)
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	network := createTestNetwork(t, s, "100.120.0.0/24")

	s.now = func() time.Time { return base.Add(time.Minute) }
	if _, err := s.IssueEnrollmentToken(context.Background(), network.ID, "newest", base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	events, err := s.AuditEvents(context.Background(), network.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "enrollment_token.issue" {
		t.Fatalf("newest audit event = %+v", events)
	}
}

func TestAuditEventsPageTraversesEqualTimestampsExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	base := time.Date(2026, time.August, 19, 14, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	network := createTestNetwork(t, store, "100.119.0.0/24")
	for i := range 5 {
		if _, err := store.IssueEnrollmentToken(ctx, network.ID, string(rune('a'+i)), base.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	want, err := store.AuditEvents(ctx, network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 6 {
		t.Fatalf("audit event count=%d want 6", len(want))
	}

	first, err := store.AuditEventsPage(ctx, network.ID, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 2 || first.NextCursor == nil {
		t.Fatalf("first page=%+v", first)
	}

	// A newer event committed between requests must not displace or duplicate
	// any record that was reachable from the first page's cursor.
	store.now = func() time.Time { return base.Add(time.Minute) }
	if _, err := store.IssueEnrollmentToken(ctx, network.ID, "new-after-page-one", base.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := append([]AuditEvent(nil), first.Events...)
	cursor := first.NextCursor
	for cursor != nil {
		page, err := store.AuditEventsPage(ctx, network.ID, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page.Events...)
		cursor = page.NextCursor
	}
	if len(got) != len(want) {
		t.Fatalf("traversed event count=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Fatalf("event %d=%s want %s", i, got[i].ID, want[i].ID)
		}
	}
}

func TestAuditEventsPageRejectsInvalidCursor(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "100.118.0.0/24")
	cursor := &AuditPageCursor{CreatedAt: time.Now().UTC().Truncate(time.Second).Add(time.Nanosecond)}
	if _, err := store.AuditEventsPage(context.Background(), network.ID, 10, cursor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid audit cursor error=%v want ErrInvalid", err)
	}
}

func TestNodeEnrollmentAndCertificateAuditActors(t *testing.T) {
	ctx := context.Background()
	store, _ := openTestStore(t)
	base := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	network := createTestNetwork(t, store, "100.121.0.0/24")
	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "audited-exit", base.Add(time.Hour), EnrollmentTokenOptions{
		Class:               EnrollmentClassDurable,
		RequestedName:       "audited-exit",
		EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1),
	})
	if err != nil {
		t.Fatal(err)
	}

	serial := byte(1)
	issuer := func(context.Context, Node) (CertificateMaterial, error) {
		material := CertificateMaterial{
			Serial:    []byte{serial},
			DER:       []byte{0x30, serial},
			NotBefore: base.Add(-time.Minute),
			NotAfter:  base.Add(time.Hour),
		}
		serial++
		return material, nil
	}
	enrollment, err := store.EnrollNodeWithCertificate(ctx, token.Secret, "", 0, issuer)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := store.RenewNodeBound(ctx, network.ID, enrollment.Node.ID, WireGuardPublicKey{}, issuer)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := store.AddCertificate(ctx, network.ID, enrollment.Node.ID, []byte{serial}, []byte{0x30, serial}, base.Add(-time.Minute), base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.AuditEvents(ctx, network.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantNodeActor := identity.ID(enrollment.Node.ID)
	wantCertificateTargets := map[identity.ID]bool{
		enrollment.Certificate.ID: false,
		renewal.Certificate.ID:    false,
		direct.ID:                 false,
	}
	var enrollEvents, invitedExitEvents, certificateEvents int
	for _, event := range events {
		switch event.Action {
		case "node.enroll":
			enrollEvents++
			assertAuditActor(t, event, adminauth.ActorNode, &wantNodeActor)
			if event.TargetID == nil || *event.TargetID != wantNodeActor {
				t.Fatalf("node enrollment target = %v, want %s", event.TargetID, wantNodeActor)
			}
		case "route.invited_exit.approve":
			invitedExitEvents++
			assertAuditActor(t, event, adminauth.ActorSystem, nil)
		case "certificate.issue":
			certificateEvents++
			assertAuditActor(t, event, adminauth.ActorNode, &wantNodeActor)
			if event.TargetID == nil {
				t.Fatal("certificate issue audit event has no target")
			}
			seen, ok := wantCertificateTargets[*event.TargetID]
			if !ok || seen {
				t.Fatalf("unexpected or duplicate certificate audit target %s", *event.TargetID)
			}
			wantCertificateTargets[*event.TargetID] = true
		}
	}
	if enrollEvents != 1 || invitedExitEvents != 1 || certificateEvents != len(wantCertificateTargets) {
		t.Fatalf("audit counts: enrollment=%d invited_exit=%d certificate=%d", enrollEvents, invitedExitEvents, certificateEvents)
	}
	for target, seen := range wantCertificateTargets {
		if !seen {
			t.Fatalf("certificate audit target %s not found", target)
		}
	}
}

func assertAuditActor(t *testing.T, event AuditEvent, kind adminauth.ActorKind, id *identity.ID) {
	t.Helper()
	if event.Actor.Kind != kind {
		t.Fatalf("%s actor kind = %q, want %q", event.Action, event.Actor.Kind, kind)
	}
	if id == nil {
		if event.Actor.ID != nil {
			t.Fatalf("%s actor ID = %s, want none", event.Action, *event.Actor.ID)
		}
		return
	}
	if event.Actor.ID == nil || *event.Actor.ID != *id {
		t.Fatalf("%s actor ID = %v, want %s", event.Action, event.Actor.ID, *id)
	}
}
