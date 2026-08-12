package controller

import (
	"context"
	"testing"
	"time"
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
