package adminauth

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestLoginLimiterAppliesGlobalSourceAndUsernameBounds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	limiter, err := NewLoginLimiter(LoginLimiterOptions{
		Window: time.Minute, GlobalLimit: 4, SourceLimit: 2, UsernameLimit: 2,
		MaximumSources: 4, MaximumUsernames: 4, Now: func() time.Time { return now },
		Key: bytes.Repeat([]byte{1}, loginLimiterKeyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceOne := netip.MustParseAddr("192.0.2.1")
	sourceTwo := netip.MustParseAddr("192.0.2.2")
	for index, attempt := range []struct {
		source   netip.Addr
		username string
		allowed  bool
	}{
		{sourceOne, "Owner", true},
		{sourceOne, "owner", true},
		{sourceOne, "other", false},
		{sourceTwo, "owner", false},
		{sourceTwo, "other", true},
		{netip.MustParseAddr("192.0.2.3"), "third", true},
		{netip.MustParseAddr("192.0.2.4"), "fourth", false},
	} {
		decision, err := limiter.Allow(attempt.source, attempt.username)
		if err != nil || decision.Allowed != attempt.allowed {
			t.Fatalf("attempt %d decision=%+v err=%v", index, decision, err)
		}
		if !decision.Allowed && decision.RetryAfter != time.Minute {
			t.Fatalf("attempt %d retry=%s", index, decision.RetryAfter)
		}
	}
	if limiter.global.count != 4 {
		t.Fatalf("global verification admissions=%d want 4", limiter.global.count)
	}
	now = now.Add(time.Minute)
	decision, err := limiter.Allow(sourceOne, "owner")
	if err != nil || !decision.Allowed {
		t.Fatalf("attempt after window decision=%+v err=%v", decision, err)
	}
}

func TestLoginLimiterDeniedSourceDoesNotConsumeGlobalVerificationBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	limiter, err := NewLoginLimiter(LoginLimiterOptions{
		Window: time.Minute, GlobalLimit: 3, SourceLimit: 1, UsernameLimit: 3,
		MaximumSources: 16, MaximumUsernames: 16, Now: func() time.Time { return now },
		Key: bytes.Repeat([]byte{4}, loginLimiterKeyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	abusive := netip.MustParseAddr("192.0.2.10")
	if decision, err := limiter.Allow(abusive, "owner"); err != nil || !decision.Allowed {
		t.Fatalf("initial abusive-source admission=%+v err=%v", decision, err)
	}
	for attempt := range 8 {
		decision, err := limiter.Allow(abusive, "blocked"+string(rune('a'+attempt)))
		if err != nil || decision.Allowed || decision.RetryAfter != time.Minute {
			t.Fatalf("blocked abusive-source attempt %d=%+v err=%v", attempt, decision, err)
		}
	}
	if limiter.global.count != 1 {
		t.Fatalf("abusive source consumed global verification budget: admissions=%d", limiter.global.count)
	}
	for index, source := range []netip.Addr{
		netip.MustParseAddr("192.0.2.11"),
		netip.MustParseAddr("192.0.2.12"),
	} {
		decision, err := limiter.Allow(source, "fresh"+string(rune('a'+index)))
		if err != nil || !decision.Allowed {
			t.Fatalf("fresh admission %d=%+v err=%v", index, decision, err)
		}
	}
	decision, err := limiter.Allow(netip.MustParseAddr("192.0.2.13"), "last")
	if err != nil || decision.Allowed || decision.RetryAfter != time.Minute {
		t.Fatalf("global limit decision=%+v err=%v", decision, err)
	}
}

func TestLoginLimiterUsesIPv6PrefixesAndBoundsState(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	limiter, err := NewLoginLimiter(LoginLimiterOptions{
		Window: time.Minute, GlobalLimit: 20, SourceLimit: 1, UsernameLimit: 20,
		MaximumSources: 1, MaximumUsernames: 2, Now: func() time.Time { return now },
		Key: bytes.Repeat([]byte{2}, loginLimiterKeyBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := netip.MustParseAddr("2001:db8:1::1")
	samePrefix := netip.MustParseAddr("2001:db8:1::2")
	otherPrefix := netip.MustParseAddr("2001:db8:2::1")
	if decision, err := limiter.Allow(first, "owner"); err != nil || !decision.Allowed {
		t.Fatalf("first attempt=%+v err=%v", decision, err)
	}
	if decision, err := limiter.Allow(samePrefix, "other"); err != nil || decision.Allowed {
		t.Fatalf("same-prefix attempt=%+v err=%v", decision, err)
	}
	if decision, err := limiter.Allow(otherPrefix, "third"); err != nil || decision.Allowed || decision.RetryAfter == 0 {
		t.Fatalf("bounded-map attempt=%+v err=%v", decision, err)
	}
	if limiter.global.count != 1 {
		t.Fatalf("local and map-capacity denials consumed global verification budget: admissions=%d", limiter.global.count)
	}
	now = now.Add(time.Minute)
	if decision, err := limiter.Allow(otherPrefix, "third"); err != nil || !decision.Allowed {
		t.Fatalf("attempt after cleanup=%+v err=%v", decision, err)
	}
}

func TestLoginLimiterRejectsInvalidConfiguration(t *testing.T) {
	validKey := bytes.Repeat([]byte{3}, loginLimiterKeyBytes)
	for _, options := range []LoginLimiterOptions{
		{Window: time.Millisecond, Key: validKey},
		{GlobalLimit: 1, SourceLimit: 2, Key: validKey},
		{MaximumSources: 65537, Key: validKey},
		{Key: []byte("short")},
	} {
		if _, err := NewLoginLimiter(options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
	failing := &errorReader{err: errTestEntropy}
	if _, err := NewLoginLimiter(LoginLimiterOptions{Random: failing}); err == nil {
		t.Fatal("entropy failure accepted")
	}
	var limiter *LoginLimiter
	if _, err := limiter.Allow(netip.Addr{}, "owner"); err == nil {
		t.Fatal("nil limiter accepted")
	}
}

var errTestEntropy = &loginLimiterTestError{}

type loginLimiterTestError struct{}

func (*loginLimiterTestError) Error() string { return "test entropy error" }
