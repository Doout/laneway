package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPublicRateLimiterSharesUnknownNetworkBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newPublicRateLimiter()
	limiter.now = func() time.Time { return now }
	for index := 0; index < 10; index++ {
		address := "192.0.2.10:443"
		if index%2 != 0 {
			address = "192.0.2.200:443"
		}
		if !limiter.Allow(address) {
			t.Fatalf("unknown request %d unexpectedly rejected", index+1)
		}
	}
	if limiter.Allow("192.0.2.99:443") {
		t.Fatal("shared IPv4 /24 budget was not enforced")
	}
	now = now.Add(time.Second)
	if !limiter.Allow("192.0.2.99:443") {
		t.Fatal("unknown network budget did not refill")
	}
}

func TestPublicRateLimiterPromotesOnlyAuthenticatedIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newPublicRateLimiter()
	limiter.now = func() time.Time { return now }
	trusted := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.8:4433"))
	limiter.MarkAuthenticated(trusted)
	for index := 0; index < 20; index++ {
		if !limiter.Allow("198.51.100.8:50000") {
			t.Fatalf("authenticated request %d unexpectedly rejected", index+1)
		}
	}
	for index := 0; index < 10; index++ {
		if !limiter.Allow("198.51.100.9:50000") {
			t.Fatalf("unknown request %d unexpectedly rejected", index+1)
		}
	}
	if limiter.Allow("198.51.100.9:50000") {
		t.Fatal("neighboring address inherited authenticated allowance")
	}
	now = now.Add(publicTrustLifetime + time.Second)
	for index := 0; index < 10; index++ {
		if !limiter.Allow("198.51.100.8:50000") {
			t.Fatalf("expired source baseline request %d unexpectedly rejected", index+1)
		}
	}
	if limiter.Allow("198.51.100.8:50000") {
		t.Fatal("authenticated allowance did not expire")
	}
}

func TestPublicRateLimiterRejectsMalformedSource(t *testing.T) {
	limiter := newPublicRateLimiter()
	for _, address := range []string{"", "not-an-address", "0.0.0.0:1", "[ff02::1]:1"} {
		if limiter.Allow(address) {
			t.Fatalf("malformed source %q was allowed", address)
		}
	}
}
