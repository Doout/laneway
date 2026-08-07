package relay

import (
	"testing"
	"time"
)

func TestPacketLimiterSharesOneBucketAcrossSessions(t *testing.T) {
	now := time.Unix(1, 0)
	limiter := newPacketLimiter(8_000, 2_000)
	limiter.clock = func() time.Time { return now }
	limiter.lastRefill = now
	a, b := &Session{}, &Session{}

	if !limiter.allow(a, 1_000, false) || !limiter.allow(b, 1_000, false) {
		t.Fatal("initial shared burst should admit both packets")
	}
	if limiter.allow(a, 1, false) {
		t.Fatal("a second session must not multiply the exhausted global bucket")
	}
	if !limiter.saturated() {
		t.Fatal("recent rejection must expose limiter saturation")
	}
	now = now.Add(time.Second)
	if !limiter.allow(a, 1_000, false) {
		t.Fatal("one second should refill 1000 bytes at 8000 bits/s")
	}
}

func TestPacketLimiterBoundsConsecutiveSenderForFairness(t *testing.T) {
	now := time.Unix(1, 0)
	limiter := newPacketLimiter(8_000_000, 2_000)
	limiter.clock = func() time.Time { return now }
	limiter.lastRefill = now
	a, b := &Session{}, &Session{}

	if !limiter.allow(a, 1_000, true) {
		t.Fatal("first sender should receive half the burst")
	}
	if limiter.allow(a, 1, true) {
		t.Fatal("same sender should be gated while another session is contending")
	}
	if !limiter.allow(b, 1_000, true) {
		t.Fatal("a different sender should receive the reserved remainder")
	}
}

func TestPacketLimiterPreservesFractionalRefills(t *testing.T) {
	now := time.Unix(1, 0)
	limiter := newPacketLimiter(8, 1285)
	limiter.clock = func() time.Time { return now }
	limiter.lastRefill = now
	limiter.tokensBits = 0
	for range 10 {
		now = now.Add(100 * time.Millisecond)
		limiter.refill(now)
	}
	if limiter.tokensBits != 8 {
		t.Fatalf("tokens = %d bits, want 8", limiter.tokensBits)
	}
}

func TestRegistryRejectsIncompletePacketLimiterConfig(t *testing.T) {
	base := Config{
		MaxSessions: 2, MaxHandlesPerSession: 2, OutboundQueueCapacity: 2,
		MaxPacketPayload: 1280, DuplicatePolicy: RejectDuplicate, QueuePolicy: DropNewest,
	}
	for name, mutate := range map[string]func(*Config){
		"rate only":  func(c *Config) { c.PacketRateBitsPerSecond = 1 },
		"burst only": func(c *Config) { c.PacketBurstBytes = 1285 },
		"small burst": func(c *Config) {
			c.PacketRateBitsPerSecond, c.PacketBurstBytes = 1, 1284
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := NewRegistry(config); err != ErrInvalidConfig {
				t.Fatalf("NewRegistry() error = %v, want %v", err, ErrInvalidConfig)
			}
		})
	}
}
