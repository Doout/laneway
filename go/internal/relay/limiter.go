package relay

import (
	"sync"
	"time"
)

// packetLimiter is one process-wide, non-blocking token bucket. Tokens are
// measured in bits so rates configured in bits per second retain their exact
// operator-facing meaning. The small consecutive-sender gate prevents a hot
// session from consuming every refill while another authenticated session is
// contending; it never queues or delays a packet.
type packetLimiter struct {
	mu sync.Mutex

	rateBitsPerSecond uint64
	capacityBits      uint64
	tokensBits        uint64
	refillRemainder   uint64
	lastRefill        time.Time
	clock             func() time.Time

	lastSender       *Session
	consecutiveBits  uint64
	lastSenderChange time.Time
	fairnessWindow   time.Duration
	lastThrottled    time.Time
}

func newPacketLimiter(rateBitsPerSecond uint64, burstBytes int) *packetLimiter {
	if rateBitsPerSecond == 0 || burstBytes == 0 {
		return nil
	}
	now := time.Now()
	capacityBits := uint64(burstBytes) * 8
	window := time.Duration(max(uint64(1), (capacityBits/2)*uint64(time.Second)/rateBitsPerSecond))
	return &packetLimiter{
		rateBitsPerSecond: rateBitsPerSecond,
		capacityBits:      capacityBits, tokensBits: capacityBits,
		lastRefill: now, clock: time.Now, fairnessWindow: window,
		lastSenderChange: now,
	}
}

func (l *packetLimiter) allow(sender *Session, bytes int, multipleSessions bool) bool {
	if l == nil {
		return true
	}
	now := l.clock()
	needed := uint64(bytes) * 8
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill(now)

	if sender != l.lastSender {
		l.lastSender = sender
		l.consecutiveBits = 0
		l.lastSenderChange = now
	} else if multipleSessions && l.consecutiveBits+needed > l.capacityBits/2 &&
		now.Sub(l.lastSenderChange) < l.fairnessWindow {
		l.lastThrottled = now
		return false
	}
	if needed > l.tokensBits {
		l.lastThrottled = now
		return false
	}
	l.tokensBits -= needed
	l.consecutiveBits += needed
	return true
}

func (l *packetLimiter) refill(now time.Time) {
	if !now.After(l.lastRefill) {
		return
	}
	elapsed := now.Sub(l.lastRefill)
	fillTime := time.Duration(l.capacityBits * uint64(time.Second) / l.rateBitsPerSecond)
	if fillTime <= 0 || elapsed >= fillTime {
		l.tokensBits = l.capacityBits
		l.refillRemainder = 0
		l.lastRefill = now
		return
	}
	numerator := uint64(elapsed)*l.rateBitsPerSecond + l.refillRemainder
	added := numerator / uint64(time.Second)
	l.refillRemainder = numerator % uint64(time.Second)
	l.tokensBits = min(l.capacityBits, l.tokensBits+added)
	if l.tokensBits == l.capacityBits {
		l.refillRemainder = 0
	}
	l.lastRefill = now
}

func (l *packetLimiter) saturated() bool {
	if l == nil {
		return false
	}
	now := l.clock()
	l.mu.Lock()
	l.refill(now)
	saturated := !l.lastThrottled.IsZero() && now.Sub(l.lastThrottled) <= time.Second
	l.mu.Unlock()
	return saturated
}
