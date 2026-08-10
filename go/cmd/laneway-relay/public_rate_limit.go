package main

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	publicRateMaxEntries = 4096
	publicTrustLifetime  = time.Hour
)

type rateBucket struct {
	tokens float64
	last   time.Time
}

// publicRateLimiter bounds unauthenticated discovery by source network and
// the service as a whole. A source IP is temporarily promoted only after a
// successful Laneway mTLS fallback handshake, which cannot be forged with an
// HTTP header or a guessed public value.
type publicRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	global  rateBucket
	ranges  map[netip.Prefix]rateBucket
	trusted map[netip.Addr]time.Time
	clients map[netip.Addr]rateBucket
}

func newPublicRateLimiter() *publicRateLimiter {
	return &publicRateLimiter{
		now: time.Now, ranges: make(map[netip.Prefix]rateBucket),
		trusted: make(map[netip.Addr]time.Time), clients: make(map[netip.Addr]rateBucket),
	}
}

func (l *publicRateLimiter) MarkAuthenticated(address net.Addr) {
	if l == nil {
		return
	}
	ip, ok := remoteIP(address.String())
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	if len(l.trusted) >= publicRateMaxEntries {
		l.evictOldestTrust()
	}
	l.trusted[ip] = now.Add(publicTrustLifetime)
}

func (l *publicRateLimiter) Allow(remoteAddress string) bool {
	if l == nil {
		return false
	}
	ip, ok := remoteIP(remoteAddress)
	if !ok {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.prune(now)
	if !take(&l.global, now, 200, 400) {
		return false
	}
	if deadline, elevated := l.trusted[ip]; elevated && deadline.After(now) {
		bucket := l.clients[ip]
		allowed := take(&bucket, now, 20, 100)
		l.clients[ip] = bucket
		return allowed
	}
	prefix := sourceRange(ip)
	if _, exists := l.ranges[prefix]; !exists && len(l.ranges) >= publicRateMaxEntries {
		l.evictOldestRange()
	}
	bucket := l.ranges[prefix]
	allowed := take(&bucket, now, 2, 10)
	l.ranges[prefix] = bucket
	return allowed
}

func remoteIP(address string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func sourceRange(ip netip.Addr) netip.Prefix {
	if ip.Is4() {
		return netip.PrefixFrom(ip, 24).Masked()
	}
	return netip.PrefixFrom(ip, 64).Masked()
}

func take(bucket *rateBucket, now time.Time, rate, burst float64) bool {
	if bucket.last.IsZero() {
		bucket.tokens = burst
		bucket.last = now
	} else if now.After(bucket.last) {
		bucket.tokens += now.Sub(bucket.last).Seconds() * rate
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *publicRateLimiter) prune(now time.Time) {
	for ip, deadline := range l.trusted {
		if !deadline.After(now) {
			delete(l.trusted, ip)
			delete(l.clients, ip)
		}
	}
}

func (l *publicRateLimiter) evictOldestTrust() {
	var oldestIP netip.Addr
	var oldest time.Time
	for ip, deadline := range l.trusted {
		if oldest.IsZero() || deadline.Before(oldest) {
			oldestIP, oldest = ip, deadline
		}
	}
	delete(l.trusted, oldestIP)
	delete(l.clients, oldestIP)
}

func (l *publicRateLimiter) evictOldestRange() {
	var oldestPrefix netip.Prefix
	var oldest time.Time
	for prefix, bucket := range l.ranges {
		if oldest.IsZero() || bucket.last.Before(oldest) {
			oldestPrefix, oldest = prefix, bucket.last
		}
	}
	delete(l.ranges, oldestPrefix)
}
