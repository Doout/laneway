package controllerservice

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	enrollmentRateBurst  = 10.0
	enrollmentRatePerSec = 1.0
	maxEnrollmentSources = 4096
	enrollmentSourceTTL  = 10 * time.Minute
)

type enrollmentRateState struct {
	tokens float64
	last   time.Time
}

type enrollmentRateLimiter struct {
	mu      sync.Mutex
	sources map[netip.Addr]enrollmentRateState
}

func newEnrollmentRateLimiter() *enrollmentRateLimiter {
	return &enrollmentRateLimiter{sources: make(map[netip.Addr]enrollmentRateState)}
}

func (l *enrollmentRateLimiter) allow(remoteAddress string, now time.Time) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	address = address.Unmap()
	now = now.UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, exists := l.sources[address]
	if !exists {
		if len(l.sources) >= maxEnrollmentSources {
			cutoff := now.Add(-enrollmentSourceTTL)
			for candidate, candidateState := range l.sources {
				if candidateState.last.Before(cutoff) {
					delete(l.sources, candidate)
				}
			}
			if len(l.sources) >= maxEnrollmentSources {
				return false
			}
		}
		state = enrollmentRateState{tokens: enrollmentRateBurst, last: now}
	}
	if now.After(state.last) {
		state.tokens += now.Sub(state.last).Seconds() * enrollmentRatePerSec
		if state.tokens > enrollmentRateBurst {
			state.tokens = enrollmentRateBurst
		}
		state.last = now
	}
	if state.tokens < 1 {
		l.sources[address] = state
		return false
	}
	state.tokens--
	l.sources[address] = state
	return true
}
