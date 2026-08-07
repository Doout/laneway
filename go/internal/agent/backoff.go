package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

var ErrInvalidBackoff = errors.New("invalid Laneway reconnect backoff configuration")

const (
	DefaultBackoffInitial = 500 * time.Millisecond
	DefaultBackoffMaximum = 30 * time.Second
	DefaultBackoffJitter  = 0.25
)

// Clock is the minimal time source needed by reconnect waiting. Tests can
// inject a manually controlled implementation.
type Clock interface {
	After(time.Duration) <-chan time.Time
}

// Random is the minimal randomness source needed for jitter. Float64 must
// normally return a value in [0,1); out-of-range injected values are clamped.
type Random interface {
	Float64() float64
}

type realClock struct{}

func (realClock) After(duration time.Duration) <-chan time.Time { return time.After(duration) }

type globalRandom struct{}

func (globalRandom) Float64() float64 { return rand.Float64() }

type BackoffConfig struct {
	Initial time.Duration
	Maximum time.Duration
	// Jitter is the maximum fractional reduction from the exponential cap.
	// For example, 0.25 produces a delay in [75% of cap, cap].
	Jitter float64
	Clock  Clock
	Random Random
}

// Backoff is a concurrency-safe bounded exponential reconnect schedule. Reset
// should be called after a connection has remained healthy.
type Backoff struct {
	mu      sync.Mutex
	initial time.Duration
	maximum time.Duration
	jitter  float64
	clock   Clock
	random  Random
	cap     time.Duration
}

func NewBackoff(config BackoffConfig) (*Backoff, error) {
	useDefaultJitter := config.Initial == 0 && config.Maximum == 0 && config.Jitter == 0
	if config.Initial == 0 {
		config.Initial = DefaultBackoffInitial
	}
	if config.Maximum == 0 {
		config.Maximum = DefaultBackoffMaximum
	}
	if useDefaultJitter {
		config.Jitter = DefaultBackoffJitter
	}
	if config.Initial < 0 || config.Maximum < 0 || config.Initial > config.Maximum || config.Jitter < 0 || config.Jitter > 1 || math.IsNaN(config.Jitter) || math.IsInf(config.Jitter, 0) {
		return nil, fmt.Errorf("%w: initial=%s maximum=%s jitter=%g", ErrInvalidBackoff, config.Initial, config.Maximum, config.Jitter)
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	if config.Random == nil {
		config.Random = globalRandom{}
	}
	return &Backoff{
		initial: config.Initial,
		maximum: config.Maximum,
		jitter:  config.Jitter,
		clock:   config.Clock,
		random:  config.Random,
	}, nil
}

// Next returns the next jittered delay and advances the exponential cap. Every
// result is in [Initial*(1-Jitter), Maximum]. Growth saturates without integer
// overflow.
func (b *Backoff) Next() time.Duration {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cap == 0 {
		b.cap = b.initial
	}
	capForAttempt := b.cap
	if b.cap >= b.maximum || b.cap > b.maximum/2 {
		b.cap = b.maximum
	} else {
		b.cap *= 2
	}
	random := b.random.Float64()
	if random < 0 {
		random = 0
	} else if random >= 1 {
		random = 1
	}
	reduction := time.Duration(float64(capForAttempt) * b.jitter * random)
	if reduction < 0 || reduction > capForAttempt {
		reduction = capForAttempt
	}
	return capForAttempt - reduction
}

func (b *Backoff) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.cap = 0
	b.mu.Unlock()
}

// Wait advances the schedule, waits using the injected clock, and remains
// cancelable even when a test clock has not fired.
func (b *Backoff) Wait(ctx context.Context) (time.Duration, error) {
	if b == nil {
		return 0, fmt.Errorf("%w: nil backoff", ErrInvalidBackoff)
	}
	delay := b.Next()
	b.mu.Lock()
	clock := b.clock
	b.mu.Unlock()
	select {
	case <-ctx.Done():
		return delay, ctx.Err()
	case <-clock.After(delay):
		return delay, nil
	}
}
