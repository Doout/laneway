package agent

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

type randomSequence struct {
	mu     sync.Mutex
	values []float64
}

func (r *randomSequence) Float64() float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.values) == 0 {
		return 0
	}
	value := r.values[0]
	r.values = r.values[1:]
	return value
}

type clockRequest struct {
	delay time.Duration
	ch    chan time.Time
}

type manualClock struct {
	requests chan clockRequest
}

func newManualClock() *manualClock {
	return &manualClock{requests: make(chan clockRequest, 1)}
}

func (c *manualClock) After(delay time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.requests <- clockRequest{delay: delay, ch: ch}
	return ch
}

func TestBackoffBoundedExponentialJitterAndReset(t *testing.T) {
	random := &randomSequence{values: []float64{0, 1, .5, -10, 2}}
	backoff, err := NewBackoff(BackoffConfig{
		Initial: 100 * time.Millisecond,
		Maximum: 400 * time.Millisecond,
		Jitter:  .25,
		Random:  random,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{
		100 * time.Millisecond,
		150 * time.Millisecond,
		350 * time.Millisecond,
		400 * time.Millisecond,
		300 * time.Millisecond,
	}
	for i, expected := range want {
		if got := backoff.Next(); got != expected {
			t.Fatalf("attempt %d = %s, want %s", i, got, expected)
		}
	}
	backoff.Reset()
	if got := backoff.Next(); got != 100*time.Millisecond {
		t.Fatalf("after Reset = %s", got)
	}
}

func TestBackoffZeroJitter(t *testing.T) {
	backoff, err := NewBackoff(BackoffConfig{Initial: time.Second, Maximum: 4 * time.Second, Jitter: 0})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		if got := backoff.Next(); got != want {
			t.Fatalf("attempt %d = %s, want %s", i, got, want)
		}
	}
}

func TestBackoffWaitUsesInjectedClock(t *testing.T) {
	clock := newManualClock()
	backoff, err := NewBackoff(BackoffConfig{Initial: time.Second, Maximum: time.Second, Clock: clock, Random: &randomSequence{}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		delay, err := backoff.Wait(context.Background())
		if delay != time.Second && err == nil {
			err = errors.New("unexpected delay")
		}
		done <- err
	}()
	request := <-clock.requests
	if request.delay != time.Second {
		t.Fatalf("clock delay = %s", request.delay)
	}
	request.ch <- time.Time{}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBackoffWaitCancellation(t *testing.T) {
	clock := newManualClock()
	backoff, err := NewBackoff(BackoffConfig{Initial: time.Second, Maximum: time.Second, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if delay, err := backoff.Wait(ctx); delay <= 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %s, %v", delay, err)
	}
}

func TestBackoffDefaultsAndInvalidConfig(t *testing.T) {
	backoff, err := NewBackoff(BackoffConfig{Random: &randomSequence{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := backoff.Next(); got != DefaultBackoffInitial {
		t.Fatalf("default first delay = %s", got)
	}
	for _, config := range []BackoffConfig{
		{Initial: -1, Maximum: time.Second},
		{Initial: 2 * time.Second, Maximum: time.Second},
		{Initial: time.Second, Maximum: time.Second, Jitter: -0.1},
		{Initial: time.Second, Maximum: time.Second, Jitter: 1.1},
		{Initial: time.Second, Maximum: time.Second, Jitter: math.NaN()},
	} {
		if _, err := NewBackoff(config); !errors.Is(err, ErrInvalidBackoff) {
			t.Fatalf("NewBackoff(%+v) error = %v", config, err)
		}
	}
}
