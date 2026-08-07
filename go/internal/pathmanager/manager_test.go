package pathmanager

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type fakePath struct{ name string }

func (p *fakePath) Name() string                                     { return p.name }
func (p *fakePath) MaxPayload(PeerID) int                            { return 1200 }
func (p *fakePath) Send(context.Context, PeerID, PacketBuffer) error { return nil }
func (p *fakePath) Receive(context.Context) (ReceivedPacket, error)  { return ReceivedPacket{}, nil }
func (p *fakePath) Health(PeerID) PathHealth                         { return PathHealth{State: HealthHealthy} }
func (p *fakePath) Close() error                                     { return nil }

func testPeer(last byte) PeerID {
	var peer PeerID
	peer[len(peer)-1] = last
	return peer
}

func selectedName(t *testing.T, manager *Manager, peer PeerID) string {
	t.Helper()
	path := manager.BestPath(peer)
	if path == nil {
		return ""
	}
	return path.Name()
}

func pathMetrics(t *testing.T, manager *Manager, peer PeerID, name string) PathMetrics {
	t.Helper()
	view, ok := manager.Snapshot().Peer(peer)
	if !ok {
		t.Fatalf("peer missing")
	}
	for _, path := range view.Paths {
		if path.Name == name {
			return path
		}
	}
	t.Fatalf("path %q missing", name)
	return PathMetrics{}
}

func TestDeterministicKindOrderAndStableSwitch(t *testing.T) {
	clock := &fakeClock{now: time.Unix(100, 0)}
	manager := MustNew(Config{Clock: clock, MinStableTime: 10 * time.Second})
	peer := testPeer(1)
	tcp, relay, direct := &fakePath{"tcp"}, &fakePath{"relay"}, &fakePath{"direct"}
	if err := manager.AddPath(peer, PathTCPFallback, tcp); err != nil {
		t.Fatal(err)
	}
	if err := manager.AddPath(peer, PathRelayQUIC, relay); err != nil {
		t.Fatal(err)
	}
	if got := selectedName(t, manager, peer); got != "relay" {
		t.Fatalf("better path kind was not promoted immediately: %q", got)
	}
	if err := manager.AddPath(peer, PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	if got := selectedName(t, manager, peer); got != "direct" {
		t.Fatalf("direct path was not promoted immediately: %q", got)
	}
}

func TestRelayDirectRelayTrafficSelection(t *testing.T) {
	manager := MustNew(Config{})
	peer := testPeer(9)
	relay, direct := &fakePath{"relay"}, &fakePath{"direct"}
	if err := manager.AddPath(peer, PathRelayQUIC, relay); err != nil {
		t.Fatal(err)
	}
	if got := selectedName(t, manager, peer); got != "relay" {
		t.Fatalf("initial = %q", got)
	}
	if err := manager.AddPath(peer, PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	if got := selectedName(t, manager, peer); got != "direct" {
		t.Fatalf("promotion = %q", got)
	}
	manager.MarkFailedReason(peer, "direct", "direct connection closed")
	if got := selectedName(t, manager, peer); got != "relay" {
		t.Fatalf("fallback = %q", got)
	}
}

func TestHysteresisPreventsLatencyFlapping(t *testing.T) {
	clock := &fakeClock{now: time.Unix(200, 0)}
	manager := MustNew(Config{Clock: clock, EWMAAlpha: 1, Hysteresis: 10 * time.Millisecond, MinStableTime: 5 * time.Second})
	peer := testPeer(2)
	a, b := &fakePath{"a"}, &fakePath{"b"}
	if err := manager.SetPaths(peer, []Candidate{{PathRelayQUIC, a}, {PathRelayQUIC, b}}); err != nil {
		t.Fatal(err)
	}
	manager.Observe(peer, PathSample{Path: "a", Latency: 50 * time.Millisecond})
	manager.Observe(peer, PathSample{Path: "b", Latency: 45 * time.Millisecond})
	clock.Advance(20 * time.Second)
	manager.Observe(peer, PathSample{Path: "b", Latency: 44 * time.Millisecond})
	if got := selectedName(t, manager, peer); got != "a" {
		t.Fatalf("small improvement flapped to %q", got)
	}
	manager.Observe(peer, PathSample{Path: "b", Latency: 20 * time.Millisecond})
	clock.Advance(4 * time.Second)
	manager.Observe(peer, PathSample{Path: "b", Latency: 20 * time.Millisecond})
	if got := selectedName(t, manager, peer); got != "a" {
		t.Fatalf("switched before stable: %q", got)
	}
	clock.Advance(time.Second)
	manager.Observe(peer, PathSample{Path: "b", Latency: 20 * time.Millisecond})
	if got := selectedName(t, manager, peer); got != "b" {
		t.Fatalf("did not switch after stable: %q", got)
	}
}

func TestImmediateFallbackAndRecoveryProbing(t *testing.T) {
	clock := &fakeClock{now: time.Unix(300, 0)}
	manager := MustNew(Config{Clock: clock, MinStableTime: 5 * time.Second, RecoverySamples: 2})
	peer := testPeer(3)
	direct, relay := &fakePath{"direct"}, &fakePath{"relay"}
	if err := manager.SetPaths(peer, []Candidate{{PathDirect, direct}, {PathRelayQUIC, relay}}); err != nil {
		t.Fatal(err)
	}
	manager.MarkFailedReason(peer, "direct", "socket closed")
	if got := selectedName(t, manager, peer); got != "relay" {
		t.Fatalf("hard failure did not fall back: %q", got)
	}
	failed := pathMetrics(t, manager, peer, "direct")
	if failed.State != HealthFailed || failed.FailureReason != "socket closed" {
		t.Fatalf("failed metrics = %+v", failed)
	}
	if metrics := manager.Snapshot().Metrics(); metrics.DirectFailures != 1 || metrics.HardFailures != 1 || metrics.Switches != 1 {
		t.Fatalf("aggregate failover metrics = %+v", metrics)
	}
	manager.Observe(peer, PathSample{Path: "direct", Latency: 10 * time.Millisecond})
	if state := pathMetrics(t, manager, peer, "direct").State; state != HealthProbing {
		t.Fatalf("first recovery state = %s", state)
	}
	manager.Observe(peer, PathSample{Path: "direct", Latency: 10 * time.Millisecond})
	if state := pathMetrics(t, manager, peer, "direct").State; state != HealthHealthy {
		t.Fatalf("second recovery state = %s", state)
	}
	if got := selectedName(t, manager, peer); got != "direct" {
		t.Fatalf("recovered preferred path not selected: %q", got)
	}
}

func TestProbeLossReturnsPathToFailed(t *testing.T) {
	manager := MustNew(Config{FailureThreshold: 10, RecoverySamples: 3})
	peer := testPeer(4)
	direct, relay := &fakePath{"direct"}, &fakePath{"relay"}
	if err := manager.SetPaths(peer, []Candidate{{PathDirect, direct}, {PathRelayQUIC, relay}}); err != nil {
		t.Fatal(err)
	}
	manager.MarkFailed(peer, "direct")
	manager.Observe(peer, PathSample{Path: "direct", Latency: time.Millisecond})
	manager.Observe(peer, PathSample{Path: "direct", Lost: true})
	if state := pathMetrics(t, manager, peer, "direct").State; state != HealthFailed {
		t.Fatalf("probe loss state = %s", state)
	}
}

func TestEWMAAndBoundedChronologicalObservations(t *testing.T) {
	manager := MustNew(Config{EWMAAlpha: 0.5, ObservationWindow: 3, FailureThreshold: 10})
	peer := testPeer(5)
	path := &fakePath{"relay"}
	if err := manager.AddPath(peer, PathRelayQUIC, path); err != nil {
		t.Fatal(err)
	}
	for i, latency := range []time.Duration{10, 20, 30, 40} {
		manager.Observe(peer, PathSample{Path: "relay", Latency: latency * time.Millisecond, Lost: i == 1})
	}
	metrics := pathMetrics(t, manager, peer, "relay")
	// Latency ignores the lost 20 ms sample: ((10+30)/2+40)/2 = 30 ms.
	if metrics.LatencyEWMA != 30*time.Millisecond {
		t.Fatalf("latency EWMA = %s", metrics.LatencyEWMA)
	}
	if metrics.LossEWMA != 0.125 {
		t.Fatalf("loss EWMA = %g", metrics.LossEWMA)
	}
	if len(metrics.Observations) != 3 || metrics.Observations[0].Latency != 20*time.Millisecond || metrics.Observations[2].Latency != 40*time.Millisecond {
		t.Fatalf("bounded observations = %+v", metrics.Observations)
	}
	// A caller cannot mutate the published snapshot through defensive copies.
	metrics.Observations[0].Latency = 99 * time.Second
	if got := pathMetrics(t, manager, peer, "relay").Observations[0].Latency; got != 20*time.Millisecond {
		t.Fatalf("snapshot mutated through accessor: %s", got)
	}
}

func TestBestPathAllocationFreeAndConcurrent(t *testing.T) {
	manager := MustNew(Config{EWMAAlpha: 1, FailureThreshold: 100})
	peer := testPeer(6)
	direct, relay := &fakePath{"direct"}, &fakePath{"relay"}
	if err := manager.SetPaths(peer, []Candidate{{PathDirect, direct}, {PathRelayQUIC, relay}}); err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(1000, func() { _ = manager.BestPath(peer) }); allocations != 0 {
		t.Fatalf("BestPath allocations = %g", allocations)
	}
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 1000 {
				path := manager.BestPath(peer)
				if path == nil || (path.Name() != "direct" && path.Name() != "relay") {
					t.Errorf("invalid concurrent path %v", path)
					return
				}
				_ = manager.Snapshot().Metrics()
			}
		}()
	}
	for i := range 1000 {
		if i%2 == 0 {
			manager.MarkFailed(peer, "direct")
			manager.Observe(peer, PathSample{Path: "direct", Latency: time.Millisecond})
			manager.Observe(peer, PathSample{Path: "direct", Latency: time.Millisecond})
			manager.Observe(peer, PathSample{Path: "direct", Latency: time.Millisecond})
		} else {
			manager.Observe(peer, PathSample{Path: "relay", Latency: time.Millisecond})
		}
	}
	wait.Wait()
}
