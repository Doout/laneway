package wireguard

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
)

type testCarrierPath struct {
	name    string
	peer    identity.NodeID
	sendErr error
	recv    chan pathmanager.ReceivedPacket
	closed  chan struct{}
	mu      sync.Mutex
	sent    [][]byte
}

func newTestCarrierPath(name string, peer identity.NodeID) *testCarrierPath {
	return &testCarrierPath{name: name, peer: peer, recv: make(chan pathmanager.ReceivedPacket, 4), closed: make(chan struct{})}
}

func (p *testCarrierPath) Name() string                   { return p.name }
func (p *testCarrierPath) MaxPayload(identity.NodeID) int { return 1280 }
func (p *testCarrierPath) Health(identity.NodeID) pathmanager.PathHealth {
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}
func (p *testCarrierPath) Send(_ context.Context, peer identity.NodeID, packet pathmanager.PacketBuffer) error {
	if peer != p.peer {
		return errors.New("wrong peer")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendErr != nil {
		return p.sendErr
	}
	p.sent = append(p.sent, append([]byte(nil), packet...))
	return nil
}
func (p *testCarrierPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	select {
	case packet := <-p.recv:
		return packet, nil
	case <-ctx.Done():
		return pathmanager.ReceivedPacket{}, ctx.Err()
	case <-p.closed:
		return pathmanager.ReceivedPacket{}, errors.New("closed")
	}
}
func (p *testCarrierPath) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}
func (p *testCarrierPath) sentCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sent)
}

func TestCarrierMuxPrefersDirectAndFallsBackToRelay(t *testing.T) {
	peer := relayNode(71)
	direct := newTestCarrierPath("direct", peer)
	relay := newTestCarrierPath("relay", peer)
	mux, err := NewCarrierMux(pathmanager.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.Attach(peer, pathmanager.PathRelayQUIC, relay); err != nil {
		t.Fatal(err)
	}
	if err := mux.Attach(peer, pathmanager.PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	packet := wireGuardInitiation()
	if err := mux.Send(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	if direct.sentCount() != 1 || relay.sentCount() != 0 {
		t.Fatalf("direct sends=%d relay sends=%d", direct.sentCount(), relay.sentCount())
	}
	direct.mu.Lock()
	direct.sendErr = errors.New("direct failed")
	direct.mu.Unlock()
	if err := mux.Send(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	if relay.sentCount() != 1 {
		t.Fatalf("relay sends=%d", relay.sentCount())
	}
	metrics := mux.Metrics()
	if metrics.PacketsSent != 2 || metrics.PathFailures != 1 || metrics.PathSwitchRetries != 1 {
		t.Fatalf("metrics=%+v", metrics)
	}
}

func TestCarrierMuxReceivesOnlyFromExactAttachedPeer(t *testing.T) {
	peer, attacker := relayNode(72), relayNode(73)
	direct := newTestCarrierPath("direct", peer)
	mux, err := NewCarrierMux(pathmanager.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.Attach(peer, pathmanager.PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan pathmanager.ReceivedPacket, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- mux.Run(ctx, func(_ context.Context, source identity.NodeID, packet []byte) error {
			delivered <- pathmanager.ReceivedPacket{Peer: source, Packet: append([]byte(nil), packet...)}
			return nil
		})
	}()
	packet := wireGuardInitiation()
	direct.recv <- pathmanager.ReceivedPacket{Peer: attacker, Packet: packet}
	select {
	case value := <-delivered:
		t.Fatalf("unauthorized packet delivered: %+v", value)
	case <-time.After(100 * time.Millisecond):
	}
	direct.recv <- pathmanager.ReceivedPacket{Peer: peer, Packet: packet}
	select {
	case value := <-delivered:
		if value.Peer != peer || !bytes.Equal(value.Packet, packet) {
			t.Fatalf("delivered=%+v", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorized packet was not delivered")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error=%v", err)
	}
	metrics := mux.Metrics()
	if metrics.PacketsReceived != 1 || metrics.PacketsDropped != 1 {
		t.Fatalf("metrics=%+v", metrics)
	}
}

func TestCarrierMuxRejectsPlaintextAndNameConflicts(t *testing.T) {
	peer := relayNode(74)
	first := newTestCarrierPath("same", peer)
	second := newTestCarrierPath("same", peer)
	mux, err := NewCarrierMux(pathmanager.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.Attach(peer, pathmanager.PathDirect, first); err != nil {
		t.Fatal(err)
	}
	if err := mux.Attach(peer, pathmanager.PathRelayQUIC, second); !errors.Is(err, ErrCarrierPathConflict) {
		t.Fatalf("path conflict error=%v", err)
	}
	if err := mux.Send(context.Background(), peer, make([]byte, 20)); err == nil {
		t.Fatal("plaintext payload accepted")
	}
	if first.sentCount() != 0 {
		t.Fatal("invalid payload reached carrier")
	}
}
