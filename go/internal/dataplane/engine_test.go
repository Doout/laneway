package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/routing"
)

func nodeID(last byte) identity.NodeID {
	var id identity.NodeID
	id[len(id)-1] = last
	return id
}

func networkID(last byte) identity.NetworkID {
	var id identity.NetworkID
	id[len(id)-1] = last
	return id
}

func ipv4(source, destination netip.Addr) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 20
	packet[8], packet[9] = 64, 1
	sourceBytes, destinationBytes := source.As4(), destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	return packet
}

type memoryPackets struct {
	input  chan []byte
	output chan []byte
}

func newMemoryPackets() *memoryPackets {
	return &memoryPackets{input: make(chan []byte, 16), output: make(chan []byte, 16)}
}

func (m *memoryPackets) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case packet := <-m.input:
		if len(packet) > len(buffer) {
			return 0, errors.New("short buffer")
		}
		return copy(buffer, packet), nil
	}
}

func (m *memoryPackets) WritePacket(ctx context.Context, packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.output <- copyPacket:
		return nil
	}
}

type fakePacketPath struct {
	name       string
	max        int
	mu         sync.Mutex
	sendErr    error
	sent       [][]byte
	received   chan pathmanager.ReceivedPacket
	failures   chan error
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Uint32
}

func newFakePath(name string) *fakePacketPath {
	return &fakePacketPath{name: name, max: 1200, received: make(chan pathmanager.ReceivedPacket, 16), failures: make(chan error, 1), closed: make(chan struct{})}
}

func (p *fakePacketPath) Name() string                      { return p.name }
func (p *fakePacketPath) MaxPayload(pathmanager.PeerID) int { return p.max }
func (p *fakePacketPath) Send(_ context.Context, _ pathmanager.PeerID, packet pathmanager.PacketBuffer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendErr != nil {
		return p.sendErr
	}
	p.sent = append(p.sent, append([]byte(nil), packet...))
	return nil
}
func (p *fakePacketPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	select {
	case <-ctx.Done():
		return pathmanager.ReceivedPacket{}, ctx.Err()
	case <-p.closed:
		return pathmanager.ReceivedPacket{}, errors.New("closed")
	case err := <-p.failures:
		return pathmanager.ReceivedPacket{}, err
	case packet := <-p.received:
		return packet, nil
	}
}
func (p *fakePacketPath) Health(pathmanager.PeerID) pathmanager.PathHealth {
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}
func (p *fakePacketPath) Close() error {
	p.closeOnce.Do(func() {
		p.closeCalls.Add(1)
		close(p.closed)
	})
	return nil
}
func (p *fakePacketPath) sentCount() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.sent) }

func newTestEngine(t *testing.T, packets PacketIO, paths PathTable, policy PacketPolicy) (*Engine, identity.NodeIdentity, identity.NodeID, netip.Addr, netip.Addr) {
	t.Helper()
	localAddress := netip.MustParseAddr("100.64.0.1")
	peerAddress := netip.MustParseAddr("100.64.0.2")
	peer := nodeID(2)
	local := identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)}
	snapshot := routing.MustSnapshot([]routing.Route{
		{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer},
		{Prefix: netip.MustParsePrefix("10.0.0.0/24"), NextHop: peer},
	})
	engine, err := New(Config{Identity: local, Routes: routing.NewTable(snapshot), Packets: packets, Paths: paths, Policy: policy, LocalAddresses: []netip.Addr{localAddress}})
	if err != nil {
		t.Fatal(err)
	}
	return engine, local, peer, localAddress, peerAddress
}

type allocationPath struct{}

func (allocationPath) Name() string                      { return "allocation" }
func (allocationPath) MaxPayload(pathmanager.PeerID) int { return 1200 }
func (allocationPath) Send(context.Context, pathmanager.PeerID, pathmanager.PacketBuffer) error {
	return nil
}
func (allocationPath) Receive(context.Context) (pathmanager.ReceivedPacket, error) {
	return pathmanager.ReceivedPacket{}, context.Canceled
}
func (allocationPath) Health(pathmanager.PeerID) pathmanager.PathHealth {
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}
func (allocationPath) Close() error { return nil }

type allocationPaths struct{ path pathmanager.PacketPath }

func (p allocationPaths) BestPath(pathmanager.PeerID) pathmanager.PacketPath { return p.path }
func (allocationPaths) Observe(pathmanager.PeerID, pathmanager.PathSample)   {}
func (allocationPaths) MarkFailed(pathmanager.PeerID, string)                {}
func (allocationPaths) AddPath(pathmanager.PeerID, pathmanager.PathKind, pathmanager.PacketPath) error {
	return nil
}
func (allocationPaths) RemovePath(pathmanager.PeerID, string) bool { return true }

func TestSendWithFailoverDoesNotAllocateVisitedMap(t *testing.T) {
	peer := nodeID(2)
	engine := &Engine{config: Config{Paths: allocationPaths{path: allocationPath{}}}}
	packet := ipv4(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"))
	if allocations := testing.AllocsPerRun(1000, func() {
		if !engine.sendWithFailover(context.Background(), peer, packet) {
			t.Fatal("send failed")
		}
	}); allocations != 0 {
		t.Fatalf("sendWithFailover allocations = %v, want zero", allocations)
	}
}

func BenchmarkSendWithFailover(b *testing.B) {
	peer := nodeID(2)
	engine := &Engine{config: Config{Paths: allocationPaths{path: allocationPath{}}}}
	packet := ipv4(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		engine.sendWithFailover(context.Background(), peer, packet)
	}
}

func TestEngineUsesPreferredPathAndImmediatelyFailsOver(t *testing.T) {
	packets := newMemoryPackets()
	manager := pathmanager.MustNew(pathmanager.Config{})
	engine, _, peer, localAddress, peerAddress := newTestEngine(t, packets, manager, nil)
	direct, relay, tcp := newFakePath("direct"), newFakePath("relay"), newFakePath("tcp")
	direct.sendErr = errors.New("direct socket failed")
	if err := engine.Attach(peer, pathmanager.PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	if err := engine.Attach(peer, pathmanager.PathRelayQUIC, relay); err != nil {
		t.Fatal(err)
	}
	if err := engine.Attach(peer, pathmanager.PathTCPFallback, tcp); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	packets.input <- ipv4(localAddress, peerAddress)
	eventually(t, func() bool { return relay.sentCount() == 1 })
	if direct.sentCount() != 0 || tcp.sentCount() != 0 {
		t.Fatalf("send counts direct=%d relay=%d tcp=%d", direct.sentCount(), relay.sentCount(), tcp.sentCount())
	}
	if got := manager.BestPath(peer); got == nil || got.Name() != "relay" {
		t.Fatalf("best after direct failure = %v", got)
	}
	manager.MarkFailed(peer, "relay")
	packets.input <- ipv4(localAddress, peerAddress)
	eventually(t, func() bool { return tcp.sentCount() == 1 })
	if got := manager.BestPath(peer); got == nil || got.Name() != "tcp" {
		t.Fatalf("best after relay failure = %v", got)
	}
	metrics := engine.Metrics()
	if metrics.PacketsSent != 2 || metrics.PathFailures != 1 || metrics.PathSwitchRetries != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func TestEngineAppliesSharedInboundValidationAndPolicy(t *testing.T) {
	packets := newMemoryPackets()
	manager := pathmanager.MustNew(pathmanager.Config{})
	var denied atomic.Bool
	policy := PacketPolicyFunc(func(_, _ identity.NodeID, _ []byte) bool { return !denied.Load() })
	engine, _, peer, localAddress, peerAddress := newTestEngine(t, packets, manager, policy)
	direct := newFakePath("direct")
	if err := engine.Attach(peer, pathmanager.PathDirect, direct); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	valid := ipv4(peerAddress, localAddress)
	direct.received <- pathmanager.ReceivedPacket{Peer: peer, Packet: valid}
	select {
	case got := <-packets.output:
		if string(got) != string(valid) {
			t.Fatal("valid packet changed")
		}
	case <-time.After(time.Second):
		t.Fatal("valid inbound packet was not delivered")
	}
	// Source route names another network and must not be accepted from peer.
	direct.received <- pathmanager.ReceivedPacket{Peer: peer, Packet: ipv4(netip.MustParseAddr("192.0.2.1"), localAddress)}
	// Destination is not local.
	direct.received <- pathmanager.ReceivedPacket{Peer: peer, Packet: ipv4(peerAddress, netip.MustParseAddr("100.64.0.9"))}
	denied.Store(true)
	direct.received <- pathmanager.ReceivedPacket{Peer: peer, Packet: valid}
	eventually(t, func() bool { return engine.Metrics().PacketsDropped == 3 })
	select {
	case packet := <-packets.output:
		t.Fatalf("invalid packet delivered: %x", packet)
	default:
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func TestReceiverFailureDetachesClosesAndAllowsSameNameReconnect(t *testing.T) {
	packets := newMemoryPackets()
	manager := pathmanager.MustNew(pathmanager.Config{})
	engine, _, peer, localAddress, peerAddress := newTestEngine(t, packets, manager, nil)
	failed := newFakePath("direct/same-peer-address")
	if err := engine.Attach(peer, pathmanager.PathDirect, failed); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()

	failed.failures <- errors.New("remote direct connection closed")
	eventually(t, func() bool {
		return manager.BestPath(peer) == nil && failed.closeCalls.Load() == 1
	})
	engine.mu.Lock()
	_, stillAttached := engine.attachments[failed.Name()]
	engine.mu.Unlock()
	if stillAttached {
		t.Fatal("failed receiver remained in the engine attachment table")
	}

	replacement := newFakePath(failed.Name())
	if err := engine.Attach(peer, pathmanager.PathDirect, replacement); err != nil {
		t.Fatalf("attach replacement with same peer/name: %v", err)
	}
	if got := manager.BestPath(peer); got != replacement {
		t.Fatalf("best replacement = %v, want %v", got, replacement)
	}
	packet := ipv4(peerAddress, localAddress)
	replacement.received <- pathmanager.ReceivedPacket{Peer: peer, Packet: packet}
	select {
	case got := <-packets.output:
		if string(got) != string(packet) {
			t.Fatalf("replacement packet = %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement receiver did not deliver a packet")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v", err)
	}
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not satisfied")
		}
		time.Sleep(time.Millisecond)
	}
}
