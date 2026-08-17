package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
)

type fakeRelayCarrier struct {
	sent     chan []byte
	received chan []byte
	done     chan struct{}
}

type allocationRelayCarrier struct{ done chan struct{} }

func (allocationRelayCarrier) SendPacket(context.Context, []byte) error { return nil }
func (allocationRelayCarrier) ReceivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error) {
	return nil, nil, context.Canceled
}
func (c allocationRelayCarrier) Done() <-chan struct{} { return c.done }
func (allocationRelayCarrier) Close() error            { return nil }

func newFakeRelayCarrier() *fakeRelayCarrier {
	return &fakeRelayCarrier{sent: make(chan []byte, 4), received: make(chan []byte, 4), done: make(chan struct{})}
}

func (c *fakeRelayCarrier) SendPacket(ctx context.Context, packet []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.sent <- append([]byte(nil), packet...):
		return nil
	}
}
func (c *fakeRelayCarrier) ReceivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-c.done:
		return nil, nil, errors.New("closed")
	case packet := <-c.received:
		return packet, nil, nil
	}
}
func (c *fakeRelayCarrier) Done() <-chan struct{} { return c.done }
func (c *fakeRelayCarrier) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return nil
}

func TestRelayPathBindingFramingReceiveAndHealth(t *testing.T) {
	carrier := newFakeRelayCarrier()
	path, err := NewRelayPath("relay", carrier)
	if err != nil {
		t.Fatal(err)
	}
	peer := nodeID(2)
	if err := path.ReplaceBindings([]RelayBinding{{Peer: peer, Handle: 42, MaxPacketPayload: 1200}}); err != nil {
		t.Fatal(err)
	}
	packet := ipv4AddressPacket()
	if err := path.Send(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	frame := <-carrier.sent
	header, payload, err := protocol.DecodePacket(frame)
	if err != nil || header.RouteHandle != 42 || string(payload) != string(packet) {
		t.Fatalf("frame header=%+v payload=%x err=%v", header, payload, err)
	}
	carrier.received <- frame
	received, err := path.Receive(context.Background())
	if err != nil || received.Peer != peer || string(received.Packet) != string(packet) {
		t.Fatalf("received=%#v err=%v", received, err)
	}
	if &received.Packet[0] != &frame[protocol.PacketHeaderSize] {
		t.Fatal("relay receive copied its caller-owned carrier buffer")
	}
	if health := path.Health(peer); health.State != pathmanager.HealthHealthy {
		t.Fatalf("health = %+v", health)
	}
	if released, ok := path.ReleaseHandle(42); !ok || released != peer {
		t.Fatalf("release = %s, %v", released, ok)
	}
	if path.MaxPayload(peer) != 0 {
		t.Fatal("released peer remains bound")
	}
	if err := path.Send(context.Background(), peer, packet); !errors.Is(err, ErrRelayBinding) {
		t.Fatalf("released send error = %v", err)
	}
	if err := path.SetBinding(RelayBinding{Peer: peer, Handle: 7, MaxPacketPayload: 1200}); err != nil {
		t.Fatal(err)
	}
	_ = path.Close()
	if health := path.Health(peer); health.State != pathmanager.HealthFailed {
		t.Fatalf("closed health = %+v", health)
	}
}

func TestRelayPathRejectsAmbiguousAndMalformedBindings(t *testing.T) {
	path, _ := NewRelayPath("relay", newFakeRelayCarrier())
	a, b := nodeID(1), nodeID(2)
	if err := path.ReplaceBindings([]RelayBinding{{Peer: a, Handle: 1, MaxPacketPayload: 1200}, {Peer: b, Handle: 1, MaxPacketPayload: 1200}}); !errors.Is(err, ErrDuplicateRelayBinding) {
		t.Fatalf("duplicate handle error = %v", err)
	}
	if err := path.ReplaceBindings([]RelayBinding{{Peer: a, Handle: 0, MaxPacketPayload: 1200}}); !errors.Is(err, ErrRelayBinding) {
		t.Fatalf("zero handle error = %v", err)
	}
}

func TestRelayPathWarmSendDoesNotAllocateFrame(t *testing.T) {
	path, err := NewRelayPath("relay", allocationRelayCarrier{done: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	peer := nodeID(2)
	if err := path.SetBinding(RelayBinding{Peer: peer, Handle: 42, MaxPacketPayload: 1200}); err != nil {
		t.Fatal(err)
	}
	packet := ipv4AddressPacket()
	if err := path.Send(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if err := path.Send(context.Background(), peer, packet); err != nil {
			t.Fatal(err)
		}
	}); allocations != 0 {
		t.Fatalf("warm relay send allocations = %v, want zero", allocations)
	}
}

func BenchmarkRelayPathSend(b *testing.B) {
	path, _ := NewRelayPath("relay", allocationRelayCarrier{done: make(chan struct{})})
	peer := nodeID(2)
	_ = path.SetBinding(RelayBinding{Peer: peer, Handle: 42, MaxPacketPayload: 1200})
	packet := make([]byte, 1200)
	packet[0], packet[2], packet[3] = 0x45, 4, 176
	_ = path.Send(context.Background(), peer, packet)
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for range b.N {
		_ = path.Send(context.Background(), peer, packet)
	}
}

func ipv4AddressPacket() []byte {
	return ipv4AddressPacketFrom([4]byte{100, 64, 0, 1}, [4]byte{100, 64, 0, 2})
}

func ipv4AddressPacketFrom(source, destination [4]byte) []byte {
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3] = 0x45, 0, 20
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	return packet
}
