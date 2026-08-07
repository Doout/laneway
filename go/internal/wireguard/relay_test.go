package wireguard

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
	"laneway.dev/laneway/internal/protocol"
)

type fakeRelayCarrier struct {
	sent     chan []byte
	received chan []byte
	done     chan struct{}
}

func newFakeRelayCarrier() *fakeRelayCarrier {
	return &fakeRelayCarrier{sent: make(chan []byte, 4), received: make(chan []byte, 4), done: make(chan struct{})}
}

func (c *fakeRelayCarrier) SendPacket(ctx context.Context, packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case c.sent <- copyPacket:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *fakeRelayCarrier) ReceivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	select {
	case packet := <-c.received:
		return packet, nil, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
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

func relayNode(value byte) identity.NodeID {
	var result identity.NodeID
	for i := range result {
		result[i] = value
	}
	return result
}

func wireGuardInitiation() []byte {
	packet := make([]byte, 148)
	packet[0] = 1
	packet[4] = 0xa5
	return packet
}

func TestRelayMuxRequiresCapabilityAndStrictBindings(t *testing.T) {
	carrier := newFakeRelayCarrier()
	if _, err := NewRelayMux(carrier, protocol.CapabilityRelayV1); !errors.Is(err, ErrRelayCapability) {
		t.Fatalf("capability error = %v", err)
	}
	mux, err := NewRelayMux(carrier, protocol.CapabilityRelayV1|protocol.CapabilityE2EPacketV1)
	if err != nil {
		t.Fatal(err)
	}
	a, b := relayNode(1), relayNode(2)
	if err := mux.ReplaceBindings([]RelayBinding{{Peer: a, Handle: 7, MaxPacketPayload: 1280}, {Peer: b, Handle: 7, MaxPacketPayload: 1280}}); !errors.Is(err, ErrDuplicateRelayBinding) {
		t.Fatalf("duplicate handle error = %v", err)
	}
	if len(mux.Peers()) != 0 {
		t.Fatal("invalid snapshot was published")
	}
	if err := mux.SetBinding(RelayBinding{Peer: a, Handle: 7, MaxPacketPayload: 1280}); err != nil {
		t.Fatal(err)
	}
	if err := mux.SetBinding(RelayBinding{Peer: b, Handle: 7, MaxPacketPayload: 1280}); !errors.Is(err, ErrDuplicateRelayBinding) {
		t.Fatalf("duplicate handle error = %v", err)
	}
}

func TestRelayMuxFramesOpaqueWireGuardAndMapsAuthenticatedPeer(t *testing.T) {
	carrier := newFakeRelayCarrier()
	mux, err := NewRelayMux(carrier, protocol.CapabilityE2EPacketV1)
	if err != nil {
		t.Fatal(err)
	}
	peer := relayNode(3)
	if err := mux.SetBinding(RelayBinding{Peer: peer, Handle: 42, MaxPacketPayload: 1280}); err != nil {
		t.Fatal(err)
	}
	packet := wireGuardInitiation()
	if err := mux.Send(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	sent := <-carrier.sent
	header, payload, err := protocol.DecodeFrame(sent)
	if err != nil || header.Flags != protocol.PacketFlagE2EEncrypted || header.RouteHandle != 42 || !bytes.Equal(payload, packet) {
		t.Fatalf("header=%#v payload_equal=%t error=%v", header, bytes.Equal(payload, packet), err)
	}
	carrier.received <- sent
	received, err := mux.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer received.Release()
	if received.Peer != peer || !bytes.Equal(received.Packet, packet) {
		t.Fatalf("peer=%s payload_equal=%t", received.Peer, bytes.Equal(received.Packet, packet))
	}
}

func TestRelayMuxRejectsPlaintextMalformedAndStaleFrames(t *testing.T) {
	carrier := newFakeRelayCarrier()
	mux, _ := NewRelayMux(carrier, protocol.CapabilityE2EPacketV1)
	peer := relayNode(4)
	if err := mux.SetBinding(RelayBinding{Peer: peer, Handle: 9, MaxPacketPayload: 1280}); err != nil {
		t.Fatal(err)
	}
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	ipv4[2], ipv4[3] = 0, 20
	plaintext, err := protocol.EncodePacket(nil, protocol.PacketHeader{Version: 1, RouteHandle: 9}, ipv4)
	if err != nil {
		t.Fatal(err)
	}
	carrier.received <- plaintext
	if _, err := mux.Receive(context.Background()); !errors.Is(err, protocol.ErrInvalidPacketFlags) {
		t.Fatalf("plaintext error = %v", err)
	}
	stale, err := protocol.EncodeWireGuardPacket(nil, 10, wireGuardInitiation())
	if err != nil {
		t.Fatal(err)
	}
	carrier.received <- stale
	if _, err := mux.Receive(context.Background()); !errors.Is(err, ErrRelayBinding) {
		t.Fatalf("stale handle error = %v", err)
	}
	oversized := make([]byte, 592)
	oversized[0] = 4
	oversizedFrame, err := protocol.EncodeWireGuardPacket(nil, 9, oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SetBinding(RelayBinding{Peer: peer, Handle: 9, MaxPacketPayload: 576}); err != nil {
		t.Fatal(err)
	}
	carrier.received <- oversizedFrame
	if _, err := mux.Receive(context.Background()); !errors.Is(err, protocol.ErrPacketTooLarge) {
		t.Fatalf("oversized receive error = %v", err)
	}
	if err := mux.Send(context.Background(), peer, []byte{1, 0, 0, 0}); !errors.Is(err, protocol.ErrInvalidWireGuard) {
		t.Fatalf("malformed send error = %v", err)
	}
	if released, ok := mux.ReleaseHandle(9); !ok || released != peer {
		t.Fatalf("released=%s ok=%t", released, ok)
	}
	if err := mux.Send(context.Background(), peer, wireGuardInitiation()); !errors.Is(err, ErrRelayBinding) {
		t.Fatalf("released peer error = %v", err)
	}
}
