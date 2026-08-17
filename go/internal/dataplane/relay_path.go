package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/transport"
)

var (
	ErrRelayBinding          = errors.New("dataplane: relay route handle is not bound")
	ErrDuplicateRelayBinding = errors.New("dataplane: duplicate relay route binding")
)

type RelayCarrier interface {
	// SendPacket must not retain packet after it returns. ReceivePacket returns
	// a caller-owned buffer that remains valid after the next receive.
	SendPacket(context.Context, []byte) error
	ReceivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error)
	Done() <-chan struct{}
	Close() error
}

type RelayBinding struct {
	Peer             identity.NodeID
	Handle           uint32
	MaxPacketPayload int
}

type relayBindings struct {
	byPeer   map[identity.NodeID]RelayBinding
	byHandle map[uint32]identity.NodeID
}

// RelayPath adapts one authenticated relay connection to PacketPath. The same
// object is attached to every peer bound on that relay session.
type RelayPath struct {
	name     string
	carrier  RelayCarrier
	mu       sync.RWMutex
	bindings relayBindings
	frames   *packetbuffer.Pool
}

func NewRelayPath(name string, carrier RelayCarrier) (*RelayPath, error) {
	if carrier == nil {
		return nil, ErrInvalidConfiguration
	}
	if name == "" {
		name = "relay-quic"
	}
	return &RelayPath{
		name: name, carrier: carrier,
		bindings: relayBindings{byPeer: make(map[identity.NodeID]RelayBinding), byHandle: make(map[uint32]identity.NodeID)},
		frames:   packetbuffer.NewPool(protocol.PacketHeaderSize + protocol.MaxPacketPayload),
	}, nil
}

func (p *RelayPath) Name() string { return p.name }

// ReplaceBindings validates then publishes a whole session-local handle table.
func (p *RelayPath) ReplaceBindings(bindings []RelayBinding) error {
	next := relayBindings{byPeer: make(map[identity.NodeID]RelayBinding, len(bindings)), byHandle: make(map[uint32]identity.NodeID, len(bindings))}
	for _, binding := range bindings {
		if binding.Peer.IsZero() || binding.Handle == 0 || binding.MaxPacketPayload < 576 || binding.MaxPacketPayload > protocol.MaxPacketPayload {
			return ErrRelayBinding
		}
		if _, exists := next.byPeer[binding.Peer]; exists {
			return fmt.Errorf("%w: peer %s", ErrDuplicateRelayBinding, binding.Peer)
		}
		if _, exists := next.byHandle[binding.Handle]; exists {
			return fmt.Errorf("%w: handle %d", ErrDuplicateRelayBinding, binding.Handle)
		}
		next.byPeer[binding.Peer] = binding
		next.byHandle[binding.Handle] = binding.Peer
	}
	p.mu.Lock()
	p.bindings = next
	p.mu.Unlock()
	return nil
}

func (p *RelayPath) SetBinding(binding RelayBinding) error {
	if binding.Peer.IsZero() || binding.Handle == 0 || binding.MaxPacketPayload < 576 || binding.MaxPacketPayload > protocol.MaxPacketPayload {
		return ErrRelayBinding
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.bindings.byHandle[binding.Handle]; ok && existing != binding.Peer {
		return ErrDuplicateRelayBinding
	}
	if existing, ok := p.bindings.byPeer[binding.Peer]; ok && existing.Handle != binding.Handle {
		delete(p.bindings.byHandle, existing.Handle)
	}
	p.bindings.byPeer[binding.Peer] = binding
	p.bindings.byHandle[binding.Handle] = binding.Peer
	return nil
}

func (p *RelayPath) ReleaseHandle(handle uint32) (identity.NodeID, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	peer, ok := p.bindings.byHandle[handle]
	if !ok {
		return identity.NodeID{}, false
	}
	delete(p.bindings.byHandle, handle)
	delete(p.bindings.byPeer, peer)
	return peer, true
}

func (p *RelayPath) Peers() []identity.NodeID {
	p.mu.RLock()
	defer p.mu.RUnlock()
	peers := make([]identity.NodeID, 0, len(p.bindings.byPeer))
	for peer := range p.bindings.byPeer {
		peers = append(peers, peer)
	}
	return peers
}

func (p *RelayPath) MaxPayload(peer pathmanager.PeerID) int {
	p.mu.RLock()
	binding, ok := p.bindings.byPeer[peer]
	p.mu.RUnlock()
	if !ok {
		return 0
	}
	return binding.MaxPacketPayload
}

func (p *RelayPath) Send(ctx context.Context, peer pathmanager.PeerID, packet pathmanager.PacketBuffer) error {
	p.mu.RLock()
	binding, ok := p.bindings.byPeer[peer]
	p.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: peer %s", ErrRelayBinding, peer)
	}
	if len(packet) > binding.MaxPacketPayload {
		return protocol.ErrPacketTooLarge
	}
	buffer := p.frames.Acquire(protocol.PacketHeaderSize + len(packet))
	defer buffer.Release()
	frame, err := protocol.EncodePacket(buffer.Bytes()[:0], protocol.PacketHeader{Version: protocol.PacketVersion1, RouteHandle: binding.Handle}, packet)
	if err != nil {
		return fmt.Errorf("dataplane: encode relay packet: %w", err)
	}
	return p.carrier.SendPacket(ctx, frame)
}

func (p *RelayPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	frame, owner, err := p.carrier.ReceivePacket(ctx)
	if err != nil {
		return pathmanager.ReceivedPacket{}, err
	}
	header, packet, err := protocol.DecodePacket(frame)
	if err != nil {
		owner.Release()
		return pathmanager.ReceivedPacket{}, fmt.Errorf("dataplane: decode relay packet: %w", err)
	}
	p.mu.RLock()
	peer, ok := p.bindings.byHandle[header.RouteHandle]
	p.mu.RUnlock()
	if !ok {
		owner.Release()
		return pathmanager.ReceivedPacket{}, fmt.Errorf("%w: handle %d", ErrRelayBinding, header.RouteHandle)
	}
	// RelayCarrier returns a caller-owned frame. DecodePacket's payload view
	// therefore remains valid for the complete PacketPath receive handoff.
	return pathmanager.ReceivedPacket{Peer: peer, Packet: packet, Buffer: owner}, nil
}

func (p *RelayPath) Health(peer pathmanager.PeerID) pathmanager.PathHealth {
	p.mu.RLock()
	_, bound := p.bindings.byPeer[peer]
	p.mu.RUnlock()
	if !bound {
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: ErrRelayBinding.Error()}
	}
	select {
	case <-p.carrier.Done():
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: "relay connection closed"}
	default:
		return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
	}
}

func (p *RelayPath) Close() error { return p.carrier.Close() }

type QUICCarrier struct{ Conn *transport.Conn }

func (c QUICCarrier) SendPacket(_ context.Context, packet []byte) error {
	return c.Conn.SendDatagram(packet)
}
func (c QUICCarrier) ReceivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	packet, err := c.Conn.ReceiveDatagram(ctx)
	return packet, nil, err
}
func (c QUICCarrier) Done() <-chan struct{} { return c.Conn.Context().Done() }
func (c QUICCarrier) Close() error          { return c.Conn.Close() }

var _ pathmanager.PacketPath = (*RelayPath)(nil)
var _ RelayCarrier = QUICCarrier{}
