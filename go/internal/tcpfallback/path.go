package tcpfallback

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/protocol"
)

var (
	ErrRouteNotBound        = errors.New("tcp fallback: peer route is not bound")
	ErrDuplicateRouteHandle = errors.New("tcp fallback: duplicate receive route handle")
)

type routeBindings struct {
	send    map[identity.NodeID]uint32
	receive map[uint32]identity.NodeID
}

// PacketPath adapts a Session to pathmanager.PacketPath. Route handles are
// session-local and can be atomically replaced after a controller/relay update.
type PacketPath struct {
	name    string
	session *Session
	mu      sync.RWMutex
	routes  routeBindings
	frames  *packetbuffer.Pool
}

var _ pathmanager.PacketPath = (*PacketPath)(nil)

func NewPacketPath(name string, session *Session) (*PacketPath, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: nil session", ErrInvalidConfiguration)
	}
	if name == "" {
		name = "tcp-fallback"
	}
	return &PacketPath{
		name: name, session: session,
		routes: routeBindings{send: make(map[identity.NodeID]uint32), receive: make(map[uint32]identity.NodeID)},
		frames: packetbuffer.NewPool(session.config.maxPacket),
	}, nil
}

func (p *PacketPath) Name() string { return p.name }

// ReplaceBindings validates then atomically publishes the complete route map.
// sendHandle is used for packets sent to Peer; receiveHandle identifies packets
// received from Peer after relay-side handle rewriting.
func (p *PacketPath) ReplaceBindings(bindings []Binding) error {
	next := routeBindings{send: make(map[identity.NodeID]uint32, len(bindings)), receive: make(map[uint32]identity.NodeID, len(bindings))}
	for _, binding := range bindings {
		if binding.Peer.IsZero() || binding.SendHandle == 0 || binding.ReceiveHandle == 0 {
			return fmt.Errorf("%w: zero peer or handle", ErrRouteNotBound)
		}
		if _, exists := next.send[binding.Peer]; exists {
			return fmt.Errorf("%w: duplicate peer %s", ErrRouteNotBound, binding.Peer)
		}
		if _, exists := next.receive[binding.ReceiveHandle]; exists {
			return fmt.Errorf("%w: %d", ErrDuplicateRouteHandle, binding.ReceiveHandle)
		}
		next.send[binding.Peer] = binding.SendHandle
		next.receive[binding.ReceiveHandle] = binding.Peer
	}
	p.mu.Lock()
	p.routes = next
	p.mu.Unlock()
	return nil
}

type Binding struct {
	Peer          identity.NodeID
	SendHandle    uint32
	ReceiveHandle uint32
}

func (p *PacketPath) MaxPayload(peer pathmanager.PeerID) int {
	p.mu.RLock()
	_, exists := p.routes.send[peer]
	p.mu.RUnlock()
	if !exists {
		return 0
	}
	return p.session.config.maxPacket - protocol.PacketHeaderSize
}

func (p *PacketPath) Send(ctx context.Context, peer pathmanager.PeerID, packet pathmanager.PacketBuffer) error {
	p.mu.RLock()
	handle, exists := p.routes.send[peer]
	p.mu.RUnlock()
	if !exists {
		return fmt.Errorf("%w: %s", ErrRouteNotBound, peer)
	}
	if len(packet) > p.session.config.maxPacket-protocol.PacketHeaderSize {
		return ErrFrameTooLarge
	}
	buffer, frame, err := p.encodePacket(handle, packet)
	if err != nil {
		return fmt.Errorf("tcp fallback: encode packet: %w", err)
	}
	defer buffer.Release()
	return p.session.WritePacket(ctx, frame)
}

func (p *PacketPath) encodePacket(handle uint32, packet pathmanager.PacketBuffer) (*packetbuffer.Buffer, []byte, error) {
	buffer := p.frames.Acquire(protocol.PacketHeaderSize + len(packet))
	frame, err := protocol.EncodePacket(buffer.Bytes()[:0], protocol.PacketHeader{Version: protocol.PacketVersion1, RouteHandle: handle}, packet)
	if err != nil {
		buffer.Release()
		return nil, nil, err
	}
	return buffer, frame, nil
}

func (p *PacketPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	buffer, err := p.session.ReadPacketBuffer(ctx)
	if err != nil {
		return pathmanager.ReceivedPacket{}, err
	}
	frame := buffer.Bytes()
	header, packet, err := protocol.DecodePacket(frame)
	if err != nil {
		buffer.Release()
		return pathmanager.ReceivedPacket{}, fmt.Errorf("tcp fallback: decode packet: %w", err)
	}
	p.mu.RLock()
	peer, exists := p.routes.receive[header.RouteHandle]
	p.mu.RUnlock()
	if !exists {
		buffer.Release()
		return pathmanager.ReceivedPacket{}, fmt.Errorf("%w: receive handle %d", ErrRouteNotBound, header.RouteHandle)
	}
	return pathmanager.ReceivedPacket{Peer: peer, Packet: packet, Buffer: buffer}, nil
}

func (p *PacketPath) Health(peer pathmanager.PeerID) pathmanager.PathHealth {
	p.mu.RLock()
	_, exists := p.routes.send[peer]
	p.mu.RUnlock()
	if !exists {
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: ErrRouteNotBound.Error()}
	}
	select {
	case <-p.session.Done():
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: p.session.sessionError().Error()}
	default:
		return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
	}
}

func (p *PacketPath) Close() error { return p.session.Close() }
