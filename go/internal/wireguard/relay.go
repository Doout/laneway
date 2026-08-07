package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
	"laneway.dev/laneway/internal/protocol"
)

var (
	ErrRelayCapability       = errors.New("wireguard: encrypted relay capability was not negotiated")
	ErrRelayBinding          = errors.New("wireguard: relay route handle is not bound")
	ErrDuplicateRelayBinding = errors.New("wireguard: duplicate relay route binding")
)

// RelayCarrier is one authenticated QUIC or TCP relay connection. Implementors
// must not retain a packet passed to SendPacket. ReceivePacket transfers
// ownership of the optional buffer to the caller.
type RelayCarrier interface {
	SendPacket(context.Context, []byte) error
	ReceivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error)
	Done() <-chan struct{}
	Close() error
}

// RelayBinding is scoped to one authenticated relay session. Handles are never
// persisted or reused as identity credentials.
type RelayBinding struct {
	Peer             identity.NodeID
	Handle           uint32
	MaxPacketPayload int
}

type relayBindingSnapshot struct {
	byPeer   map[identity.NodeID]RelayBinding
	byHandle map[uint32]identity.NodeID
}

// ReceivedRelayDatagram is one opaque WireGuard message from an exact,
// authenticated peer. Release must be called after Packet is consumed.
type ReceivedRelayDatagram struct {
	Peer   identity.NodeID
	Packet []byte
	owner  *packetbuffer.Buffer
}

func (d *ReceivedRelayDatagram) Release() {
	if d != nil && d.owner != nil {
		d.owner.Release()
		d.owner = nil
	}
}

// RelayMux maps controller-authenticated peers to ephemeral relay handles and
// carries only structurally valid WireGuard ciphertext. It deliberately does
// not parse or authorize decrypted IP; that remains the endpoint's job.
type RelayMux struct {
	carrier  RelayCarrier
	frames   *packetbuffer.Pool
	mu       sync.RWMutex
	bindings relayBindingSnapshot
}

func NewRelayMux(carrier RelayCarrier, negotiated protocol.Capability) (*RelayMux, error) {
	if carrier == nil {
		return nil, fmt.Errorf("%w: missing carrier", ErrRelayBinding)
	}
	if !negotiated.Has(protocol.CapabilityE2EPacketV1) {
		return nil, ErrRelayCapability
	}
	return &RelayMux{
		carrier: carrier,
		frames:  packetbuffer.NewPool(protocol.PacketHeaderSize + protocol.MaxPacketPayload),
		bindings: relayBindingSnapshot{
			byPeer: make(map[identity.NodeID]RelayBinding), byHandle: make(map[uint32]identity.NodeID),
		},
	}, nil
}

func validateRelayBinding(binding RelayBinding) error {
	if binding.Peer.IsZero() || binding.Handle == 0 || binding.MaxPacketPayload < 576 || binding.MaxPacketPayload > protocol.MaxPacketPayload {
		return ErrRelayBinding
	}
	return nil
}

func (m *RelayMux) ReplaceBindings(bindings []RelayBinding) error {
	next := relayBindingSnapshot{byPeer: make(map[identity.NodeID]RelayBinding, len(bindings)), byHandle: make(map[uint32]identity.NodeID, len(bindings))}
	for _, binding := range bindings {
		if err := validateRelayBinding(binding); err != nil {
			return err
		}
		if _, duplicate := next.byPeer[binding.Peer]; duplicate {
			return fmt.Errorf("%w: peer %s", ErrDuplicateRelayBinding, binding.Peer)
		}
		if _, duplicate := next.byHandle[binding.Handle]; duplicate {
			return fmt.Errorf("%w: handle %d", ErrDuplicateRelayBinding, binding.Handle)
		}
		next.byPeer[binding.Peer] = binding
		next.byHandle[binding.Handle] = binding.Peer
	}
	m.mu.Lock()
	m.bindings = next
	m.mu.Unlock()
	return nil
}

func (m *RelayMux) SetBinding(binding RelayBinding) error {
	if err := validateRelayBinding(binding); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if peer, duplicate := m.bindings.byHandle[binding.Handle]; duplicate && peer != binding.Peer {
		return fmt.Errorf("%w: handle %d", ErrDuplicateRelayBinding, binding.Handle)
	}
	if previous, exists := m.bindings.byPeer[binding.Peer]; exists && previous.Handle != binding.Handle {
		delete(m.bindings.byHandle, previous.Handle)
	}
	m.bindings.byPeer[binding.Peer] = binding
	m.bindings.byHandle[binding.Handle] = binding.Peer
	return nil
}

func (m *RelayMux) ReleaseHandle(handle uint32) (identity.NodeID, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	peer, exists := m.bindings.byHandle[handle]
	if !exists {
		return identity.NodeID{}, false
	}
	delete(m.bindings.byHandle, handle)
	delete(m.bindings.byPeer, peer)
	return peer, true
}

func (m *RelayMux) Peers() []identity.NodeID {
	m.mu.RLock()
	peers := make([]identity.NodeID, 0, len(m.bindings.byPeer))
	for peer := range m.bindings.byPeer {
		peers = append(peers, peer)
	}
	m.mu.RUnlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].String() < peers[j].String() })
	return peers
}

func (m *RelayMux) Send(ctx context.Context, peer identity.NodeID, packet []byte) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrRelayBinding)
	}
	m.mu.RLock()
	binding, exists := m.bindings.byPeer[peer]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("%w: peer %s", ErrRelayBinding, peer)
	}
	if len(packet) > binding.MaxPacketPayload {
		return protocol.ErrPacketTooLarge
	}
	buffer := m.frames.Acquire(protocol.PacketHeaderSize + len(packet))
	defer buffer.Release()
	frame, err := protocol.EncodeWireGuardPacket(buffer.Bytes()[:0], binding.Handle, packet)
	if err != nil {
		return err
	}
	return m.carrier.SendPacket(ctx, frame)
}

func (m *RelayMux) Receive(ctx context.Context) (ReceivedRelayDatagram, error) {
	if ctx == nil {
		return ReceivedRelayDatagram{}, fmt.Errorf("%w: missing context", ErrRelayBinding)
	}
	frame, owner, err := m.carrier.ReceivePacket(ctx)
	if err != nil {
		return ReceivedRelayDatagram{}, err
	}
	release := func() {
		if owner != nil {
			owner.Release()
		}
	}
	header, packet, err := protocol.DecodeFrame(frame)
	if err != nil {
		release()
		return ReceivedRelayDatagram{}, err
	}
	if header.Flags != protocol.PacketFlagE2EEncrypted {
		release()
		return ReceivedRelayDatagram{}, protocol.ErrInvalidPacketFlags
	}
	m.mu.RLock()
	peer, exists := m.bindings.byHandle[header.RouteHandle]
	binding := m.bindings.byPeer[peer]
	m.mu.RUnlock()
	if !exists {
		release()
		return ReceivedRelayDatagram{}, fmt.Errorf("%w: handle %d", ErrRelayBinding, header.RouteHandle)
	}
	if len(packet) > binding.MaxPacketPayload {
		release()
		return ReceivedRelayDatagram{}, protocol.ErrPacketTooLarge
	}
	return ReceivedRelayDatagram{Peer: peer, Packet: packet, owner: owner}, nil
}

func (m *RelayMux) Done() <-chan struct{} { return m.carrier.Done() }
func (m *RelayMux) Close() error          { return m.carrier.Close() }
