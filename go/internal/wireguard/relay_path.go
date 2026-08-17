package wireguard

import (
	"context"
	"errors"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pathmanager"
)

var ErrInvalidRelayPath = errors.New("wireguard: invalid relay path")

// RelayPath adapts one authenticated QUIC or TCP relay session to the opaque
// carrier selector. Route-handle bindings remain owned by RelayMux.
type RelayPath struct {
	name string
	mux  *RelayMux
}

func NewRelayPath(name string, mux *RelayMux) (*RelayPath, error) {
	if name == "" || mux == nil {
		return nil, ErrInvalidRelayPath
	}
	return &RelayPath{name: name, mux: mux}, nil
}

func (p *RelayPath) Name() string { return p.name }

func (p *RelayPath) MaxPayload(peer identity.NodeID) int {
	if p == nil || p.mux == nil {
		return 0
	}
	return p.mux.MaxPayload(peer)
}

func (p *RelayPath) Send(ctx context.Context, peer identity.NodeID, packet pathmanager.PacketBuffer) error {
	if p == nil || p.mux == nil {
		return ErrInvalidRelayPath
	}
	return p.mux.Send(ctx, peer, packet)
}

func (p *RelayPath) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	if p == nil || p.mux == nil {
		return pathmanager.ReceivedPacket{}, ErrInvalidRelayPath
	}
	datagram, err := p.mux.Receive(ctx)
	if err != nil {
		return pathmanager.ReceivedPacket{}, err
	}
	received := pathmanager.ReceivedPacket{Peer: datagram.Peer, Packet: datagram.Packet, Buffer: datagram.owner}
	datagram.owner = nil
	return received, nil
}

func (p *RelayPath) Health(peer identity.NodeID) pathmanager.PathHealth {
	if p == nil || p.mux == nil || p.mux.MaxPayload(peer) == 0 {
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: ErrRelayBinding.Error()}
	}
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}

func (p *RelayPath) Close() error {
	if p == nil || p.mux == nil {
		return nil
	}
	return p.mux.Close()
}

var _ pathmanager.PacketPath = (*RelayPath)(nil)
