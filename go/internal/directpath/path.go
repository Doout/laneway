package directpath

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/protocol"
)

// Path adapts an authenticated QUIC peer connection to pathmanager.PacketPath.
// Direct datagrams carry one raw IP packet: peer identity is connection-bound,
// so relay-local route handles have no meaning on this carrier.
type Path struct {
	conn           *quic.Conn
	peer           pathmanager.PeerID
	maxPayload     int
	payloadMode    PayloadMode
	name           string
	initialLatency time.Duration
	remote         netip.AddrPort
	closeOnce      sync.Once
	closeErr       error
	onClose        func() error
}

func newAuthenticatedPath(conn *quic.Conn, peer pathmanager.PeerID, maxPayload int, mode PayloadMode, remote netip.AddrPort, latency time.Duration) *Path {
	return &Path{conn: conn, peer: peer, maxPayload: maxPayload, payloadMode: mode,
		name: "direct-quic/" + peer.String() + "/" + remote.String(), initialLatency: latency, remote: remote}
}

func (p *Path) Name() string { return p.name }

func (p *Path) PeerIdentity() pathmanager.PeerID {
	if p == nil {
		return pathmanager.PeerID{}
	}
	return p.peer
}

func (p *Path) MaxPayload(peer pathmanager.PeerID) int {
	if p == nil || peer != p.peer {
		return 0
	}
	return p.maxPayload
}

func (p *Path) Send(ctx context.Context, peer pathmanager.PeerID, packet pathmanager.PacketBuffer) error {
	if p == nil || peer != p.peer {
		return ErrWrongPeer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(packet) > p.maxPayload {
		return ErrPacketTooLarge
	}
	if err := p.validatePayload(packet); err != nil {
		return fmt.Errorf("directpath: send invalid packet: %w", err)
	}
	if err := p.conn.SendDatagram(packet); err != nil {
		return fmt.Errorf("directpath: send datagram: %w", err)
	}
	return nil
}

func (p *Path) Receive(ctx context.Context) (pathmanager.ReceivedPacket, error) {
	if p == nil {
		return pathmanager.ReceivedPacket{}, net.ErrClosed
	}
	packet, err := p.conn.ReceiveDatagram(ctx)
	if err != nil {
		return pathmanager.ReceivedPacket{}, err
	}
	if len(packet) > p.maxPayload {
		return pathmanager.ReceivedPacket{}, ErrPacketTooLarge
	}
	if err := p.validatePayload(packet); err != nil {
		return pathmanager.ReceivedPacket{}, fmt.Errorf("directpath: receive invalid packet: %w", err)
	}
	// quic-go transfers ownership of the received datagram slice to the caller;
	// no defensive hot-path copy is needed before the synchronous dataplane
	// handoff.
	return pathmanager.ReceivedPacket{Peer: p.peer, Packet: packet}, nil
}

func (p *Path) validatePayload(packet []byte) error {
	if p.payloadMode == PayloadWireGuard {
		return protocol.ValidateWireGuardPayload(packet)
	}
	return protocol.ValidateIPPayload(packet)
}

func (p *Path) Health(peer pathmanager.PeerID) pathmanager.PathHealth {
	if p == nil || peer != p.peer {
		return pathmanager.PathHealth{State: pathmanager.HealthUnknown}
	}
	select {
	case <-p.conn.Context().Done():
		return pathmanager.PathHealth{State: pathmanager.HealthFailed, FailureReason: p.conn.Context().Err().Error()}
	default:
		return pathmanager.PathHealth{State: pathmanager.HealthHealthy, Latency: p.initialLatency}
	}
}

func (p *Path) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		p.closeErr = p.conn.CloseWithError(peerCloseCode, "shutdown")
		if p.onClose != nil {
			p.closeErr = errors.Join(p.closeErr, p.onClose())
		}
	})
	return p.closeErr
}

var _ pathmanager.PacketPath = (*Path)(nil)
