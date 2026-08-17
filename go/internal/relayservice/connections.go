package relayservice

import (
	"context"
	"io"
	"net"
	"net/netip"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
)

// packetConnection is the carrier-neutral surface used after authentication.
// Both carriers carry identical control protobufs and Laneway packet frames.
type packetConnection interface {
	peerNodeIdentity() (identity.NodeIdentity, bool)
	peerCertificateSerial() []byte
	controlStream() io.ReadWriter
	receivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error)
	// sendPacket is synchronous and must not retain the packet after return.
	sendPacket(context.Context, []byte) error
	done() <-chan struct{}
	observedUDPEndpoint() (netip.AddrPort, bool)
	close() error
}

type quicConnection struct{ conn *transport.Conn }

func (c quicConnection) peerNodeIdentity() (identity.NodeIdentity, bool) {
	return c.conn.PeerNodeIdentity()
}
func (c quicConnection) peerCertificateSerial() []byte { return c.conn.PeerCertificateSerial() }
func (c quicConnection) controlStream() io.ReadWriter  { return c.conn.ControlStream() }
func (c quicConnection) receivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	packet, err := c.conn.ReceiveDatagram(ctx)
	return packet, nil, err
}
func (c quicConnection) sendPacket(_ context.Context, packet []byte) error {
	return c.conn.SendDatagram(packet)
}
func (c quicConnection) done() <-chan struct{} { return c.conn.Context().Done() }
func (c quicConnection) observedUDPEndpoint() (netip.AddrPort, bool) {
	address, ok := c.conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	endpoint := address.AddrPort()
	return endpoint, endpoint.IsValid() && endpoint.Port() != 0
}
func (c quicConnection) close() error { return c.conn.Close() }

type tcpConnection struct{ conn *tcpfallback.Session }

func (c tcpConnection) peerNodeIdentity() (identity.NodeIdentity, bool) {
	return c.conn.PeerNodeIdentity()
}
func (c tcpConnection) peerCertificateSerial() []byte { return c.conn.PeerCertificateSerial() }
func (c tcpConnection) controlStream() io.ReadWriter  { return c.conn.ControlStream() }
func (c tcpConnection) receivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	buffer, err := c.conn.ReadPacketBuffer(ctx)
	if err != nil {
		return nil, nil, err
	}
	return buffer.Bytes(), buffer, nil
}
func (c tcpConnection) sendPacket(ctx context.Context, packet []byte) error {
	return c.conn.WritePacket(ctx, packet)
}
func (c tcpConnection) done() <-chan struct{} { return c.conn.Done() }
func (c tcpConnection) observedUDPEndpoint() (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}
func (c tcpConnection) close() error { return c.conn.Close() }

type connectionAcceptor interface {
	accept(context.Context) (packetConnection, error)
}

type quicAcceptor struct{ listener *transport.Listener }

func (a quicAcceptor) accept(ctx context.Context) (packetConnection, error) {
	conn, err := a.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return quicConnection{conn}, nil
}

type tcpAcceptor struct{ listener *tcpfallback.Listener }

func (a tcpAcceptor) accept(ctx context.Context) (packetConnection, error) {
	conn, err := a.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return tcpConnection{conn}, nil
}
