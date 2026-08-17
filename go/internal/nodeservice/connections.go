package nodeservice

import (
	"context"
	"crypto/tls"
	"io"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
)

type nodeConnection interface {
	peerIdentity() identity.AuthenticatedIdentity
	controlStream() io.ReadWriter
	sendPacket(context.Context, []byte) error
	receivePacket(context.Context) ([]byte, *packetbuffer.Buffer, error)
	done() <-chan struct{}
	close() error
}

type RelayDialer interface {
	DialRelay(context.Context, string, *tls.Config, *transport.Config) (*transport.Conn, error)
}

type nodeRelayCarrier struct{ conn nodeConnection }

func (c nodeRelayCarrier) SendPacket(ctx context.Context, packet []byte) error {
	return c.conn.sendPacket(ctx, packet)
}
func (c nodeRelayCarrier) ReceivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	return c.conn.receivePacket(ctx)
}
func (c nodeRelayCarrier) Done() <-chan struct{} { return c.conn.done() }
func (c nodeRelayCarrier) Close() error          { return c.conn.close() }

type quicNodeConnection struct{ conn *transport.Conn }

func (c quicNodeConnection) peerIdentity() identity.AuthenticatedIdentity {
	return c.conn.PeerIdentity()
}
func (c quicNodeConnection) controlStream() io.ReadWriter { return c.conn.ControlStream() }
func (c quicNodeConnection) sendPacket(_ context.Context, packet []byte) error {
	return c.conn.SendDatagram(packet)
}
func (c quicNodeConnection) receivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	packet, err := c.conn.ReceiveDatagram(ctx)
	return packet, nil, err
}
func (c quicNodeConnection) done() <-chan struct{} { return c.conn.Context().Done() }
func (c quicNodeConnection) close() error          { return c.conn.Close() }

type tcpNodeConnection struct{ conn *tcpfallback.Session }

func (c tcpNodeConnection) peerIdentity() identity.AuthenticatedIdentity {
	return c.conn.PeerIdentity()
}
func (c tcpNodeConnection) controlStream() io.ReadWriter { return c.conn.ControlStream() }
func (c tcpNodeConnection) sendPacket(ctx context.Context, packet []byte) error {
	return c.conn.WritePacket(ctx, packet)
}
func (c tcpNodeConnection) receivePacket(ctx context.Context) ([]byte, *packetbuffer.Buffer, error) {
	buffer, err := c.conn.ReadPacketBuffer(ctx)
	if err != nil {
		return nil, nil, err
	}
	return buffer.Bytes(), buffer, nil
}
func (c tcpNodeConnection) done() <-chan struct{} { return c.conn.Done() }
func (c tcpNodeConnection) close() error          { return c.conn.Close() }
