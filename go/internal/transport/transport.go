package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"laneway.dev/laneway/internal/identity"
)

const (
	defaultHandshakeIdleTimeout = 10 * time.Second
	defaultMaxIdleTimeout       = 45 * time.Second
	defaultKeepAlivePeriod      = 15 * time.Second

	protocolErrorCode quic.ApplicationErrorCode = 0x100
	shutdownErrorCode quic.ApplicationErrorCode = 0
	controlPreface                              = "LWC1"
)

var (
	ErrDatagramsNotNegotiated = errors.New("transport: QUIC datagrams not negotiated")
	ErrInvalidConfiguration   = errors.New("transport: invalid configuration")
	ErrProtocolNegotiation    = errors.New("transport: invalid protocol negotiation")
)

// Config controls connection liveness. A nil Config or zero-valued fields use
// conservative defaults. Stream and datagram limits are fixed by the Laneway
// protocol and are not caller-configurable.
type Config struct {
	HandshakeIdleTimeout time.Duration
	MaxIdleTimeout       time.Duration
	KeepAlivePeriod      time.Duration
}

func (c *Config) quicConfig() (*quic.Config, error) {
	handshakeTimeout := defaultHandshakeIdleTimeout
	idleTimeout := defaultMaxIdleTimeout
	keepAlive := defaultKeepAlivePeriod
	if c != nil {
		if c.HandshakeIdleTimeout < 0 || c.MaxIdleTimeout < 0 || c.KeepAlivePeriod < 0 {
			return nil, fmt.Errorf("%w: timeouts must not be negative", ErrInvalidConfiguration)
		}
		if c.HandshakeIdleTimeout != 0 {
			handshakeTimeout = c.HandshakeIdleTimeout
		}
		if c.MaxIdleTimeout != 0 {
			idleTimeout = c.MaxIdleTimeout
		}
		if c.KeepAlivePeriod != 0 {
			keepAlive = c.KeepAlivePeriod
		}
	}
	if keepAlive >= idleTimeout {
		return nil, fmt.Errorf("%w: keepalive period must be shorter than idle timeout", ErrInvalidConfiguration)
	}
	return &quic.Config{
		HandshakeIdleTimeout:  handshakeTimeout,
		MaxIdleTimeout:        idleTimeout,
		KeepAlivePeriod:       keepAlive,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}, nil
}

// Conn is an authenticated Laneway connection. Each connection owns exactly
// one reliable bidirectional control stream and also supports QUIC datagrams.
type Conn struct {
	conn       *quic.Conn
	control    *quic.Stream
	peer       identity.AuthenticatedIdentity
	closeOnce  sync.Once
	closeError error
}

// PeerIdentity returns the identity authenticated from the peer certificate.
func (c *Conn) PeerIdentity() identity.AuthenticatedIdentity { return c.peer }

// PeerNodeIdentity returns the legacy node identity for node-role peers. It is
// false for relay and controller peers.
func (c *Conn) PeerNodeIdentity() (identity.NodeIdentity, bool) { return c.peer.NodeIdentity() }

func (c *Conn) PeerCertificateSerial() []byte {
	if c == nil || c.conn == nil {
		return nil
	}
	certificates := c.conn.ConnectionState().TLS.PeerCertificates
	if len(certificates) == 0 || certificates[0].SerialNumber == nil {
		return nil
	}
	return append([]byte(nil), certificates[0].SerialNumber.Bytes()...)
}

// ControlStream returns the connection's sole reliable control stream.
func (c *Conn) ControlStream() *quic.Stream { return c.control }

func (c *Conn) SendDatagram(payload []byte) error { return c.conn.SendDatagram(payload) }

func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *Conn) Context() context.Context { return c.conn.Context() }
func (c *Conn) LocalAddr() net.Addr      { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

// Close gracefully closes the control stream and then the QUIC connection. It
// is safe to call concurrently and more than once.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		streamErr := c.control.Close()
		connErr := c.conn.CloseWithError(shutdownErrorCode, "shutdown")
		c.closeError = errors.Join(streamErr, connErr)
	})
	return c.closeError
}

// Listener accepts authenticated Laneway connections.
type Listener struct {
	listener *quic.Listener
}

// Listen starts a QUIC listener. The supplied TLS config is cloned before use.
func Listen(addr string, tlsConfig *tls.Config, config *Config) (*Listener, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("%w: nil TLS config", ErrInvalidConfiguration)
	}
	quicConfig, err := config.quicConfig()
	if err != nil {
		return nil, err
	}
	tlsConfig = strictTLSConfig(tlsConfig)
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	if tlsConfig.ClientCAs == nil {
		return nil, fmt.Errorf("%w: server TLS config has no client CA pool", ErrInvalidConfiguration)
	}
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("transport: listen: %w", err)
	}
	return &Listener{listener: listener}, nil
}

func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error   { return l.listener.Close() }

// Accept waits for a completed mTLS handshake and the peer's control stream.
// If ctx is canceled during either operation, any partially accepted
// connection is closed before returning.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	wrapped, err := acceptConn(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(protocolErrorCode, err.Error())
		return nil, err
	}
	return wrapped, nil
}

// Dial establishes an authenticated QUIC connection and opens its control
// stream. Dial never uses QUIC 0-RTT.
func Dial(ctx context.Context, addr string, tlsConfig *tls.Config, config *Config) (*Conn, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("%w: nil TLS config", ErrInvalidConfiguration)
	}
	quicConfig, err := config.quicConfig()
	if err != nil {
		return nil, err
	}
	conn, err := quic.DialAddr(ctx, addr, strictTLSConfig(tlsConfig), quicConfig)
	if err != nil {
		return nil, fmt.Errorf("transport: dial: %w", err)
	}
	wrapped, err := dialConn(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(protocolErrorCode, err.Error())
		return nil, err
	}
	return wrapped, nil
}

// DialOnTransport establishes a relay connection on a caller-owned QUIC
// transport. Direct-path endpoints use this to share one UDP socket between
// their relay connection, rendezvous probes, and peer listener, preserving the
// relay-observed NAT mapping. The caller retains ownership of transport.
func DialOnTransport(ctx context.Context, quicTransport *quic.Transport, address net.Addr, tlsConfig *tls.Config, config *Config) (*Conn, error) {
	if quicTransport == nil || address == nil || tlsConfig == nil {
		return nil, fmt.Errorf("%w: nil shared transport, address, or TLS config", ErrInvalidConfiguration)
	}
	quicConfig, err := config.quicConfig()
	if err != nil {
		return nil, err
	}
	conn, err := quicTransport.Dial(ctx, address, strictTLSConfig(tlsConfig), quicConfig)
	if err != nil {
		return nil, fmt.Errorf("transport: shared dial: %w", err)
	}
	wrapped, err := dialConn(ctx, conn)
	if err != nil {
		_ = conn.CloseWithError(protocolErrorCode, err.Error())
		return nil, err
	}
	return wrapped, nil
}

func dialConn(ctx context.Context, conn *quic.Conn) (*Conn, error) {
	peer, err := validateConnection(conn, identity.IdentityRoleRelay)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport: open control stream: %w", err)
	}
	if err := writePreface(ctx, stream); err != nil {
		return nil, err
	}
	return &Conn{conn: conn, control: stream, peer: peer}, nil
}

func acceptConn(ctx context.Context, conn *quic.Conn) (*Conn, error) {
	peer, err := validateConnection(conn, identity.IdentityRoleNode)
	if err != nil {
		return nil, err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("transport: accept control stream: %w", err)
	}
	if err := readPreface(ctx, stream); err != nil {
		return nil, err
	}
	return &Conn{conn: conn, control: stream, peer: peer}, nil
}

// QUIC doesn't put a newly allocated stream on the wire until it carries data.
// A short transport-level preface makes the control stream immediately
// observable by the accepting peer and is consumed before the stream is
// exposed to callers.
func writePreface(ctx context.Context, stream *quic.Stream) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("transport: set control stream deadline: %w", err)
		}
		defer stream.SetWriteDeadline(time.Time{}) //nolint:errcheck
	}
	if _, err := io.WriteString(stream, controlPreface); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("transport: initialize control stream: %w", ctx.Err())
		}
		return fmt.Errorf("transport: initialize control stream: %w", err)
	}
	return nil
}

func readPreface(ctx context.Context, stream *quic.Stream) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("transport: set control stream deadline: %w", err)
		}
		defer stream.SetReadDeadline(time.Time{}) //nolint:errcheck
	}
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			_ = stream.SetReadDeadline(time.Now())
		case <-stop:
		}
	}()
	defer func() {
		close(stop)
		<-finished
	}()

	var preface [len(controlPreface)]byte
	if _, err := io.ReadFull(stream, preface[:]); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("transport: read control stream preface: %w", ctx.Err())
		}
		return fmt.Errorf("transport: read control stream preface: %w", err)
	}
	if string(preface[:]) != controlPreface {
		return fmt.Errorf("%w: invalid control stream preface", ErrProtocolNegotiation)
	}
	return nil
}

func validateConnection(conn *quic.Conn, role identity.IdentityRole) (identity.AuthenticatedIdentity, error) {
	state := conn.ConnectionState()
	if state.Used0RTT {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("%w: 0-RTT is forbidden", ErrProtocolNegotiation)
	}
	if state.TLS.Version != tls.VersionTLS13 || state.TLS.NegotiatedProtocol != ALPN {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("%w: TLS version or ALPN", ErrProtocolNegotiation)
	}
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return identity.AuthenticatedIdentity{}, ErrDatagramsNotNegotiated
	}
	peer, err := peerIdentityWithRole(state.TLS, role)
	if err != nil {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("transport: peer identity: %w", err)
	}
	return peer, nil
}

func strictTLSConfig(config *tls.Config) *tls.Config {
	clone := config.Clone()
	clone.MinVersion = tls.VersionTLS13
	clone.MaxVersion = tls.VersionTLS13
	clone.NextProtos = []string{ALPN}
	return clone
}
