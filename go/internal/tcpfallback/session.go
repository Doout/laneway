// Package tcpfallback provides Laneway's authenticated packet fallback over
// TLS 1.3/TCP. It is deliberately separate from the QUIC transport: TCP is a
// last-resort path and its ordered stream must not stall the preferred paths.
package tcpfallback

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
	"laneway.dev/laneway/internal/protocol"
)

const (
	// ALPN is distinct from the QUIC transport so the two protocols can never
	// accidentally be served on the same TLS endpoint.
	ALPN = "laneway-fallback/1"

	DefaultMaxControlPayload = 1 << 20
	DefaultQueueDepth        = 128
	DefaultHandshakeTimeout  = 10 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 45 * time.Second
	DefaultKeepAlivePeriod   = 15 * time.Second

	maxControlPayloadLimit = 16 << 20
	maxQueueDepthLimit     = 4096
	maxPacketFramePayload  = protocol.PacketHeaderSize + protocol.MaxPacketPayload
	frameHeaderSize        = 5 // uint32 payload length including the type, then uint8 type
)

var (
	ErrInvalidConfiguration = errors.New("tcp fallback: invalid configuration")
	ErrProtocol             = errors.New("tcp fallback: protocol error")
	ErrFrameTooLarge        = errors.New("tcp fallback: frame too large")
	ErrBackpressure         = errors.New("tcp fallback: receive queue full")
	ErrClosed               = errors.New("tcp fallback: session closed")
)

type frameType byte

const (
	frameControl frameType = 1
	framePacket  frameType = 2
	framePing    frameType = 3
	framePong    frameType = 4
)

// Config bounds all network and memory resources owned by a Session. Zero
// values select conservative defaults. MaxPacketPayload includes Laneway's
// five-byte packet header, not the outer TCP framing header.
type Config struct {
	HandshakeTimeout  time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	KeepAlivePeriod   time.Duration
	MaxControlPayload int
	MaxPacketPayload  int
	QueueDepth        int
}

type sessionConfig struct {
	handshakeTimeout time.Duration
	writeTimeout     time.Duration
	idleTimeout      time.Duration
	keepAlivePeriod  time.Duration
	maxControl       int
	maxPacket        int
	queueDepth       int
}

func normalizeConfig(config *Config) (sessionConfig, error) {
	result := sessionConfig{
		handshakeTimeout: DefaultHandshakeTimeout,
		writeTimeout:     DefaultWriteTimeout,
		idleTimeout:      DefaultIdleTimeout,
		keepAlivePeriod:  DefaultKeepAlivePeriod,
		maxControl:       DefaultMaxControlPayload,
		maxPacket:        maxPacketFramePayload,
		queueDepth:       DefaultQueueDepth,
	}
	if config != nil {
		if config.HandshakeTimeout < 0 || config.WriteTimeout < 0 || config.IdleTimeout < 0 || config.KeepAlivePeriod < 0 ||
			config.MaxControlPayload < 0 || config.MaxPacketPayload < 0 || config.QueueDepth < 0 {
			return sessionConfig{}, fmt.Errorf("%w: values must not be negative", ErrInvalidConfiguration)
		}
		if config.HandshakeTimeout != 0 {
			result.handshakeTimeout = config.HandshakeTimeout
		}
		if config.WriteTimeout != 0 {
			result.writeTimeout = config.WriteTimeout
		}
		if config.IdleTimeout != 0 {
			result.idleTimeout = config.IdleTimeout
		}
		if config.KeepAlivePeriod != 0 {
			result.keepAlivePeriod = config.KeepAlivePeriod
		}
		if config.MaxControlPayload != 0 {
			result.maxControl = config.MaxControlPayload
		}
		if config.MaxPacketPayload != 0 {
			result.maxPacket = config.MaxPacketPayload
		}
		if config.QueueDepth != 0 {
			result.queueDepth = config.QueueDepth
		}
	}
	if result.keepAlivePeriod >= result.idleTimeout {
		return sessionConfig{}, fmt.Errorf("%w: keepalive must be shorter than idle timeout", ErrInvalidConfiguration)
	}
	if result.maxControl < 1 || result.maxControl > maxControlPayloadLimit {
		return sessionConfig{}, fmt.Errorf("%w: control payload limit %d is outside [1,%d]", ErrInvalidConfiguration, result.maxControl, maxControlPayloadLimit)
	}
	if result.maxPacket < protocol.PacketHeaderSize+20 || result.maxPacket > maxPacketFramePayload {
		return sessionConfig{}, fmt.Errorf("%w: packet payload limit %d is outside [%d,%d]", ErrInvalidConfiguration, result.maxPacket, protocol.PacketHeaderSize+20, maxPacketFramePayload)
	}
	if result.queueDepth < 1 || result.queueDepth > maxQueueDepthLimit {
		return sessionConfig{}, fmt.Errorf("%w: queue depth %d is outside [1,%d]", ErrInvalidConfiguration, result.queueDepth, maxQueueDepthLimit)
	}
	return result, nil
}

// ValidateConfig validates bounds without opening a socket. Nil selects the
// documented defaults and is valid.
func ValidateConfig(config *Config) error {
	_, err := normalizeConfig(config)
	return err
}

// Session is one authenticated, multiplexed TCP connection. It has one
// logical reliable control path and one packet path. A single read loop owns
// the stream; concurrent writers are serialized without ignoring context
// cancellation.
type Session struct {
	conn   *tls.Conn
	peer   identity.AuthenticatedIdentity
	config sessionConfig

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	control    chan []byte
	packets    chan *packetbuffer.Buffer
	packetPool *packetbuffer.Pool
	write      chan struct{}

	lastReceive atomic.Int64
	lastSend    atomic.Int64

	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
	stream    *ControlStream
}

func newSession(conn *tls.Conn, peer identity.AuthenticatedIdentity, config sessionConfig) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UnixNano()
	s := &Session{
		conn: conn, peer: peer, config: config,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
		control:    make(chan []byte, config.queueDepth),
		packets:    make(chan *packetbuffer.Buffer, config.queueDepth),
		packetPool: packetbuffer.NewPool(config.maxPacket),
		write:      make(chan struct{}, 1),
	}
	s.stream = &ControlStream{session: s}
	s.write <- struct{}{}
	s.lastReceive.Store(now)
	s.lastSend.Store(now)
	go s.readLoop()
	go s.keepAliveLoop()
	return s
}

func (s *Session) PeerIdentity() identity.AuthenticatedIdentity { return s.peer }

func (s *Session) PeerNodeIdentity() (identity.NodeIdentity, bool) { return s.peer.NodeIdentity() }

func (s *Session) PeerCertificateSerial() []byte {
	if s == nil || s.conn == nil {
		return nil
	}
	certificates := s.conn.ConnectionState().PeerCertificates
	if len(certificates) == 0 || certificates[0].SerialNumber == nil {
		return nil
	}
	return append([]byte(nil), certificates[0].SerialNumber.Bytes()...)
}

func (s *Session) LocalAddr() net.Addr   { return s.conn.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr  { return s.conn.RemoteAddr() }
func (s *Session) Done() <-chan struct{} { return s.done }

// ControlStream exposes control records as one reliable byte stream so the
// transport-independent agent and relay codecs can be reused unchanged.
func (s *Session) ControlStream() *ControlStream { return s.stream }

// Err reports why the session ended. A caller-initiated Close reports
// ErrClosed; remote EOF and protocol errors retain their original cause.
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *Session) WriteControl(ctx context.Context, payload []byte) error {
	return s.writeFrame(ctx, frameControl, payload)
}

func (s *Session) ReadControl(ctx context.Context) ([]byte, error) {
	return s.receive(ctx, s.control)
}

// WritePacket sends one complete Laneway packet frame. The authenticated
// session owner remains responsible for enforcing negotiated capabilities;
// this carrier boundary accepts either a plaintext IP frame or a structurally
// valid opaque WireGuard frame. Callers that have only an IP packet should use
// PacketPath.
func (s *Session) WritePacket(ctx context.Context, frame []byte) error {
	if _, _, err := protocol.DecodeFrame(frame); err != nil {
		return fmt.Errorf("%w: invalid packet: %w", ErrProtocol, err)
	}
	return s.writeFrame(ctx, framePacket, frame)
}

func (s *Session) ReadPacket(ctx context.Context) ([]byte, error) {
	buffer, err := s.ReadPacketBuffer(ctx)
	if err != nil {
		return nil, err
	}
	defer buffer.Release()
	return append([]byte(nil), buffer.Bytes()...), nil
}

// ReadPacketBuffer transfers ownership of one fixed-capacity pooled packet
// frame to the caller. Release must be called exactly once after the final
// synchronous consumer. Hot-path users should prefer this method to the
// allocation-compatible ReadPacket wrapper.
func (s *Session) ReadPacketBuffer(ctx context.Context) (*packetbuffer.Buffer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case payload := <-s.packets:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.sessionError()
	}
}

func (s *Session) receive(ctx context.Context, queue <-chan []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case payload := <-queue:
		return payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.sessionError()
	}
}

func (s *Session) sessionError() error {
	if err := s.Err(); err != nil {
		return err
	}
	return ErrClosed
}

func (s *Session) Close() error {
	s.terminate(ErrClosed)
	return nil
}

func (s *Session) terminate(err error) {
	s.closeOnce.Do(func() {
		if err == nil {
			err = ErrClosed
		}
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		s.cancel()
		_ = s.conn.Close()
		close(s.done)
	})
}

func (s *Session) readLoop() {
	for {
		kind, payload, owner, err := s.readFrame()
		if err != nil {
			s.terminate(err)
			return
		}
		s.lastReceive.Store(time.Now().UnixNano())
		switch kind {
		case frameControl:
			if !s.enqueue(s.control, payload) {
				s.terminate(fmt.Errorf("%w: control", ErrBackpressure))
				return
			}
		case framePacket:
			if _, _, err := protocol.DecodeFrame(payload); err != nil {
				owner.Release()
				s.terminate(fmt.Errorf("%w: invalid packet: %w", ErrProtocol, err))
				return
			}
			if !s.enqueuePacket(owner) {
				owner.Release()
				s.terminate(fmt.Errorf("%w: packet", ErrBackpressure))
				return
			}
		case framePing:
			if len(payload) != 0 {
				s.terminate(fmt.Errorf("%w: ping payload", ErrProtocol))
				return
			}
			if err := s.writeFrame(s.ctx, framePong, nil); err != nil {
				s.terminate(err)
				return
			}
		case framePong:
			if len(payload) != 0 {
				s.terminate(fmt.Errorf("%w: pong payload", ErrProtocol))
				return
			}
		default:
			s.terminate(fmt.Errorf("%w: unknown frame type %d", ErrProtocol, kind))
			return
		}
	}
}

func (s *Session) enqueuePacket(payload *packetbuffer.Buffer) bool {
	select {
	case s.packets <- payload:
		return true
	default:
		return false
	}
}

func (s *Session) enqueue(queue chan<- []byte, payload []byte) bool {
	select {
	case queue <- payload:
		return true
	default:
		return false
	}
}

func (s *Session) readFrame() (frameType, []byte, *packetbuffer.Buffer, error) {
	if err := s.conn.SetReadDeadline(time.Now().Add(s.config.idleTimeout)); err != nil {
		return 0, nil, nil, fmt.Errorf("tcp fallback: set read deadline: %w", err)
	}
	var header [frameHeaderSize]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return 0, nil, nil, fmt.Errorf("tcp fallback: read frame header: %w", err)
	}
	length := uint64(binary.BigEndian.Uint32(header[:4]))
	if length < 1 {
		return 0, nil, nil, fmt.Errorf("%w: empty frame", ErrProtocol)
	}
	kind := frameType(header[4])
	payloadLength := length - 1
	limit, ok := s.frameLimit(kind)
	if !ok {
		return 0, nil, nil, fmt.Errorf("%w: unknown frame type %d", ErrProtocol, kind)
	}
	if payloadLength > uint64(limit) {
		return 0, nil, nil, fmt.Errorf("%w: type=%d length=%d limit=%d", ErrFrameTooLarge, kind, payloadLength, limit)
	}
	var owner *packetbuffer.Buffer
	var payload []byte
	if kind == framePacket {
		owner = s.packetPool.Acquire(int(payloadLength))
		payload = owner.Bytes()
	} else {
		payload = make([]byte, int(payloadLength))
	}
	if _, err := io.ReadFull(s.conn, payload); err != nil {
		owner.Release()
		return 0, nil, nil, fmt.Errorf("tcp fallback: read frame payload: %w", err)
	}
	return kind, payload, owner, nil
}

func (s *Session) frameLimit(kind frameType) (int, bool) {
	switch kind {
	case frameControl:
		return s.config.maxControl, true
	case framePacket:
		return s.config.maxPacket, true
	case framePing, framePong:
		return 0, true
	default:
		return 0, false
	}
}

func (s *Session) writeFrame(ctx context.Context, kind frameType, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	limit, ok := s.frameLimit(kind)
	if !ok {
		return fmt.Errorf("%w: unknown frame type %d", ErrProtocol, kind)
	}
	if len(payload) > limit {
		return fmt.Errorf("%w: type=%d length=%d limit=%d", ErrFrameTooLarge, kind, len(payload), limit)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.sessionError()
	case <-s.write:
	}
	defer func() { s.write <- struct{}{} }()

	deadline := time.Now().Add(s.config.writeTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("tcp fallback: set write deadline: %w", err)
	}
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)+1))
	header[4] = byte(kind)
	if err := writeAll(s.conn, header[:]); err != nil {
		return s.writeError(ctx, err)
	}
	if err := writeAll(s.conn, payload); err != nil {
		return s.writeError(ctx, err)
	}
	s.lastSend.Store(time.Now().UnixNano())
	return nil
}

func (s *Session) writeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	wrapped := fmt.Errorf("tcp fallback: write frame: %w", err)
	s.terminate(wrapped)
	return wrapped
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func (s *Session) keepAliveLoop() {
	ticker := time.NewTicker(s.config.keepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			lastReceive := time.Unix(0, s.lastReceive.Load())
			if now.Sub(lastReceive) >= s.config.idleTimeout {
				s.terminate(fmt.Errorf("tcp fallback: peer idle for %s", now.Sub(lastReceive)))
				return
			}
			lastSend := time.Unix(0, s.lastSend.Load())
			if now.Sub(lastSend) >= s.config.keepAlivePeriod {
				if err := s.writeFrame(s.ctx, framePing, nil); err != nil {
					s.terminate(err)
					return
				}
			}
		}
	}
}

func prepareTLS(config *tls.Config, localRole identity.IdentityRole, server bool) (*tls.Config, identity.AuthenticatedIdentity, error) {
	if config == nil {
		return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("%w: nil TLS config", ErrInvalidConfiguration)
	}
	if len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("%w: TLS config has no local certificate", ErrInvalidConfiguration)
	}
	leaf := config.Certificates[0].Leaf
	var err error
	if leaf == nil {
		leaf, err = x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("tcp fallback: parse local certificate: %w", err)
		}
	}
	local, err := identity.AuthenticatedIdentityFromCertificate(leaf)
	if err != nil {
		return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("tcp fallback: local certificate identity: %w", err)
	}
	if err := local.RequireRole(localRole); err != nil {
		return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("tcp fallback: local certificate identity: %w", err)
	}
	clone := config.Clone()
	clone.MinVersion = tls.VersionTLS13
	clone.MaxVersion = tls.VersionTLS13
	clone.NextProtos = []string{ALPN}
	if server {
		clone.ClientAuth = tls.RequireAndVerifyClientCert
		if clone.ClientCAs == nil {
			return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("%w: server TLS config has no client CA pool", ErrInvalidConfiguration)
		}
	} else if clone.InsecureSkipVerify && clone.VerifyConnection == nil {
		return nil, identity.AuthenticatedIdentity{}, fmt.Errorf("%w: client disabled certificate verification without a callback", ErrInvalidConfiguration)
	}
	return clone, local, nil
}

func validateTLSState(state tls.ConnectionState, local identity.AuthenticatedIdentity, peerRole identity.IdentityRole) (identity.AuthenticatedIdentity, error) {
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ALPN {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("%w: TLS version or ALPN", ErrProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("%w: peer sent no certificate", ErrProtocol)
	}
	peer, err := identity.AuthenticatedIdentityFromCertificate(state.PeerCertificates[0])
	if err != nil {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("tcp fallback: peer identity: %w", err)
	}
	if err := peer.RequireRole(peerRole); err != nil {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("tcp fallback: peer identity: %w", err)
	}
	if peer.NetworkID != local.NetworkID {
		return identity.AuthenticatedIdentity{}, fmt.Errorf("%w: peer belongs to another network", ErrProtocol)
	}
	return peer, nil
}
