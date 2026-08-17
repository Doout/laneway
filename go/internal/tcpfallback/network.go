package tcpfallback

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
)

// Listener accepts node-authenticated TCP fallback sessions.
type Listener struct {
	listener          *net.TCPListener
	tls               *tls.Config
	local             identity.AuthenticatedIdentity
	config            sessionConfig
	mu                sync.Mutex // serializes deadline changes around Accept
	publicTLS         *tls.Config
	publicConnections chan net.Conn
	publicClosed      chan struct{}
	publicServer      *http.Server
	authenticated     func(net.Addr)
	multiplexSessions chan *Session
	handshakeSlots    chan struct{}
	closeOnce         sync.Once
}

// HTTPSOptions configures a bounded HTTPS server sharing the fallback socket.
// PublicTLS must use Web-PKI certificates and must not trust Laneway client
// identities; ALPN is the hard protocol boundary.
type HTTPSOptions struct {
	TLSConfig     *tls.Config
	Handler       http.Handler
	Authenticated func(net.Addr)
}

func Listen(address string, tlsConfig *tls.Config, config *Config) (*Listener, error) {
	return listen(address, tlsConfig, config, nil)
}

// ListenWithHTTPS multiplexes public HTTPS and authenticated fallback on one
// TCP port. Existing fallback clients continue to negotiate ALPN unchanged.
func ListenWithHTTPS(address string, tlsConfig *tls.Config, config *Config, public HTTPSOptions) (*Listener, error) {
	if public.TLSConfig == nil || public.Handler == nil {
		return nil, fmt.Errorf("tcp fallback: public HTTPS requires TLS config and handler")
	}
	return listen(address, tlsConfig, config, &public)
}

func listen(address string, tlsConfig *tls.Config, config *Config, public *HTTPSOptions) (*Listener, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	prepared, local, err := prepareTLS(tlsConfig, identity.IdentityRoleRelay, true)
	if err != nil {
		return nil, err
	}
	addressValue, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp fallback: resolve listen address: %w", err)
	}
	listener, err := net.ListenTCP("tcp", addressValue)
	if err != nil {
		return nil, fmt.Errorf("tcp fallback: listen: %w", err)
	}
	result := &Listener{listener: listener, tls: prepared, local: local, config: normalized}
	if public != nil {
		result.publicTLS = public.TLSConfig.Clone()
		result.authenticated = public.Authenticated
		result.publicConnections = make(chan net.Conn, 16)
		result.publicClosed = make(chan struct{})
		result.multiplexSessions = make(chan *Session, normalized.queueDepth)
		result.handshakeSlots = make(chan struct{}, 64)
		result.publicServer = &http.Server{
			Handler: public.Handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		go func() {
			_ = result.publicServer.Serve(&connectionListener{connections: result.publicConnections, closed: result.publicClosed, address: listener.Addr()})
		}()
		go result.acceptMultiplexed()
	}
	return result, nil
}

func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		if l.publicClosed != nil {
			close(l.publicClosed)
			_ = l.publicServer.Close()
		}
		err = l.listener.Close()
	})
	return err
}

type connectionListener struct {
	connections <-chan net.Conn
	closed      <-chan struct{}
	address     net.Addr
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *connectionListener) Close() error   { return nil }
func (l *connectionListener) Addr() net.Addr { return l.address }

// Accept performs TCP accept and the mTLS handshake. Accept calls are
// serialized because TCP listener deadlines are listener-wide.
func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l.publicTLS != nil {
		select {
		case session := <-l.multiplexSessions:
			return session, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.publicClosed:
			return nil, net.ErrClosed
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		_ = l.listener.SetDeadline(deadline)
	} else {
		_ = l.listener.SetDeadline(time.Time{})
	}
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = l.listener.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	raw, err := l.listener.AcceptTCP()
	close(stop)
	_ = l.listener.SetDeadline(time.Time{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tcp fallback: accept: %w", err)
	}
	return establish(ctx, raw, l.tls, l.local, identity.IdentityRoleNode, l.config, true)
}

func (l *Listener) acceptMultiplexed() {
	for {
		raw, err := l.listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case l.handshakeSlots <- struct{}{}:
			go func() {
				defer func() { <-l.handshakeSlots }()
				l.handleMultiplexed(raw)
			}()
		default:
			_ = raw.Close()
		}
	}
}

func (l *Listener) handleMultiplexed(raw net.Conn) {
	session, publicConnection, err := l.establishMultiplexed(context.Background(), raw)
	if err != nil {
		return
	}
	if session != nil {
		select {
		case l.multiplexSessions <- session:
		case <-l.publicClosed:
			_ = session.Close()
		}
		return
	}
	if publicConnection != nil {
		select {
		case l.publicConnections <- publicConnection:
		case <-l.publicClosed:
			_ = publicConnection.Close()
		default:
			_ = publicConnection.Close()
		}
	}
}

func (l *Listener) establishMultiplexed(ctx context.Context, raw net.Conn) (*Session, net.Conn, error) {
	deadline := time.Now().Add(l.config.handshakeTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	publicTLS := l.publicTLS
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Contains(hello.SupportedProtos, ALPN) {
				return l.tls.Clone(), nil
			}
			return publicTLS.Clone(), nil
		},
	}
	connection := tls.Server(raw, config)
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	state := connection.ConnectionState()
	if state.NegotiatedProtocol == ALPN {
		peer, err := validateTLSState(state, l.local, identity.IdentityRoleNode)
		if err != nil {
			_ = connection.Close()
			return nil, nil, err
		}
		if l.authenticated != nil {
			l.authenticated(raw.RemoteAddr())
		}
		return newSession(connection, peer, l.config), nil, nil
	}
	if state.NegotiatedProtocol != "h2" && state.NegotiatedProtocol != "http/1.1" {
		_ = connection.Close()
		return nil, nil, errors.New("tcp fallback: unsupported public ALPN")
	}
	return nil, connection, nil
}

// Dialer is reusable and safe for concurrent Dial calls. TLSConfig is cloned
// for every connection.
type Dialer struct {
	Address   string
	TLSConfig *tls.Config
	Config    *Config
}

func Dial(ctx context.Context, address string, tlsConfig *tls.Config, config *Config) (*Session, error) {
	return (&Dialer{Address: address, TLSConfig: tlsConfig, Config: config}).Dial(ctx)
}

func (d *Dialer) Dial(ctx context.Context) (*Session, error) {
	if d == nil || d.Address == "" {
		return nil, fmt.Errorf("%w: empty dial address", ErrInvalidConfiguration)
	}
	normalized, err := normalizeConfig(d.Config)
	if err != nil {
		return nil, err
	}
	prepared, local, err := prepareTLS(d.TLSConfig, identity.IdentityRoleNode, false)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := (&net.Dialer{Timeout: normalized.handshakeTimeout, KeepAlive: normalized.keepAlivePeriod}).DialContext(ctx, "tcp", d.Address)
	if err != nil {
		return nil, fmt.Errorf("tcp fallback: dial: %w", err)
	}
	return establish(ctx, raw, prepared, local, identity.IdentityRoleRelay, normalized, false)
}

func establish(ctx context.Context, raw net.Conn, config *tls.Config, local identity.AuthenticatedIdentity, peerRole identity.IdentityRole, normalized sessionConfig, server bool) (*Session, error) {
	deadline := time.Now().Add(normalized.handshakeTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tcp fallback: set handshake deadline: %w", err)
	}
	var conn *tls.Conn
	if server {
		conn = tls.Server(raw, config.Clone())
	} else {
		conn = tls.Client(raw, config.Clone())
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tcp fallback: TLS handshake: %w", err)
	}
	peer, err := validateTLSState(conn.ConnectionState(), local, peerRole)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tcp fallback: clear handshake deadline: %w", err)
	}
	return newSession(conn, peer, normalized), nil
}

// ReconnectConfig controls Dialer.Run. A successful session that lasts at
// least ResetAfter resets the exponential delay.
type ReconnectConfig struct {
	Initial    time.Duration
	Maximum    time.Duration
	ResetAfter time.Duration
}

func normalizeReconnect(config ReconnectConfig) (ReconnectConfig, error) {
	if config.Initial == 0 {
		config.Initial = 500 * time.Millisecond
	}
	if config.Maximum == 0 {
		config.Maximum = 30 * time.Second
	}
	if config.ResetAfter == 0 {
		config.ResetAfter = 30 * time.Second
	}
	if config.Initial < 0 || config.Maximum < config.Initial || config.ResetAfter < 0 {
		return ReconnectConfig{}, fmt.Errorf("%w: reconnect initial=%s maximum=%s reset_after=%s", ErrInvalidConfiguration, config.Initial, config.Maximum, config.ResetAfter)
	}
	return config, nil
}

// Run reconnects until ctx is canceled. Handler owns no connection resources;
// the session is closed after it returns. Transient dial and handler failures
// trigger bounded exponential backoff.
func (d *Dialer) Run(ctx context.Context, config ReconnectConfig, handler func(context.Context, *Session) error) error {
	if handler == nil {
		return fmt.Errorf("%w: nil reconnect handler", ErrInvalidConfiguration)
	}
	config, err := normalizeReconnect(config)
	if err != nil {
		return err
	}
	delay := config.Initial
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		started := time.Now()
		session, dialErr := d.Dial(ctx)
		if dialErr == nil {
			started = time.Now()
			dialErr = handler(ctx, session)
			_ = session.Close()
			if errors.Is(dialErr, context.Canceled) && ctx.Err() != nil {
				return ctx.Err()
			}
			if time.Since(started) >= config.ResetAfter {
				delay = config.Initial
			}
		} else if errors.Is(dialErr, ErrInvalidConfiguration) {
			return dialErr
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if delay < config.Maximum {
			if delay > config.Maximum/2 {
				delay = config.Maximum
			} else {
				delay *= 2
			}
		}
	}
}
