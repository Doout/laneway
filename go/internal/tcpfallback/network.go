package tcpfallback

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"laneway.dev/laneway/internal/identity"
)

// Listener accepts node-authenticated TCP fallback sessions.
type Listener struct {
	listener *net.TCPListener
	tls      *tls.Config
	local    identity.AuthenticatedIdentity
	config   sessionConfig
	mu       sync.Mutex // serializes deadline changes around Accept
}

func Listen(address string, tlsConfig *tls.Config, config *Config) (*Listener, error) {
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
	return &Listener{listener: listener, tls: prepared, local: local, config: normalized}, nil
}

func (l *Listener) Addr() net.Addr { return l.listener.Addr() }
func (l *Listener) Close() error   { return l.listener.Close() }

// Accept performs TCP accept and the mTLS handshake. Accept calls are
// serialized because TCP listener deadlines are listener-wide.
func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
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
