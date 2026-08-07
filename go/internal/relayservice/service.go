package relayservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/agent"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/relay"
	"laneway.dev/laneway/internal/revocation"
	"laneway.dev/laneway/internal/tcpfallback"
	"laneway.dev/laneway/internal/transport"
)

const (
	defaultControlWriteTimeout = 5 * time.Second
	// Stay below the common QUIC DATAGRAM path-MTU budget. Deployments with a
	// measured larger budget may opt in explicitly.
	defaultMaxPacketPayload = 1280
)

var (
	ErrInvalidConfig  = errors.New("relay service: invalid configuration")
	ErrAlreadyServing = errors.New("relay service: already serving")
)

type Config struct {
	Authorizer Authorizer
	// PacketPolicy is evaluated after structural and route-handle decoding but
	// before a packet enters the relay registry. A nil policy preserves the
	// static-authorizer behavior and permits every otherwise valid packet.
	PacketPolicy PacketPolicy
	Revocations  *revocation.Set

	Registry    relay.Config
	Transport   *transport.Config
	TCPFallback *tcpfallback.Config

	MaxConcurrentSessions int
	MaxRequestedRoutes    uint32
	MaxControlPayload     uint32
	MaxPacketPayload      uint32
	ConfigurationEpoch    uint64
	// ConfigurationEpochSource supplies the epoch included in each Welcome.
	// It is intended for controller-backed relays whose immutable snapshot can
	// advance while the listener remains up. A zero value is rejected for the
	// individual connection rather than advertising an uninitialized state.
	ConfigurationEpochSource func() uint64
	ProtocolVersion          protocol.Version
	Capabilities             protocol.Capability
	ControlWriteTimeout      time.Duration
	// CandidateMinInterval rate-limits repeated rendezvous publication while
	// still allowing direct paths to be retried during a long-lived relay
	// session.
	CandidateMinInterval time.Duration
}

// PacketPolicy makes the authenticated node identities available to a
// controller-compiled packet policy without coupling this package to a
// particular policy storage or distribution implementation.
type PacketPolicy interface {
	Allow(source, destination identity.NodeIdentity, packet []byte) bool
}

type PacketPolicyFunc func(source, destination identity.NodeIdentity, packet []byte) bool

func (f PacketPolicyFunc) Allow(source, destination identity.NodeIdentity, packet []byte) bool {
	return f(source, destination, packet)
}

// Server owns one relay registry and may be served once.
type Server struct {
	config   Config
	registry *relay.Registry
	metrics  serviceCounters

	mu        sync.Mutex
	sessionMu sync.Mutex
	serving   bool
	active    map[identity.NodeIdentity]*wireSession
	conns     map[packetConnection]struct{}
	wg        sync.WaitGroup
}

type serviceCounters struct {
	connectionsAccepted   atomic.Uint64
	acceptFailures        atomic.Uint64
	malformedInput        atomic.Uint64
	authorizationFailures atomic.Uint64
	policyDrops           atomic.Uint64
}

// Metrics combines the carrier/control counters owned by Server with the
// packet registry snapshot. All counter fields are monotonic for the process
// lifetime; Registry contains the active-session and queue gauges.
type Metrics struct {
	Registry              relay.Metrics
	ConnectionsAccepted   uint64
	AcceptFailures        uint64
	MalformedInput        uint64
	AuthorizationFailures uint64
	PolicyDrops           uint64
}

type wireSession struct {
	server             *Server
	conn               packetConnection
	identity           identity.NodeIdentity
	serial             []byte
	relay              *relay.Session
	codec              *relayCodec
	maxRoutes          uint32
	authorization      Authorization
	capabilities       protocol.Capability
	candidate          *lanewayv1.EndpointCandidate
	candidatePublished time.Time

	writeMu  sync.Mutex
	bindings map[*wireSession]uint32
}

func New(config Config) (*Server, error) {
	if config.Authorizer == nil {
		return nil, fmt.Errorf("%w: nil authorizer", ErrInvalidConfig)
	}
	if config.Registry == (relay.Config{}) {
		config.Registry = relay.Config{
			MaxSessions: 1024, MaxHandlesPerSession: 1024,
			OutboundQueueCapacity: 256, MaxPacketPayload: defaultMaxPacketPayload,
			DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest,
		}
	}
	registry, err := relay.NewRegistry(config.Registry)
	if err != nil {
		return nil, fmt.Errorf("%w: registry: %v", ErrInvalidConfig, err)
	}
	if config.MaxConcurrentSessions == 0 {
		config.MaxConcurrentSessions = config.Registry.MaxSessions
	}
	if config.MaxRequestedRoutes == 0 {
		config.MaxRequestedRoutes = uint32(config.Registry.MaxHandlesPerSession)
	}
	if config.MaxControlPayload == 0 {
		config.MaxControlPayload = protocol.DefaultMaxControlFrame
	}
	if config.MaxPacketPayload == 0 {
		config.MaxPacketPayload = uint32(config.Registry.MaxPacketPayload)
	}
	if config.ProtocolVersion == (protocol.Version{}) {
		config.ProtocolVersion = protocol.Version{Major: protocol.ProtocolMajor1}
	}
	if config.Capabilities == 0 {
		config.Capabilities = agent.RequiredRelayCapabilities |
			protocol.CapabilityTCPFallbackV1 |
			protocol.CapabilityDirectPeerV1 |
			protocol.CapabilityIPv6V1 |
			protocol.CapabilitySubnetRouterV1 |
			protocol.CapabilityExitNodeV1
	}
	if config.ControlWriteTimeout == 0 {
		config.ControlWriteTimeout = defaultControlWriteTimeout
	}
	if config.CandidateMinInterval == 0 {
		config.CandidateMinInterval = 5 * time.Second
	}
	if config.MaxConcurrentSessions <= 0 || config.MaxConcurrentSessions > config.Registry.MaxSessions ||
		config.MaxRequestedRoutes == 0 || uint64(config.MaxRequestedRoutes) > uint64(config.Registry.MaxHandlesPerSession) ||
		config.MaxControlPayload == 0 || config.MaxControlPayload > protocol.DefaultMaxControlFrame ||
		config.MaxPacketPayload == 0 || config.MaxPacketPayload > uint32(config.Registry.MaxPacketPayload) ||
		config.ProtocolVersion.Major != protocol.ProtocolMajor1 ||
		(!config.Capabilities.Has(agent.RequiredRelayCapabilities) && !config.Capabilities.Has(agent.RequiredTCPFallbackCapabilities)) || config.Capabilities.Unknown() != 0 ||
		config.ControlWriteTimeout < 0 || config.CandidateMinInterval < 10*time.Millisecond || config.CandidateMinInterval > 5*time.Minute || tcpfallback.ValidateConfig(config.TCPFallback) != nil {
		registry.Close()
		return nil, ErrInvalidConfig
	}
	if config.TCPFallback != nil &&
		((config.TCPFallback.MaxControlPayload != 0 && config.TCPFallback.MaxControlPayload < int(config.MaxControlPayload)) ||
			(config.TCPFallback.MaxPacketPayload != 0 && config.TCPFallback.MaxPacketPayload < int(config.MaxPacketPayload)+protocol.PacketHeaderSize)) {
		registry.Close()
		return nil, ErrInvalidConfig
	}
	return &Server{
		config: config, registry: registry,
		active: make(map[identity.NodeIdentity]*wireSession),
		conns:  make(map[packetConnection]struct{}),
	}, nil
}

// Registry exposes the server registry for metrics and read-only lookup.
func (s *Server) Registry() *relay.Registry { return s.registry }

// Metrics returns one bounded-cardinality operational snapshot without
// touching the controller or performing database work.
func (s *Server) Metrics() Metrics {
	var registryMetrics relay.Metrics
	if s != nil && s.registry != nil {
		registryMetrics = s.registry.Metrics()
	}
	if s == nil {
		return Metrics{}
	}
	return Metrics{
		Registry:              registryMetrics,
		ConnectionsAccepted:   s.metrics.connectionsAccepted.Load(),
		AcceptFailures:        s.metrics.acceptFailures.Load(),
		MalformedInput:        s.metrics.malformedInput.Load(),
		AuthorizationFailures: s.metrics.authorizationFailures.Load(),
		PolicyDrops:           s.metrics.policyDrops.Load(),
	}
}

// ListenAndServe creates an authenticated QUIC listener and serves it until
// ctx is canceled or the listener fails.
func (s *Server) ListenAndServe(ctx context.Context, address string, tlsConfig *tls.Config) error {
	listener, err := transport.Listen(address, tlsConfig, s.config.Transport)
	if err != nil {
		return err
	}
	defer listener.Close()
	return s.Serve(ctx, listener)
}

// Serve runs a bounded Accept loop. Cancellation closes all accepted
// connections, waits for their loops, unregisters all state, and returns the
// context error. The caller retains ownership of listener.
func (s *Server) Serve(ctx context.Context, listener *transport.Listener) error {
	if ctx == nil || listener == nil {
		return fmt.Errorf("%w: nil context or listener", ErrInvalidConfig)
	}
	return s.serve(ctx, []connectionAcceptor{quicAcceptor{listener}})
}

// ServeTCP serves only the TLS/TCP fallback carrier. It is primarily useful
// for constrained deployments and tests; production relays normally call
// ServeTransports so QUIC remains preferred.
func (s *Server) ServeTCP(ctx context.Context, listener *tcpfallback.Listener) error {
	if ctx == nil || listener == nil {
		return fmt.Errorf("%w: nil context or listener", ErrInvalidConfig)
	}
	return s.serve(ctx, []connectionAcceptor{tcpAcceptor{listener}})
}

// ServeTransports accepts QUIC and TCP fallback sessions into the same bounded
// registry. A node identity may have only one live session across both
// carriers; a replacement atomically closes the stale carrier.
func (s *Server) ServeTransports(ctx context.Context, quic *transport.Listener, tcp *tcpfallback.Listener) error {
	if ctx == nil || quic == nil || tcp == nil {
		return fmt.Errorf("%w: nil context or listener", ErrInvalidConfig)
	}
	return s.serve(ctx, []connectionAcceptor{quicAcceptor{quic}, tcpAcceptor{tcp}})
}

func (s *Server) serve(ctx context.Context, acceptors []connectionAcceptor) error {
	s.mu.Lock()
	if s.serving {
		s.mu.Unlock()
		return ErrAlreadyServing
	}
	s.serving = true
	s.mu.Unlock()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, s.config.MaxConcurrentSessions)
	acceptErrors := make(chan error, len(acceptors))
	var acceptWG sync.WaitGroup
	for _, acceptor := range acceptors {
		acceptWG.Add(1)
		go func(acceptor connectionAcceptor) {
			defer acceptWG.Done()
			acceptErrors <- s.acceptLoop(serveCtx, acceptor, slots)
		}(acceptor)
	}
	var serveErr error
	select {
	case <-ctx.Done():
		serveErr = ctx.Err()
	case err := <-acceptErrors:
		if serveCtx.Err() != nil {
			serveErr = serveCtx.Err()
		} else {
			serveErr = fmt.Errorf("relay service: accept: %w", err)
		}
	}
	cancel()
	acceptWG.Wait()
	s.mu.Lock()
	connections := make([]packetConnection, 0, len(s.conns))
	for conn := range s.conns {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		_ = conn.close()
	}
	s.wg.Wait()
	s.registry.Close()
	return serveErr
}

func (s *Server) acceptLoop(ctx context.Context, acceptor connectionAcceptor, slots chan struct{}) error {
	var retryDelay time.Duration
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		conn, err := acceptor.accept(ctx)
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.metrics.acceptFailures.Add(1)
			// A failed TLS/QUIC handshake belongs to one untrusted connection,
			// not to the listener. Back off to avoid a permanent listener error
			// becoming a busy loop, but keep serving healthy peers.
			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else {
				retryDelay = min(retryDelay*2, time.Second)
			}
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		retryDelay = 0
		s.metrics.connectionsAccepted.Add(1)
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-slots }()
			s.serveConn(ctx, conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, conn packetConnection) {
	defer conn.close()
	peer, ok := conn.peerNodeIdentity()
	if !ok {
		s.metrics.authorizationFailures.Add(1)
		return
	}
	serial := conn.peerCertificateSerial()
	if s.config.Revocations != nil && s.config.Revocations.IsRevoked(serial) {
		s.metrics.authorizationFailures.Add(1)
		return
	}
	authorization, err := s.config.Authorizer.Authorize(ctx, peer)
	if err != nil {
		s.metrics.authorizationFailures.Add(1)
		_ = writeControlError(conn.controlStream(), s.config.MaxControlPayload,
			lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "identity is not authorized", false)
		return
	}
	sessionID, err := identity.NewID()
	if err != nil {
		return
	}
	configurationEpoch := s.config.ConfigurationEpoch
	if s.config.ConfigurationEpochSource != nil {
		configurationEpoch = s.config.ConfigurationEpochSource()
		if configurationEpoch == 0 {
			return
		}
	}
	handshake, err := agent.NewRelayHandshake(peer, s.config.ProtocolVersion, s.config.Capabilities, agent.WelcomeConfig{
		SessionID: sessionID, ConfigurationEpoch: configurationEpoch,
		OverlayAddresses:  authorization.OverlayAddresses,
		MaxControlPayload: s.config.MaxControlPayload, MaxPacketPayload: s.config.MaxPacketPayload,
	})
	if err != nil {
		return
	}
	stream := conn.controlStream()
	controlCodec := agent.ControlCodec{Framer: protocol.ControlFramer{MaxPayload: s.config.MaxControlPayload}}
	var inbound agent.SequenceValidator
	request, err := controlCodec.Read(stream, &inbound, agent.BodyHello)
	if err != nil {
		s.metrics.malformedInput.Add(1)
		_ = writeControlError(stream, s.config.MaxControlPayload,
			agent.ErrorCode(err), "invalid Hello", false)
		return
	}
	welcome, helloResult, err := handshake.AcceptHello(request)
	if err != nil {
		if errors.Is(err, agent.ErrUnauthenticated) || errors.Is(err, agent.ErrPermissionDenied) {
			s.metrics.authorizationFailures.Add(1)
		} else {
			s.metrics.malformedInput.Add(1)
		}
		_ = writeControlError(stream, s.config.MaxControlPayload,
			agent.ErrorCode(err), "Hello rejected", false)
		return
	}
	if err := writeControlEnvelope(stream, s.config.MaxControlPayload, welcome); err != nil {
		return
	}

	codec := newRelayCodec(s.config.MaxControlPayload)
	registration, err := codec.read(stream)
	if err != nil || registration.GetRegister() == nil {
		s.metrics.malformedInput.Add(1)
		_ = codec.write(stream, &lanewayv1.ProtocolError{
			Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "RelayRegister must be the first relay message",
		})
		return
	}
	register := registration.GetRegister()
	if err := agent.SameSessionID(sessionID, register.GetSessionId()); err != nil ||
		register.GetRequestedMaxRoutes() == 0 || register.GetRequestedMaxRoutes() > s.config.MaxRequestedRoutes {
		s.metrics.malformedInput.Add(1)
		_ = codec.write(stream, &lanewayv1.ProtocolError{
			Code: lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED, Detail: "invalid relay registration",
		})
		return
	}
	// Registration and service-side activation are serialized so the
	// registry's ReplaceDuplicate policy and the wire-session index change as
	// one operation.
	s.sessionMu.Lock()
	relaySession, err := s.registry.Register(relay.SessionConfig{
		Identity: peer, AuthorizedPrefixes: authorization.AuthorizedPrefixes,
		MaxPacketPayload: int(s.config.MaxPacketPayload),
		AllowIPv6:        helloResult.Negotiated.Capabilities.Has(protocol.CapabilityIPv6V1),
	})
	if err != nil {
		s.sessionMu.Unlock()
		_ = codec.write(stream, &lanewayv1.ProtocolError{
			Code: lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED, Detail: "relay registration rejected", Retryable: true,
		})
		return
	}
	wire := &wireSession{
		server: s, conn: conn, identity: peer, serial: append([]byte(nil), serial...), relay: relaySession,
		codec: codec, maxRoutes: register.GetRequestedMaxRoutes(), authorization: cloneAuthorization(authorization),
		capabilities: helloResult.Negotiated.Capabilities,
		bindings:     make(map[*wireSession]uint32),
	}
	if s.config.Registry.DuplicatePolicy == relay.ReplaceDuplicate {
		s.mu.Lock()
		old := s.active[wire.identity]
		s.mu.Unlock()
		if old != nil {
			s.deactivateLocked(old)
			_ = old.conn.close()
		}
	}
	if !s.activate(wire) {
		s.registry.Unregister(relaySession)
		s.sessionMu.Unlock()
		return
	}
	s.sessionMu.Unlock()
	defer s.deactivate(wire)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, 3)
	go func() { errorsCh <- s.receiveControl(sessionCtx, wire) }()
	go func() { errorsCh <- s.receivePackets(sessionCtx, wire) }()
	go func() { errorsCh <- s.sendPackets(sessionCtx, wire) }()
	received := 0
	select {
	case <-errorsCh:
		received = 1
	case <-sessionCtx.Done():
	case <-conn.done():
	}
	cancel()
	_ = conn.close()
	for ; received < 3; received++ {
		<-errorsCh
	}
}

// Reauthorize rechecks active identities against the current immutable
// authorizer snapshot. Removed identities and any assignment change are closed
// so a reconnect installs fresh prefixes and overlay addresses atomically.
// Packet forwarding never calls the Authorizer.
func (s *Server) Reauthorize(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("%w: nil context", ErrInvalidConfig)
	}
	s.mu.Lock()
	active := make([]*wireSession, 0, len(s.active))
	for _, wire := range s.active {
		active = append(active, wire)
	}
	s.mu.Unlock()

	closed := 0
	for _, wire := range active {
		if err := ctx.Err(); err != nil {
			return closed, err
		}
		next, err := s.config.Authorizer.Authorize(ctx, wire.identity)
		changed := err != nil || !equalAuthorization(wire.authorization, next) ||
			(s.config.Revocations != nil && s.config.Revocations.IsRevoked(wire.serial))
		if !changed {
			continue
		}
		s.mu.Lock()
		current := s.active[wire.identity] == wire
		s.mu.Unlock()
		if current {
			s.metrics.authorizationFailures.Add(1)
			_ = wire.conn.close()
			closed++
		}
	}
	return closed, nil
}

func equalAuthorization(first, second Authorization) bool {
	return slices.Equal(first.OverlayAddresses, second.OverlayAddresses) &&
		slices.Equal(first.AuthorizedPrefixes, second.AuthorizedPrefixes)
}

func writeControlEnvelope(w io.Writer, max uint32, envelope *lanewayv1.ControlEnvelope) error {
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		return err
	}
	return (protocol.ControlFramer{MaxPayload: max}).Write(w, payload)
}

func writeControlError(w io.Writer, max uint32, code lanewayv1.ErrorCode, detail string, retryable bool) error {
	var sequence agent.SequenceGenerator
	envelope, err := sequence.Next(&lanewayv1.ProtocolError{Code: code, Detail: detail, Retryable: retryable})
	if err != nil {
		return err
	}
	return writeControlEnvelope(w, max, envelope)
}

func (s *Server) activate(wire *wireSession) bool {
	s.mu.Lock()
	if s.active[wire.identity] != nil {
		s.mu.Unlock()
		return false
	}
	peers := make([]*wireSession, 0, len(s.active))
	for identity, peer := range s.active {
		if identity.NetworkID == wire.identity.NetworkID {
			peers = append(peers, peer)
		}
	}
	s.active[wire.identity] = wire
	s.mu.Unlock()

	for _, peer := range peers {
		s.mu.Lock()
		atLimit := uint32(len(wire.bindings)) >= wire.maxRoutes || uint32(len(peer.bindings)) >= peer.maxRoutes
		s.mu.Unlock()
		if atLimit {
			continue
		}
		pair, err := s.registry.BindPeers(wire.relay, peer.relay)
		if err != nil {
			continue
		}
		s.mu.Lock()
		if s.active[wire.identity] != wire || s.active[peer.identity] != peer {
			s.mu.Unlock()
			continue
		}
		wire.bindings[peer] = pair.First.Handle
		peer.bindings[wire] = pair.Second.Handle
		s.mu.Unlock()
		if err := wire.write(&lanewayv1.RouteHandleBinding{
			RouteHandle: pair.First.Handle, PeerNodeId: append([]byte(nil), pair.First.PeerNodeID[:]...),
			MaxPacketPayload: pair.First.MaxPacketPayload,
		}); err != nil {
			_ = wire.conn.close()
		}
		if err := peer.write(&lanewayv1.RouteHandleBinding{
			RouteHandle: pair.Second.Handle, PeerNodeId: append([]byte(nil), pair.Second.PeerNodeID[:]...),
			MaxPacketPayload: pair.Second.MaxPacketPayload,
		}); err != nil {
			_ = peer.conn.close()
		}
	}
	return true
}

func (s *Server) deactivate(wire *wireSession) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.deactivateLocked(wire)
}

func (s *Server) deactivateLocked(wire *wireSession) {
	type release struct {
		peer   *wireSession
		handle uint32
	}
	s.mu.Lock()
	if s.active[wire.identity] != wire {
		s.mu.Unlock()
		return
	}
	delete(s.active, wire.identity)
	releases := make([]release, 0, len(s.active))
	// Scan all live peers so a one-way client release does not hide the peer's
	// remaining reverse handle from disconnect cleanup.
	for _, peer := range s.active {
		if handle, ok := peer.bindings[wire]; ok {
			delete(peer.bindings, wire)
			releases = append(releases, release{peer: peer, handle: handle})
		}
		delete(wire.bindings, peer)
	}
	s.mu.Unlock()
	s.registry.Unregister(wire.relay)
	for _, release := range releases {
		if err := release.peer.write(&lanewayv1.RouteHandleRelease{RouteHandle: release.handle}); err != nil {
			_ = release.peer.conn.close()
		}
	}
}

func (w *wireSession) write(body proto.Message) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	stream := w.conn.controlStream()
	if timeout := w.server.config.ControlWriteTimeout; timeout > 0 {
		if deadlineStream, ok := stream.(interface{ SetWriteDeadline(time.Time) error }); ok {
			if err := deadlineStream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
				return err
			}
			defer deadlineStream.SetWriteDeadline(time.Time{}) //nolint:errcheck
		}
	}
	return w.codec.write(stream, body)
}

func (s *Server) receiveControl(ctx context.Context, wire *wireSession) error {
	for {
		envelope, err := wire.codec.read(wire.conn.controlStream())
		if err != nil {
			s.metrics.malformedInput.Add(1)
			_ = wire.write(&lanewayv1.ProtocolError{
				Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "invalid relay envelope",
			})
			return err
		}
		switch body := envelope.GetBody().(type) {
		case *lanewayv1.RelayEnvelope_EndpointCandidate:
			if !wire.capabilities.Has(protocol.CapabilityDirectPeerV1) || body.EndpointCandidate == nil {
				s.metrics.malformedInput.Add(1)
				_ = wire.write(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "direct candidate was not negotiated"})
				return ErrUnexpectedRelayMessage
			}
			if err := s.publishObservedCandidate(wire); err != nil {
				s.metrics.malformedInput.Add(1)
				_ = wire.write(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "candidate publication rejected"})
				return err
			}
		case *lanewayv1.RelayEnvelope_RouteHandleRelease:
			release := body.RouteHandleRelease
			if release == nil || release.GetRouteHandle() == 0 {
				s.metrics.malformedInput.Add(1)
				_ = wire.write(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "unexpected relay message"})
				return ErrUnexpectedRelayMessage
			}
			if err := s.registry.Release(wire.relay, release.GetRouteHandle()); err != nil {
				s.metrics.malformedInput.Add(1)
				_ = wire.write(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "unknown route handle"})
				return err
			}
			s.mu.Lock()
			for peer, handle := range wire.bindings {
				if handle == release.GetRouteHandle() {
					delete(wire.bindings, peer)
					break
				}
			}
			s.mu.Unlock()
		default:
			s.metrics.malformedInput.Add(1)
			_ = wire.write(&lanewayv1.ProtocolError{
				Code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, Detail: "unexpected relay message",
			})
			return ErrUnexpectedRelayMessage
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (s *Server) publishObservedCandidate(wire *wireSession) error {
	endpoint, ok := wire.conn.observedUDPEndpoint()
	if !ok {
		return ErrUnexpectedRelayMessage
	}
	address := endpoint.Addr().Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || endpoint.Port() == 0 {
		return ErrUnexpectedRelayMessage
	}
	observed := &lanewayv1.EndpointCandidate{
		NodeId: append([]byte(nil), wire.identity.NodeID[:]...), IpAddress: append([]byte(nil), address.AsSlice()...),
		Port: uint32(endpoint.Port()), Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP,
	}
	s.mu.Lock()
	now := time.Now()
	if s.active[wire.identity] != wire || (!wire.candidatePublished.IsZero() && now.Sub(wire.candidatePublished) < s.config.CandidateMinInterval) {
		s.mu.Unlock()
		return ErrUnexpectedRelayMessage
	}
	wire.candidate = observed
	wire.candidatePublished = now
	peers := make([]*wireSession, 0, len(wire.bindings))
	for peer := range wire.bindings {
		if peer.candidate != nil && peer.capabilities.Has(protocol.CapabilityDirectPeerV1) {
			peers = append(peers, peer)
		}
	}
	s.mu.Unlock()
	for _, peer := range peers {
		if err := s.coordinateCandidates(wire, peer); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) coordinateCandidates(first, second *wireSession) error {
	s.mu.Lock()
	if s.active[first.identity] != first || s.active[second.identity] != second || first.candidate == nil || second.candidate == nil {
		s.mu.Unlock()
		return nil
	}
	firstCandidate := proto.Clone(first.candidate).(*lanewayv1.EndpointCandidate)
	secondCandidate := proto.Clone(second.candidate).(*lanewayv1.EndpointCandidate)
	s.mu.Unlock()
	token, err := identity.NewID()
	if err != nil {
		return err
	}
	start := uint64(time.Now().Add(250 * time.Millisecond).UnixNano())
	firstCandidate.RendezvousToken, firstCandidate.ProbeStartUnixNano = append([]byte(nil), token[:]...), start
	secondCandidate.RendezvousToken, secondCandidate.ProbeStartUnixNano = append([]byte(nil), token[:]...), start
	// Each receiver gets the other node's relay-observed endpoint.
	if err := first.write(secondCandidate); err != nil {
		return err
	}
	return second.write(firstCandidate)
}

func (s *Server) receivePackets(ctx context.Context, wire *wireSession) error {
	for {
		frame, owner, err := wire.conn.receivePacket(ctx)
		if err != nil {
			return err
		}
		if s.config.PacketPolicy != nil {
			header, packet, decodeErr := protocol.DecodePacket(frame)
			if decodeErr != nil {
				s.metrics.malformedInput.Add(1)
				owner.Release()
				continue
			}
			peer, ok := s.peerForHandle(wire, header.RouteHandle)
			if !ok || !s.config.PacketPolicy.Allow(wire.identity, peer.identity, packet) {
				s.metrics.authorizationFailures.Add(1)
				s.metrics.policyDrops.Add(1)
				owner.Release()
				continue
			}
		}
		// Invalid and spoofed packets are dropped without killing an otherwise
		// healthy authenticated session.
		_ = s.registry.Forward(wire.relay, frame)
		owner.Release()
	}
}

func (s *Server) peerForHandle(wire *wireSession, handle uint32) (*wireSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for peer, boundHandle := range wire.bindings {
		if boundHandle == handle && s.active[peer.identity] == peer {
			return peer, true
		}
	}
	return nil, false
}

func (s *Server) sendPackets(ctx context.Context, wire *wireSession) error {
	for {
		frame, err := wire.relay.DequeueBuffer(ctx)
		if err != nil {
			return err
		}
		sendErr := wire.conn.sendPacket(ctx, frame.Bytes())
		frame.Release()
		if sendErr != nil {
			return sendErr
		}
	}
}
