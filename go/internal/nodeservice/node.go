// Package nodeservice runs the unprivileged portion of lanewayd: authenticated
// relay sessions, control negotiation, route-handle tracking, packet framing,
// validation, forwarding, and reconnect. Platform TUN and route lifecycle are
// injected through PacketIO and remain outside the transport fast path.
package nodeservice

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/agent"
	"github.com/Doout/laneway/go/internal/dataplane"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
	"github.com/Doout/laneway/go/internal/wireguard"
)

const DefaultMaxRoutes = 4096

var (
	ErrInvalidConfig    = errors.New("invalid node service configuration")
	ErrRelayNetwork     = errors.New("relay certificate belongs to another network")
	ErrControlSequence  = errors.New("invalid relay control sequence")
	ErrControlBody      = errors.New("invalid relay control body")
	ErrSourceValidation = errors.New("received packet source validation failed")
	ErrDestination      = errors.New("received packet is not addressed to this node")
)

type PacketIO interface {
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) error
}

type PacketPolicy interface {
	Allow(source, destination identity.NodeID, packet []byte) bool
}

type PacketPolicyFunc func(source, destination identity.NodeID, packet []byte) bool

func (f PacketPolicyFunc) Allow(source, destination identity.NodeID, packet []byte) bool {
	return f(source, destination, packet)
}

type RelayTarget struct {
	ServiceID identity.ID
	Address   string
}

type RelayAuthority interface {
	RelayTargets() []RelayTarget
	RelayAuthorityChanges() <-chan struct{}
}

// WireGuardRelayHandler bridges the stable local WireGuard device/socket to
// one authenticated relay session. RunRelay must stop when ctx is canceled and
// must release every received datagram after delivering it locally.
type WireGuardRelayHandler interface {
	RunRelay(context.Context, *wireguard.RelayMux, pathmanager.PathKind, string) error
}

type Config struct {
	Identity           identity.NodeIdentity
	BootID             identity.ID
	RelayAddress       string
	RelayServiceID     identity.ID
	TLSConfig          *tls.Config
	Transport          *transport.Config
	TCPFallbackAddress string
	TCPFallback        *tcpfallback.Config
	Routes             *routing.Table
	Packets            PacketIO
	PacketPolicy       PacketPolicy
	// DataPlane enables unified direct > relay QUIC > TCP selection. When set,
	// this service owns relay control sessions but does not read or write TUN.
	DataPlane *dataplane.Engine
	// WireGuardRelay selects the opaque encrypted dataplane. It is mutually
	// exclusive with the legacy plaintext PacketIO/DataPlane paths.
	WireGuardRelay     WireGuardRelayHandler
	CandidateSink      dataplane.CandidateSink
	CandidateAuthority interface{ CandidateExchangeEnabled() bool }
	LocalCandidate     *lanewayv1.EndpointCandidate
	RelayDialer        RelayDialer
	RelayAuthority     RelayAuthority
	MaxRoutes          uint32
	MaxControlPayload  uint32
	ReconnectInitial   time.Duration
	ReconnectMaximum   time.Duration
	ReconnectJitter    float64
	// QUICRecoveryInterval bounds periodic QUIC-first recovery attempts while
	// a healthy TCP fallback session is carrying traffic.
	QUICRecoveryInterval     time.Duration
	DirectRendezvousInterval time.Duration
	// ForwardPrefixes are controller-authorized subnet/exit destinations owned
	// by this node. They are accepted in addition to the node's overlay IPs.
	ForwardPrefixes []netip.Prefix
}

func (s *Service) candidateExchangeEnabled() bool {
	return s.config.CandidateAuthority == nil || s.config.CandidateAuthority.CandidateExchangeEnabled()
}

type Metrics struct {
	Connections      uint64
	Reconnects       uint64
	PacketsSent      uint64
	PacketsReceived  uint64
	PacketsDropped   uint64
	MalformedPackets uint64
	ControlErrors    uint64
	TCPConnections   uint64
	QUICFailures     uint64
	TCPFailures      uint64
}

type counters struct {
	connections      atomic.Uint64
	reconnects       atomic.Uint64
	packetsSent      atomic.Uint64
	packetsReceived  atomic.Uint64
	packetsDropped   atomic.Uint64
	malformedPackets atomic.Uint64
	controlErrors    atomic.Uint64
	tcpConnections   atomic.Uint64
	quicFailures     atomic.Uint64
	tcpFailures      atomic.Uint64
	carrier          atomic.Uint32
}

type Service struct {
	config          Config
	backoff         *agent.Backoff
	metrics         counters
	bindings        bindingTable
	forwardPrefixes atomic.Pointer[forwardPrefixSnapshot]
}

const (
	carrierDisconnected uint32 = iota
	carrierQUIC
	carrierTCP
)

type forwardPrefixSnapshot struct {
	prefixes []netip.Prefix
}

type bindingTable struct {
	mu       sync.RWMutex
	byPeer   map[identity.NodeID]uint32
	byHandle map[uint32]identity.NodeID
}

// PathAvailable reports whether the active relay session has a route binding
// for peer. Bindings are cleared synchronously when the carrier disconnects.
func (s *Service) PathAvailable(peer identity.NodeID) bool {
	if s == nil {
		return false
	}
	_, ok := s.bindings.handle(peer)
	return ok
}

func (s *Service) SelectedCarrier() string {
	if s == nil {
		return "disconnected"
	}
	switch s.metrics.carrier.Load() {
	case carrierQUIC:
		if s.config.WireGuardRelay != nil {
			return "wireguard-relay-quic"
		}
		return "relay-quic"
	case carrierTCP:
		if s.config.WireGuardRelay != nil {
			return "wireguard-relay-tcp"
		}
		return "tcp-fallback"
	default:
		return "disconnected"
	}
}

func (s *Service) AdvertisedCapabilities() protocol.Capability {
	if s == nil {
		return 0
	}
	capabilities := agent.RequiredRelayCapabilities | protocol.CapabilityIPv6V1 |
		protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1
	if s.config.CandidateSink != nil {
		capabilities |= protocol.CapabilityDirectPeerV1
	}
	if s.config.TCPFallbackAddress != "" {
		capabilities |= protocol.CapabilityTCPFallbackV1
	}
	if s.config.WireGuardRelay != nil {
		capabilities |= protocol.CapabilityE2EPacketV1
	}
	return capabilities
}

func New(config Config) (*Service, error) {
	if err := config.Identity.Validate(); err != nil || config.BootID.IsZero() || config.RelayAddress == "" ||
		config.TLSConfig == nil || config.Routes == nil || (config.Packets == nil && config.DataPlane == nil && config.WireGuardRelay == nil) {
		return nil, ErrInvalidConfig
	}
	if config.WireGuardRelay != nil && (config.Packets != nil || config.DataPlane != nil) {
		return nil, ErrInvalidConfig
	}
	if (config.CandidateSink == nil) != (config.LocalCandidate == nil) ||
		(config.CandidateSink != nil && config.DataPlane == nil && config.WireGuardRelay == nil) {
		return nil, ErrInvalidConfig
	}
	if config.RelayAuthority != nil && config.RelayServiceID.IsZero() {
		return nil, ErrInvalidConfig
	}
	if (config.TCPFallbackAddress == "" && config.TCPFallback != nil) ||
		(config.TCPFallbackAddress != "" && tcpfallback.ValidateConfig(config.TCPFallback) != nil) {
		return nil, ErrInvalidConfig
	}
	if config.MaxRoutes == 0 {
		config.MaxRoutes = DefaultMaxRoutes
	}
	if config.MaxControlPayload == 0 {
		config.MaxControlPayload = protocol.DefaultMaxControlFrame
	}
	if config.QUICRecoveryInterval == 0 {
		config.QUICRecoveryInterval = 30 * time.Second
	}
	if config.QUICRecoveryInterval < 10*time.Millisecond || config.QUICRecoveryInterval > 5*time.Minute {
		return nil, ErrInvalidConfig
	}
	if config.DirectRendezvousInterval == 0 {
		config.DirectRendezvousInterval = 30 * time.Second
	}
	if config.DirectRendezvousInterval < 10*time.Millisecond || config.DirectRendezvousInterval > 5*time.Minute {
		return nil, ErrInvalidConfig
	}
	for _, prefix := range config.ForwardPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, ErrInvalidConfig
		}
	}
	backoff, err := agent.NewBackoff(agent.BackoffConfig{
		Initial: config.ReconnectInitial,
		Maximum: config.ReconnectMaximum,
		Jitter:  config.ReconnectJitter,
	})
	if err != nil {
		return nil, err
	}
	service := &Service{
		config:  config,
		backoff: backoff,
		bindings: bindingTable{
			byPeer:   make(map[identity.NodeID]uint32),
			byHandle: make(map[uint32]identity.NodeID),
		},
	}
	service.forwardPrefixes.Store(&forwardPrefixSnapshot{prefixes: append([]netip.Prefix(nil), config.ForwardPrefixes...)})
	return service, nil
}

// SetForwardPrefixes atomically replaces the controller-authorized subnet and
// exit destinations accepted by active packet loops.
func (s *Service) SetForwardPrefixes(prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return ErrInvalidConfig
		}
	}
	s.forwardPrefixes.Store(&forwardPrefixSnapshot{prefixes: append([]netip.Prefix(nil), prefixes...)})
	return nil
}

func (s *Service) currentForwardPrefixes() []netip.Prefix {
	if snapshot := s.forwardPrefixes.Load(); snapshot != nil {
		return snapshot.prefixes
	}
	return nil
}

func (s *Service) Run(ctx context.Context) error {
	first := true
	for ctx.Err() == nil {
		sessionCtx, cancel := context.WithCancel(ctx)
		var authorityChanges <-chan struct{}
		if s.config.RelayAuthority != nil {
			authorityChanges = s.config.RelayAuthority.RelayAuthorityChanges()
		}
		done := make(chan error, 1)
		go func() { done <- s.runSession(sessionCtx) }()
		var err error
		if s.config.RelayAuthority == nil {
			err = <-done
		} else {
			select {
			case err = <-done:
			case <-authorityChanges:
				cancel()
				err = <-done
			}
		}
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			s.backoff.Reset()
		}
		if !first {
			s.metrics.reconnects.Add(1)
		}
		first = false
		if _, waitErr := s.backoff.Wait(ctx); waitErr != nil {
			return waitErr
		}
	}
	return ctx.Err()
}

func (s *Service) RunSession(ctx context.Context) error { return s.runSession(ctx) }

func (s *Service) runSession(ctx context.Context) error {
	capabilities := agent.RequiredRelayCapabilities | protocol.CapabilityIPv6V1 |
		protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1
	if s.config.WireGuardRelay != nil {
		capabilities |= protocol.CapabilityE2EPacketV1
	}
	if s.config.CandidateSink != nil {
		capabilities |= protocol.CapabilityDirectPeerV1
	}
	quic, err := s.dialQUIC(ctx)
	if err == nil {
		err = s.runConnected(ctx, quicNodeConnection{quic}, capabilities)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.metrics.quicFailures.Add(1)
	if s.config.TCPFallbackAddress == "" {
		return err
	}
	tcpTLS := s.config.TLSConfig
	if s.config.RelayAuthority != nil {
		authorized := false
		for _, target := range s.config.RelayAuthority.RelayTargets() {
			authorized = authorized || target.ServiceID == s.config.RelayServiceID
		}
		if !authorized {
			return errors.Join(err, errors.New("configured TCP relay is no longer controller-authorized"))
		}
		tcpTLS = s.config.TLSConfig.Clone()
		if tlsErr := transport.RequirePeerService(tcpTLS, identity.AuthenticatedIdentity{
			NetworkID: s.config.Identity.NetworkID, Role: identity.IdentityRoleRelay, SubjectID: s.config.RelayServiceID,
		}); tlsErr != nil {
			return errors.Join(err, tlsErr)
		}
	}
	tcp, tcpErr := tcpfallback.Dial(ctx, s.config.TCPFallbackAddress, tcpTLS, s.config.TCPFallback)
	if tcpErr != nil {
		s.metrics.tcpFailures.Add(1)
		return errors.Join(err, tcpErr)
	}
	s.metrics.tcpConnections.Add(1)
	tcpErr = s.runTCPWithQUICRecovery(ctx, tcpNodeConnection{tcp}, capabilities)
	if ctx.Err() == nil && tcpErr != nil {
		s.metrics.tcpFailures.Add(1)
	}
	return tcpErr
}

func (s *Service) dialQUIC(ctx context.Context) (*transport.Conn, error) {
	targets := []RelayTarget{{Address: s.config.RelayAddress}}
	if s.config.RelayAuthority != nil {
		targets = s.config.RelayAuthority.RelayTargets()
		sort.Slice(targets, func(i, j int) bool {
			if targets[i].ServiceID != targets[j].ServiceID {
				return targets[i].ServiceID.String() < targets[j].ServiceID.String()
			}
			return targets[i].Address < targets[j].Address
		})
	}
	var result error
	for _, target := range targets {
		tlsConfig := s.config.TLSConfig.Clone()
		if !target.ServiceID.IsZero() {
			if err := transport.RequirePeerService(tlsConfig, identity.AuthenticatedIdentity{
				NetworkID: s.config.Identity.NetworkID, Role: identity.IdentityRoleRelay, SubjectID: target.ServiceID,
			}); err != nil {
				result = errors.Join(result, err)
				continue
			}
		}
		var connection *transport.Conn
		var err error
		if s.config.RelayDialer != nil {
			connection, err = s.config.RelayDialer.DialRelay(ctx, target.Address, tlsConfig, s.config.Transport)
		} else {
			connection, err = transport.Dial(ctx, target.Address, tlsConfig, s.config.Transport)
		}
		if err == nil {
			return connection, nil
		}
		result = errors.Join(result, err)
	}
	if result == nil {
		result = errors.New("controller authorized no relay targets")
	}
	return nil, result
}

// runTCPWithQUICRecovery keeps the authenticated TCP carrier live while
// periodically attempting QUIC. A recovered QUIC session completes its
// handshake and registration first, then waits behind a gate until the TCP
// packet loops have stopped. This preserves QUIC-first preference without two
// sessions concurrently reading the same TUN device.
func (s *Service) runTCPWithQUICRecovery(ctx context.Context, tcp nodeConnection, quicCapabilities protocol.Capability) error {
	tcpCapabilities := agent.RequiredTCPFallbackCapabilities | protocol.CapabilityIPv6V1 |
		protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1
	if s.config.WireGuardRelay != nil {
		tcpCapabilities |= protocol.CapabilityE2EPacketV1
	}
	tcpCtx, cancelTCP := context.WithCancel(ctx)
	defer cancelTCP()
	tcpDone := make(chan error, 1)
	go func() { tcpDone <- s.runConnected(tcpCtx, tcp, tcpCapabilities) }()
	timer := time.NewTimer(s.config.QUICRecoveryInterval)
	defer timer.Stop()
	for {
		select {
		case err := <-tcpDone:
			return err
		case <-ctx.Done():
			cancelTCP()
			<-tcpDone
			return ctx.Err()
		case <-timer.C:
		}

		quic, err := s.dialQUIC(ctx)
		if err != nil {
			s.metrics.quicFailures.Add(1)
			timer.Reset(s.config.QUICRecoveryInterval)
			continue
		}
		quicCtx, cancelQUIC := context.WithCancel(ctx)
		ready := make(chan struct{}, 1)
		proceed := make(chan struct{})
		quicDone := make(chan error, 1)
		go func() {
			quicDone <- s.runConnectedGated(quicCtx, quicNodeConnection{quic}, quicCapabilities, ready, proceed)
		}()
		select {
		case <-ready:
			cancelTCP()
			<-tcpDone
			close(proceed)
			err := <-quicDone
			cancelQUIC()
			return err
		case err := <-quicDone:
			cancelQUIC()
			s.metrics.quicFailures.Add(1)
			if ctx.Err() != nil {
				cancelTCP()
				<-tcpDone
				return ctx.Err()
			}
			_ = err // The healthy TCP path remains authoritative.
			timer.Reset(s.config.QUICRecoveryInterval)
		case err := <-tcpDone:
			// A ReplaceDuplicate relay closes the stale TCP carrier as it
			// accepts the recovered QUIC registration. Prefer the ready QUIC
			// handshake in that race instead of treating the expected TCP close
			// as a failed recovery.
			select {
			case <-ready:
				close(proceed)
				promotedErr := <-quicDone
				cancelQUIC()
				return promotedErr
			default:
			}
			select {
			case <-ready:
				close(proceed)
				promotedErr := <-quicDone
				cancelQUIC()
				return promotedErr
			case <-quicDone:
				cancelQUIC()
				return err
			case <-ctx.Done():
				cancelQUIC()
				_ = quic.Close()
				<-quicDone
				return ctx.Err()
			}
		case <-ctx.Done():
			cancelQUIC()
			cancelTCP()
			_ = quic.Close()
			<-quicDone
			<-tcpDone
			return ctx.Err()
		}
	}
}

func (s *Service) runConnected(ctx context.Context, conn nodeConnection, capabilities protocol.Capability) error {
	return s.runConnectedGated(ctx, conn, capabilities, nil, nil)
}

func (s *Service) runConnectedGated(ctx context.Context, conn nodeConnection, capabilities protocol.Capability, ready chan<- struct{}, proceed <-chan struct{}) error {
	defer conn.close()
	peer := conn.peerIdentity()
	if peer.NetworkID != s.config.Identity.NetworkID {
		return ErrRelayNetwork
	}
	params, err := s.handshakeWithCapabilities(conn.controlStream(), capabilities)
	if err != nil {
		return err
	}
	if ready != nil {
		select {
		case ready <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-proceed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	carrier := carrierQUIC
	if capabilities.Has(protocol.CapabilityTCPFallbackV1) {
		carrier = carrierTCP
	}
	s.metrics.carrier.Store(carrier)
	defer s.metrics.carrier.CompareAndSwap(carrier, carrierDisconnected)
	s.metrics.connections.Add(1)
	s.bindings.reset()
	defer s.bindings.reset()
	if s.config.WireGuardRelay != nil {
		return s.runWireGuardConnected(ctx, conn, params, carrier)
	}
	if s.config.DataPlane != nil {
		return s.runUnifiedConnected(ctx, conn, params, capabilities)
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsOut := make(chan error, 3)
	go func() { errorsOut <- s.controlLoop(sessionCtx, conn.controlStream(), params) }()
	go func() { errorsOut <- s.outgoingLoop(sessionCtx, conn, params) }()
	go func() { errorsOut <- s.incomingLoop(sessionCtx, conn, params) }()
	received := 0
	select {
	case err = <-errorsOut:
		received = 1
	case <-sessionCtx.Done():
		err = sessionCtx.Err()
	case <-conn.done():
		err = errors.New("relay connection closed")
	}
	cancel()
	_ = conn.close()
	for ; received < 3; received++ {
		<-errorsOut
	}
	return err
}

func (s *Service) runWireGuardConnected(ctx context.Context, conn nodeConnection, params agent.SessionParameters, carrier uint32) error {
	mux, err := wireguard.NewRelayMux(nodeRelayCarrier{conn}, params.Capabilities)
	if err != nil {
		return err
	}
	kind, name := pathmanager.PathRelayQUIC, "wireguard-relay-quic"
	if carrier == carrierTCP {
		kind, name = pathmanager.PathTCPFallback, "wireguard-tcp-fallback"
	}
	candidateConfigured := s.config.LocalCandidate != nil && params.Capabilities.Has(protocol.CapabilityDirectPeerV1) && kind == pathmanager.PathRelayQUIC
	candidateSequence := uint64(2)
	if candidateConfigured && s.candidateExchangeEnabled() {
		envelope := &lanewayv1.RelayEnvelope{
			SchemaVersion: 1, Sequence: 2,
			Body: &lanewayv1.RelayEnvelope_EndpointCandidate{EndpointCandidate: proto.Clone(s.config.LocalCandidate).(*lanewayv1.EndpointCandidate)},
		}
		if err := writeMessage(conn.controlStream(), params.ControlFramer(), envelope); err != nil {
			return err
		}
		candidateSequence++
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workers := 2
	done := make(chan error, 3)
	go func() { done <- s.controlLoopWireGuard(sessionCtx, conn.controlStream(), params, mux) }()
	go func() { done <- s.config.WireGuardRelay.RunRelay(sessionCtx, mux, kind, name) }()
	if candidateConfigured {
		workers++
		go func() { done <- s.candidatePublishLoop(sessionCtx, conn.controlStream(), params, candidateSequence) }()
	}
	select {
	case err = <-done:
	case <-sessionCtx.Done():
		err = sessionCtx.Err()
	case <-conn.done():
		err = errors.New("relay connection closed")
	}
	cancel()
	_ = conn.close()
	for range workers - 1 {
		<-done
	}
	return err
}

func (s *Service) controlLoopWireGuard(ctx context.Context, stream io.Reader, params agent.SessionParameters, mux *wireguard.RelayMux) error {
	var sequence uint64 = 1
	for {
		envelope := new(lanewayv1.RelayEnvelope)
		if err := readMessage(stream, params.ControlFramer(), envelope); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if envelope.GetSchemaVersion() != 1 || envelope.GetSequence() != sequence {
			return ErrControlSequence
		}
		sequence++
		switch body := envelope.GetBody().(type) {
		case *lanewayv1.RelayEnvelope_RouteHandleBinding:
			binding := body.RouteHandleBinding
			if binding.GetRouteHandle() == 0 || len(binding.GetPeerNodeId()) != identity.IDSize || binding.GetMaxPacketPayload() == 0 {
				return ErrControlBody
			}
			var peer identity.NodeID
			copy(peer[:], binding.GetPeerNodeId())
			if peer.IsZero() {
				return ErrControlBody
			}
			if err := mux.SetBinding(wireguard.RelayBinding{Peer: peer, Handle: binding.GetRouteHandle(), MaxPacketPayload: int(binding.GetMaxPacketPayload())}); err != nil {
				return err
			}
		case *lanewayv1.RelayEnvelope_RouteHandleRelease:
			if _, ok := mux.ReleaseHandle(body.RouteHandleRelease.GetRouteHandle()); !ok {
				return ErrControlBody
			}
		case *lanewayv1.RelayEnvelope_EndpointCandidate:
			if s.config.CandidateSink == nil || !params.Capabilities.Has(protocol.CapabilityDirectPeerV1) || body.EndpointCandidate == nil {
				return ErrControlBody
			}
			if !s.candidateExchangeEnabled() {
				continue
			}
			if err := s.config.CandidateSink.HandleCandidate(ctx, body.EndpointCandidate); err != nil {
				return err
			}
		case *lanewayv1.RelayEnvelope_Error:
			return agent.RemoteError(body.Error)
		default:
			return ErrControlBody
		}
	}
}

func (s *Service) runUnifiedConnected(ctx context.Context, conn nodeConnection, params agent.SessionParameters, capabilities protocol.Capability) error {
	kind, name := pathmanager.PathRelayQUIC, "relay-quic"
	if capabilities.Has(protocol.CapabilityTCPFallbackV1) {
		kind, name = pathmanager.PathTCPFallback, "tcp-fallback"
	}
	path, err := dataplane.NewRelayPath(name, nodeRelayCarrier{conn})
	if err != nil {
		return err
	}
	defer func() {
		for _, peer := range path.Peers() {
			s.config.DataPlane.Detach(peer, path.Name())
		}
	}()
	candidateConfigured := s.config.LocalCandidate != nil &&
		params.Capabilities.Has(protocol.CapabilityDirectPeerV1) && kind == pathmanager.PathRelayQUIC
	candidateSequence := uint64(2)
	if candidateConfigured && s.candidateExchangeEnabled() {
		envelope := &lanewayv1.RelayEnvelope{
			SchemaVersion: 1, Sequence: 2,
			Body: &lanewayv1.RelayEnvelope_EndpointCandidate{EndpointCandidate: proto.Clone(s.config.LocalCandidate).(*lanewayv1.EndpointCandidate)},
		}
		if err := writeMessage(conn.controlStream(), params.ControlFramer(), envelope); err != nil {
			return err
		}
		candidateSequence++
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	controlDone := make(chan error, 1)
	go func() { controlDone <- s.controlLoopUnified(sessionCtx, conn.controlStream(), params, path, kind) }()
	var candidateDone <-chan error
	if candidateConfigured {
		result := make(chan error, 1)
		candidateDone = result
		go func() { result <- s.candidatePublishLoop(sessionCtx, conn.controlStream(), params, candidateSequence) }()
	}
	receivedControl := false
	select {
	case err = <-controlDone:
		receivedControl = true
	case err = <-candidateDone:
	case <-sessionCtx.Done():
		err = sessionCtx.Err()
	case <-conn.done():
		err = errors.New("relay connection closed")
	}
	cancel()
	_ = conn.close()
	if !receivedControl {
		<-controlDone
	}
	return err
}

func (s *Service) candidatePublishLoop(ctx context.Context, stream io.Writer, params agent.SessionParameters, sequence uint64) error {
	ticker := time.NewTicker(s.config.DirectRendezvousInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if !s.candidateExchangeEnabled() {
			continue
		}
		envelope := &lanewayv1.RelayEnvelope{
			SchemaVersion: 1, Sequence: sequence,
			Body: &lanewayv1.RelayEnvelope_EndpointCandidate{EndpointCandidate: proto.Clone(s.config.LocalCandidate).(*lanewayv1.EndpointCandidate)},
		}
		if err := writeMessage(stream, params.ControlFramer(), envelope); err != nil {
			return err
		}
		sequence++
	}
}

func (s *Service) controlLoopUnified(ctx context.Context, stream io.Reader, params agent.SessionParameters, path *dataplane.RelayPath, kind pathmanager.PathKind) error {
	var sequence uint64 = 1
	for {
		envelope := new(lanewayv1.RelayEnvelope)
		if err := readMessage(stream, params.ControlFramer(), envelope); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if envelope.GetSchemaVersion() != 1 || envelope.GetSequence() != sequence {
			return ErrControlSequence
		}
		sequence++
		switch body := envelope.GetBody().(type) {
		case *lanewayv1.RelayEnvelope_RouteHandleBinding:
			binding := body.RouteHandleBinding
			if binding.GetRouteHandle() == 0 || len(binding.GetPeerNodeId()) != identity.IDSize || binding.GetMaxPacketPayload() == 0 {
				return ErrControlBody
			}
			var peer identity.NodeID
			copy(peer[:], binding.GetPeerNodeId())
			if peer.IsZero() {
				return ErrControlBody
			}
			if err := path.SetBinding(dataplane.RelayBinding{Peer: peer, Handle: binding.GetRouteHandle(), MaxPacketPayload: int(binding.GetMaxPacketPayload())}); err != nil {
				return err
			}
			if err := s.config.DataPlane.Attach(peer, kind, path); err != nil {
				return err
			}
		case *lanewayv1.RelayEnvelope_RouteHandleRelease:
			peer, ok := path.ReleaseHandle(body.RouteHandleRelease.GetRouteHandle())
			if !ok {
				return ErrControlBody
			}
			s.config.DataPlane.Detach(peer, path.Name())
		case *lanewayv1.RelayEnvelope_EndpointCandidate:
			if s.config.CandidateSink == nil || !params.Capabilities.Has(protocol.CapabilityDirectPeerV1) || body.EndpointCandidate == nil {
				return ErrControlBody
			}
			if !s.candidateExchangeEnabled() {
				continue
			}
			if err := s.config.CandidateSink.HandleCandidate(ctx, body.EndpointCandidate); err != nil {
				return err
			}
		case *lanewayv1.RelayEnvelope_Error:
			return agent.RemoteError(body.Error)
		default:
			return ErrControlBody
		}
	}
}

func (s *Service) handshake(stream io.ReadWriter) (agent.SessionParameters, error) {
	return s.handshakeWithCapabilities(stream, agent.RequiredRelayCapabilities)
}

func (s *Service) handshakeWithCapabilities(stream io.ReadWriter, capabilities protocol.Capability) (agent.SessionParameters, error) {
	handshake, err := agent.NewClientHandshake(s.config.Identity, s.config.BootID,
		protocol.Version{Major: protocol.ProtocolMajor1}, capabilities)
	if err != nil {
		return agent.SessionParameters{}, err
	}
	hello, err := handshake.HelloEnvelope()
	if err != nil {
		return agent.SessionParameters{}, err
	}
	framer := protocol.ControlFramer{MaxPayload: s.config.MaxControlPayload}
	if err := writeMessage(stream, framer, hello); err != nil {
		return agent.SessionParameters{}, err
	}
	welcome := new(lanewayv1.ControlEnvelope)
	if err := readMessage(stream, framer, welcome); err != nil {
		return agent.SessionParameters{}, err
	}
	params, err := handshake.AcceptWelcome(welcome, s.config.MaxControlPayload)
	if err != nil {
		return agent.SessionParameters{}, err
	}
	register := &lanewayv1.RelayEnvelope{
		SchemaVersion: 1,
		Sequence:      1,
		Body: &lanewayv1.RelayEnvelope_Register{Register: &lanewayv1.RelayRegister{
			SessionId:          append([]byte(nil), params.SessionID[:]...),
			RequestedMaxRoutes: s.config.MaxRoutes,
		}},
	}
	if err := writeMessage(stream, params.ControlFramer(), register); err != nil {
		return agent.SessionParameters{}, err
	}
	return params, nil
}

func (s *Service) controlLoop(ctx context.Context, stream io.Reader, params agent.SessionParameters) error {
	var sequence uint64 = 1
	for {
		envelope := new(lanewayv1.RelayEnvelope)
		if err := readMessage(stream, params.ControlFramer(), envelope); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.metrics.controlErrors.Add(1)
			return err
		}
		if envelope.GetSchemaVersion() != 1 || envelope.GetSequence() != sequence {
			s.metrics.controlErrors.Add(1)
			return ErrControlSequence
		}
		sequence++
		switch body := envelope.GetBody().(type) {
		case *lanewayv1.RelayEnvelope_RouteHandleBinding:
			binding := body.RouteHandleBinding
			if binding.GetRouteHandle() == 0 || len(binding.GetPeerNodeId()) != identity.IDSize || binding.GetMaxPacketPayload() == 0 {
				return ErrControlBody
			}
			var peer identity.NodeID
			copy(peer[:], binding.GetPeerNodeId())
			if peer.IsZero() {
				return ErrControlBody
			}
			s.bindings.set(peer, binding.GetRouteHandle())
		case *lanewayv1.RelayEnvelope_RouteHandleRelease:
			if body.RouteHandleRelease.GetRouteHandle() == 0 || !s.bindings.release(body.RouteHandleRelease.GetRouteHandle()) {
				return ErrControlBody
			}
		case *lanewayv1.RelayEnvelope_EndpointCandidate:
			// Reserved for direct-path selection; validated by that capability.
			continue
		case *lanewayv1.RelayEnvelope_Error:
			return agent.RemoteError(body.Error)
		default:
			return ErrControlBody
		}
	}
}

func (s *Service) outgoingLoop(ctx context.Context, conn nodeConnection, params agent.SessionParameters) error {
	packet := make([]byte, params.MaxPacketPayload)
	frame := make([]byte, 0, int(params.MaxPacketPayload)+protocol.PacketHeaderSize)
	for {
		n, err := s.config.Packets.ReadPacket(ctx, packet)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(packet) || protocol.ValidateIPPayload(packet[:n]) != nil {
			s.metrics.malformedPackets.Add(1)
			continue
		}
		source, destination, ok := packetAddresses(packet[:n])
		if !ok {
			s.metrics.malformedPackets.Add(1)
			continue
		}
		if !containsAddress(params.OverlayAddresses, s.currentForwardPrefixes(), source) {
			s.metrics.packetsDropped.Add(1)
			continue
		}
		route, ok := s.config.Routes.Lookup(destination)
		if !ok {
			s.metrics.packetsDropped.Add(1)
			continue
		}
		if s.config.PacketPolicy != nil && !s.config.PacketPolicy.Allow(s.config.Identity.NodeID, route.NextHop, packet[:n]) {
			s.metrics.packetsDropped.Add(1)
			continue
		}
		handle, ok := s.bindings.handle(route.NextHop)
		if !ok {
			s.metrics.packetsDropped.Add(1)
			continue
		}
		frame = frame[:0]
		frame, err = protocol.EncodePacket(frame, protocol.PacketHeader{Version: protocol.PacketVersion1, RouteHandle: handle}, packet[:n])
		if err != nil {
			s.metrics.malformedPackets.Add(1)
			continue
		}
		if err := conn.sendPacket(ctx, frame); err != nil {
			return err
		}
		s.metrics.packetsSent.Add(1)
	}
}

func (s *Service) incomingLoop(ctx context.Context, conn nodeConnection, params agent.SessionParameters) error {
	for {
		frame, owner, err := conn.receivePacket(ctx)
		if err != nil {
			return err
		}
		if err := s.processIncomingPacket(ctx, frame, owner, params); err != nil {
			return err
		}
	}
}

func (s *Service) processIncomingPacket(ctx context.Context, frame []byte, owner *packetbuffer.Buffer, params agent.SessionParameters) error {
	defer owner.Release()
	header, payload, err := protocol.DecodePacket(frame)
	if err != nil {
		s.metrics.malformedPackets.Add(1)
		return nil
	}
	peer, ok := s.bindings.peer(header.RouteHandle)
	if !ok {
		s.metrics.packetsDropped.Add(1)
		return nil
	}
	source, destination, ok := packetAddresses(payload)
	if !ok {
		s.metrics.malformedPackets.Add(1)
		return nil
	}
	route, found := s.config.Routes.Lookup(source)
	if !found || route.NextHop != peer {
		s.metrics.packetsDropped.Add(1)
		return nil
	}
	if !containsAddress(params.OverlayAddresses, s.currentForwardPrefixes(), destination) {
		s.metrics.packetsDropped.Add(1)
		return nil
	}
	if s.config.PacketPolicy != nil && !s.config.PacketPolicy.Allow(peer, s.config.Identity.NodeID, payload) {
		s.metrics.packetsDropped.Add(1)
		return nil
	}
	if err := s.config.Packets.WritePacket(ctx, payload); err != nil {
		return err
	}
	s.metrics.packetsReceived.Add(1)
	return nil
}

func containsAddress(addresses []netip.Addr, prefixes []netip.Prefix, address netip.Addr) bool {
	for _, candidate := range addresses {
		if candidate == address {
			return true
		}
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func writeMessage(w io.Writer, framer protocol.ControlFramer, message proto.Message) error {
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return err
	}
	return framer.Write(w, payload)
}

func readMessage(r io.Reader, framer protocol.ControlFramer, message proto.Message) error {
	payload, err := framer.Read(r)
	if err != nil {
		return err
	}
	return (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, message)
}

func packetAddresses(packet []byte) (netip.Addr, netip.Addr, bool) {
	if len(packet) < 20 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		var source, destination [4]byte
		copy(source[:], packet[12:16])
		copy(destination[:], packet[16:20])
		return netip.AddrFrom4(source), netip.AddrFrom4(destination), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		var source, destination [16]byte
		copy(source[:], packet[8:24])
		copy(destination[:], packet[24:40])
		return netip.AddrFrom16(source), netip.AddrFrom16(destination), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func (b *bindingTable) reset() {
	b.mu.Lock()
	clear(b.byPeer)
	clear(b.byHandle)
	b.mu.Unlock()
}

func (b *bindingTable) set(peer identity.NodeID, handle uint32) {
	b.mu.Lock()
	if old, ok := b.byPeer[peer]; ok {
		delete(b.byHandle, old)
	}
	if oldPeer, ok := b.byHandle[handle]; ok {
		delete(b.byPeer, oldPeer)
	}
	b.byPeer[peer] = handle
	b.byHandle[handle] = peer
	b.mu.Unlock()
}

func (b *bindingTable) release(handle uint32) bool {
	b.mu.Lock()
	peer, ok := b.byHandle[handle]
	if ok {
		delete(b.byHandle, handle)
		delete(b.byPeer, peer)
	}
	b.mu.Unlock()
	return ok
}

func (b *bindingTable) handle(peer identity.NodeID) (uint32, bool) {
	b.mu.RLock()
	handle, ok := b.byPeer[peer]
	b.mu.RUnlock()
	return handle, ok
}

func (b *bindingTable) peer(handle uint32) (identity.NodeID, bool) {
	b.mu.RLock()
	peer, ok := b.byHandle[handle]
	b.mu.RUnlock()
	return peer, ok
}

func (s *Service) Metrics() Metrics {
	return Metrics{
		Connections:      s.metrics.connections.Load(),
		Reconnects:       s.metrics.reconnects.Load(),
		PacketsSent:      s.metrics.packetsSent.Load(),
		PacketsReceived:  s.metrics.packetsReceived.Load(),
		PacketsDropped:   s.metrics.packetsDropped.Load(),
		MalformedPackets: s.metrics.malformedPackets.Load(),
		ControlErrors:    s.metrics.controlErrors.Load(),
		TCPConnections:   s.metrics.tcpConnections.Load(),
		QUICFailures:     s.metrics.quicFailures.Load(),
		TCPFailures:      s.metrics.tcpFailures.Load(),
	}
}

// IPv4Packet is a test/integration helper for constructing a complete packet.
func IPv4Packet(source, destination netip.Addr, payload []byte) ([]byte, error) {
	if !source.Is4() || !destination.Is4() || len(payload) > 65535-20 {
		return nil, errors.New("invalid IPv4 packet arguments")
	}
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 253
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	copy(packet[20:], payload)
	return packet, nil
}
