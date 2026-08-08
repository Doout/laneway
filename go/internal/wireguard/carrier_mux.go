package wireguard

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/protocol"
)

var (
	ErrCarrierMuxConfiguration = errors.New("wireguard: invalid carrier mux configuration")
	ErrCarrierUnavailable      = errors.New("wireguard: no encrypted carrier is available")
	ErrCarrierPathConflict     = errors.New("wireguard: carrier path name is already attached")
	ErrCarrierMuxRunning       = errors.New("wireguard: carrier mux is already running")
	ErrCarrierMuxClosed        = errors.New("wireguard: carrier mux is closed")
	ErrCarrierUnauthorized     = errors.New("wireguard: carrier peer is not authorized")
)

// CarrierMuxMetrics count opaque WireGuard messages at the carrier selection
// boundary. Packet contents and decrypted addresses are never observed here.
type CarrierMuxMetrics struct {
	PacketsSent       uint64
	PacketsReceived   uint64
	PacketsDropped    uint64
	PathFailures      uint64
	PathSwitchRetries uint64
}

// CarrierStatus is the bounded, non-secret view of one peer's encrypted
// carrier selection. Transport object names and endpoint addresses are not
// exposed because they may contain peer or network details.
type CarrierStatus struct {
	Selected string
	State    pathmanager.HealthState
}

type carrierMuxCounters struct {
	packetsSent       atomic.Uint64
	packetsReceived   atomic.Uint64
	packetsDropped    atomic.Uint64
	pathFailures      atomic.Uint64
	pathSwitchRetries atomic.Uint64
}

type carrierAttachment struct {
	path   pathmanager.PacketPath
	peers  map[identity.NodeID]struct{}
	cancel context.CancelFunc
}

// CarrierMux selects direct QUIC, relay QUIC, or TCP fallback for opaque
// WireGuard messages. It authenticates every received peer against the exact
// path attachment before handing ciphertext to the kernel boundary.
type CarrierMux struct {
	paths *pathmanager.Manager

	mu          sync.Mutex
	attachments map[string]*carrierAttachment
	runContext  context.Context
	runCancel   context.CancelFunc
	deliver     func(context.Context, identity.NodeID, []byte) error
	running     bool
	finished    bool
	closed      atomic.Bool
	wg          sync.WaitGroup
	metrics     carrierMuxCounters
}

func NewCarrierMux(config pathmanager.Config) (*CarrierMux, error) {
	paths, err := pathmanager.New(config)
	if err != nil {
		return nil, errors.Join(ErrCarrierMuxConfiguration, err)
	}
	return &CarrierMux{paths: paths, attachments: make(map[string]*carrierAttachment)}, nil
}

// Attach registers an authenticated carrier for one peer. A relay path may be
// shared by many peers, while direct paths normally have one peer attachment.
func (m *CarrierMux) Attach(peer identity.NodeID, kind pathmanager.PathKind, path pathmanager.PacketPath) error {
	if m == nil || peer.IsZero() || path == nil || path.Name() == "" {
		return ErrCarrierMuxConfiguration
	}
	if m.closed.Load() {
		return ErrCarrierMuxClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return ErrCarrierMuxClosed
	}
	attached := m.attachments[path.Name()]
	if attached != nil && !sameCarrierPath(attached.path, path) {
		return ErrCarrierPathConflict
	}
	if err := m.paths.AddPath(peer, kind, path); err != nil {
		return err
	}
	if attached == nil {
		attached = &carrierAttachment{path: path, peers: make(map[identity.NodeID]struct{})}
		m.attachments[path.Name()] = attached
	}
	attached.peers[peer] = struct{}{}
	if m.running && attached.cancel == nil {
		m.startReceiverLocked(attached)
	}
	return nil
}

func sameCarrierPath(first, second pathmanager.PacketPath) bool {
	firstValue, secondValue := reflect.ValueOf(first), reflect.ValueOf(second)
	return firstValue.IsValid() && secondValue.IsValid() && firstValue.Type() == secondValue.Type() &&
		firstValue.Comparable() && firstValue.Interface() == secondValue.Interface()
}

// Detach removes one peer binding without closing the transport. The owner of
// a direct or relay session remains responsible for its ordinary lifecycle.
func (m *CarrierMux) Detach(peer identity.NodeID, name string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := m.paths.RemovePath(peer, name)
	attached := m.attachments[name]
	if attached == nil {
		return removed
	}
	delete(attached.peers, peer)
	if len(attached.peers) == 0 {
		if attached.cancel != nil {
			attached.cancel()
		}
		delete(m.attachments, name)
	}
	return removed
}

// Send validates an opaque WireGuard message and retries the next selected
// carrier after a hard path failure. At most the three defined path kinds are
// attempted, so a faulty transport cannot create an unbounded retry loop.
func (m *CarrierMux) Send(ctx context.Context, peer identity.NodeID, packet []byte) error {
	if m == nil || ctx == nil || peer.IsZero() {
		return ErrCarrierMuxConfiguration
	}
	if m.closed.Load() {
		return ErrCarrierMuxClosed
	}
	if err := protocol.ValidateWireGuardPayload(packet); err != nil {
		m.metrics.packetsDropped.Add(1)
		return err
	}
	var visited [3]string
	for attempt := 0; attempt < len(visited); attempt++ {
		path := m.paths.BestPath(peer)
		if path == nil {
			m.metrics.packetsDropped.Add(1)
			return ErrCarrierUnavailable
		}
		name := path.Name()
		for index := 0; index < attempt; index++ {
			if visited[index] == name {
				m.metrics.packetsDropped.Add(1)
				return ErrCarrierUnavailable
			}
		}
		visited[attempt] = name
		if maximum := path.MaxPayload(peer); maximum <= 0 || len(packet) > maximum {
			m.paths.MarkFailed(peer, name)
			m.metrics.pathFailures.Add(1)
			m.metrics.pathSwitchRetries.Add(1)
			continue
		}
		started := time.Now()
		if err := path.Send(ctx, peer, packet); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			m.paths.Observe(peer, pathmanager.PathSample{Path: name, Lost: true, HardFailure: true, Reason: err.Error(), ObservedAt: time.Now()})
			m.metrics.pathFailures.Add(1)
			m.metrics.pathSwitchRetries.Add(1)
			continue
		}
		m.paths.Observe(peer, pathmanager.PathSample{Path: name, Latency: time.Since(started), ObservedAt: time.Now()})
		m.metrics.packetsSent.Add(1)
		return nil
	}
	m.metrics.packetsDropped.Add(1)
	return ErrCarrierUnavailable
}

// Run starts one receive loop per transport and delivers only structurally
// valid messages from peers attached to that exact authenticated path.
func (m *CarrierMux) Run(ctx context.Context, deliver func(context.Context, identity.NodeID, []byte) error) error {
	if m == nil || ctx == nil || deliver == nil {
		return ErrCarrierMuxConfiguration
	}
	if m.closed.Load() {
		return ErrCarrierMuxClosed
	}
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		return ErrCarrierMuxClosed
	}
	if m.running || m.finished {
		m.mu.Unlock()
		return ErrCarrierMuxRunning
	}
	m.runContext, m.runCancel = context.WithCancel(ctx)
	m.deliver = deliver
	m.running = true
	for _, attached := range m.attachments {
		m.startReceiverLocked(attached)
	}
	runContext := m.runContext
	m.mu.Unlock()

	<-runContext.Done()
	m.mu.Lock()
	m.running = false
	m.finished = true
	m.closed.Store(true)
	for _, attached := range m.attachments {
		if attached.cancel != nil {
			attached.cancel()
			attached.cancel = nil
		}
	}
	m.mu.Unlock()
	m.wg.Wait()
	return ctx.Err()
}

func (m *CarrierMux) startReceiverLocked(attached *carrierAttachment) {
	receiveContext, cancel := context.WithCancel(m.runContext)
	attached.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.receiveLoop(receiveContext, attached)
	}()
}

func (m *CarrierMux) receiveLoop(ctx context.Context, attached *carrierAttachment) {
	for {
		received, err := attached.path.Receive(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.failAttachment(attached, err)
			}
			return
		}
		func() {
			defer received.Release()
			if protocol.ValidateWireGuardPayload(received.Packet) != nil || !m.authorized(attached, received.Peer) {
				m.metrics.packetsDropped.Add(1)
				return
			}
			if err := m.deliver(ctx, received.Peer, received.Packet); err != nil {
				m.metrics.packetsDropped.Add(1)
				return
			}
			m.paths.Observe(received.Peer, pathmanager.PathSample{Path: attached.path.Name(), ObservedAt: time.Now()})
			m.metrics.packetsReceived.Add(1)
		}()
	}
}

func (m *CarrierMux) authorized(attached *carrierAttachment, peer identity.NodeID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.attachments[attached.path.Name()]
	if current != attached {
		return false
	}
	_, authorized := attached.peers[peer]
	return authorized
}

func (m *CarrierMux) failAttachment(attached *carrierAttachment, receiveErr error) {
	m.mu.Lock()
	name := attached.path.Name()
	if m.attachments[name] != attached {
		m.mu.Unlock()
		return
	}
	for peer := range attached.peers {
		m.paths.Observe(peer, pathmanager.PathSample{Path: name, Lost: true, HardFailure: true, Reason: receiveErr.Error(), ObservedAt: time.Now()})
		m.paths.RemovePath(peer, name)
	}
	delete(m.attachments, name)
	m.mu.Unlock()
	_ = attached.path.Close()
	m.metrics.pathFailures.Add(1)
}

func (m *CarrierMux) Metrics() CarrierMuxMetrics {
	if m == nil {
		return CarrierMuxMetrics{}
	}
	return CarrierMuxMetrics{
		PacketsSent: m.metrics.packetsSent.Load(), PacketsReceived: m.metrics.packetsReceived.Load(),
		PacketsDropped: m.metrics.packetsDropped.Load(), PathFailures: m.metrics.pathFailures.Load(),
		PathSwitchRetries: m.metrics.pathSwitchRetries.Load(),
	}
}

// PathMetrics reports aggregate selection health without exposing peers,
// endpoint addresses, or failure strings.
func (m *CarrierMux) PathMetrics() pathmanager.Metrics {
	if m == nil {
		return pathmanager.Metrics{}
	}
	return m.paths.Snapshot().Metrics()
}

// Carrier reports the selected product carrier for one authenticated peer.
// Peers with attached but unhealthy paths are degraded; peers whose paths are
// not yet selected are negotiating. Unknown peers are disconnected.
func (m *CarrierMux) Carrier(peer identity.NodeID) CarrierStatus {
	if m == nil || peer.IsZero() {
		return CarrierStatus{Selected: "disconnected", State: pathmanager.HealthUnknown}
	}
	view, ok := m.paths.Snapshot().Peer(peer)
	if !ok || len(view.Paths) == 0 {
		return CarrierStatus{Selected: "disconnected", State: pathmanager.HealthUnknown}
	}
	if view.Selected != "" {
		for _, path := range view.Paths {
			if path.Selected {
				return CarrierStatus{Selected: carrierProductName(path.Kind), State: path.State}
			}
		}
	}
	for _, path := range view.Paths {
		if path.State == pathmanager.HealthFailed || path.State == pathmanager.HealthProbing {
			return CarrierStatus{Selected: "degraded", State: path.State}
		}
	}
	return CarrierStatus{Selected: "negotiating", State: pathmanager.HealthUnknown}
}

func carrierProductName(kind pathmanager.PathKind) string {
	switch kind {
	case pathmanager.PathDirect:
		return "direct-wireguard"
	case pathmanager.PathRelayQUIC:
		return "wireguard-relay-quic"
	case pathmanager.PathTCPFallback:
		return "wireguard-relay-tcp"
	default:
		return "disconnected"
	}
}

func (m *CarrierMux) PathAvailable(peer identity.NodeID) bool {
	if m == nil || peer.IsZero() {
		return false
	}
	path := m.paths.BestPath(peer)
	return path != nil && path.Health(peer).State != pathmanager.HealthFailed
}

func (m *CarrierMux) Close() {
	if m == nil {
		return
	}
	m.closed.Store(true)
	m.mu.Lock()
	if m.runCancel != nil {
		m.runCancel()
	}
	m.mu.Unlock()
}

var _ interface {
	Attach(identity.NodeID, pathmanager.PathKind, pathmanager.PacketPath) error
	Detach(identity.NodeID, string) bool
} = (*CarrierMux)(nil)
