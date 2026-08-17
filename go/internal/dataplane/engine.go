// Package dataplane unifies Laneway packet routing across direct, relay QUIC,
// and TCP fallback paths.
package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/routing"
)

const DefaultMaxPacketSize = 65535

var (
	ErrInvalidConfiguration = errors.New("dataplane: invalid configuration")
	ErrAlreadyRunning       = errors.New("dataplane: engine already running")
	ErrPathNameConflict     = errors.New("dataplane: path name is already attached to another transport")
)

type PacketIO interface {
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) error
}

type PacketPolicy interface {
	Allow(source, destination identity.NodeID, packet []byte) bool
}

type PacketPolicyFunc func(identity.NodeID, identity.NodeID, []byte) bool

func (f PacketPolicyFunc) Allow(source, destination identity.NodeID, packet []byte) bool {
	return f(source, destination, packet)
}

type PathTable interface {
	pathmanager.PathManager
	AddPath(pathmanager.PeerID, pathmanager.PathKind, pathmanager.PacketPath) error
	RemovePath(pathmanager.PeerID, string) bool
}

type Config struct {
	Identity        identity.NodeIdentity
	Routes          *routing.Table
	Packets         PacketIO
	Paths           PathTable
	Policy          PacketPolicy
	LocalAddresses  []netip.Addr
	ForwardPrefixes []netip.Prefix
	MaxPacketSize   int
}

type Metrics struct {
	PacketsSent       uint64
	PacketsReceived   uint64
	PacketsDropped    uint64
	MalformedPackets  uint64
	PathFailures      uint64
	PathSwitchRetries uint64
}

type metricCounters struct {
	packetsSent       atomic.Uint64
	packetsReceived   atomic.Uint64
	packetsDropped    atomic.Uint64
	malformedPackets  atomic.Uint64
	pathFailures      atomic.Uint64
	pathSwitchRetries atomic.Uint64
}

type attachment struct {
	path   pathmanager.PacketPath
	peers  map[identity.NodeID]struct{}
	cancel context.CancelFunc
}

// Engine owns exactly one reader of Packets and one receiver goroutine per
// transport path. It never creates a goroutine per packet.
type Engine struct {
	config          Config
	metrics         metricCounters
	forwardPrefixes atomic.Pointer[forwardPrefixSnapshot]

	mu          sync.Mutex
	attachments map[string]*attachment
	runContext  context.Context
	runCancel   context.CancelFunc
	running     bool
	finished    bool
	wg          sync.WaitGroup
}

type forwardPrefixSnapshot struct {
	prefixes []netip.Prefix
}

// PathAvailable reports whether the unified dataplane currently has a usable
// carrier for peer. Unknown health is treated as usable because newly attached
// relay paths have not necessarily produced a sample yet; failed paths are not.
func (e *Engine) PathAvailable(peer identity.NodeID) bool {
	if e == nil || e.config.Paths == nil {
		return false
	}
	path := e.config.Paths.BestPath(peer)
	return path != nil && path.Health(peer).State != pathmanager.HealthFailed
}

func New(config Config) (*Engine, error) {
	if err := config.Identity.Validate(); err != nil || config.Routes == nil || config.Packets == nil || config.Paths == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = DefaultMaxPacketSize
	}
	if config.MaxPacketSize < 576 || config.MaxPacketSize > DefaultMaxPacketSize {
		return nil, ErrInvalidConfiguration
	}
	if len(config.LocalAddresses) == 0 && len(config.ForwardPrefixes) == 0 {
		return nil, ErrInvalidConfiguration
	}
	for _, address := range config.LocalAddresses {
		if !address.IsValid() || address.IsUnspecified() || address.Is4In6() {
			return nil, ErrInvalidConfiguration
		}
	}
	for _, prefix := range config.ForwardPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, ErrInvalidConfiguration
		}
	}
	config.LocalAddresses = append([]netip.Addr(nil), config.LocalAddresses...)
	config.ForwardPrefixes = append([]netip.Prefix(nil), config.ForwardPrefixes...)
	engine := &Engine{config: config, attachments: make(map[string]*attachment)}
	engine.forwardPrefixes.Store(&forwardPrefixSnapshot{prefixes: append([]netip.Prefix(nil), config.ForwardPrefixes...)})
	return engine, nil
}

// SetForwardPrefixes atomically replaces the controller-authorized subnet and
// exit destinations accepted by active packet loops.
func (e *Engine) SetForwardPrefixes(prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return ErrInvalidConfiguration
		}
	}
	e.forwardPrefixes.Store(&forwardPrefixSnapshot{prefixes: append([]netip.Prefix(nil), prefixes...)})
	return nil
}

// Attach registers a path as a candidate for peer and starts its single receive
// loop if Run is active. A shared relay/TCP path may be attached to many peers.
func (e *Engine) Attach(peer identity.NodeID, kind pathmanager.PathKind, path pathmanager.PacketPath) error {
	if peer.IsZero() || path == nil || path.Name() == "" {
		return ErrInvalidConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	attached := e.attachments[path.Name()]
	if attached != nil && !samePacketPath(attached.path, path) {
		return ErrPathNameConflict
	}
	if err := e.config.Paths.AddPath(peer, kind, path); err != nil {
		return err
	}
	if attached == nil {
		attached = &attachment{path: path, peers: make(map[identity.NodeID]struct{})}
		e.attachments[path.Name()] = attached
	}
	attached.peers[peer] = struct{}{}
	if e.running && attached.cancel == nil {
		e.startReceiverLocked(attached)
	}
	return nil
}

func samePacketPath(a, b pathmanager.PacketPath) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	return av.IsValid() && bv.IsValid() && av.Type() == bv.Type() && av.Comparable() && av.Interface() == bv.Interface()
}

func (e *Engine) Detach(peer identity.NodeID, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	removed := e.config.Paths.RemovePath(peer, name)
	attached := e.attachments[name]
	if attached == nil {
		return removed
	}
	delete(attached.peers, peer)
	if len(attached.peers) == 0 {
		if attached.cancel != nil {
			attached.cancel()
		}
		delete(e.attachments, name)
	}
	return removed
}

func (e *Engine) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.running || e.finished {
		e.mu.Unlock()
		return ErrAlreadyRunning
	}
	e.runContext, e.runCancel = context.WithCancel(ctx)
	e.running = true
	for _, attached := range e.attachments {
		e.startReceiverLocked(attached)
	}
	runContext := e.runContext
	e.mu.Unlock()

	err := e.outgoingLoop(runContext)
	e.mu.Lock()
	e.running = false
	e.finished = true
	e.runCancel()
	e.mu.Unlock()
	e.wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (e *Engine) Close() {
	e.mu.Lock()
	if e.runCancel != nil {
		e.runCancel()
	}
	e.mu.Unlock()
}

func (e *Engine) startReceiverLocked(attached *attachment) {
	receiveContext, cancel := context.WithCancel(e.runContext)
	attached.cancel = cancel
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.incomingLoop(receiveContext, attached)
	}()
}

func (e *Engine) outgoingLoop(ctx context.Context) error {
	packet := make([]byte, e.config.MaxPacketSize)
	for {
		n, err := e.config.Packets.ReadPacket(ctx, packet)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(packet) || protocol.ValidateIPPayload(packet[:n]) != nil {
			e.metrics.malformedPackets.Add(1)
			continue
		}
		source, destination, ok := packetAddresses(packet[:n])
		if !ok {
			e.metrics.malformedPackets.Add(1)
			continue
		}
		if !e.localAddress(source) {
			e.metrics.packetsDropped.Add(1)
			continue
		}
		route, ok := e.config.Routes.Lookup(destination)
		if !ok || route.NextHop.IsZero() {
			e.metrics.packetsDropped.Add(1)
			continue
		}
		if e.config.Policy != nil && !e.config.Policy.Allow(e.config.Identity.NodeID, route.NextHop, packet[:n]) {
			e.metrics.packetsDropped.Add(1)
			continue
		}
		if !e.sendWithFailover(ctx, route.NextHop, packet[:n]) {
			e.metrics.packetsDropped.Add(1)
		}
	}
}

func (e *Engine) sendWithFailover(ctx context.Context, peer identity.NodeID, packet []byte) bool {
	var visited [3]string
	visitedCount := 0
	for visitedCount < len(visited) {
		path := e.config.Paths.BestPath(peer)
		if path == nil {
			return false
		}
		name := path.Name()
		seen := false
		for i := range visitedCount {
			if visited[i] == name {
				seen = true
				break
			}
		}
		if seen {
			return false
		}
		visited[visitedCount] = name
		visitedCount++
		if maximum := path.MaxPayload(peer); maximum <= 0 || len(packet) > maximum {
			e.config.Paths.MarkFailed(peer, path.Name())
			e.metrics.pathFailures.Add(1)
			e.metrics.pathSwitchRetries.Add(1)
			continue
		}
		started := time.Now()
		if err := path.Send(ctx, peer, packet); err != nil {
			if ctx.Err() != nil {
				return false
			}
			e.config.Paths.Observe(peer, pathmanager.PathSample{Path: path.Name(), Lost: true, HardFailure: true, Reason: err.Error(), ObservedAt: time.Now()})
			e.metrics.pathFailures.Add(1)
			e.metrics.pathSwitchRetries.Add(1)
			continue
		}
		e.config.Paths.Observe(peer, pathmanager.PathSample{Path: path.Name(), Latency: time.Since(started), ObservedAt: time.Now()})
		e.metrics.packetsSent.Add(1)
		return true
	}
	return false
}

func (e *Engine) incomingLoop(ctx context.Context, attached *attachment) {
	for {
		received, err := attached.path.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if malformedPathError(err) {
				e.metrics.malformedPackets.Add(1)
				continue
			}
			e.failAttachment(attached, err)
			return
		}
		if e.handleIncomingPacket(ctx, attached, &received) {
			return
		}
	}
}

// handleIncomingPacket returns true when the engine must stop. It releases
// carrier-owned packet storage on every validation, policy, and write path.
func (e *Engine) handleIncomingPacket(ctx context.Context, attached *attachment, received *pathmanager.ReceivedPacket) bool {
	defer received.Release()
	if received.Peer.IsZero() || protocol.ValidateIPPayload(received.Packet) != nil {
		e.metrics.malformedPackets.Add(1)
		return false
	}
	source, destination, ok := packetAddresses(received.Packet)
	if !ok {
		e.metrics.malformedPackets.Add(1)
		return false
	}
	route, found := e.config.Routes.Lookup(source)
	if !found || route.NextHop != received.Peer || !e.localAddress(destination) {
		e.metrics.packetsDropped.Add(1)
		return false
	}
	if e.config.Policy != nil && !e.config.Policy.Allow(received.Peer, e.config.Identity.NodeID, received.Packet) {
		e.metrics.packetsDropped.Add(1)
		return false
	}
	if err := e.config.Packets.WritePacket(ctx, received.Packet); err != nil {
		if ctx.Err() == nil {
			e.Close()
		}
		return true
	}
	e.config.Paths.Observe(received.Peer, pathmanager.PathSample{Path: attached.path.Name(), ObservedAt: time.Now()})
	e.metrics.packetsReceived.Add(1)
	return false
}

func malformedPathError(err error) bool {
	return errors.Is(err, protocol.ErrShortPacket) || errors.Is(err, protocol.ErrUnsupportedVersion) ||
		errors.Is(err, protocol.ErrInvalidPacketFlags) || errors.Is(err, protocol.ErrInvalidRouteHandle) ||
		errors.Is(err, protocol.ErrPacketTooLarge) || errors.Is(err, protocol.ErrInvalidIPPacket) || errors.Is(err, ErrRelayBinding)
}

func (e *Engine) failAttachment(attached *attachment, err error) {
	e.mu.Lock()
	name := attached.path.Name()
	// A receiver belongs to the exact attachment pointer it was started for.
	// If a concurrent explicit detach already removed or replaced it, it must
	// not tear down the replacement.
	if e.attachments[name] != attached {
		e.mu.Unlock()
		return
	}
	for peer := range attached.peers {
		e.config.Paths.Observe(peer, pathmanager.PathSample{Path: name, Lost: true, HardFailure: true, Reason: err.Error(), ObservedAt: time.Now()})
		e.config.Paths.RemovePath(peer, name)
	}
	if attached.cancel != nil {
		attached.cancel()
		attached.cancel = nil
	}
	clear(attached.peers)
	delete(e.attachments, name)
	e.mu.Unlock()
	_ = attached.path.Close()
	e.metrics.pathFailures.Add(1)
}

func (e *Engine) localAddress(address netip.Addr) bool {
	for _, local := range e.config.LocalAddresses {
		if local == address {
			return true
		}
	}
	snapshot := e.forwardPrefixes.Load()
	if snapshot == nil {
		return false
	}
	for _, prefix := range snapshot.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
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

func (e *Engine) Metrics() Metrics {
	return Metrics{
		PacketsSent: e.metrics.packetsSent.Load(), PacketsReceived: e.metrics.packetsReceived.Load(),
		PacketsDropped: e.metrics.packetsDropped.Load(), MalformedPackets: e.metrics.malformedPackets.Load(),
		PathFailures: e.metrics.pathFailures.Load(), PathSwitchRetries: e.metrics.pathSwitchRetries.Load(),
	}
}
