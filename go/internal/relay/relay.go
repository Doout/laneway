// Package relay implements the authenticated, transport-independent Laneway
// relay dataplane. Transport servers register sessions only after mutual TLS
// authentication and pass frames received on that exact session to Forward.
package relay

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
	"laneway.dev/laneway/internal/protocol"
)

var (
	ErrInvalidConfig           = errors.New("invalid relay configuration")
	ErrInvalidSession          = errors.New("invalid relay session")
	ErrInvalidPrefix           = errors.New("invalid authorized prefix")
	ErrRegistryClosed          = errors.New("relay registry is closed")
	ErrSessionClosed           = errors.New("relay session is closed")
	ErrSessionLimit            = errors.New("relay session limit reached")
	ErrDuplicateSession        = errors.New("duplicate relay session")
	ErrUnknownSession          = errors.New("unknown relay session")
	ErrCrossNetwork            = errors.New("relay peers belong to different networks")
	ErrSelfBinding             = errors.New("cannot bind a relay session to itself")
	ErrHandleLimit             = errors.New("relay handle limit reached")
	ErrHandleExhausted         = errors.New("relay handle space exhausted")
	ErrUnknownHandle           = errors.New("unknown relay route handle")
	ErrNoReturnHandle          = errors.New("recipient has no handle for the sender")
	ErrSourceUnauthorized      = errors.New("packet source is not authorized for sender")
	ErrDestinationUnauthorized = errors.New("packet destination is not authorized for recipient")
	ErrPacketTooLarge          = errors.New("packet exceeds session payload limit")
	ErrCapabilityNotNegotiated = errors.New("packet family capability was not negotiated")
	ErrQueueFull               = errors.New("relay outbound queue is full")
	ErrRateLimited             = errors.New("relay aggregate packet-data limit exhausted")
)

// DuplicatePolicy defines what Register does when the authenticated
// NetworkID+NodeID already has a live session.
type DuplicatePolicy uint8

const (
	RejectDuplicate DuplicatePolicy = iota
	ReplaceDuplicate
)

// QueuePolicy documents packet behavior when a bounded outbound queue is full.
// DropNewest never blocks a transport read loop and leaves already queued
// packets in FIFO order.
type QueuePolicy uint8

const (
	DropNewest QueuePolicy = iota
)

type Config struct {
	MaxSessions           int
	MaxHandlesPerSession  int
	OutboundQueueCapacity int
	MaxPacketPayload      int
	DuplicatePolicy       DuplicatePolicy
	QueuePolicy           QueuePolicy
	// PacketRateBitsPerSecond and PacketBurstBytes configure one aggregate
	// non-blocking bucket shared by every QUIC and TCP packet session. Both zero
	// disables limiting; otherwise both must be positive.
	PacketRateBitsPerSecond uint64
	PacketBurstBytes        int
}

type SessionConfig struct {
	Identity           identity.NodeIdentity
	AuthorizedPrefixes []netip.Prefix
	// MaxPacketPayload is the negotiated raw IP payload limit. Zero uses the
	// registry limit; a nonzero value may only reduce it.
	MaxPacketPayload int
	// AllowIPv6 must be true only when both transport endpoints negotiated
	// LANEWAY_IPV6_V1. IPv4 remains available for every v1 relay session.
	AllowIPv6 bool
}

type sessionKey struct {
	network identity.NetworkID
	node    identity.NodeID
}

// Session is one authenticated transport connection. It is safe for concurrent
// use. The Registry owns route bindings; the transport consumes frames through
// Dequeue or TryDequeue.
type Session struct {
	registry   *Registry
	identity   identity.NodeIdentity
	prefixes   prefixSet
	maxPayload int
	allowIPv6  bool

	// Binding state is mutated only on the control path under Registry.mu.
	// Forward never consults these maps: every mutation publishes a complete,
	// immutable registry-wide forwarding snapshot through Registry.forwarding. This keeps
	// packet lookup independent of the process-wide registry lock.
	byHandle   map[uint32]*Session
	byPeer     map[*Session]uint32
	nextHandle uint64
	active     atomic.Bool

	outbound *packetQueue
}

func (s *Session) Identity() identity.NodeIdentity { return s.identity }
func (s *Session) MaxPacketPayload() int           { return s.maxPayload }
func (s *Session) QueueCapacity() int              { return s.outbound.capacity() }
func (s *Session) QueueLen() int                   { return s.outbound.len() }
func (s *Session) Done() <-chan struct{}           { return s.outbound.done }

// AuthorizedPrefixes returns a defensive copy of the controller-authorized
// source/destination ownership set installed at registration.
func (s *Session) AuthorizedPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), s.prefixes.prefixes...)
}

// Dequeue waits for the next frame. Frames are returned in FIFO order and are
// owned by the caller. Disconnect discards pending frames and returns
// ErrSessionClosed.
func (s *Session) Dequeue(ctx context.Context) ([]byte, error) {
	buffer, err := s.DequeueBuffer(ctx)
	if err != nil {
		return nil, err
	}
	defer buffer.Release()
	return append([]byte(nil), buffer.Bytes()...), nil
}

// DequeueBuffer is the allocation-hardened form used by transport writers.
// The buffer remains owned by the caller until Release, which must happen only
// after the synchronous send operation returns.
func (s *Session) DequeueBuffer(ctx context.Context) (*packetbuffer.Buffer, error) {
	return s.outbound.dequeue(ctx)
}

// TryDequeue is the nonblocking form of Dequeue. ok is false when the queue is
// currently empty. ErrSessionClosed is returned after disconnect.
func (s *Session) TryDequeue() (frame []byte, ok bool, err error) {
	buffer, ok, err := s.outbound.tryDequeue()
	if err != nil || !ok {
		return nil, ok, err
	}
	defer buffer.Release()
	return append([]byte(nil), buffer.Bytes()...), true, nil
}

// Binding is the control-plane state a server communicates to Session. Handle
// is meaningful only when sent by that session and identifies PeerNodeID.
type Binding struct {
	Session          *Session
	Handle           uint32
	PeerNodeID       identity.NodeID
	MaxPacketPayload uint32
}

// BindingPair contains the two directional handles for a peer relationship.
type BindingPair struct {
	First  Binding
	Second Binding
}

// forwardingTable is an immutable dataplane snapshot. A route includes the
// peer's reverse handle so Forward never needs to read either session's
// control-plane maps. One registry snapshot containing every session table is
// built under Registry.mu and atomically replaced, so bilateral handle changes
// cannot become partially visible. Readers safely retain the old snapshot
// until their packet completes.
type forwardingTable struct {
	byHandle map[uint32]forwardingRoute
}

type registryForwarding struct {
	bySession map[*Session]*forwardingTable
}

type forwardingRoute struct {
	recipient    *Session
	returnHandle uint32
	hasReturn    bool
	maxPayload   int
}

// Registry owns all ephemeral session and handle state for one relay process.
type Registry struct {
	mu         sync.RWMutex
	config     Config
	sessions   map[sessionKey]*Session
	closed     bool
	metrics    counters
	frames     *packetbuffer.Pool
	limiter    *packetLimiter
	forwarding atomic.Pointer[registryForwarding]
}

func NewRegistry(config Config) (*Registry, error) {
	if config.MaxSessions <= 0 || config.MaxHandlesPerSession <= 0 ||
		config.OutboundQueueCapacity <= 0 || config.MaxPacketPayload <= 0 ||
		config.MaxPacketPayload > protocol.MaxPacketPayload ||
		(config.DuplicatePolicy != RejectDuplicate && config.DuplicatePolicy != ReplaceDuplicate) ||
		config.QueuePolicy != DropNewest ||
		((config.PacketRateBitsPerSecond == 0) != (config.PacketBurstBytes == 0)) ||
		config.PacketRateBitsPerSecond > 1_000_000_000_000 || config.PacketBurstBytes > 64<<20 ||
		(config.PacketBurstBytes != 0 && config.PacketBurstBytes < protocol.PacketHeaderSize+config.MaxPacketPayload) {
		return nil, ErrInvalidConfig
	}
	registry := &Registry{
		config: config, sessions: make(map[sessionKey]*Session),
		frames:  packetbuffer.NewPool(protocol.PacketHeaderSize + config.MaxPacketPayload),
		limiter: newPacketLimiter(config.PacketRateBitsPerSecond, config.PacketBurstBytes),
	}
	registry.forwarding.Store(&registryForwarding{bySession: map[*Session]*forwardingTable{}})
	return registry, nil
}

// Register installs an authenticated session. With ReplaceDuplicate, the old
// connection is atomically detached before the new one becomes visible. A late
// Unregister call for the old connection cannot remove its replacement.
func (r *Registry) Register(config SessionConfig) (*Session, error) {
	if config.Identity.NetworkID.IsZero() || config.Identity.NodeID.IsZero() {
		return nil, ErrInvalidSession
	}
	prefixes, err := newPrefixSet(config.AuthorizedPrefixes)
	if err != nil {
		return nil, err
	}
	maxPayload := config.MaxPacketPayload
	if maxPayload == 0 {
		maxPayload = r.config.MaxPacketPayload
	}
	if maxPayload <= 0 || maxPayload > r.config.MaxPacketPayload {
		return nil, fmt.Errorf("%w: max packet payload %d", ErrInvalidSession, maxPayload)
	}

	s := &Session{
		registry:   r,
		identity:   config.Identity,
		prefixes:   prefixes,
		maxPayload: maxPayload,
		allowIPv6:  config.AllowIPv6,
		byHandle:   make(map[uint32]*Session),
		byPeer:     make(map[*Session]uint32),
		nextHandle: 1,
		outbound:   newPacketQueue(r.config.OutboundQueueCapacity),
	}
	s.active.Store(true)
	key := keyFor(s.identity)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		s.active.Store(false)
		s.outbound.close()
		return nil, ErrRegistryClosed
	}
	if old := r.sessions[key]; old != nil {
		if r.config.DuplicatePolicy == RejectDuplicate {
			r.metrics.duplicateRejected.Add(1)
			r.mu.Unlock()
			s.active.Store(false)
			s.outbound.close()
			return nil, ErrDuplicateSession
		}
		r.detachLocked(old)
		r.metrics.sessionsReplaced.Add(1)
	}
	if len(r.sessions) >= r.config.MaxSessions {
		r.mu.Unlock()
		s.active.Store(false)
		s.outbound.close()
		return nil, ErrSessionLimit
	}
	r.sessions[key] = s
	r.publishForwardingLocked()
	r.metrics.registrations.Add(1)
	r.mu.Unlock()
	return s, nil
}

// Lookup returns the current session for an authenticated identity.
func (r *Registry) Lookup(network identity.NetworkID, node identity.NodeID) (*Session, bool) {
	r.mu.RLock()
	s := r.sessions[sessionKey{network: network, node: node}]
	ok := s != nil && s.active.Load()
	r.mu.RUnlock()
	return s, ok
}

// BindPeers atomically creates any missing directional handles between two live
// sessions in the same network. Repeated calls are idempotent while both
// bindings remain installed.
func (r *Registry) BindPeers(first, second *Session) (BindingPair, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.currentLocked(first) || !r.currentLocked(second) {
		return BindingPair{}, ErrUnknownSession
	}
	if first == second {
		return BindingPair{}, ErrSelfBinding
	}
	if first.identity.NetworkID != second.identity.NetworkID {
		return BindingPair{}, ErrCrossNetwork
	}

	firstHandle, firstExists := first.byPeer[second]
	secondHandle, secondExists := second.byPeer[first]
	neededFirst, neededSecond := !firstExists, !secondExists
	if neededFirst && len(first.byHandle) >= r.config.MaxHandlesPerSession ||
		neededSecond && len(second.byHandle) >= r.config.MaxHandlesPerSession {
		return BindingPair{}, ErrHandleLimit
	}
	if neededFirst && first.nextHandle > math.MaxUint32 ||
		neededSecond && second.nextHandle > math.MaxUint32 {
		return BindingPair{}, ErrHandleExhausted
	}
	if neededFirst {
		firstHandle = uint32(first.nextHandle)
		first.nextHandle++
		first.byHandle[firstHandle] = second
		first.byPeer[second] = firstHandle
		r.metrics.bindingsCreated.Add(1)
	}
	if neededSecond {
		secondHandle = uint32(second.nextHandle)
		second.nextHandle++
		second.byHandle[secondHandle] = first
		second.byPeer[first] = secondHandle
		r.metrics.bindingsCreated.Add(1)
	}
	r.publishForwardingLocked()
	limit := min(first.maxPayload, second.maxPayload)
	return BindingPair{
		First:  Binding{Session: first, Handle: firstHandle, PeerNodeID: second.identity.NodeID, MaxPacketPayload: uint32(limit)},
		Second: Binding{Session: second, Handle: secondHandle, PeerNodeID: first.identity.NodeID, MaxPacketPayload: uint32(limit)},
	}, nil
}

// Release removes one directional handle. The peer's reverse handle remains
// installed until explicitly released or either session disconnects.
func (r *Registry) Release(session *Session, handle uint32) error {
	if handle == 0 {
		return ErrUnknownHandle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.currentLocked(session) {
		return ErrUnknownSession
	}
	peer := session.byHandle[handle]
	if peer == nil {
		return ErrUnknownHandle
	}
	delete(session.byHandle, handle)
	delete(session.byPeer, peer)
	// The reverse direction remains installed by design, but the single atomic
	// publication makes it lose its embedded return handle at the same instant.
	r.publishForwardingLocked()
	r.metrics.bindingsReleased.Add(1)
	return nil
}

// Unregister atomically invalidates a session, removes every local and peer-side
// handle referring to it, discards queued frames, and wakes blocked Dequeue calls.
// It returns false for a stale or already removed session.
func (r *Registry) Unregister(session *Session) bool {
	if session == nil {
		return false
	}
	r.mu.Lock()
	if !r.currentLocked(session) {
		r.mu.Unlock()
		return false
	}
	r.detachLocked(session)
	r.publishForwardingLocked()
	r.metrics.unregistrations.Add(1)
	r.mu.Unlock()
	return true
}

// Close unregisters all sessions and permanently rejects new registrations.
func (r *Registry) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	for _, session := range r.sessions {
		if session.active.Load() {
			r.detachLocked(session)
			r.metrics.unregistrations.Add(1)
		}
	}
	r.publishForwardingLocked()
	r.mu.Unlock()
}

func (r *Registry) currentLocked(s *Session) bool {
	return s != nil && s.registry == r && s.active.Load() && r.sessions[keyFor(s.identity)] == s
}

func (r *Registry) detachLocked(session *Session) {
	delete(r.sessions, keyFor(session.identity))
	session.active.Store(false)
	for handle, peer := range session.byHandle {
		delete(session.byHandle, handle)
		delete(session.byPeer, peer)
		r.metrics.bindingsReleased.Add(1)
		if reverse, ok := peer.byPeer[session]; ok {
			delete(peer.byPeer, session)
			delete(peer.byHandle, reverse)
			r.metrics.bindingsReleased.Add(1)
		}
	}
	// A one-way Release may have removed session's local record while leaving a
	// peer's reverse direction installed. Disconnect must invalidate those
	// handles too. This bounded registry scan is a cold-path operation.
	for _, peer := range r.sessions {
		if peer == session {
			continue
		}
		if handle, ok := peer.byPeer[session]; ok {
			delete(peer.byPeer, session)
			delete(peer.byHandle, handle)
			r.metrics.bindingsReleased.Add(1)
		}
	}
	discarded, discardedBytes := session.outbound.close()
	r.metrics.droppedDisconnect.Add(uint64(discarded))
	r.metrics.droppedPackets.Add(uint64(discarded))
	r.metrics.droppedBytes.Add(discardedBytes)
}

func (r *Registry) publishForwardingLocked() {
	snapshot := &registryForwarding{bySession: make(map[*Session]*forwardingTable, len(r.sessions))}
	for _, session := range r.sessions {
		if !session.active.Load() {
			continue
		}
		table := &forwardingTable{byHandle: make(map[uint32]forwardingRoute, len(session.byHandle))}
		for handle, recipient := range session.byHandle {
			returnHandle, hasReturn := recipient.byPeer[session]
			table.byHandle[handle] = forwardingRoute{
				recipient: recipient, returnHandle: returnHandle, hasReturn: hasReturn,
				maxPayload: min(session.maxPayload, recipient.maxPayload),
			}
		}
		snapshot.bySession[session] = table
	}
	r.forwarding.Store(snapshot)
}

func keyFor(id identity.NodeIdentity) sessionKey {
	return sessionKey{network: id.NetworkID, node: id.NodeID}
}

type prefixSet struct{ prefixes []netip.Prefix }

func newPrefixSet(prefixes []netip.Prefix) (prefixSet, error) {
	set := prefixSet{prefixes: make([]netip.Prefix, len(prefixes))}
	for i, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return prefixSet{}, fmt.Errorf("%w: %v", ErrInvalidPrefix, prefix)
		}
		set.prefixes[i] = prefix
	}
	return set, nil
}

func (s prefixSet) contains(addr netip.Addr) bool {
	for _, prefix := range s.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type packetQueue struct {
	mu     sync.Mutex
	frames []*packetbuffer.Buffer
	head   int
	size   int
	closed bool
	notify chan struct{}
	done   chan struct{}
}

func newPacketQueue(capacity int) *packetQueue {
	return &packetQueue{frames: make([]*packetbuffer.Buffer, capacity), notify: make(chan struct{}, 1), done: make(chan struct{})}
}

func (q *packetQueue) capacity() int { return len(q.frames) }

func (q *packetQueue) len() int {
	q.mu.Lock()
	n := q.size
	q.mu.Unlock()
	return n
}

func (q *packetQueue) enqueue(frame *packetbuffer.Buffer) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrSessionClosed
	}
	if q.size == len(q.frames) {
		return ErrQueueFull
	}
	q.frames[(q.head+q.size)%len(q.frames)] = frame
	q.size++
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return nil
}

func (q *packetQueue) tryDequeue() (*packetbuffer.Buffer, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil, false, ErrSessionClosed
	}
	if q.size == 0 {
		return nil, false, nil
	}
	frame := q.popLocked()
	return frame, true, nil
}

func (q *packetQueue) dequeue(ctx context.Context) (*packetbuffer.Buffer, error) {
	for {
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return nil, ErrSessionClosed
		}
		if q.size > 0 {
			frame := q.popLocked()
			q.mu.Unlock()
			return frame, nil
		}
		notify, done := q.notify, q.done
		q.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-done:
			return nil, ErrSessionClosed
		case <-notify:
		}
	}
}

func (q *packetQueue) popLocked() *packetbuffer.Buffer {
	frame := q.frames[q.head]
	q.frames[q.head] = nil
	q.head = (q.head + 1) % len(q.frames)
	q.size--
	if q.size > 0 {
		select {
		case q.notify <- struct{}{}:
		default:
		}
	}
	return frame
}

func (q *packetQueue) close() (int, uint64) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return 0, 0
	}
	q.closed = true
	discarded := q.size
	var discardedBytes uint64
	for i, frame := range q.frames {
		if frame != nil {
			discardedBytes += uint64(len(frame.Bytes()))
			frame.Release()
			q.frames[i] = nil
		}
	}
	q.size = 0
	close(q.done)
	q.mu.Unlock()
	return discarded, discardedBytes
}

type counters struct {
	registrations        atomic.Uint64
	unregistrations      atomic.Uint64
	duplicateRejected    atomic.Uint64
	sessionsReplaced     atomic.Uint64
	bindingsCreated      atomic.Uint64
	bindingsReleased     atomic.Uint64
	forwardedPackets     atomic.Uint64
	forwardedBytes       atomic.Uint64
	droppedMalformed     atomic.Uint64
	droppedUnknownHandle atomic.Uint64
	droppedNoReturn      atomic.Uint64
	droppedSource        atomic.Uint64
	droppedDestination   atomic.Uint64
	droppedTooLarge      atomic.Uint64
	droppedCapability    atomic.Uint64
	droppedQueueFull     atomic.Uint64
	droppedClosed        atomic.Uint64
	droppedDisconnect    atomic.Uint64
	throttledPackets     atomic.Uint64
	throttledBytes       atomic.Uint64
	droppedPackets       atomic.Uint64
	droppedBytes         atomic.Uint64
}

// Metrics is a point-in-time, concurrency-safe snapshot. Counter fields are
// monotonic; Sessions, Bindings, QueuedPackets, and QueuedBytes are gauges.
type Metrics struct {
	Sessions              uint64
	Bindings              uint64
	QueuedPackets         uint64
	QueuedBytes           uint64
	Registrations         uint64
	Unregistrations       uint64
	DuplicateRejected     uint64
	SessionsReplaced      uint64
	BindingsCreated       uint64
	BindingsReleased      uint64
	ForwardedPackets      uint64
	ForwardedBytes        uint64
	DroppedMalformed      uint64
	DroppedUnknownHandle  uint64
	DroppedNoReturnHandle uint64
	DroppedSource         uint64
	DroppedDestination    uint64
	DroppedTooLarge       uint64
	DroppedCapability     uint64
	DroppedQueueFull      uint64
	DroppedClosed         uint64
	DroppedDisconnect     uint64
	ThrottledPackets      uint64
	ThrottledBytes        uint64
	LimiterSaturated      uint64
	DroppedPackets        uint64
	DroppedBytes          uint64
}

func (r *Registry) Metrics() Metrics {
	m := Metrics{
		Registrations: r.metrics.registrations.Load(), Unregistrations: r.metrics.unregistrations.Load(),
		DuplicateRejected: r.metrics.duplicateRejected.Load(), SessionsReplaced: r.metrics.sessionsReplaced.Load(),
		BindingsCreated: r.metrics.bindingsCreated.Load(), BindingsReleased: r.metrics.bindingsReleased.Load(),
		ForwardedPackets: r.metrics.forwardedPackets.Load(), ForwardedBytes: r.metrics.forwardedBytes.Load(),
		DroppedMalformed: r.metrics.droppedMalformed.Load(), DroppedUnknownHandle: r.metrics.droppedUnknownHandle.Load(),
		DroppedNoReturnHandle: r.metrics.droppedNoReturn.Load(), DroppedSource: r.metrics.droppedSource.Load(),
		DroppedDestination: r.metrics.droppedDestination.Load(), DroppedTooLarge: r.metrics.droppedTooLarge.Load(),
		DroppedCapability: r.metrics.droppedCapability.Load(),
		DroppedQueueFull:  r.metrics.droppedQueueFull.Load(), DroppedClosed: r.metrics.droppedClosed.Load(),
		DroppedDisconnect: r.metrics.droppedDisconnect.Load(),
		ThrottledPackets:  r.metrics.throttledPackets.Load(), ThrottledBytes: r.metrics.throttledBytes.Load(),
		DroppedPackets: r.metrics.droppedPackets.Load(), DroppedBytes: r.metrics.droppedBytes.Load(),
	}
	if r.limiter.saturated() {
		m.LimiterSaturated = 1
	}
	r.mu.RLock()
	m.Sessions = uint64(len(r.sessions))
	for _, session := range r.sessions {
		m.Bindings += uint64(len(session.byHandle))
		session.outbound.mu.Lock()
		m.QueuedPackets += uint64(session.outbound.size)
		for i := 0; i < session.outbound.size; i++ {
			m.QueuedBytes += uint64(len(session.outbound.frames[(session.outbound.head+i)%len(session.outbound.frames)].Bytes()))
		}
		session.outbound.mu.Unlock()
	}
	r.mu.RUnlock()
	return m
}
