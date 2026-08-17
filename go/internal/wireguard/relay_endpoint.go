package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

const (
	DefaultMaxRelayEndpointPeers = 4096
	relayEndpointReadInterval    = 250 * time.Millisecond
)

var (
	ErrInvalidRelayEndpoint = errors.New("wireguard: invalid relay endpoint configuration")
	ErrRelayEndpointClosed  = errors.New("wireguard: relay endpoint is closed")
	ErrRelayEndpointRunning = errors.New("wireguard: relay endpoint already has an active session")
)

// RelayEndpointConfig describes the loopback-only boundary between one kernel
// WireGuard interface and Laneway's authenticated relay carriers. KernelEndpoint
// is the local WireGuard UDP listener. ListenAddress must be a loopback address;
// one ephemeral UDP socket is allocated per authorized peer so opaque outgoing
// handshakes can be mapped to a NodeID without inspecting or decrypting them.
type RelayEndpointConfig struct {
	KernelEndpoint netip.AddrPort
	ListenAddress  netip.Addr
	MaxPeers       int
}

// RelayEndpointMetrics are local counters. Dropped packets never include packet
// contents and are split by the authorization boundary that rejected them.
type RelayEndpointMetrics struct {
	PacketsSent       uint64
	PacketsReceived   uint64
	PacketsDropped    uint64
	UnknownSources    uint64
	UnauthorizedPeers uint64
}

type relayEndpointPeer struct {
	id       identity.NodeID
	endpoint netip.AddrPort
	conn     *net.UDPConn
}

// RelayEndpoint keeps the kernel WireGuard device stable while authenticated
// QUIC/TCP relay sessions reconnect. ApplyPeers transactionally preserves
// sockets for retained peers and closes removed peers before any more packets
// can be forwarded for them.
type RelayEndpoint struct {
	kernel   netip.AddrPort
	listen   netip.Addr
	maxPeers int

	mu      sync.Mutex
	peers   map[identity.NodeID]*relayEndpointPeer
	changed chan struct{}
	closed  bool
	running bool

	packetsSent       atomic.Uint64
	packetsReceived   atomic.Uint64
	packetsDropped    atomic.Uint64
	unknownSources    atomic.Uint64
	unauthorizedPeers atomic.Uint64
}

func NewRelayEndpoint(config RelayEndpointConfig) (*RelayEndpoint, error) {
	if !validRelayKernelEndpoint(config.KernelEndpoint) {
		return nil, fmt.Errorf("%w: kernel endpoint must be a unicast loopback UDP address and nonzero port", ErrInvalidRelayEndpoint)
	}
	if !config.ListenAddress.IsValid() {
		if config.KernelEndpoint.Addr().Is4() {
			config.ListenAddress = netip.MustParseAddr("127.0.0.1")
		} else {
			config.ListenAddress = netip.IPv6Loopback()
		}
	}
	if !config.ListenAddress.IsLoopback() || config.ListenAddress.Is4In6() ||
		config.ListenAddress.BitLen() != config.KernelEndpoint.Addr().BitLen() {
		return nil, fmt.Errorf("%w: relay sockets must use the same loopback address family as the kernel endpoint", ErrInvalidRelayEndpoint)
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = DefaultMaxRelayEndpointPeers
	}
	if config.MaxPeers < 1 || config.MaxPeers > DefaultMaxRelayEndpointPeers {
		return nil, fmt.Errorf("%w: max peers must be in [1,%d]", ErrInvalidRelayEndpoint, DefaultMaxRelayEndpointPeers)
	}
	return &RelayEndpoint{
		kernel: config.KernelEndpoint, listen: config.ListenAddress, maxPeers: config.MaxPeers,
		peers: make(map[identity.NodeID]*relayEndpointPeer), changed: make(chan struct{}),
	}, nil
}

func validRelayKernelEndpoint(endpoint netip.AddrPort) bool {
	return endpoint.IsValid() && endpoint.Port() != 0 && endpoint.Addr().IsLoopback() && !endpoint.Addr().Is4In6()
}

// ApplyPeers atomically publishes an exact authorized peer set. New sockets are
// fully staged before publication; a bind failure leaves the old set untouched.
func (e *RelayEndpoint) ApplyPeers(ctx context.Context, peers []identity.NodeID) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidRelayEndpoint)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(peers) > e.maxPeers {
		return fmt.Errorf("%w: %d peers exceeds limit %d", ErrInvalidRelayEndpoint, len(peers), e.maxPeers)
	}
	nextIDs := make(map[identity.NodeID]struct{}, len(peers))
	for _, peer := range peers {
		if peer.IsZero() {
			return fmt.Errorf("%w: zero peer identity", ErrInvalidRelayEndpoint)
		}
		if _, duplicate := nextIDs[peer]; duplicate {
			return fmt.Errorf("%w: duplicate peer %s", ErrInvalidRelayEndpoint, peer)
		}
		nextIDs[peer] = struct{}{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrRelayEndpointClosed
	}
	if sameRelayPeerSet(e.peers, nextIDs) {
		return nil
	}
	next := make(map[identity.NodeID]*relayEndpointPeer, len(peers))
	for peer := range nextIDs {
		if existing := e.peers[peer]; existing != nil {
			next[peer] = existing
			continue
		}
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(e.listen, 0)))
		if err != nil {
			for stagedPeer, staged := range next {
				if _, retained := e.peers[stagedPeer]; !retained {
					_ = staged.conn.Close()
				}
			}
			return fmt.Errorf("wireguard: allocate relay endpoint for peer %s: %w", peer, err)
		}
		endpoint := conn.LocalAddr().(*net.UDPAddr).AddrPort()
		next[peer] = &relayEndpointPeer{id: peer, endpoint: endpoint, conn: conn}
	}
	if err := ctx.Err(); err != nil {
		for stagedPeer, staged := range next {
			if _, retained := e.peers[stagedPeer]; !retained {
				_ = staged.conn.Close()
			}
		}
		return err
	}
	previous := e.peers
	e.peers = next
	close(e.changed)
	e.changed = make(chan struct{})
	for peer, removed := range previous {
		if _, retained := next[peer]; !retained {
			_ = removed.conn.Close()
		}
	}
	return nil
}

func sameRelayPeerSet(current map[identity.NodeID]*relayEndpointPeer, next map[identity.NodeID]struct{}) bool {
	if len(current) != len(next) {
		return false
	}
	for peer := range next {
		if current[peer] == nil {
			return false
		}
	}
	return true
}

// Endpoints returns the loopback peer endpoints that must be installed in the
// kernel WireGuard peer snapshot. Retained peers keep the same endpoint.
func (e *RelayEndpoint) Endpoints() map[identity.NodeID]netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make(map[identity.NodeID]netip.AddrPort, len(e.peers))
	for peer, entry := range e.peers {
		result[peer] = entry.endpoint
	}
	return result
}

func (e *RelayEndpoint) Peers() []identity.NodeID {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]identity.NodeID, 0, len(e.peers))
	for peer := range e.peers {
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result
}

func (e *RelayEndpoint) Metrics() RelayEndpointMetrics {
	return RelayEndpointMetrics{
		PacketsSent: e.packetsSent.Load(), PacketsReceived: e.packetsReceived.Load(),
		PacketsDropped: e.packetsDropped.Load(), UnknownSources: e.unknownSources.Load(),
		UnauthorizedPeers: e.unauthorizedPeers.Load(),
	}
}

// RunCarriers keeps the loopback kernel sockets active independently of relay
// session reconnects. Carrier attachments may be added or removed while it is
// running; neither operation changes the kernel WireGuard interface.
func (e *RelayEndpoint) RunCarriers(ctx context.Context, carriers *CarrierMux) error {
	if ctx == nil || carriers == nil {
		return fmt.Errorf("%w: missing context or carrier mux", ErrInvalidRelayEndpoint)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrRelayEndpointClosed
	}
	if e.running {
		e.mu.Unlock()
		return ErrRelayEndpointRunning
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()

	carrierDone := make(chan error, 1)
	go func() { carrierDone <- carriers.Run(ctx, e.deliverCarrier) }()
	for {
		peers, changed, closed := e.snapshot()
		if closed {
			carriers.Close()
			<-carrierDone
			return ErrRelayEndpointClosed
		}
		workerCtx, cancelWorkers := context.WithCancel(ctx)
		outboundDone := e.startCarrierOutbound(workerCtx, carriers, peers)
		select {
		case <-ctx.Done():
			cancelWorkers()
			carriers.Close()
			<-outboundDone
			<-carrierDone
			return ctx.Err()
		case err := <-carrierDone:
			cancelWorkers()
			<-outboundDone
			return err
		case <-changed:
			cancelWorkers()
			<-outboundDone
		case err := <-outboundDone:
			cancelWorkers()
			carriers.Close()
			<-carrierDone
			return err
		}
	}
}

func (e *RelayEndpoint) startCarrierOutbound(ctx context.Context, carriers *CarrierMux, peers []*relayEndpointPeer) <-chan error {
	done := make(chan error, 1)
	if len(peers) == 0 {
		go func() { <-ctx.Done(); done <- ctx.Err() }()
		return done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	errorsCh := make(chan error, len(peers))
	var workers sync.WaitGroup
	for _, peer := range peers {
		workers.Add(1)
		go func(peer *relayEndpointPeer) {
			defer workers.Done()
			if err := e.forwardKernelCarrier(workerCtx, carriers, peer); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errorsCh <- err:
				default:
				}
			}
		}(peer)
	}
	go func() {
		workers.Wait()
		close(errorsCh)
	}()
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			cancel()
			workers.Wait()
			done <- ctx.Err()
		case err, ok := <-errorsCh:
			if !ok {
				done <- ctx.Err()
				return
			}
			cancel()
			workers.Wait()
			done <- err
		}
	}()
	return done
}

func (e *RelayEndpoint) forwardKernelCarrier(ctx context.Context, carriers *CarrierMux, peer *relayEndpointPeer) error {
	buffer := make([]byte, protocol.MaxPacketPayload+1)
	for {
		if err := peer.conn.SetReadDeadline(time.Now().Add(relayEndpointReadInterval)); err != nil {
			return err
		}
		n, source, err := peer.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			if !e.owns(peer) {
				<-ctx.Done()
				return ctx.Err()
			}
			return fmt.Errorf("wireguard: read kernel packet for peer %s: %w", peer.id, err)
		}
		if source != e.kernel {
			e.unknownSources.Add(1)
			e.packetsDropped.Add(1)
			continue
		}
		if n > protocol.MaxPacketPayload {
			e.packetsDropped.Add(1)
			continue
		}
		if err := carriers.Send(ctx, peer.id, buffer[:n]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			e.packetsDropped.Add(1)
			continue
		}
		e.packetsSent.Add(1)
	}
}

func (e *RelayEndpoint) deliverCarrier(_ context.Context, peerID identity.NodeID, packet []byte) error {
	peer := e.peer(peerID)
	if peer == nil {
		e.unauthorizedPeers.Add(1)
		e.packetsDropped.Add(1)
		return ErrCarrierUnauthorized
	}
	if _, err := peer.conn.WriteToUDPAddrPort(packet, e.kernel); err != nil {
		if !e.owns(peer) {
			e.unauthorizedPeers.Add(1)
			e.packetsDropped.Add(1)
			return ErrCarrierUnauthorized
		}
		return fmt.Errorf("wireguard: deliver carrier packet for peer %s: %w", peer.id, err)
	}
	e.packetsReceived.Add(1)
	return nil
}

// RunRelay attaches one authenticated relay session. Only one session may be
// active; reconnects reuse the endpoint sockets and therefore do not recreate
// the kernel WireGuard interface or change peer endpoints.
func (e *RelayEndpoint) RunRelay(ctx context.Context, mux *RelayMux) error {
	if ctx == nil || mux == nil {
		return fmt.Errorf("%w: missing context or relay mux", ErrInvalidRelayEndpoint)
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ErrRelayEndpointClosed
	}
	if e.running {
		e.mu.Unlock()
		return ErrRelayEndpointRunning
	}
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.mu.Unlock()
	}()
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	inboundDone := make(chan error, 1)
	go func() { inboundDone <- e.receiveRelay(sessionCtx, mux) }()
	for {
		peers, changed, closed := e.snapshot()
		if closed {
			return ErrRelayEndpointClosed
		}
		workerCtx, cancelWorkers := context.WithCancel(sessionCtx)
		outboundDone := e.startOutbound(workerCtx, mux, peers)
		select {
		case <-ctx.Done():
			cancelSession()
			cancelWorkers()
			<-outboundDone
			return ctx.Err()
		case err := <-inboundDone:
			cancelSession()
			cancelWorkers()
			<-outboundDone
			return err
		case <-changed:
			cancelWorkers()
			<-outboundDone
		case err := <-outboundDone:
			cancelSession()
			cancelWorkers()
			return err
		}
	}
}

func (e *RelayEndpoint) snapshot() ([]*relayEndpointPeer, <-chan struct{}, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	peers := make([]*relayEndpointPeer, 0, len(e.peers))
	for _, peer := range e.peers {
		peers = append(peers, peer)
	}
	return peers, e.changed, e.closed
}

func (e *RelayEndpoint) startOutbound(ctx context.Context, mux *RelayMux, peers []*relayEndpointPeer) <-chan error {
	done := make(chan error, 1)
	if len(peers) == 0 {
		go func() { <-ctx.Done(); done <- ctx.Err() }()
		return done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	errorsCh := make(chan error, len(peers))
	var workers sync.WaitGroup
	for _, peer := range peers {
		workers.Add(1)
		go func(peer *relayEndpointPeer) {
			defer workers.Done()
			if err := e.forwardKernel(workerCtx, mux, peer); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errorsCh <- err:
				default:
				}
			}
		}(peer)
	}
	go func() {
		workers.Wait()
		close(errorsCh)
	}()
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			cancel()
			workers.Wait()
			done <- ctx.Err()
		case err, ok := <-errorsCh:
			if !ok {
				done <- ctx.Err()
				return
			}
			cancel()
			workers.Wait()
			done <- err
		}
	}()
	return done
}

func (e *RelayEndpoint) forwardKernel(ctx context.Context, mux *RelayMux, peer *relayEndpointPeer) error {
	buffer := make([]byte, protocol.MaxPacketPayload+1)
	for {
		if err := peer.conn.SetReadDeadline(time.Now().Add(relayEndpointReadInterval)); err != nil {
			return err
		}
		n, source, err := peer.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				continue
			}
			if !e.owns(peer) {
				<-ctx.Done()
				return ctx.Err()
			}
			return fmt.Errorf("wireguard: read kernel packet for peer %s: %w", peer.id, err)
		}
		if source != e.kernel {
			e.unknownSources.Add(1)
			e.packetsDropped.Add(1)
			continue
		}
		if n > protocol.MaxPacketPayload {
			e.packetsDropped.Add(1)
			continue
		}
		if err := mux.Send(ctx, peer.id, buffer[:n]); err != nil {
			if errors.Is(err, ErrRelayBinding) {
				e.unauthorizedPeers.Add(1)
				e.packetsDropped.Add(1)
				continue
			}
			return err
		}
		e.packetsSent.Add(1)
	}
}

func (e *RelayEndpoint) receiveRelay(ctx context.Context, mux *RelayMux) error {
	for {
		datagram, err := mux.Receive(ctx)
		if err != nil {
			return err
		}
		peer := e.peer(datagram.Peer)
		if peer == nil {
			datagram.Release()
			e.unauthorizedPeers.Add(1)
			e.packetsDropped.Add(1)
			continue
		}
		_, err = peer.conn.WriteToUDPAddrPort(datagram.Packet, e.kernel)
		datagram.Release()
		if err != nil {
			if !e.owns(peer) {
				e.unauthorizedPeers.Add(1)
				e.packetsDropped.Add(1)
				continue
			}
			return fmt.Errorf("wireguard: deliver relay packet for peer %s: %w", peer.id, err)
		}
		e.packetsReceived.Add(1)
	}
}

func (e *RelayEndpoint) peer(id identity.NodeID) *relayEndpointPeer {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.peers[id]
}

func (e *RelayEndpoint) owns(peer *relayEndpointPeer) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.closed && e.peers[peer.id] == peer
}

func (e *RelayEndpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.changed)
	peers := e.peers
	e.peers = make(map[identity.NodeID]*relayEndpointPeer)
	e.mu.Unlock()
	var result error
	for _, peer := range peers {
		result = errors.Join(result, peer.conn.Close())
	}
	return result
}
