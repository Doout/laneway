package platform

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
)

// MemoryTUN is an unprivileged, bounded TUN implementation for tests. Inject
// supplies a packet as if read from the kernel; Receive observes a packet
// written toward the kernel.
type MemoryTUN struct {
	name      string
	mtu       int
	addresses []netip.Prefix
	inbound   chan []byte
	outbound  chan []byte
	done      chan struct{}
	close     sync.Once
}

var _ TUNDevice = (*MemoryTUN)(nil)

func NewMemoryTUN(config TUNConfig, queueDepth int) (*MemoryTUN, error) {
	config, err := normalizeTUNConfig(config)
	if err != nil {
		return nil, err
	}
	if queueDepth <= 0 {
		return nil, fmt.Errorf("%w: queue depth must be positive", ErrInvalidTUN)
	}
	return &MemoryTUN{
		name: config.Name, mtu: config.MTU, addresses: append([]netip.Prefix(nil), config.Addresses...),
		inbound: make(chan []byte, queueDepth), outbound: make(chan []byte, queueDepth),
		done: make(chan struct{}),
	}, nil
}

func (t *MemoryTUN) Name() string { return t.name }
func (t *MemoryTUN) MTU() int     { return t.mtu }
func (t *MemoryTUN) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), t.addresses...)
}

func (t *MemoryTUN) Read(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := t.closedError(); err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.done:
		return 0, ErrClosed
	case packet := <-t.inbound:
		if len(buffer) < len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, packet), nil
	}
}

func (t *MemoryTUN) Write(ctx context.Context, packet []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(packet) > t.mtu {
		return 0, fmt.Errorf("%w: packet length %d exceeds MTU %d", ErrInvalidTUN, len(packet), t.mtu)
	}
	if err := t.closedError(); err != nil {
		return 0, err
	}
	clone := append([]byte(nil), packet...)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.done:
		return 0, ErrClosed
	case t.outbound <- clone:
		return len(packet), nil
	}
}

func (t *MemoryTUN) Inject(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(packet) > t.mtu {
		return fmt.Errorf("%w: packet length %d exceeds MTU %d", ErrInvalidTUN, len(packet), t.mtu)
	}
	clone := append([]byte(nil), packet...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return ErrClosed
	case t.inbound <- clone:
		return nil
	}
}

func (t *MemoryTUN) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, ErrClosed
	case packet := <-t.outbound:
		return packet, nil
	}
}

func (t *MemoryTUN) Close() error {
	t.close.Do(func() { close(t.done) })
	return nil
}

func (t *MemoryTUN) closedError() error {
	select {
	case <-t.done:
		return ErrClosed
	default:
		return nil
	}
}

// MemoryRouteManager is an unprivileged transactional route manager. It uses
// the same validation and bypass filtering as the OS implementation.
type MemoryRouteManager struct {
	mu     sync.RWMutex
	routes map[string]Route
	closed bool
}

var _ RouteManager = (*MemoryRouteManager)(nil)

func NewMemoryRouteManager() *MemoryRouteManager {
	return &MemoryRouteManager{routes: make(map[string]Route)}
}

func (m *MemoryRouteManager) Apply(ctx context.Context, plan RoutePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	desired, err := normalizePlan(plan)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.routes = desired
	return nil
}

func (m *MemoryRouteManager) Restore(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.routes = make(map[string]Route)
	return nil
}

func (m *MemoryRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.routes = make(map[string]Route)
		m.closed = true
	}
	return nil
}

func (m *MemoryRouteManager) Routes() []Route {
	m.mu.RLock()
	defer m.mu.RUnlock()
	routes := make([]Route, 0, len(m.routes))
	for _, route := range m.routes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Prefix.String() < routes[j].Prefix.String() })
	return routes
}
