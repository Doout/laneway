package exitnode

import (
	"context"
	"net/netip"
	"sync"
)

type MemoryGatewayManager struct {
	mu      sync.RWMutex
	plan    GatewayPlan
	active  bool
	drained bool
	closed  bool
}

func NewMemoryGatewayManager() *MemoryGatewayManager { return &MemoryGatewayManager{} }
func (m *MemoryGatewayManager) Apply(ctx context.Context, plan GatewayPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, enabled, err := normalizeGatewayPlan(plan)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.plan, m.active, m.drained = normalized, enabled, false
	return nil
}
func (m *MemoryGatewayManager) Drain(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if m.active {
		m.drained = true
	}
	return nil
}
func (m *MemoryGatewayManager) Restore(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.plan, m.active, m.drained = GatewayPlan{}, false, false
	return nil
}
func (m *MemoryGatewayManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.plan, m.active, m.drained, m.closed = GatewayPlan{}, false, false, true
	}
	return nil
}
func (m *MemoryGatewayManager) Draining() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active && m.drained
}
func (m *MemoryGatewayManager) Snapshot() (GatewayPlan, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p := m.plan
	p.OverlaySources = append([]netip.Prefix(nil), p.OverlaySources...)
	return p, m.active
}
