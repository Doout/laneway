package subnet

import (
	"context"
	"sync"
)

// MemoryForwardingManager is an unprivileged fake with the same validation,
// idempotency, and close semantics as the platform implementation.
type MemoryForwardingManager struct {
	mu      sync.Mutex
	plan    ForwardingPlan
	enabled bool
	closed  bool
}

var _ ForwardingManager = (*MemoryForwardingManager)(nil)

func NewMemoryForwardingManager() *MemoryForwardingManager {
	return &MemoryForwardingManager{}
}

func (m *MemoryForwardingManager) Apply(ctx context.Context, plan ForwardingPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizePlan(plan)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.plan = clonePlan(normalized)
	m.enabled = len(normalized.AuthorizedPrefixes) != 0
	return nil
}

func (m *MemoryForwardingManager) Restore(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.plan = ForwardingPlan{}
	m.enabled = false
	return nil
}

func (m *MemoryForwardingManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.plan = ForwardingPlan{}
	m.enabled = false
	m.closed = true
	return nil
}

// Snapshot returns a copy of the fake's current state for tests and callers
// that use it as a dry-run backend.
func (m *MemoryForwardingManager) Snapshot() (ForwardingPlan, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clonePlan(m.plan), m.enabled
}
