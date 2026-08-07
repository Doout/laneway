package exitnode

import (
	"context"
	"errors"
	"net/netip"
	"sync"
)

type MemoryRouteManager struct {
	mu         sync.RWMutex
	plan       RoutePlan
	active     bool
	closed     bool
	ApplyError error
}

func NewMemoryRouteManager() *MemoryRouteManager { return &MemoryRouteManager{} }

func (m *MemoryRouteManager) Apply(ctx context.Context, plan RoutePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := normalizeRoutePlan(&plan); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if m.ApplyError != nil {
		return m.ApplyError
	}
	m.plan, m.active = cloneRoutePlan(plan), true
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
	m.plan, m.active = RoutePlan{}, false
	return nil
}
func (m *MemoryRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.plan, m.active, m.closed = RoutePlan{}, false, true
	}
	return nil
}
func (m *MemoryRouteManager) Snapshot() (RoutePlan, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneRoutePlan(m.plan), m.active
}

type MemoryDNSManager struct {
	mu         sync.RWMutex
	servers    []netip.Addr
	active     bool
	closed     bool
	ApplyError error
}

func NewMemoryDNSManager() *MemoryDNSManager { return &MemoryDNSManager{} }
func (m *MemoryDNSManager) Apply(ctx context.Context, servers []netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizeAddresses(servers, true)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if m.ApplyError != nil {
		return m.ApplyError
	}
	m.servers, m.active = normalized, true
	return nil
}
func (m *MemoryDNSManager) Restore(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.servers, m.active = nil, false
	return nil
}
func (m *MemoryDNSManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.servers, m.active, m.closed = nil, false, true
	}
	return nil
}
func (m *MemoryDNSManager) Snapshot() ([]netip.Addr, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]netip.Addr(nil), m.servers...), m.active
}

func normalizeRoutePlan(plan *RoutePlan) error {
	if !validSplitDefaults(plan.TunnelPrefixes) {
		return ErrInvalid
	}
	addresses, err := normalizeAddresses(plan.TransportBypass, false)
	if err != nil {
		return fmtInvalid(err)
	}
	prefixes, err := normalizePrefixes(plan.LocalLANBypass)
	if err != nil {
		return err
	}
	plan.TransportBypass, plan.LocalLANBypass = addresses, prefixes
	return nil
}

func validSplitDefaults(prefixes []netip.Prefix) bool {
	if len(prefixes) != 2 && len(prefixes) != 4 {
		return false
	}
	index := 0
	if len(prefixes) >= 2 && prefixes[0] == ipv4SplitDefaultPrefixes[0] && prefixes[1] == ipv4SplitDefaultPrefixes[1] {
		index = 2
	}
	if len(prefixes)-index == 2 && prefixes[index] == ipv6SplitDefaultPrefixes[0] && prefixes[index+1] == ipv6SplitDefaultPrefixes[1] {
		return true
	}
	return index == len(prefixes)
}

func fmtInvalid(err error) error { return errors.Join(ErrInvalid, err) }

func cloneRoutePlan(plan RoutePlan) RoutePlan {
	plan.TunnelPrefixes = append([]netip.Prefix(nil), plan.TunnelPrefixes...)
	plan.TransportBypass = append([]netip.Addr(nil), plan.TransportBypass...)
	plan.LocalLANBypass = append([]netip.Prefix(nil), plan.LocalLANBypass...)
	return plan
}
