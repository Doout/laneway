//go:build linux

package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

type dnsState struct {
	servers      []string
	domains      []string
	defaultRoute string
}

type linuxDNSManager struct {
	mu      sync.Mutex
	config  DNSManagerConfig
	runner  CommandRunner
	prior   dnsState
	applied dnsState
	active  bool
	dirty   bool
	closed  bool
}

var _ DNSManager = (*linuxDNSManager)(nil)

func NewDNSManager(config DNSManagerConfig) (DNSManager, error) {
	normalized, err := normalizeDNSConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.Runner == nil {
		normalized.Runner = execRunner{}
	}
	return &linuxDNSManager{config: normalized, runner: normalized.Runner}, nil
}

func (m *linuxDNSManager) Apply(ctx context.Context, servers []netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, err := normalizeAddresses(servers, false)
	if err != nil {
		return fmt.Errorf("%w: DNS servers: %v", ErrInvalid, err)
	}
	desired := dnsState{servers: make([]string, len(normalized)), domains: []string{"~."}, defaultRoute: "yes"}
	for i, addr := range normalized {
		desired.servers[i] = addr.String()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if m.dirty {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
	}
	if m.active && dnsStatesEqual(m.applied, desired) {
		return nil
	}
	if !m.active {
		prior, err := m.snapshot(ctx)
		if err != nil {
			return err
		}
		m.prior = prior
	}
	previous := m.applied
	m.dirty = true
	if err := m.applyState(ctx, desired); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
		defer cancel()
		rollback := m.prior
		if m.active {
			rollback = previous
		}
		if rollbackErr := m.applyState(rollbackCtx, rollback); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("exitnode: DNS rollback: %w", rollbackErr))
		}
		m.dirty = false
		return err
	}
	m.applied, m.active, m.dirty = cloneDNSState(desired), true, false
	return nil
}

func (m *linuxDNSManager) Restore(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	return m.restoreLocked(ctx)
}

func (m *linuxDNSManager) restoreLocked(ctx context.Context) error {
	if !m.active && !m.dirty {
		return nil
	}
	if m.dirty {
		if err := m.applyState(ctx, m.prior); err != nil {
			return err
		}
		m.active, m.dirty, m.prior, m.applied = false, false, dnsState{}, dnsState{}
		return nil
	}
	current, err := m.snapshot(ctx)
	if err != nil {
		return err
	}
	if !dnsStatesEqual(current, m.applied) {
		return fmt.Errorf("%w: per-link DNS state was replaced externally", ErrOwnership)
	}
	if err := m.applyState(ctx, m.prior); err != nil {
		return err
	}
	m.active, m.dirty, m.prior, m.applied = false, false, dnsState{}, dnsState{}
	return nil
}

func (m *linuxDNSManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()
	if err := m.restoreLocked(ctx); err != nil {
		return err
	}
	m.closed = true
	return nil
}

func (m *linuxDNSManager) snapshot(ctx context.Context) (dnsState, error) {
	dns, err := m.query(ctx, "dns")
	if err != nil {
		return dnsState{}, err
	}
	domains, err := m.query(ctx, "domain")
	if err != nil {
		return dnsState{}, err
	}
	defaultRoute, err := m.query(ctx, "default-route")
	if err != nil {
		return dnsState{}, err
	}
	state := dnsState{servers: parseResolveValues(dns), domains: parseResolveValues(domains)}
	values := parseResolveValues(defaultRoute)
	if len(values) > 1 {
		return dnsState{}, fmt.Errorf("%w: ambiguous default-route DNS state", ErrInvalid)
	}
	if len(values) == 1 {
		value := strings.ToLower(values[0])
		if value != "yes" && value != "no" {
			return dnsState{}, fmt.Errorf("%w: invalid default-route state %q", ErrInvalid, value)
		}
		state.defaultRoute = value
	}
	return state, nil
}

func (m *linuxDNSManager) query(ctx context.Context, property string) ([]byte, error) {
	output, err := m.runner.Run(ctx, m.config.ResolveCommand, property, m.config.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("exitnode: query DNS %s: %w: %s", property, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (m *linuxDNSManager) applyState(ctx context.Context, state dnsState) error {
	if _, err := m.run(ctx, "revert", m.config.InterfaceName); err != nil {
		return err
	}
	if len(state.servers) > 0 {
		args := append([]string{"dns", m.config.InterfaceName}, state.servers...)
		if _, err := m.run(ctx, args...); err != nil {
			return err
		}
	}
	if len(state.domains) > 0 {
		args := append([]string{"domain", m.config.InterfaceName}, state.domains...)
		if _, err := m.run(ctx, args...); err != nil {
			return err
		}
	}
	if state.defaultRoute != "" {
		if _, err := m.run(ctx, "default-route", m.config.InterfaceName, state.defaultRoute); err != nil {
			return err
		}
	}
	return nil
}

func (m *linuxDNSManager) run(ctx context.Context, args ...string) ([]byte, error) {
	output, err := m.runner.Run(ctx, m.config.ResolveCommand, args...)
	if err != nil {
		return output, fmt.Errorf("exitnode: %s %s: %w: %s", m.config.ResolveCommand, strconv.Quote(strings.Join(args, " ")), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func parseResolveValues(output []byte) []string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return nil
	}
	if index := strings.IndexByte(text, ':'); index >= 0 {
		text = strings.TrimSpace(text[index+1:])
	}
	if text == "" || strings.EqualFold(text, "none") || strings.EqualFold(text, "n/a") {
		return nil
	}
	return strings.Fields(text)
}

func cloneDNSState(state dnsState) dnsState {
	state.servers = append([]string(nil), state.servers...)
	state.domains = append([]string(nil), state.domains...)
	return state
}
func dnsStatesEqual(a, b dnsState) bool {
	if a.defaultRoute != b.defaultRoute || len(a.servers) != len(b.servers) || len(a.domains) != len(b.domains) {
		return false
	}
	for i := range a.servers {
		if a.servers[i] != b.servers[i] {
			return false
		}
	}
	for i := range a.domains {
		if a.domains[i] != b.domains[i] {
			return false
		}
	}
	return true
}
