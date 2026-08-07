// Package exitnode owns the host state required by explicitly selected
// dual-stack
// exit nodes. It is deliberately separate from ordinary overlay routing: a
// default route is a security-sensitive local choice, not merely another
// controller-advertised prefix.
package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const DefaultShutdownTimeout = 5 * time.Second

var (
	ErrUnsupported  = errors.New("exitnode: operation unsupported on this operating system")
	ErrClosed       = errors.New("exitnode: manager is closed")
	ErrInvalid      = errors.New("exitnode: invalid configuration")
	ErrUnauthorized = errors.New("exitnode: exit selection is not controller-authorized")
	ErrOwnership    = errors.New("exitnode: host state is no longer owned by Laneway")
)

// FailureMode is mandatory whenever full tunnel is enabled. Its zero value is
// intentionally invalid so adding an exit selection cannot silently choose a
// leak policy.
type FailureMode uint8

const (
	FailureModeUnspecified FailureMode = iota
	// FailureModeOpen removes the exit routes and restores DNS when the selected
	// path is unavailable.
	FailureModeOpen
	// FailureModeClosed retains the lane0 /1 routes and tunnel DNS when the path
	// is unavailable. It does not install a firewall kill switch.
	FailureModeClosed
)

var ipv4SplitDefaultPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

var ipv6SplitDefaultPrefixes = []netip.Prefix{
	netip.MustParsePrefix("::/1"),
	netip.MustParsePrefix("8000::/1"),
}

// ClientPlan is the complete desired local exit selection. Enabled is the
// explicit local opt-in; Authorized records a current controller grant. The
// caller supplies every transport endpoint that must remain reachable outside
// lane0 (relay, controller, and any direct exit endpoint).
type ClientPlan struct {
	Enabled         bool
	Authorized      bool
	FailureMode     FailureMode
	PathAvailable   bool
	ExitPrefixes    []netip.Prefix
	TransportBypass []netip.Addr
	LocalLANBypass  []netip.Prefix
	DNSServers      []netip.Addr
}

// ValidateClientPlan validates a complete exit-client snapshot without
// changing routes or DNS state.
func ValidateClientPlan(plan ClientPlan) error {
	_, _, err := normalizeClientPlan(plan)
	return err
}

// RoutePlan is passed to the exit-specific route backend. TunnelPrefixes are
// always the IPv4 split default and never 0.0.0.0/0.
type RoutePlan struct {
	TunnelPrefixes  []netip.Prefix
	TransportBypass []netip.Addr
	LocalLANBypass  []netip.Prefix
}

type RouteManager interface {
	Apply(context.Context, RoutePlan) error
	Restore(context.Context) error
	Close() error
}

type DNSManager interface {
	Apply(context.Context, []netip.Addr) error
	Restore(context.Context) error
	Close() error
}

// ClientManager coordinates route and DNS changes as one logical transaction.
// It is safe for concurrent reconciliation calls.
type ClientManager struct {
	mu      sync.Mutex
	routes  RouteManager
	dns     DNSManager
	timeout time.Duration
	active  bool
	plan    ClientPlan
	closed  bool
}

func NewClientManager(routes RouteManager, dns DNSManager, shutdownTimeout time.Duration) (*ClientManager, error) {
	if routes == nil || dns == nil {
		return nil, fmt.Errorf("%w: route and DNS managers are required", ErrInvalid)
	}
	if shutdownTimeout == 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	if shutdownTimeout < 0 {
		return nil, fmt.Errorf("%w: negative shutdown timeout", ErrInvalid)
	}
	return &ClientManager{routes: routes, dns: dns, timeout: shutdownTimeout}, nil
}

func (m *ClientManager) Apply(ctx context.Context, plan ClientPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	normalized, effective, err := normalizeClientPlan(plan)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if !effective {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
		m.plan = normalized
		return nil
	}
	if m.active && clientPlansEqual(m.plan, normalized) {
		return nil
	}

	previous, hadPrevious := cloneClientPlan(m.plan), m.active
	routePlan := routePlanFor(normalized)
	if err := m.routes.Apply(ctx, routePlan); err != nil {
		return err
	}
	if err := m.dns.Apply(ctx, normalized.DNSServers); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
		var rollbackErr error
		if hadPrevious {
			rollbackErr = errors.Join(rollbackErr, m.routes.Apply(rollbackCtx, routePlanFor(previous)))
			rollbackErr = errors.Join(rollbackErr, m.dns.Apply(rollbackCtx, previous.DNSServers))
		} else {
			rollbackErr = errors.Join(rollbackErr, m.routes.Restore(rollbackCtx), m.dns.Restore(rollbackCtx))
		}
		if rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("exitnode: activation rollback: %w", rollbackErr))
		}
		return err
	}
	m.plan, m.active = cloneClientPlan(normalized), true
	return nil
}

func (m *ClientManager) Restore(ctx context.Context) error {
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

func (m *ClientManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	// Restore the native resolver before removing the /1 routes. This avoids a
	// transition window in which the tunnel resolver is queried over the native
	// default route.
	dnsErr := m.dns.Restore(ctx)
	routeErr := m.routes.Restore(ctx)
	err := errors.Join(dnsErr, routeErr)
	if err == nil {
		m.active = false
	}
	return err
}

func (m *ClientManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	if err := m.restoreLocked(ctx); err != nil {
		return err
	}
	err := errors.Join(m.routes.Close(), m.dns.Close())
	if err == nil {
		m.closed = true
	}
	return err
}

func normalizeClientPlan(plan ClientPlan) (ClientPlan, bool, error) {
	if !plan.Enabled {
		return ClientPlan{}, false, nil
	}
	if !plan.Authorized {
		return ClientPlan{}, false, ErrUnauthorized
	}
	if plan.FailureMode != FailureModeOpen && plan.FailureMode != FailureModeClosed {
		return ClientPlan{}, false, fmt.Errorf("%w: failure mode must be explicit", ErrInvalid)
	}
	if len(plan.TransportBypass) == 0 {
		return ClientPlan{}, false, fmt.Errorf("%w: at least one transport bypass endpoint is required", ErrInvalid)
	}
	addresses, err := normalizeAddresses(plan.TransportBypass, false)
	if err != nil {
		return ClientPlan{}, false, fmt.Errorf("%w: transport bypass: %v", ErrInvalid, err)
	}
	dns, err := normalizeAddresses(plan.DNSServers, false)
	if err != nil {
		return ClientPlan{}, false, fmt.Errorf("%w: DNS server: %v", ErrInvalid, err)
	}
	local, err := normalizePrefixes(plan.LocalLANBypass)
	if err != nil {
		return ClientPlan{}, false, err
	}
	exits, err := normalizeExitPrefixes(plan.ExitPrefixes)
	if err != nil {
		return ClientPlan{}, false, err
	}
	plan.TransportBypass, plan.DNSServers, plan.LocalLANBypass, plan.ExitPrefixes = addresses, dns, local, exits
	effective := plan.PathAvailable || plan.FailureMode == FailureModeClosed
	return plan, effective, nil
}

func normalizeAddresses(values []netip.Addr, allowEmpty bool) ([]netip.Addr, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, errors.New("empty address set")
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	result := make([]netip.Addr, 0, len(values))
	for _, addr := range values {
		if !addr.IsValid() || addr.Is4In6() || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, fmt.Errorf("invalid unicast IP address %q", addr)
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		result = append(result, addr)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}

func normalizePrefixes(values []netip.Prefix) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	result := make([]netip.Prefix, 0, len(values))
	for _, prefix := range values {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() == 0 || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, fmt.Errorf("%w: prefix must be canonical and non-default, got %q", ErrInvalid, prefix)
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		if c := result[i].Addr().Compare(result[j].Addr()); c != 0 {
			return c < 0
		}
		return result[i].Bits() < result[j].Bits()
	})
	return result, nil
}

func normalizeExitPrefixes(values []netip.Prefix) ([]netip.Prefix, error) {
	seen := make(map[int]struct{}, len(values))
	result := make([]netip.Prefix, 0, len(values))
	for _, prefix := range values {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() != 0 {
			return nil, fmt.Errorf("%w: exit prefix must be canonical 0.0.0.0/0 or ::/0, got %q", ErrInvalid, prefix)
		}
		family := prefix.Addr().BitLen()
		if _, duplicate := seen[family]; duplicate {
			continue
		}
		seen[family] = struct{}{}
		result = append(result, prefix)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: at least one exit address family is required", ErrInvalid)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Addr().BitLen() < result[j].Addr().BitLen() })
	return result, nil
}

func routePlanFor(plan ClientPlan) RoutePlan {
	var tunnelPrefixes []netip.Prefix
	for _, prefix := range plan.ExitPrefixes {
		if prefix.Addr().Is4() {
			tunnelPrefixes = append(tunnelPrefixes, ipv4SplitDefaultPrefixes...)
		} else {
			tunnelPrefixes = append(tunnelPrefixes, ipv6SplitDefaultPrefixes...)
		}
	}
	return RoutePlan{
		TunnelPrefixes:  tunnelPrefixes,
		TransportBypass: append([]netip.Addr(nil), plan.TransportBypass...),
		LocalLANBypass:  append([]netip.Prefix(nil), plan.LocalLANBypass...),
	}
}

func cloneClientPlan(plan ClientPlan) ClientPlan {
	plan.TransportBypass = append([]netip.Addr(nil), plan.TransportBypass...)
	plan.ExitPrefixes = append([]netip.Prefix(nil), plan.ExitPrefixes...)
	plan.LocalLANBypass = append([]netip.Prefix(nil), plan.LocalLANBypass...)
	plan.DNSServers = append([]netip.Addr(nil), plan.DNSServers...)
	return plan
}

func clientPlansEqual(a, b ClientPlan) bool {
	if a.Enabled != b.Enabled || a.Authorized != b.Authorized || a.FailureMode != b.FailureMode || a.PathAvailable != b.PathAvailable ||
		len(a.ExitPrefixes) != len(b.ExitPrefixes) || len(a.TransportBypass) != len(b.TransportBypass) || len(a.LocalLANBypass) != len(b.LocalLANBypass) || len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	for i := range a.ExitPrefixes {
		if a.ExitPrefixes[i] != b.ExitPrefixes[i] {
			return false
		}
	}
	for i := range a.TransportBypass {
		if a.TransportBypass[i] != b.TransportBypass[i] {
			return false
		}
	}
	for i := range a.LocalLANBypass {
		if a.LocalLANBypass[i] != b.LocalLANBypass[i] {
			return false
		}
	}
	for i := range a.DNSServers {
		if a.DNSServers[i] != b.DNSServers[i] {
			return false
		}
	}
	return true
}
