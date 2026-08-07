//go:build linux

package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type exitRouteRecord struct {
	prefix    netip.Prefix
	prior     []string
	hadPrior  bool
	installed []string
}

type exitRuleRecord struct {
	family string
}

type linuxRouteManager struct {
	mu      sync.Mutex
	config  RouteManagerConfig
	runner  CommandRunner
	records []exitRouteRecord
	rules   []exitRuleRecord
	plan    RoutePlan
	active  bool
	closed  bool
}

var _ RouteManager = (*linuxRouteManager)(nil)

func NewRouteManager(config RouteManagerConfig) (RouteManager, error) {
	normalized, err := normalizeRouteConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.Runner == nil {
		normalized.Runner = execRunner{}
	}
	return &linuxRouteManager{config: normalized, runner: normalized.Runner}, nil
}

func (m *linuxRouteManager) Apply(ctx context.Context, plan RoutePlan) error {
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
	if m.active && routePlansEqual(m.plan, plan) {
		return nil
	}
	// A failed activation rollback retains its owned records with an empty
	// logical plan. Finish that cleanup before starting a new reconciliation.
	if m.active && len(m.plan.TunnelPrefixes) == 0 {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
	}
	previous, hadPrevious := cloneRoutePlan(m.plan), m.active
	if hadPrevious {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
	}
	if err := m.activateLocked(ctx, plan); err != nil {
		if hadPrevious {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
			defer cancel()
			if rollbackErr := m.activateLocked(rollbackCtx, previous); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("exitnode: route reconciliation rollback: %w", rollbackErr))
			}
		}
		return err
	}
	return nil
}

func (m *linuxRouteManager) activateLocked(ctx context.Context, plan RoutePlan) error {
	type desiredRoute struct {
		prefix netip.Prefix
		args   []string
	}
	desired := make([]desiredRoute, 0, len(plan.TransportBypass)+len(plan.LocalLANBypass)+2)
	seen := make(map[netip.Prefix]struct{}, cap(desired))
	// Resolve all bypasses against the native table before installing either /1.
	for _, addr := range plan.TransportBypass {
		prefix := netip.PrefixFrom(addr, addr.BitLen())
		args, err := m.nativeRouteArgs(ctx, prefix)
		if err != nil {
			return err
		}
		desired = append(desired, desiredRoute{prefix, args})
		seen[prefix] = struct{}{}
	}
	for _, prefix := range plan.LocalLANBypass {
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		args, err := m.nativeRouteArgs(ctx, prefix)
		if err != nil {
			return err
		}
		desired = append(desired, desiredRoute{prefix, args})
		seen[prefix] = struct{}{}
	}
	for _, prefix := range plan.TunnelPrefixes {
		desired = append(desired, desiredRoute{prefix, []string{prefix.String(), "dev", m.config.InterfaceName}})
	}
	// A deterministic order installs narrow bypasses before broad tunnel routes.
	sort.SliceStable(desired, func(i, j int) bool { return desired[i].prefix.Bits() > desired[j].prefix.Bits() })

	installed := make([]exitRouteRecord, 0, len(desired))
	for _, route := range desired {
		prior, hadPrior, err := m.snapshot(ctx, route.prefix)
		if err != nil {
			return m.rollbackActivation(err, installed, nil)
		}
		args := append([]string{exitRouteFamily(route.prefix), "route", "replace", "table", strconv.Itoa(m.config.Table)}, route.args...)
		args = append(args, "proto", strconv.Itoa(m.config.Protocol))
		if _, err := m.run(ctx, args...); err != nil {
			return m.rollbackActivation(fmt.Errorf("exitnode: install route %s: %w", route.prefix, err), installed, nil)
		}
		installed = append(installed, exitRouteRecord{prefix: route.prefix, prior: prior, hadPrior: hadPrior, installed: append([]string(nil), route.args...)})
		m.records = append([]exitRouteRecord(nil), installed...)
		m.active = true
	}
	families := make(map[string]struct{}, 2)
	for _, prefix := range plan.TunnelPrefixes {
		families[exitRouteFamily(prefix)] = struct{}{}
	}
	orderedFamilies := make([]string, 0, len(families))
	for family := range families {
		orderedFamilies = append(orderedFamilies, family)
	}
	sort.Strings(orderedFamilies)
	installedRules := make([]exitRuleRecord, 0, len(orderedFamilies))
	for _, family := range orderedFamilies {
		adopted, stale, err := m.installRule(ctx, family)
		if err != nil {
			return m.rollbackActivation(err, installed, installedRules)
		}
		if adopted {
			installed = append(installed, stale...)
			for index := range installed {
				if exitRouteFamily(installed[index].prefix) == family {
					installed[index].hadPrior = false
					installed[index].prior = nil
				}
			}
			m.records = append([]exitRouteRecord(nil), installed...)
		}
		installedRules = append(installedRules, exitRuleRecord{family: family})
		m.rules = append([]exitRuleRecord(nil), installedRules...)
	}
	m.records, m.rules, m.plan, m.active = installed, installedRules, cloneRoutePlan(plan), true
	return nil
}

func (m *linuxRouteManager) rollbackActivation(cause error, installed []exitRouteRecord, rules []exitRuleRecord) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()
	var rollbackErr error
	remainingRules := append([]exitRuleRecord(nil), rules...)
	for i := len(remainingRules) - 1; i >= 0; i-- {
		if err := m.removeRule(rollbackCtx, remainingRules[i]); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
			continue
		}
		remainingRules = append(remainingRules[:i], remainingRules[i+1:]...)
	}
	remaining := append([]exitRouteRecord(nil), installed...)
	for i := len(remaining) - 1; i >= 0; i-- {
		if err := m.restoreOne(rollbackCtx, remaining[i]); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
			continue
		}
		remaining = append(remaining[:i], remaining[i+1:]...)
	}
	m.records, m.rules, m.active, m.plan = remaining, remainingRules, len(remaining) != 0 || len(remainingRules) != 0, RoutePlan{}
	if rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("exitnode: route activation rollback: %w", rollbackErr))
	}
	return cause
}

func (m *linuxRouteManager) Restore(ctx context.Context) error {
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

func (m *linuxRouteManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	var result error
	remainingRules := append([]exitRuleRecord(nil), m.rules...)
	for i := len(remainingRules) - 1; i >= 0; i-- {
		if err := m.removeRule(ctx, remainingRules[i]); err != nil {
			result = errors.Join(result, err)
			continue
		}
		remainingRules = append(remainingRules[:i], remainingRules[i+1:]...)
	}
	m.rules = remainingRules
	// Keep the dedicated table intact if a policy rule could not be removed;
	// deleting its tunnel routes first would turn an ownership conflict into an
	// unpredictable fall-through or blackhole.
	if len(remainingRules) != 0 {
		return result
	}
	remaining := append([]exitRouteRecord(nil), m.records...)
	for i := len(remaining) - 1; i >= 0; i-- {
		if err := m.restoreOne(ctx, remaining[i]); err != nil {
			result = errors.Join(result, err)
			continue
		}
		remaining = append(remaining[:i], remaining[i+1:]...)
	}
	m.records = remaining
	if result == nil {
		m.plan, m.active = RoutePlan{}, false
	}
	return result
}

func (m *linuxRouteManager) installRule(ctx context.Context, family string) (bool, []exitRouteRecord, error) {
	lines, err := m.ruleSnapshot(ctx, family)
	if err != nil {
		return false, nil, err
	}
	if len(lines) != 0 {
		if len(lines) == 1 && ownedRule(lines[0], m.config.RulePriority, m.config.Table) {
			stale, adoptable := m.adoptableFamilyResidue(ctx, family)
			if adoptable {
				return true, stale, nil
			}
		}
		return false, nil, fmt.Errorf("%w: policy-rule priority %d is already occupied for %s", ErrOwnership, m.config.RulePriority, family)
	}
	if _, err := m.run(ctx, family, "rule", "add", "priority", strconv.Itoa(m.config.RulePriority), "lookup", strconv.Itoa(m.config.Table)); err != nil {
		return false, nil, fmt.Errorf("exitnode: install %s policy rule: %w", family, err)
	}
	return false, nil, nil
}

func (m *linuxRouteManager) adoptableFamilyResidue(ctx context.Context, family string) ([]exitRouteRecord, bool) {
	expected := make(map[string]struct{})
	ownedResidue := false
	for _, record := range m.records {
		if exitRouteFamily(record.prefix) != family {
			continue
		}
		if record.hadPrior {
			if !hasFieldValue(record.prior, "proto", strconv.Itoa(m.config.Protocol)) {
				return nil, false
			}
			ownedResidue = true
		}
		expected[record.prefix.String()] = struct{}{}
	}
	// A crashed non-persistent TUN disappears with its broad routes, while
	// native endpoint bypass routes and the policy rule survive. At least one
	// protocol-marked prior route is therefore required as the ownership marker;
	// missing desired routes may be recreated, but an otherwise empty or foreign
	// table never authorizes adoption of an occupied rule priority.
	if len(expected) == 0 || !ownedResidue {
		return nil, false
	}
	args := []string{"-N", family, "-o", "route", "show", "table", strconv.Itoa(m.config.Table)}
	output, err := m.runner.Run(ctx, m.config.IPCommand, args...)
	if err != nil {
		return nil, false
	}
	lines := nonempty(string(output))
	found := make(map[string]struct{}, len(lines))
	stale := make([]exitRouteRecord, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return nil, false
		}
		prefix, err := netip.ParsePrefix(fields[0])
		if err != nil {
			address, addressErr := netip.ParseAddr(fields[0])
			if addressErr != nil {
				return nil, false
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		prefix = prefix.Masked()
		if exitRouteFamily(prefix) != family || !hasFieldValue(fields, "proto", strconv.Itoa(m.config.Protocol)) {
			return nil, false
		}
		key := prefix.String()
		found[key] = struct{}{}
		if _, wanted := expected[key]; !wanted {
			// Dynamic direct endpoints can change across a crash. Only reclaim
			// stale, protocol-marked native host bypasses; broad or lane0 routes
			// still fail closed as an ownership conflict.
			if prefix.Bits() != prefix.Addr().BitLen() || fieldAfter(fields, "dev") == m.config.InterfaceName {
				return nil, false
			}
			stale = append(stale, exitRouteRecord{prefix: prefix})
		}
	}
	for prefix := range expected {
		if _, ok := found[prefix]; !ok {
			return nil, false
		}
	}
	return stale, true
}

func (m *linuxRouteManager) removeRule(ctx context.Context, record exitRuleRecord) error {
	lines, err := m.ruleSnapshot(ctx, record.family)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	if len(lines) != 1 || !ownedRule(lines[0], m.config.RulePriority, m.config.Table) {
		return fmt.Errorf("%w: %s policy rule was replaced externally", ErrOwnership, record.family)
	}
	if _, err := m.run(ctx, record.family, "rule", "del", "priority", strconv.Itoa(m.config.RulePriority), "lookup", strconv.Itoa(m.config.Table)); err != nil {
		return fmt.Errorf("exitnode: remove %s policy rule: %w", record.family, err)
	}
	return nil
}

func (m *linuxRouteManager) ruleSnapshot(ctx context.Context, family string) ([]string, error) {
	output, err := m.run(ctx, "-N", family, "-o", "rule", "show", "priority", strconv.Itoa(m.config.RulePriority))
	if err != nil {
		return nil, fmt.Errorf("exitnode: inspect %s policy rule: %w", family, err)
	}
	return nonempty(string(output)), nil
}

func ownedRule(line string, priority, table int) bool {
	fields := strings.Fields(line)
	return len(fields) >= 4 && strings.TrimSuffix(fields[0], ":") == strconv.Itoa(priority) &&
		hasFieldValue(fields, "lookup", strconv.Itoa(table))
}

func (m *linuxRouteManager) Close() error {
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

func (m *linuxRouteManager) nativeRouteArgs(ctx context.Context, prefix netip.Prefix) ([]string, error) {
	output, err := m.run(ctx, "-N", exitRouteFamily(prefix), "-o", "route", "get", prefix.Addr().String())
	if err != nil {
		return nil, fmt.Errorf("exitnode: resolve native route for %s: %w", prefix, err)
	}
	line := strings.TrimSpace(string(output))
	if line == "" || strings.Contains(line, "\n") {
		return nil, fmt.Errorf("%w: ambiguous native route for %s", ErrInvalid, prefix)
	}
	fields := strings.Fields(line)
	dev, via, src := fieldAfter(fields, "dev"), fieldAfter(fields, "via"), fieldAfter(fields, "src")
	if dev == "" {
		return nil, fmt.Errorf("%w: native route for %s has no device", ErrInvalid, prefix)
	}
	if dev == m.config.InterfaceName {
		return nil, fmt.Errorf("%w: bypass %s already resolves through %s", ErrInvalid, prefix, dev)
	}
	args := []string{prefix.String()}
	if via != "" {
		args = append(args, "via", via)
	}
	args = append(args, "dev", dev)
	if src != "" {
		args = append(args, "src", src)
	}
	return args, nil
}

func (m *linuxRouteManager) snapshot(ctx context.Context, prefix netip.Prefix) ([]string, bool, error) {
	args := []string{"-N", exitRouteFamily(prefix), "-o", "route", "show", "table", strconv.Itoa(m.config.Table), "exact", prefix.String()}
	output, err := m.runner.Run(ctx, m.config.IPCommand, args...)
	if err != nil {
		// A dedicated numeric FIB table is created lazily by the first route.
		// iproute2 reports its pre-activation absence as an error, which is the
		// same safe snapshot as an empty table—not an ownership conflict.
		if strings.Contains(string(output), "FIB table does not exist") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("exitnode: inspect route %s: %w", prefix, err)
	}
	lines := nonempty(string(output))
	if len(lines) > 1 {
		return nil, false, fmt.Errorf("%w: multiple routes for %s", ErrOwnership, prefix)
	}
	if len(lines) == 0 {
		return nil, false, nil
	}
	return strings.Fields(lines[0]), true, nil
}

func (m *linuxRouteManager) restoreOne(ctx context.Context, record exitRouteRecord) error {
	current, exists, err := m.snapshot(ctx, record.prefix)
	if err != nil {
		return err
	}
	if exists && !hasFieldValue(current, "proto", strconv.Itoa(m.config.Protocol)) {
		if record.hadPrior && equalFields(current, record.prior) {
			return nil
		}
		return fmt.Errorf("%w: route %s was replaced externally", ErrOwnership, record.prefix)
	}
	if record.hadPrior {
		args := append([]string{exitRouteFamily(record.prefix), "route", "replace", "table", strconv.Itoa(m.config.Table)}, record.prior...)
		if _, err := m.run(ctx, args...); err != nil {
			return fmt.Errorf("exitnode: restore route %s: %w", record.prefix, err)
		}
		return nil
	}
	if !exists {
		return nil
	}
	if _, err := m.run(ctx, exitRouteFamily(record.prefix), "route", "del", "table", strconv.Itoa(m.config.Table), record.prefix.String(), "proto", strconv.Itoa(m.config.Protocol)); err != nil {
		return fmt.Errorf("exitnode: remove route %s: %w", record.prefix, err)
	}
	return nil
}

func exitRouteFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-4"
	}
	return "-6"
}

func (m *linuxRouteManager) run(ctx context.Context, args ...string) ([]byte, error) {
	output, err := m.runner.Run(ctx, m.config.IPCommand, args...)
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", m.config.IPCommand, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func fieldAfter(fields []string, name string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == name {
			return fields[i+1]
		}
	}
	return ""
}
func hasFieldValue(fields []string, name, value string) bool {
	return fieldAfter(fields, name) == value
}
func nonempty(value string) []string {
	var out []string
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}
func equalFields(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func routePlansEqual(a, b RoutePlan) bool {
	if len(a.TunnelPrefixes) != len(b.TunnelPrefixes) || len(a.TransportBypass) != len(b.TransportBypass) || len(a.LocalLANBypass) != len(b.LocalLANBypass) {
		return false
	}
	for i := range a.TunnelPrefixes {
		if a.TunnelPrefixes[i] != b.TunnelPrefixes[i] {
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
	return true
}
