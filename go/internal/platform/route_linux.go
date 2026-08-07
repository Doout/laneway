//go:build linux

package platform

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
	"time"
)

type execCommandRunner struct{}

const linuxDefaultIPv6RouteMetric uint32 = 1024

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type ownedRoute struct {
	route    Route
	prior    []string
	hadPrior bool
}

type linuxRouteManager struct {
	mu       sync.Mutex
	name     string
	ip       string
	table    int
	protocol int
	timeout  time.Duration
	runner   CommandRunner
	owned    map[string]ownedRoute
	closed   bool
}

var _ RouteManager = (*linuxRouteManager)(nil)

func NewRouteManager(config RouteManagerConfig) (RouteManager, error) {
	if config.InterfaceName == "" {
		config.InterfaceName = DefaultTUNName
	}
	if len(config.InterfaceName) > 15 || !interfaceNamePattern.MatchString(config.InterfaceName) {
		return nil, fmt.Errorf("%w: invalid route interface %q", ErrInvalidRoute, config.InterfaceName)
	}
	if config.IPCommand == "" {
		config.IPCommand = "ip"
	}
	if config.Table == 0 {
		config.Table = DefaultRouteTable
	}
	if config.Table < 1 {
		return nil, fmt.Errorf("%w: invalid route table %d", ErrInvalidRoute, config.Table)
	}
	if config.Protocol == 0 {
		config.Protocol = DefaultRouteProtocol
	}
	if config.Protocol < 1 || config.Protocol > 255 {
		return nil, fmt.Errorf("%w: invalid route protocol %d", ErrInvalidRoute, config.Protocol)
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 5 * time.Second
	}
	if config.ShutdownTimeout < 0 {
		return nil, fmt.Errorf("%w: negative shutdown timeout", ErrInvalidRoute)
	}
	if config.Runner == nil {
		config.Runner = execCommandRunner{}
	}
	return &linuxRouteManager{
		name: config.InterfaceName, ip: config.IPCommand, table: config.Table,
		protocol: config.Protocol, timeout: config.ShutdownTimeout, runner: config.Runner,
		owned: make(map[string]ownedRoute),
	}, nil
}

func (m *linuxRouteManager) Apply(ctx context.Context, plan RoutePlan) error {
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

	type undoFunc func(context.Context) error
	undos := make([]undoFunc, 0)
	next := cloneOwned(m.owned)
	rollback := func(cause error) error {
		var rollbackErr error
		// Do not inherit a cancelled apply context: rollback is required to
		// preserve the previous complete snapshot.
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
		for i := len(undos) - 1; i >= 0; i-- {
			rollbackErr = errors.Join(rollbackErr, undos[i](rollbackCtx))
		}
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("platform: route rollback: %w", rollbackErr))
		}
		return cause
	}

	for _, key := range sortedRouteKeys(desired) {
		route := desired[key]
		if previous, ok := m.owned[key]; ok && previous.route == route {
			continue
		}
		record, existed := m.owned[key]
		if !existed {
			prior, hadPrior, snapshotErr := m.snapshot(ctx, route)
			if snapshotErr != nil {
				return rollback(snapshotErr)
			}
			record = ownedRoute{prior: prior, hadPrior: hadPrior}
		} else if verifyErr := m.verifyOwned(ctx, record.route); verifyErr != nil {
			return rollback(verifyErr)
		}
		if err := m.install(ctx, route); err != nil {
			return rollback(err)
		}
		oldRecord := record
		if existed {
			undos = append(undos, func(undoCtx context.Context) error { return m.install(undoCtx, oldRecord.route) })
		} else {
			installed := ownedRoute{route: route, prior: record.prior, hadPrior: record.hadPrior}
			undos = append(undos, func(undoCtx context.Context) error { return m.restoreOne(undoCtx, installed) })
		}
		record.route = route
		next[key] = record
	}

	for _, key := range sortedOwnedKeys(m.owned) {
		if _, keep := desired[key]; keep {
			continue
		}
		record := m.owned[key]
		if err := m.restoreOne(ctx, record); err != nil {
			return rollback(err)
		}
		removed := record
		undos = append(undos, func(undoCtx context.Context) error { return m.install(undoCtx, removed.route) })
		delete(next, key)
	}

	m.owned = next
	return nil
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
	return m.restoreAllLocked(ctx)
}

func (m *linuxRouteManager) restoreAllLocked(ctx context.Context) error {
	var result error
	for _, key := range sortedOwnedKeys(m.owned) {
		record := m.owned[key]
		if err := m.restoreOne(ctx, record); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(m.owned, key)
	}
	return result
}

func (m *linuxRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	err := m.restoreAllLocked(ctx)
	if err == nil {
		m.closed = true
	}
	return err
}

func (m *linuxRouteManager) snapshot(ctx context.Context, route Route) ([]string, bool, error) {
	output, err := m.run(ctx, "-N", routeFamily(route.Prefix), "-o", "route", "show", "table", strconv.Itoa(m.table), "exact", route.Prefix.String())
	if err != nil {
		return nil, false, fmt.Errorf("platform: inspect route %s: %w", route.Prefix, err)
	}
	lines := nonemptyLines(output)
	if len(lines) > 1 {
		return nil, false, fmt.Errorf("%w: multiple prior routes for %s", ErrRouteConflict, route.Prefix)
	}
	if len(lines) == 0 {
		return nil, false, nil
	}
	return strings.Fields(lines[0]), true, nil
}

func (m *linuxRouteManager) install(ctx context.Context, route Route) error {
	_, err := m.run(ctx, routeFamily(route.Prefix), "route", "replace", "table", strconv.Itoa(m.table), route.Prefix.String(),
		"dev", m.name, "proto", strconv.Itoa(m.protocol), "metric", strconv.FormatUint(uint64(linuxRouteMetric(route)), 10))
	if err != nil {
		return fmt.Errorf("platform: install route %s: %w", route.Prefix, err)
	}
	return nil
}

func (m *linuxRouteManager) restoreOne(ctx context.Context, record ownedRoute) error {
	output, err := m.run(ctx, "-N", routeFamily(record.route.Prefix), "-o", "route", "show", "table", strconv.Itoa(m.table), "exact", record.route.Prefix.String())
	if err != nil {
		return fmt.Errorf("platform: verify owned route %s: %w", record.route.Prefix, err)
	}
	lines := nonemptyLines(output)
	if len(lines) > 1 {
		return fmt.Errorf("%w: multiple current routes for %s", ErrRouteConflict, record.route.Prefix)
	}
	if len(lines) == 0 {
		if record.hadPrior {
			// Our installed route disappeared, but the exact destination is free;
			// restoring the state we displaced cannot overwrite a replacement.
			args := []string{routeFamily(record.route.Prefix), "route", "replace", "table", strconv.Itoa(m.table)}
			args = append(args, record.prior...)
			if _, err := m.run(ctx, args...); err != nil {
				return fmt.Errorf("platform: restore displaced route %s: %w", record.route.Prefix, err)
			}
		}
		return nil
	}
	current := strings.Fields(lines[0])
	if record.hadPrior && equalFields(current, record.prior) {
		return nil // Already restored; makes retries idempotent.
	}
	if !m.matchesOwned(current, record.route) {
		return fmt.Errorf("%w: current route for %s does not match the installed route", ErrRouteConflict, record.route.Prefix)
	}
	if record.hadPrior {
		args := []string{routeFamily(record.route.Prefix), "route", "replace", "table", strconv.Itoa(m.table)}
		args = append(args, record.prior...)
		if _, err := m.run(ctx, args...); err != nil {
			return fmt.Errorf("platform: restore displaced route %s: %w", record.route.Prefix, err)
		}
		return nil
	}
	_, err = m.run(ctx, routeFamily(record.route.Prefix), "route", "del", "table", strconv.Itoa(m.table), record.route.Prefix.String(),
		"dev", m.name, "proto", strconv.Itoa(m.protocol), "metric", strconv.FormatUint(uint64(linuxRouteMetric(record.route)), 10))
	if err != nil {
		return fmt.Errorf("platform: remove owned route %s: %w", record.route.Prefix, err)
	}
	return nil
}

func (m *linuxRouteManager) verifyOwned(ctx context.Context, route Route) error {
	output, err := m.run(ctx, "-N", routeFamily(route.Prefix), "-o", "route", "show", "table", strconv.Itoa(m.table), "exact", route.Prefix.String())
	if err != nil {
		return fmt.Errorf("platform: verify owned route %s: %w", route.Prefix, err)
	}
	lines := nonemptyLines(output)
	if len(lines) != 1 || !m.matchesOwned(strings.Fields(lines[0]), route) {
		return fmt.Errorf("%w: current route for %s does not match the installed route", ErrRouteConflict, route.Prefix)
	}
	return nil
}

func routeFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-4"
	}
	return "-6"
}

func linuxRouteMetric(route Route) uint32 {
	// Linux normalizes an explicit IPv6 metric 0 to its default 1024. Use the
	// normalized value in install, ownership checks, and deletion so a route we
	// just created remains recognizable and safely removable.
	if route.Metric == 0 && route.Prefix.Addr().Is6() {
		return linuxDefaultIPv6RouteMetric
	}
	return route.Metric
}

func (m *linuxRouteManager) matchesOwned(fields []string, route Route) bool {
	destinationMatches := len(fields) > 0 && (fields[0] == route.Prefix.String() || fields[0] == route.Prefix.Addr().String())
	metricMatches := hasPair(fields, "metric", strconv.FormatUint(uint64(linuxRouteMetric(route)), 10))
	if route.Metric == 0 && route.Prefix.Addr().Is4() && !containsField(fields, "metric") {
		metricMatches = true // iproute2 omits the default metric from text output.
	}
	return destinationMatches &&
		hasPair(fields, "dev", m.name) &&
		hasPair(fields, "proto", strconv.Itoa(m.protocol)) &&
		metricMatches
}

func (m *linuxRouteManager) run(ctx context.Context, args ...string) (string, error) {
	output, err := m.runner.Run(ctx, m.ip, args...)
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return string(output), fmt.Errorf("%w: %s", err, trimmed)
		}
	}
	return string(output), err
}

func hasPair(fields []string, key, value string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key && fields[i+1] == value {
			return true
		}
	}
	return false
}

func containsField(fields []string, value string) bool {
	for _, field := range fields {
		if field == value {
			return true
		}
	}
	return false
}

func nonemptyLines(output string) []string {
	var result []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func equalFields(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }

func cloneOwned(source map[string]ownedRoute) map[string]ownedRoute {
	clone := make(map[string]ownedRoute, len(source))
	for key, value := range source {
		value.prior = append([]string(nil), value.prior...)
		clone[key] = value
	}
	return clone
}

func sortedRouteKeys(routes map[string]Route) []string {
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedOwnedKeys(routes map[string]ownedRoute) []string {
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
