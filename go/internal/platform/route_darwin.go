//go:build darwin

package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type darwinRouteRunner struct{}

func (darwinRouteRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type darwinRouteManager struct {
	mu      sync.Mutex
	name    string
	command string
	runner  CommandRunner
	timeout time.Duration
	owned   map[string]Route
	closed  bool
}

var _ RouteManager = (*darwinRouteManager)(nil)

func NewRouteManager(config RouteManagerConfig) (RouteManager, error) {
	if config.InterfaceName == "" || !interfaceNamePattern.MatchString(config.InterfaceName) {
		return nil, fmt.Errorf("%w: invalid route interface %q", ErrInvalidRoute, config.InterfaceName)
	}
	if config.Table != 0 || config.Protocol != 0 {
		return nil, fmt.Errorf("%w: macOS does not accept Linux route table or protocol settings", ErrInvalidRoute)
	}
	if config.ShutdownTimeout < 0 {
		return nil, fmt.Errorf("%w: negative shutdown timeout", ErrInvalidRoute)
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 5 * time.Second
	}
	if config.IPCommand == "" {
		config.IPCommand = "/sbin/route"
	}
	if config.Runner == nil {
		config.Runner = darwinRouteRunner{}
	}
	return &darwinRouteManager{name: config.InterfaceName, command: config.IPCommand, runner: config.Runner, timeout: config.ShutdownTimeout, owned: make(map[string]Route)}, nil
}

func (m *darwinRouteManager) Apply(ctx context.Context, plan RoutePlan) error {
	desired, err := normalizePlan(plan)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	previous := cloneDarwinRoutes(m.owned)
	for _, key := range sortedDarwinKeys(m.owned) {
		if _, keep := desired[key]; keep {
			continue
		}
		if err := m.remove(ctx, m.owned[key]); err != nil {
			return errors.Join(err, m.rollback(ctx, previous))
		}
		delete(m.owned, key)
	}
	for _, key := range sortedDarwinKeys(desired) {
		if _, exists := m.owned[key]; exists {
			m.owned[key] = desired[key]
			continue
		}
		if err := m.ensureAbsent(ctx, desired[key].Prefix); err != nil {
			return errors.Join(err, m.rollback(ctx, previous))
		}
		if err := m.add(ctx, desired[key]); err != nil {
			return errors.Join(err, m.rollback(ctx, previous))
		}
		m.owned[key] = desired[key]
	}
	return nil
}

func (m *darwinRouteManager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(ctx)
}

func (m *darwinRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	err := m.restoreLocked(ctx)
	if err == nil {
		m.closed = true
	}
	return err
}

func (m *darwinRouteManager) restoreLocked(ctx context.Context) error {
	var result error
	for _, key := range sortedDarwinKeys(m.owned) {
		if err := m.remove(ctx, m.owned[key]); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(m.owned, key)
	}
	return result
}

func (m *darwinRouteManager) rollback(ctx context.Context, previous map[string]Route) error {
	var result error
	for _, key := range sortedDarwinKeys(m.owned) {
		if _, keep := previous[key]; keep {
			continue
		}
		result = errors.Join(result, m.remove(ctx, m.owned[key]))
		delete(m.owned, key)
	}
	for _, key := range sortedDarwinKeys(previous) {
		if _, exists := m.owned[key]; exists {
			continue
		}
		if err := m.ensureAbsent(ctx, previous[key].Prefix); err == nil {
			err = m.add(ctx, previous[key])
			if err == nil {
				m.owned[key] = previous[key]
			}
			result = errors.Join(result, err)
		} else {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (m *darwinRouteManager) ensureAbsent(ctx context.Context, prefix netip.Prefix) error {
	output, err := m.runner.Run(ctx, m.command, "-n", "get", darwinRouteFamily(prefix), "-net", prefix.String())
	if err != nil || !darwinRouteMatchesPrefix(string(output), prefix) {
		return nil
	}
	return fmt.Errorf("%w: refusing to replace existing macOS route for %s: %s", ErrRouteConflict, prefix, strings.TrimSpace(string(output)))
}

func (m *darwinRouteManager) add(ctx context.Context, route Route) error {
	output, err := m.runner.Run(ctx, m.command, "-n", "add", darwinRouteFamily(route.Prefix), "-net", route.Prefix.String(), "-interface", m.name)
	if err != nil {
		return darwinCommandError("add route "+route.Prefix.String(), output, err)
	}
	return nil
}

func (m *darwinRouteManager) remove(ctx context.Context, route Route) error {
	output, err := m.runner.Run(ctx, m.command, "-n", "get", darwinRouteFamily(route.Prefix), "-net", route.Prefix.String())
	if err != nil {
		return fmt.Errorf("%w: owned route %s disappeared", ErrRouteConflict, route.Prefix)
	}
	if !darwinRouteMatchesPrefix(string(output), route.Prefix) || !darwinRouteUsesInterface(string(output), m.name) {
		return fmt.Errorf("%w: current route for %s no longer uses %s", ErrRouteConflict, route.Prefix, m.name)
	}
	output, err = m.runner.Run(ctx, m.command, "-n", "delete", darwinRouteFamily(route.Prefix), "-net", route.Prefix.String(), "-interface", m.name)
	if err != nil {
		return darwinCommandError("delete route "+route.Prefix.String(), output, err)
	}
	return nil
}

func darwinRouteFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-inet"
	}
	return "-inet6"
}

func darwinRouteUsesInterface(output, name string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "interface:" && fields[1] == name {
			return true
		}
	}
	return false
}

func darwinRouteMatchesPrefix(output string, prefix netip.Prefix) bool {
	var destination, mask string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "destination:":
			destination = fields[1]
		case "mask:", "netmask:":
			mask = fields[1]
		}
	}
	if parsed, err := netip.ParsePrefix(destination); err == nil {
		return parsed.Masked() == prefix
	}
	address, err := netip.ParseAddr(destination)
	if err != nil || address != prefix.Addr() {
		return false
	}
	if prefix.Bits() == address.BitLen() && mask == "" {
		return true
	}
	parsedMask := net.ParseIP(mask)
	if parsedMask == nil {
		return false
	}
	bytes := parsedMask.To16()
	if address.Is4() {
		bytes = parsedMask.To4()
	}
	ones, bits := net.IPMask(bytes).Size()
	return bits == address.BitLen() && ones == prefix.Bits()
}

func cloneDarwinRoutes(source map[string]Route) map[string]Route {
	result := make(map[string]Route, len(source))
	for key, route := range source {
		result[key] = route
	}
	return result
}

func sortedDarwinKeys(routes map[string]Route) []string {
	keys := make([]string, 0, len(routes))
	for key := range routes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func darwinCommandError(operation string, output []byte, err error) error {
	if detail := strings.TrimSpace(string(output)); detail != "" {
		return fmt.Errorf("platform: %s: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("platform: %s: %w", operation, err)
}
