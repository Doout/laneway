//go:build linux

package nodeapp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// daemonIPForwardManager is the single owner of the host-global IPv4/IPv6
// forwarding switch when controller-approved subnet and exit gateway roles
// coexist. Feature-specific managers see forwarding already enabled and own
// only their nftables state, so neither can disable the other on withdrawal.
type daemonIPForwardManager struct {
	mu      sync.Mutex
	prior   map[string]string
	active  bool
	closed  bool
	timeout time.Duration
	run     func(context.Context, string, ...string) ([]byte, error)
}

var forwardingKeys = []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}

func newDaemonIPForwardManager() *daemonIPForwardManager {
	return &daemonIPForwardManager{timeout: 5 * time.Second, run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
}

func (m *daemonIPForwardManager) Apply(ctx context.Context, desired ipForwardFamilies) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("IP forwarding coordinator is closed")
	}
	if m.prior == nil {
		m.prior = make(map[string]string, len(forwardingKeys))
	}
	originalPrior := make(map[string]string, len(m.prior))
	for key, value := range m.prior {
		originalPrior[key] = value
	}
	type writeUndo struct{ key, value string }
	var undos []writeUndo
	rollback := func(cause error) error {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.timeout)
		defer cancel()
		var rollbackErr error
		for i := len(undos) - 1; i >= 0; i-- {
			rollbackErr = errors.Join(rollbackErr, m.write(rollbackCtx, undos[i].key, undos[i].value))
		}
		m.prior = originalPrior
		m.active = len(m.prior) != 0
		return errors.Join(cause, rollbackErr)
	}
	desiredKeys := map[string]bool{
		forwardingKeys[0]: desired.ipv4,
		forwardingKeys[1]: desired.ipv6,
	}
	for _, key := range forwardingKeys {
		if desiredKeys[key] {
			if _, active := m.prior[key]; active {
				continue
			}
			prior, err := m.read(ctx, key)
			if err != nil {
				return rollback(err)
			}
			m.prior[key] = prior
			if prior != "1" {
				undos = append(undos, writeUndo{key: key, value: prior})
				if err := m.write(ctx, key, "1"); err != nil {
					return rollback(err)
				}
			}
		}
	}
	for i := len(forwardingKeys) - 1; i >= 0; i-- {
		key := forwardingKeys[i]
		if desiredKeys[key] {
			continue
		}
		prior, active := m.prior[key]
		if !active {
			continue
		}
		current, err := m.read(ctx, key)
		if err != nil {
			return rollback(err)
		}
		if current != "1" {
			return rollback(fmt.Errorf("%s was changed externally to %q", key, current))
		}
		if prior != "1" {
			undos = append(undos, writeUndo{key: key, value: current})
			if err := m.write(ctx, key, prior); err != nil {
				return rollback(err)
			}
		}
		delete(m.prior, key)
	}
	m.active = len(m.prior) != 0
	return nil
}

func (m *daemonIPForwardManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	for _, key := range forwardingKeys {
		if _, active := m.prior[key]; !active {
			continue
		}
		current, err := m.read(ctx, key)
		if err != nil {
			return err
		}
		if current != "1" {
			return fmt.Errorf("%s was changed externally to %q", key, current)
		}
	}
	for i := len(forwardingKeys) - 1; i >= 0; i-- {
		key := forwardingKeys[i]
		if _, active := m.prior[key]; !active {
			continue
		}
		if m.prior[key] != "1" {
			if err := m.write(ctx, key, m.prior[key]); err != nil {
				return err
			}
		}
	}
	m.active, m.prior = false, nil
	return nil
}

func (m *daemonIPForwardManager) Close() error {
	if m == nil {
		return nil
	}
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
	m.closed = true
	return nil
}

func (m *daemonIPForwardManager) read(ctx context.Context, key string) (string, error) {
	output, err := m.run(ctx, "sysctl", "-n", key)
	if err != nil {
		return "", fmt.Errorf("read shared %s: %w: %s", key, err, strings.TrimSpace(string(output)))
	}
	value := strings.TrimSpace(string(output))
	if value != "0" && value != "1" {
		return "", fmt.Errorf("unexpected %s value %q", key, value)
	}
	return value, nil
}

func (m *daemonIPForwardManager) write(ctx context.Context, key, value string) error {
	output, err := m.run(ctx, "sysctl", "-w", key+"="+value)
	if err != nil {
		return fmt.Errorf("set shared %s: %w: %s", key, err, strings.TrimSpace(string(output)))
	}
	return nil
}
