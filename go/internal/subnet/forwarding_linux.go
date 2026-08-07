//go:build linux

package subnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"laneway.dev/laneway/internal/nftstate"
)

const (
	ipv4ForwardKey = "net.ipv4.ip_forward"
	ipv6ForwardKey = "net.ipv6.conf.all.forwarding"
	nftFamily      = "inet"
)

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type linuxForwardingManager struct {
	mu sync.Mutex

	config ForwardingManagerConfig
	runner CommandRunner

	active            bool
	tableOwned        bool
	ownershipMarked   bool
	forwardingTouched map[string]bool
	priorForwarding   map[string]string
	plan              ForwardingPlan
	ownerToken        string
	ownerSession      string
	ownershipMarker   string
	closed            bool
}

var _ ForwardingManager = (*linuxForwardingManager)(nil)

func NewForwardingManager(config ForwardingManagerConfig) (ForwardingManager, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.Runner == nil {
		normalized.Runner = execCommandRunner{}
	}
	var rawToken [16]byte
	if _, err := rand.Read(rawToken[:]); err != nil {
		return nil, fmt.Errorf("subnet: create ownership token: %w", err)
	}
	return &linuxForwardingManager{
		config: normalized, runner: normalized.Runner,
		ownerToken: hex.EncodeToString(rawToken[:]),
		ownershipMarker: nftstate.Marker("subnet", normalized.TableName, normalized.OwnerChain,
			normalized.ForwardChain, normalized.NATChain, normalized.InputInterface, normalized.OutputInterface),
		forwardingTouched: make(map[string]bool), priorForwarding: make(map[string]string),
	}, nil
}

func (m *linuxForwardingManager) Apply(ctx context.Context, plan ForwardingPlan) error {
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
	if len(desired.AuthorizedPrefixes) == 0 {
		return m.restoreLocked(ctx)
	}
	// A prior failed Restore may have completed only one half of cleanup. Finish
	// that cleanup before applying again so idempotency never mistakes a missing
	// table or restored sysctl for an active configuration.
	if m.active && !m.tableOwned {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
		return m.activateLocked(ctx, desired)
	}
	if m.active && plansEqual(m.plan, desired) {
		return nil
	}
	if !m.active {
		return m.activateLocked(ctx, desired)
	}
	return m.reconcileLocked(ctx, desired)
}

func (m *linuxForwardingManager) activateLocked(ctx context.Context, desired ForwardingPlan) error {
	exists, err := m.tableExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		if err := m.recoverStaleTable(ctx, desired); err != nil {
			return err
		}
	}

	m.active = true // Keep enough state to make a failed rollback retryable.
	if _, err := m.enableForwarding(ctx, desired); err != nil {
		return m.rollbackActivation(err)
	}
	if err := m.installTable(ctx, desired); err != nil {
		return m.rollbackActivation(err)
	}
	m.plan = clonePlan(desired)
	return nil
}

func (m *linuxForwardingManager) rollbackActivation(cause error) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()
	rollbackErr := m.restoreLocked(rollbackCtx)
	if rollbackErr != nil {
		return errors.Join(cause, fmt.Errorf("subnet: activation rollback: %w", rollbackErr))
	}
	return cause
}

func (m *linuxForwardingManager) reconcileLocked(ctx context.Context, desired ForwardingPlan) error {
	previous := clonePlan(m.plan)
	newlyEnabled, err := m.enableForwarding(ctx, desired)
	if err != nil {
		return err
	}
	if err := m.deleteOwnedTable(ctx); err != nil {
		_ = m.restoreForwardingKeys(ctx, newlyEnabled)
		return err
	}
	if err := m.installTable(ctx, desired); err == nil {
		m.plan = clonePlan(desired)
		return nil
	} else {
		cause := err
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
		defer cancel()
		var rollbackErr error
		if m.tableOwned {
			rollbackErr = errors.Join(rollbackErr, m.deleteOwnedTable(rollbackCtx))
		}
		if !m.tableOwned {
			rollbackErr = errors.Join(rollbackErr, m.installTable(rollbackCtx, previous))
		}
		rollbackErr = errors.Join(rollbackErr, m.restoreForwardingKeys(rollbackCtx, newlyEnabled))
		if rollbackErr != nil {
			return errors.Join(cause, fmt.Errorf("subnet: ruleset rollback: %w", rollbackErr))
		}
		m.plan = previous
		return cause
	}
}

func (m *linuxForwardingManager) Restore(ctx context.Context) error {
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

func (m *linuxForwardingManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	var result error
	if m.tableOwned {
		result = errors.Join(result, m.deleteOwnedTable(ctx))
	}
	keys := make([]string, 0, len(m.forwardingTouched))
	for key, touched := range m.forwardingTouched {
		if touched {
			keys = append(keys, key)
		}
	}
	if err := m.restoreForwardingKeys(ctx, keys); err != nil {
		result = errors.Join(result, err)
	}
	if result == nil && !m.tableOwned && len(m.forwardingTouched) == 0 {
		m.active = false
		m.plan = ForwardingPlan{}
	}
	return result
}

func (m *linuxForwardingManager) Close() error {
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

func (m *linuxForwardingManager) readForwarding(ctx context.Context, key string) (string, error) {
	output, err := m.run(ctx, m.config.SysctlCommand, "-n", key)
	if err != nil {
		return "", fmt.Errorf("subnet: read %s: %w", key, err)
	}
	value := strings.TrimSpace(output)
	if value != "0" && value != "1" {
		return "", fmt.Errorf("subnet: read %s: unexpected value %q", key, value)
	}
	return value, nil
}

func (m *linuxForwardingManager) writeForwarding(ctx context.Context, key, value string) error {
	_, err := m.run(ctx, m.config.SysctlCommand, "-w", key+"="+value)
	if err != nil {
		return fmt.Errorf("subnet: set %s=%s: %w", key, value, err)
	}
	return nil
}

func forwardingKeysFor(plan ForwardingPlan) []string {
	var ipv4, ipv6 bool
	for _, route := range plan.Routes {
		ipv4 = ipv4 || route.Prefix.Addr().Is4()
		ipv6 = ipv6 || route.Prefix.Addr().Is6()
	}
	var result []string
	if ipv4 {
		result = append(result, ipv4ForwardKey)
	}
	if ipv6 {
		result = append(result, ipv6ForwardKey)
	}
	return result
}

func (m *linuxForwardingManager) enableForwarding(ctx context.Context, plan ForwardingPlan) ([]string, error) {
	var newlyEnabled []string
	for _, key := range forwardingKeysFor(plan) {
		if _, managed := m.priorForwarding[key]; managed {
			continue
		}
		prior, err := m.readForwarding(ctx, key)
		if err != nil {
			return newlyEnabled, errors.Join(err, m.restoreForwardingKeys(ctx, newlyEnabled))
		}
		m.priorForwarding[key] = prior
		if prior != "1" {
			if err := m.writeForwarding(ctx, key, "1"); err != nil {
				delete(m.priorForwarding, key)
				return newlyEnabled, errors.Join(err, m.restoreForwardingKeys(ctx, newlyEnabled))
			}
			m.forwardingTouched[key] = true
			newlyEnabled = append(newlyEnabled, key)
		}
	}
	return newlyEnabled, nil
}

func (m *linuxForwardingManager) restoreForwardingKeys(ctx context.Context, keys []string) error {
	var result error
	for i := len(keys) - 1; i >= 0; i-- {
		key := keys[i]
		if m.forwardingTouched[key] {
			if err := m.writeForwarding(ctx, key, m.priorForwarding[key]); err != nil {
				result = errors.Join(result, err)
				continue
			}
			delete(m.forwardingTouched, key)
		}
		delete(m.priorForwarding, key)
	}
	return result
}

func (m *linuxForwardingManager) tableExists(ctx context.Context) (bool, error) {
	output, err := m.run(ctx, m.config.NFTCommand, "list", "tables")
	if err != nil {
		return false, fmt.Errorf("subnet: list nftables tables: %w", err)
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == nftFamily && fields[2] == m.config.TableName {
			return true, nil
		}
	}
	return false, nil
}

func (m *linuxForwardingManager) installTable(ctx context.Context, plan ForwardingPlan) error {
	c := m.config
	if _, err := m.run(ctx, c.NFTCommand, "add", "table", nftFamily, c.TableName); err != nil {
		return fmt.Errorf("subnet: create owned nftables table: %w", err)
	}
	m.tableOwned = true
	if _, err := m.run(ctx, c.NFTCommand, "add", "chain", nftFamily, c.TableName, c.OwnerChain); err != nil {
		return fmt.Errorf("subnet: create ownership chain: %w", err)
	}
	if _, err := m.run(ctx, c.NFTCommand, "add", "rule", nftFamily, c.TableName, c.OwnerChain,
		"counter", "comment", m.ownershipMarker); err != nil {
		return fmt.Errorf("subnet: mark owned nftables table: %w", err)
	}
	m.ownerSession = m.newSessionMarker()
	if _, err := m.run(ctx, c.NFTCommand, "add", "rule", nftFamily, c.TableName, c.OwnerChain,
		"counter", "comment", m.ownerSession); err != nil {
		return fmt.Errorf("subnet: record nftables ownership session: %w", err)
	}
	m.ownershipMarked = true
	if _, err := m.run(ctx, c.NFTCommand, "add", "chain", nftFamily, c.TableName, c.ForwardChain,
		"{ type filter hook forward priority 0; policy accept; }"); err != nil {
		return fmt.Errorf("subnet: create forwarding chain: %w", err)
	}
	hasNAT := false
	for _, route := range plan.Routes {
		hasNAT = hasNAT || route.Mode == ModeNAT
	}
	if hasNAT {
		if _, err := m.run(ctx, c.NFTCommand, "add", "chain", nftFamily, c.TableName, c.NATChain,
			"{ type nat hook postrouting priority 100; policy accept; }"); err != nil {
			return fmt.Errorf("subnet: create NAT chain: %w", err)
		}
	}
	for _, route := range plan.Routes {
		prefix := route.Prefix
		prefixText := prefix.String()
		addressExpression := "ip"
		if prefix.Addr().Is6() {
			addressExpression = "ip6"
		}
		if _, err := m.run(ctx, c.NFTCommand, "add", "rule", nftFamily, c.TableName, c.ForwardChain,
			"iifname", c.InputInterface, "oifname", c.OutputInterface,
			addressExpression, "daddr", prefixText, "accept", "comment", "laneway-forward-out"); err != nil {
			return fmt.Errorf("subnet: add outbound rule for %s: %w", prefix, err)
		}
		if _, err := m.run(ctx, c.NFTCommand, "add", "rule", nftFamily, c.TableName, c.ForwardChain,
			"iifname", c.OutputInterface, "oifname", c.InputInterface,
			addressExpression, "saddr", prefixText, "accept", "comment", "laneway-forward-in"); err != nil {
			return fmt.Errorf("subnet: add inbound rule for %s: %w", prefix, err)
		}
		if route.Mode == ModeNAT {
			if _, err := m.run(ctx, c.NFTCommand, "add", "rule", nftFamily, c.TableName, c.NATChain,
				"iifname", c.InputInterface, "oifname", c.OutputInterface,
				addressExpression, "daddr", prefixText, "masquerade", "comment", "laneway-masquerade"); err != nil {
				return fmt.Errorf("subnet: add masquerade rule for %s: %w", prefix, err)
			}
		}
	}
	return nil
}

func (m *linuxForwardingManager) deleteOwnedTable(ctx context.Context) error {
	if !m.tableOwned {
		return nil
	}
	if m.ownershipMarked {
		output, err := m.run(ctx, m.config.NFTCommand, "list", "chain", nftFamily, m.config.TableName, m.config.OwnerChain)
		if err != nil || m.ownerSession == "" || !strings.Contains(output, m.ownerSession) {
			if err != nil {
				return fmt.Errorf("%w: verify nftables ownership marker: %v", ErrOwnership, err)
			}
			return fmt.Errorf("%w: nftables ownership marker changed", ErrOwnership)
		}
	}
	_, err := m.run(ctx, m.config.NFTCommand, "delete", "table", nftFamily, m.config.TableName)
	if err != nil {
		return fmt.Errorf("subnet: remove owned nftables table: %w", err)
	}
	m.tableOwned = false
	m.ownershipMarked = false
	m.ownerSession = ""
	return nil
}

const subnetSessionPrefix = "laneway-subnet-session-v1-"

var subnetSessionPattern = regexp.MustCompile(`^([0-9a-f]{32})-4([01n])-6([01n])$`)

func (m *linuxForwardingManager) newSessionMarker() string {
	state := func(key string) string {
		if value, ok := m.priorForwarding[key]; ok {
			return value
		}
		return "n"
	}
	return subnetSessionPrefix + m.ownerToken + "-4" + state(ipv4ForwardKey) + "-6" + state(ipv6ForwardKey)
}

func (m *linuxForwardingManager) recoverStaleTable(ctx context.Context, plan ForwardingPlan) error {
	output, err := m.run(ctx, m.config.NFTCommand, "-j", "list", "table", nftFamily, m.config.TableName)
	if err != nil {
		return fmt.Errorf("%w: inspect stale nftables table: %v", ErrOwnership, err)
	}
	session, err := nftstate.Validate([]byte(output), m.tableShape(plan))
	if err != nil {
		return fmt.Errorf("%w: existing nftables table does not exactly match Laneway state: %v", ErrOwnership, err)
	}
	match := subnetSessionPattern.FindStringSubmatch(strings.TrimPrefix(session, subnetSessionPrefix))
	if match == nil {
		return fmt.Errorf("%w: malformed stale nftables session state", ErrOwnership)
	}
	prior := map[string]string{ipv4ForwardKey: match[2], ipv6ForwardKey: match[3]}
	required := make(map[string]bool)
	for _, key := range forwardingKeysFor(plan) {
		required[key] = true
	}
	for key, value := range prior {
		if required[key] != (value != "n") {
			return fmt.Errorf("%w: stale forwarding metadata differs from ruleset", ErrOwnership)
		}
		if value == "n" {
			continue
		}
		current, readErr := m.readForwarding(ctx, key)
		if readErr != nil {
			return readErr
		}
		if current != "1" {
			return fmt.Errorf("%w: stale %s state was replaced externally", ErrOwnership, key)
		}
	}
	if _, err := m.run(ctx, m.config.NFTCommand, "delete", "table", nftFamily, m.config.TableName); err != nil {
		return fmt.Errorf("subnet: remove validated stale nftables table: %w", err)
	}
	for key, value := range prior {
		if value == "n" {
			continue
		}
		m.priorForwarding[key] = value
		m.forwardingTouched[key] = value == "0"
	}
	return nil
}

func (m *linuxForwardingManager) tableShape(plan ForwardingPlan) nftstate.Shape {
	c := m.config
	chains := []nftstate.Chain{{Name: c.OwnerChain}, {
		Name: c.ForwardChain, Type: "filter", Hook: "forward", Policy: "accept", Priority: 0, Base: true,
	}}
	hasNAT := false
	for _, route := range plan.Routes {
		hasNAT = hasNAT || route.Mode == ModeNAT
	}
	if hasNAT {
		chains = append(chains, nftstate.Chain{Name: c.NATChain, Type: "nat", Hook: "postrouting", Policy: "accept", Priority: 100, Base: true})
	}
	rules := make([]nftstate.Rule, 0, len(plan.Routes)*3)
	for _, route := range plan.Routes {
		protocol := "ip"
		if route.Prefix.Addr().Is6() {
			protocol = "ip6"
		}
		prefix := route.Prefix
		rules = append(rules,
			nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-forward-out", Expr: []any{
				nftstate.MatchMeta("iifname", c.InputInterface), nftstate.MatchMeta("oifname", c.OutputInterface),
				nftstate.MatchPrefix(protocol, "daddr", prefix.Addr().String(), prefix.Bits()), nftstate.Accept(),
			}},
			nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-forward-in", Expr: []any{
				nftstate.MatchMeta("iifname", c.OutputInterface), nftstate.MatchMeta("oifname", c.InputInterface),
				nftstate.MatchPrefix(protocol, "saddr", prefix.Addr().String(), prefix.Bits()), nftstate.Accept(),
			}},
		)
		if route.Mode == ModeNAT {
			rules = append(rules, nftstate.Rule{Chain: c.NATChain, Comment: "laneway-masquerade", Expr: []any{
				nftstate.MatchMeta("iifname", c.InputInterface), nftstate.MatchMeta("oifname", c.OutputInterface),
				nftstate.MatchPrefix(protocol, "daddr", prefix.Addr().String(), prefix.Bits()), nftstate.Masquerade(),
			}})
		}
	}
	return nftstate.Shape{Family: nftFamily, Table: c.TableName, OwnerChain: c.OwnerChain,
		Marker: m.ownershipMarker, SessionPrefix: subnetSessionPrefix, Chains: chains, Rules: rules}
}

func (m *linuxForwardingManager) run(ctx context.Context, name string, args ...string) (string, error) {
	output, err := m.runner.Run(ctx, name, args...)
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return string(output), fmt.Errorf("%w: %s", err, trimmed)
		}
	}
	return string(output), err
}
