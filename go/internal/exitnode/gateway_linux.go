//go:build linux

package exitnode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"laneway.dev/laneway/internal/nftstate"
)

const (
	ipv4ForwardKey   = "net.ipv4.ip_forward"
	gatewayNFTFamily = "inet"
)

type linuxGatewayManager struct {
	mu                sync.Mutex
	config            GatewayManagerConfig
	runner            CommandRunner
	ownerToken        string
	ownerSession      string
	ownershipMarker   string
	priorForwarding   string
	forwardingTouched bool
	tableOwned        bool
	ownershipMarked   bool
	plan              GatewayPlan
	active            bool
	drained           bool
	closed            bool
}

var _ GatewayManager = (*linuxGatewayManager)(nil)

func NewGatewayManager(config GatewayManagerConfig) (GatewayManager, error) {
	normalized, err := normalizeGatewayConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.Runner == nil {
		normalized.Runner = execRunner{}
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, fmt.Errorf("exitnode: create ownership token: %w", err)
	}
	return &linuxGatewayManager{
		config: normalized, runner: normalized.Runner, ownerToken: hex.EncodeToString(token[:]),
		ownershipMarker: nftstate.Marker("exit", normalized.TableName, normalized.OwnerChain,
			normalized.ForwardChain, normalized.NATChain, normalized.InputInterface, normalized.OutputInterface),
	}, nil
}

func (m *linuxGatewayManager) Apply(ctx context.Context, plan GatewayPlan) error {
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
	if !enabled {
		return m.restoreLocked(ctx)
	}
	if m.active && !m.drained && gatewayPlansEqual(m.plan, normalized) {
		return nil
	}
	previous, hadPrevious := cloneGatewayPlan(m.plan), m.active
	if hadPrevious {
		if err := m.restoreLocked(ctx); err != nil {
			return err
		}
	}
	if err := m.activateLocked(ctx, normalized); err != nil {
		if hadPrevious {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
			defer cancel()
			if rollbackErr := m.activateLocked(rollbackCtx, previous); rollbackErr != nil {
				return errors.Join(err, fmt.Errorf("exitnode: gateway rollback: %w", rollbackErr))
			}
		}
		return err
	}
	return nil
}

func (m *linuxGatewayManager) activateLocked(ctx context.Context, plan GatewayPlan) error {
	prior := "1"
	var err error
	if !m.config.ForwardingExternallyManaged {
		prior, err = m.readForwarding(ctx)
		if err != nil {
			return err
		}
	}
	exists, err := m.tableExists(ctx)
	if err != nil {
		return err
	}
	if exists {
		prior, err = m.recoverStaleTable(ctx, plan)
		if err != nil {
			return err
		}
	}
	m.priorForwarding = prior
	m.forwardingTouched = !m.config.ForwardingExternallyManaged && prior == "0" && exists
	m.active = true
	if !m.config.ForwardingExternallyManaged && prior != "1" {
		if err := m.writeForwarding(ctx, "1"); err != nil {
			return m.rollbackActivation(err)
		}
		m.forwardingTouched = true
	}
	if err := m.installTable(ctx, plan, false); err != nil {
		return m.rollbackActivation(err)
	}
	m.plan = cloneGatewayPlan(plan)
	m.drained = false
	return nil
}

func (m *linuxGatewayManager) Drain(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	if !m.active || m.drained {
		return nil
	}
	plan := cloneGatewayPlan(m.plan)
	if err := m.deleteOwnedTable(ctx); err != nil {
		return err
	}
	if err := m.installTable(ctx, plan, true); err != nil {
		return m.rollbackActivation(fmt.Errorf("exitnode: install draining gateway: %w", err))
	}
	m.drained = true
	return nil
}
func (m *linuxGatewayManager) rollbackActivation(cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
	defer cancel()
	if err := m.restoreLocked(ctx); err != nil {
		return errors.Join(cause, fmt.Errorf("exitnode: gateway activation rollback: %w", err))
	}
	return cause
}

func (m *linuxGatewayManager) Restore(ctx context.Context) error {
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
func (m *linuxGatewayManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	var result error
	if m.tableOwned {
		result = errors.Join(result, m.deleteOwnedTable(ctx))
	}
	if m.forwardingTouched {
		current, readErr := m.readForwarding(ctx)
		if readErr != nil {
			result = errors.Join(result, readErr)
		} else if current != "1" {
			result = errors.Join(result, fmt.Errorf("%w: IPv4 forwarding was replaced externally", ErrOwnership))
		} else if err := m.writeForwarding(ctx, m.priorForwarding); err != nil {
			result = errors.Join(result, err)
		} else {
			m.forwardingTouched = false
		}
	}
	if result == nil && !m.tableOwned && !m.forwardingTouched {
		m.active = false
		m.drained = false
		m.priorForwarding = ""
		m.plan = GatewayPlan{}
	}
	return result
}
func (m *linuxGatewayManager) Close() error {
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

func (m *linuxGatewayManager) readForwarding(ctx context.Context) (string, error) {
	out, err := m.run(ctx, m.config.SysctlCommand, "-n", ipv4ForwardKey)
	if err != nil {
		return "", fmt.Errorf("exitnode: read forwarding: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v != "0" && v != "1" {
		return "", fmt.Errorf("%w: unexpected forwarding value %q", ErrInvalid, v)
	}
	return v, nil
}
func (m *linuxGatewayManager) writeForwarding(ctx context.Context, value string) error {
	_, err := m.run(ctx, m.config.SysctlCommand, "-w", ipv4ForwardKey+"="+value)
	if err != nil {
		return fmt.Errorf("exitnode: set forwarding: %w", err)
	}
	return nil
}
func (m *linuxGatewayManager) tableExists(ctx context.Context) (bool, error) {
	out, err := m.run(ctx, m.config.NFTCommand, "list", "tables")
	if err != nil {
		return false, err
	}
	needle := "table " + gatewayNFTFamily + " " + m.config.TableName
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == needle {
			return true, nil
		}
	}
	return false, nil
}

func (m *linuxGatewayManager) installTable(ctx context.Context, plan GatewayPlan, draining bool) error {
	c := m.config
	m.ownerSession = m.newSessionMarker()
	commands := [][]string{{"add", "table", gatewayNFTFamily, c.TableName}, {"add", "chain", gatewayNFTFamily, c.TableName, c.OwnerChain}, {"add", "rule", gatewayNFTFamily, c.TableName, c.OwnerChain, "counter", "comment", m.ownershipMarker}, {"add", "rule", gatewayNFTFamily, c.TableName, c.OwnerChain, "counter", "comment", m.ownerSession}, {"add", "chain", gatewayNFTFamily, c.TableName, c.ForwardChain, "{ type filter hook forward priority 0; policy accept; }"}, {"add", "chain", gatewayNFTFamily, c.TableName, c.NATChain, "{ type nat hook postrouting priority 100; policy accept; }"}}
	for i, args := range commands {
		if _, err := m.run(ctx, c.NFTCommand, args...); err != nil {
			return fmt.Errorf("exitnode: install gateway ruleset step %d: %w", i+1, err)
		}
		if i == 0 {
			m.tableOwned = true
		}
		if i == 3 {
			m.ownershipMarked = true
		}
	}
	for _, prefix := range plan.OverlaySources {
		p := prefix.String()
		addressExpression := "ip"
		if prefix.Addr().Is6() {
			addressExpression = "ip6"
		}
		outbound := []string{"add", "rule", gatewayNFTFamily, c.TableName, c.ForwardChain, "iifname", c.InputInterface, "oifname", c.OutputInterface, addressExpression, "saddr", p}
		if draining {
			outbound = append(outbound, "ct", "state", "established,related")
		}
		outbound = append(outbound, "accept", "comment", "laneway-exit-out")
		if _, err := m.run(ctx, c.NFTCommand, outbound...); err != nil {
			return err
		}
		if _, err := m.run(ctx, c.NFTCommand, "add", "rule", gatewayNFTFamily, c.TableName, c.ForwardChain, "iifname", c.OutputInterface, "oifname", c.InputInterface, addressExpression, "daddr", p, "ct", "state", "established,related", "accept", "comment", "laneway-exit-in"); err != nil {
			return err
		}
		if _, err := m.run(ctx, c.NFTCommand, "add", "rule", gatewayNFTFamily, c.TableName, c.NATChain, "oifname", c.OutputInterface, addressExpression, "saddr", p, "masquerade", "comment", "laneway-exit-nat"); err != nil {
			return err
		}
	}
	if _, err := m.run(ctx, c.NFTCommand, "add", "rule", gatewayNFTFamily, c.TableName, c.ForwardChain,
		"iifname", c.InputInterface, "oifname", c.OutputInterface, "drop", "comment", "laneway-exit-out-deny"); err != nil {
		return err
	}
	if _, err := m.run(ctx, c.NFTCommand, "add", "rule", gatewayNFTFamily, c.TableName, c.ForwardChain,
		"iifname", c.OutputInterface, "oifname", c.InputInterface, "drop", "comment", "laneway-exit-in-deny"); err != nil {
		return err
	}
	return nil
}
func (m *linuxGatewayManager) deleteOwnedTable(ctx context.Context) error {
	if m.ownershipMarked {
		out, err := m.run(ctx, m.config.NFTCommand, "list", "chain", gatewayNFTFamily, m.config.TableName, m.config.OwnerChain)
		if err != nil {
			return fmt.Errorf("exitnode: verify gateway ownership: %w", err)
		}
		if m.ownerSession == "" || !strings.Contains(string(out), m.ownerSession) {
			return fmt.Errorf("%w: gateway marker absent", ErrOwnership)
		}
	}
	if _, err := m.run(ctx, m.config.NFTCommand, "delete", "table", gatewayNFTFamily, m.config.TableName); err != nil {
		return err
	}
	m.tableOwned = false
	m.ownershipMarked = false
	m.ownerSession = ""
	return nil
}

const gatewaySessionPrefix = "laneway-exit-session-v1-"

var gatewaySessionPattern = regexp.MustCompile(`^([0-9a-f]{32})-f([01n])$`)

func (m *linuxGatewayManager) newSessionMarker() string {
	prior := m.priorForwarding
	if m.config.ForwardingExternallyManaged {
		prior = "n"
	}
	return gatewaySessionPrefix + m.ownerToken + "-f" + prior
}

func (m *linuxGatewayManager) recoverStaleTable(ctx context.Context, plan GatewayPlan) (string, error) {
	out, err := m.run(ctx, m.config.NFTCommand, "-j", "list", "table", gatewayNFTFamily, m.config.TableName)
	if err != nil {
		return "", fmt.Errorf("%w: inspect stale gateway table: %v", ErrOwnership, err)
	}
	session, err := nftstate.Validate(out, m.tableShape(plan, false))
	if err != nil {
		session, err = nftstate.Validate(out, m.tableShape(plan, true))
	}
	if err != nil {
		return "", fmt.Errorf("%w: existing gateway table does not exactly match Laneway state: %v", ErrOwnership, err)
	}
	match := gatewaySessionPattern.FindStringSubmatch(strings.TrimPrefix(session, gatewaySessionPrefix))
	if match == nil || (m.config.ForwardingExternallyManaged != (match[2] == "n")) {
		return "", fmt.Errorf("%w: malformed stale gateway session state", ErrOwnership)
	}
	prior := match[2]
	if !m.config.ForwardingExternallyManaged {
		current, readErr := m.readForwarding(ctx)
		if readErr != nil {
			return "", readErr
		}
		if current != "1" {
			return "", fmt.Errorf("%w: stale IPv4 forwarding state was replaced externally", ErrOwnership)
		}
	}
	if _, err := m.run(ctx, m.config.NFTCommand, "delete", "table", gatewayNFTFamily, m.config.TableName); err != nil {
		return "", fmt.Errorf("exitnode: remove validated stale gateway table: %w", err)
	}
	return prior, nil
}

func (m *linuxGatewayManager) tableShape(plan GatewayPlan, draining bool) nftstate.Shape {
	c := m.config
	chains := []nftstate.Chain{{Name: c.OwnerChain},
		{Name: c.ForwardChain, Type: "filter", Hook: "forward", Policy: "accept", Priority: 0, Base: true},
		{Name: c.NATChain, Type: "nat", Hook: "postrouting", Policy: "accept", Priority: 100, Base: true}}
	rules := make([]nftstate.Rule, 0, len(plan.OverlaySources)*3)
	for _, prefix := range plan.OverlaySources {
		protocol := "ip"
		if prefix.Addr().Is6() {
			protocol = "ip6"
		}
		outbound := []any{nftstate.MatchMeta("iifname", c.InputInterface), nftstate.MatchMeta("oifname", c.OutputInterface),
			nftstate.MatchPrefix(protocol, "saddr", prefix.Addr().String(), prefix.Bits())}
		if draining {
			outbound = append(outbound, nftstate.MatchCTStates("established", "related"))
		}
		outbound = append(outbound, nftstate.Accept())
		rules = append(rules,
			nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-exit-out", Expr: outbound},
			nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-exit-in", Expr: []any{
				nftstate.MatchMeta("iifname", c.OutputInterface), nftstate.MatchMeta("oifname", c.InputInterface),
				nftstate.MatchPrefix(protocol, "daddr", prefix.Addr().String(), prefix.Bits()),
				nftstate.MatchCTStates("established", "related"), nftstate.Accept(),
			}},
			nftstate.Rule{Chain: c.NATChain, Comment: "laneway-exit-nat", Expr: []any{
				nftstate.MatchMeta("oifname", c.OutputInterface),
				nftstate.MatchPrefix(protocol, "saddr", prefix.Addr().String(), prefix.Bits()), nftstate.Masquerade(),
			}},
		)
	}
	rules = append(rules,
		nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-exit-out-deny", Expr: []any{
			nftstate.MatchMeta("iifname", c.InputInterface), nftstate.MatchMeta("oifname", c.OutputInterface), nftstate.Drop(),
		}},
		nftstate.Rule{Chain: c.ForwardChain, Comment: "laneway-exit-in-deny", Expr: []any{
			nftstate.MatchMeta("iifname", c.OutputInterface), nftstate.MatchMeta("oifname", c.InputInterface), nftstate.Drop(),
		}},
	)
	return nftstate.Shape{Family: gatewayNFTFamily, Table: c.TableName, OwnerChain: c.OwnerChain,
		Marker: m.ownershipMarker, SessionPrefix: gatewaySessionPrefix, Chains: chains, Rules: rules}
}
func (m *linuxGatewayManager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := m.runner.Run(ctx, name, args...)
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
func cloneGatewayPlan(plan GatewayPlan) GatewayPlan {
	plan.OverlaySources = append([]netip.Prefix(nil), plan.OverlaySources...)
	return plan
}
func gatewayPlansEqual(a, b GatewayPlan) bool {
	if a.Enabled != b.Enabled || a.Authorized != b.Authorized || len(a.OverlaySources) != len(b.OverlaySources) {
		return false
	}
	for i := range a.OverlaySources {
		if a.OverlaySources[i] != b.OverlaySources[i] {
			return false
		}
	}
	return true
}
