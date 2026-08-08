//go:build linux

package wireguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	firewallFamily        = "inet"
	firewallSessionPrefix = "laneway-wg-session-v1-"
)

var firewallNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

type linuxFirewallManager struct {
	mu      sync.Mutex
	config  FirewallConfig
	session string
	digest  [sha256.Size]byte
	desired [sha256.Size]byte
	batch   []byte
	active  bool
	closed  bool
}

func NewFirewallManager(config FirewallConfig) (FirewallManager, error) {
	if config.Interface == "" || len(config.Interface) > 15 || !interfacePattern.MatchString(config.Interface) {
		return nil, fmt.Errorf("%w: invalid interface", ErrInvalidFirewall)
	}
	if config.Table == "" {
		config.Table = DefaultFirewallTable
	}
	if config.OwnerChain == "" {
		config.OwnerChain = DefaultFirewallOwnerChain
	}
	if config.InboundChain == "" {
		config.InboundChain = DefaultFirewallInboundChain
	}
	if config.OutboundChain == "" {
		config.OutboundChain = DefaultFirewallOutboundChain
	}
	for _, value := range []string{config.Table, config.OwnerChain, config.InboundChain, config.OutboundChain} {
		if !firewallNamePattern.MatchString(value) {
			return nil, fmt.Errorf("%w: invalid nftables name", ErrInvalidFirewall)
		}
	}
	if config.OwnerChain == config.InboundChain || config.OwnerChain == config.OutboundChain || config.InboundChain == config.OutboundChain {
		return nil, fmt.Errorf("%w: nftables chain names must differ", ErrInvalidFirewall)
	}
	for _, value := range []string{config.OwnerChain, config.InboundChain, config.OutboundChain} {
		if value == "laneway_wg_input" || value == "laneway_wg_output" || value == "laneway_wg_forward" {
			return nil, fmt.Errorf("%w: regular and base chain names must differ", ErrInvalidFirewall)
		}
	}
	if config.NFTCommand == "" {
		config.NFTCommand = "nft"
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 5 * time.Second
	}
	if config.ShutdownTimeout < 0 {
		return nil, fmt.Errorf("%w: negative shutdown timeout", ErrInvalidFirewall)
	}
	if config.Runner == nil {
		config.Runner = execRunner{}
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, fmt.Errorf("wireguard: firewall session: %w", err)
	}
	return &linuxFirewallManager{config: config, session: firewallSessionPrefix + hex.EncodeToString(token[:])}, nil
}

func (m *linuxFirewallManager) Apply(ctx context.Context, plan FirewallPlan) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidFirewall)
	}
	_, statements, err := compileFirewallPlan(plan)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrFirewallClosed
	}
	creation := m.renderBatch(statements)
	desired := sha256.Sum256(creation)
	wasActive := m.active
	previousDigest, previousDesired := m.digest, m.desired
	previousBatch := append([]byte(nil), m.batch...)
	if m.active {
		if err := m.verifyLocked(ctx); err != nil {
			return err
		}
		if desired == m.desired {
			return nil
		}
	} else {
		exists, err := m.tableExists(ctx)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: table %s already exists", ErrFirewallOwnership, m.config.Table)
		}
	}
	batch := creation
	if m.active {
		batch = append(m.deleteBatch(), creation...)
	}
	if output, err := m.config.Runner.RunInput(ctx, batch, m.config.NFTCommand, "-f", "-"); err != nil {
		return firewallCommandError("apply atomic ruleset", output, err)
	}
	digest, err := m.currentDigest(ctx)
	if err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), m.config.ShutdownTimeout)
		defer cancel()
		rollbackBatch := m.deleteBatch()
		if wasActive {
			rollbackBatch = append(rollbackBatch, previousBatch...)
		}
		_, rollbackErr := m.config.Runner.RunInput(rollbackCtx, rollbackBatch, m.config.NFTCommand, "-f", "-")
		if rollbackErr == nil {
			m.active, m.digest, m.desired, m.batch = wasActive, previousDigest, previousDesired, previousBatch
		}
		return errors.Join(err, rollbackErr)
	}
	m.digest, m.desired, m.batch, m.active = digest, desired, creation, true
	return nil
}

func (m *linuxFirewallManager) Restore(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidFirewall)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrFirewallClosed
	}
	return m.restoreLocked(ctx)
}

func (m *linuxFirewallManager) restoreLocked(ctx context.Context) error {
	if !m.active {
		return nil
	}
	if err := m.verifyLocked(ctx); err != nil {
		return err
	}
	if output, err := m.config.Runner.RunInput(ctx, m.deleteBatch(), m.config.NFTCommand, "-f", "-"); err != nil {
		return firewallCommandError("remove owned ruleset", output, err)
	}
	m.active = false
	m.digest = [sha256.Size]byte{}
	m.desired = [sha256.Size]byte{}
	m.batch = nil
	return nil
}

func (m *linuxFirewallManager) Close() error {
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

func (m *linuxFirewallManager) tableExists(ctx context.Context) (bool, error) {
	output, err := m.config.Runner.Run(ctx, m.config.NFTCommand, "list", "tables")
	if err != nil {
		return false, firewallCommandError("list nftables tables", output, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == firewallFamily && fields[2] == m.config.Table {
			return true, nil
		}
	}
	return false, nil
}

func (m *linuxFirewallManager) verifyLocked(ctx context.Context) error {
	digest, err := m.currentDigest(ctx)
	if err != nil {
		return err
	}
	if digest != m.digest {
		return fmt.Errorf("%w: nftables table changed externally", ErrFirewallOwnership)
	}
	return nil
}

func (m *linuxFirewallManager) currentDigest(ctx context.Context) ([sha256.Size]byte, error) {
	output, err := m.config.Runner.Run(ctx, m.config.NFTCommand, "-j", "list", "table", firewallFamily, m.config.Table)
	if err != nil {
		return [sha256.Size]byte{}, firewallCommandError("inspect owned ruleset", output, err)
	}
	var document any
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("wireguard: decode nftables state: %w", err)
	}
	canonicalizeFirewallJSON(document)
	canonical, err := json.Marshal(document)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("wireguard: canonicalize nftables state: %w", err)
	}
	return sha256.Sum256(canonical), nil
}

func canonicalizeFirewallJSON(value any) {
	switch value := value.(type) {
	case map[string]any:
		delete(value, "handle")
		if counter, ok := value["counter"].(map[string]any); ok {
			counter["packets"], counter["bytes"] = json.Number("0"), json.Number("0")
		}
		for _, child := range value {
			canonicalizeFirewallJSON(child)
		}
	case []any:
		for _, child := range value {
			canonicalizeFirewallJSON(child)
		}
	}
}

func (m *linuxFirewallManager) renderBatch(statements []firewallStatement) []byte {
	c := m.config
	var lines []string
	lines = append(lines,
		"add table "+firewallFamily+" "+c.Table,
		"add chain "+firewallFamily+" "+c.Table+" "+c.OwnerChain,
		"add rule "+firewallFamily+" "+c.Table+" "+c.OwnerChain+" counter comment \""+m.session+"\"",
		"add chain "+firewallFamily+" "+c.Table+" "+c.InboundChain,
		"add chain "+firewallFamily+" "+c.Table+" "+c.OutboundChain,
	)
	for index, statement := range statements {
		chain := c.InboundChain
		if statement.Direction == firewallOutbound {
			chain = c.OutboundChain
		}
		lines = append(lines, "add rule "+firewallFamily+" "+c.Table+" "+chain+" "+renderFirewallStatement(statement)+
			" comment \"laneway-wg-rule-"+statement.RuleID.String()+"-"+strconv.Itoa(index)+"\"")
	}
	lines = append(lines,
		"add rule "+firewallFamily+" "+c.Table+" "+c.InboundChain+" drop comment \"laneway-wg-default-deny-in\"",
		"add rule "+firewallFamily+" "+c.Table+" "+c.OutboundChain+" drop comment \"laneway-wg-default-deny-out\"",
		"add chain "+firewallFamily+" "+c.Table+" laneway_wg_input { type filter hook input priority -10; policy accept; }",
		"add chain "+firewallFamily+" "+c.Table+" laneway_wg_output { type filter hook output priority -10; policy accept; }",
		"add chain "+firewallFamily+" "+c.Table+" laneway_wg_forward { type filter hook forward priority -10; policy accept; }",
		"add rule "+firewallFamily+" "+c.Table+" laneway_wg_input iifname \""+c.Interface+"\" jump "+c.InboundChain+" comment \"laneway-wg-input\"",
		"add rule "+firewallFamily+" "+c.Table+" laneway_wg_output oifname \""+c.Interface+"\" jump "+c.OutboundChain+" comment \"laneway-wg-output\"",
		"add rule "+firewallFamily+" "+c.Table+" laneway_wg_forward iifname \""+c.Interface+"\" oifname \""+c.Interface+"\" drop comment \"laneway-wg-no-transit\"",
		"add rule "+firewallFamily+" "+c.Table+" laneway_wg_forward iifname \""+c.Interface+"\" jump "+c.InboundChain+" comment \"laneway-wg-forward-in\"",
		"add rule "+firewallFamily+" "+c.Table+" laneway_wg_forward oifname \""+c.Interface+"\" jump "+c.OutboundChain+" comment \"laneway-wg-forward-out\"",
	)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func renderFirewallStatement(statement firewallStatement) string {
	var fields []string
	addPrefix := func(prefix netip.Prefix, field string) {
		if !prefix.IsValid() {
			return
		}
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		fields = append(fields, family, field, prefix.String())
	}
	addPrefix(statement.SourceOwnerPrefix, "saddr")
	addPrefix(statement.DestinationOwnerPrefix, "daddr")
	addPrefix(statement.SourcePrefix, "saddr")
	addPrefix(statement.DestinationPrefix, "daddr")
	if statement.Protocol != 256 {
		family := "ip"
		protocolField := "protocol"
		if statement.Family == 6 {
			family, protocolField = "ip6", "nexthdr"
		}
		fields = append(fields, family, protocolField, strconv.Itoa(int(statement.Protocol)))
	}
	if statement.Port.First != 0 {
		transport := "tcp"
		if statement.Protocol == 17 {
			transport = "udp"
		}
		port := strconv.Itoa(int(statement.Port.First))
		if statement.Port.Last != statement.Port.First {
			port += "-" + strconv.Itoa(int(statement.Port.Last))
		}
		fields = append(fields, transport, "dport", port)
	}
	if statement.Action == FirewallAccept {
		fields = append(fields, "accept")
	} else {
		fields = append(fields, "drop")
	}
	return strings.Join(fields, " ")
}

func (m *linuxFirewallManager) deleteBatch() []byte {
	return []byte("delete table " + firewallFamily + " " + m.config.Table + "\n")
}

func firewallCommandError(operation string, output []byte, err error) error {
	trimmed := strings.TrimSpace(string(output))
	if trimmed != "" {
		return fmt.Errorf("wireguard: %s: %w: %s", operation, err, trimmed)
	}
	return fmt.Errorf("wireguard: %s: %w", operation, err)
}
