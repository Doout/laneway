package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
)

type SecureManagerConfig struct {
	Manager  ManagerConfig
	Firewall FirewallConfig
}

type SecureSnapshot struct {
	Peers    []ManagedPeer
	Firewall FirewallPlan
}

type managedWireGuard interface {
	Name() string
	MTU() int
	ListenPort() uint16
	PublicKey() PublicKey
	Addresses() []netip.Prefix
	Peers() []ManagedPeer
	ApplyPeers(context.Context, []ManagedPeer) error
	RelayMetrics() RelayEndpointMetrics
	Run(context.Context) error
	PathAvailable(identity.NodeID) bool
	RunRelay(context.Context, *RelayMux, pathmanager.PathKind, string) error
	Attach(identity.NodeID, pathmanager.PathKind, pathmanager.PacketPath) error
	Detach(identity.NodeID, string) bool
	Close() error
}

// SecureManager commits controller ACL and kernel cryptokey-routing state as
// one fail-closed transition. It never publishes a new peer snapshot under an
// older allow policy.
type SecureManager struct {
	mu       sync.Mutex
	manager  managedWireGuard
	firewall FirewallManager
	current  *SecureSnapshot
	closed   bool
}

func OpenSecureManager(ctx context.Context, config SecureManagerConfig) (*SecureManager, error) {
	manager, err := OpenManager(ctx, config.Manager)
	if err != nil {
		return nil, err
	}
	if config.Firewall.Interface == "" {
		config.Firewall.Interface = manager.Name()
	}
	if config.Firewall.Interface != manager.Name() {
		return nil, errors.Join(fmt.Errorf("%w: firewall interface differs from WireGuard device", ErrInvalidFirewall), manager.Close())
	}
	firewall, err := NewFirewallManager(config.Firewall)
	if err != nil {
		return nil, errors.Join(err, manager.Close())
	}
	return &SecureManager{manager: manager, firewall: firewall}, nil
}

func newSecureManager(manager managedWireGuard, firewall FirewallManager) (*SecureManager, error) {
	if manager == nil || firewall == nil {
		return nil, fmt.Errorf("%w: missing secure manager component", ErrInvalidFirewall)
	}
	return &SecureManager{manager: manager, firewall: firewall}, nil
}

func (m *SecureManager) Name() string                       { return m.manager.Name() }
func (m *SecureManager) MTU() int                           { return m.manager.MTU() }
func (m *SecureManager) ListenPort() uint16                 { return m.manager.ListenPort() }
func (m *SecureManager) PublicKey() PublicKey               { return m.manager.PublicKey() }
func (m *SecureManager) Addresses() []netip.Prefix          { return m.manager.Addresses() }
func (m *SecureManager) Peers() []ManagedPeer               { return m.manager.Peers() }
func (m *SecureManager) RelayMetrics() RelayEndpointMetrics { return m.manager.RelayMetrics() }
func (m *SecureManager) Run(ctx context.Context) error      { return m.manager.Run(ctx) }
func (m *SecureManager) PathAvailable(peer identity.NodeID) bool {
	return m.manager.PathAvailable(peer)
}
func (m *SecureManager) RunRelay(ctx context.Context, mux *RelayMux, kind pathmanager.PathKind, name string) error {
	return m.manager.RunRelay(ctx, mux, kind, name)
}
func (m *SecureManager) Attach(peer identity.NodeID, kind pathmanager.PathKind, path pathmanager.PacketPath) error {
	return m.manager.Attach(peer, kind, path)
}
func (m *SecureManager) Detach(peer identity.NodeID, name string) bool {
	return m.manager.Detach(peer, name)
}

// ApplyGuard publishes an exact deny-only policy before a caller mutates
// routes, forwarding, or other native state for the same controller epoch.
func (m *SecureManager) ApplyGuard(ctx context.Context, plan FirewallPlan) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidFirewall)
	}
	validated, _, err := compileFirewallPlan(plan)
	if err != nil {
		return err
	}
	guard := FirewallPlan{Epoch: validated.Epoch, LocalNode: validated.LocalNode, PeerPrefixes: validated.PeerPrefixes,
		DefaultAction: FirewallDeny, MaxExpandedRules: validated.MaxExpandedRules}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	return m.firewall.Apply(ctx, guard)
}

// RestoreGuard restores the last committed allow policy, or removes the
// initial guard when no snapshot has ever committed.
func (m *SecureManager) RestoreGuard(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidFirewall)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	return m.restoreFirewall(ctx)
}

func (m *SecureManager) ApplySnapshot(ctx context.Context, snapshot SecureSnapshot) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidFirewall)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	peers, err := normalizeManagedPeers(snapshot.Peers, m.manager.PublicKey())
	if err != nil {
		return err
	}
	plan, _, err := compileFirewallPlan(snapshot.Firewall)
	if err != nil {
		return err
	}
	if err := requireMatchingPeerOwnership(peers, plan.PeerPrefixes); err != nil {
		return err
	}
	guard := FirewallPlan{Epoch: plan.Epoch, LocalNode: plan.LocalNode, PeerPrefixes: plan.PeerPrefixes,
		DefaultAction: FirewallDeny, MaxExpandedRules: plan.MaxExpandedRules}
	if err := m.firewall.Apply(ctx, guard); err != nil {
		return err
	}
	previousPeers := m.manager.Peers()
	if err := m.manager.ApplyPeers(ctx, peers); err != nil {
		return errors.Join(err, m.restoreFirewall(ctx))
	}
	if err := m.firewall.Apply(ctx, plan); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), managerRollbackTimeout)
		defer cancel()
		return errors.Join(err, m.manager.ApplyPeers(rollbackCtx, previousPeers), m.restoreFirewall(rollbackCtx))
	}
	committed := SecureSnapshot{Peers: cloneManagedPeers(peers), Firewall: cloneFirewallPlan(plan)}
	m.current = &committed
	return nil
}

func (m *SecureManager) restoreFirewall(ctx context.Context) error {
	if m.current == nil {
		return m.firewall.Restore(ctx)
	}
	return m.firewall.Apply(ctx, m.current.Firewall)
}

func requireMatchingPeerOwnership(peers []ManagedPeer, ownership map[identity.NodeID][]netip.Prefix) error {
	if len(peers) != len(ownership) {
		return fmt.Errorf("%w: firewall and WireGuard peer sets differ", ErrInvalidFirewall)
	}
	for _, peer := range peers {
		prefixes, present := ownership[peer.NodeID]
		if !present || !sameFirewallPrefixes(peer.AllowedIPs, prefixes) {
			return fmt.Errorf("%w: firewall ownership differs for peer %s", ErrInvalidFirewall, peer.NodeID)
		}
	}
	return nil
}

func sameFirewallPrefixes(first, second []netip.Prefix) bool {
	if len(first) != len(second) {
		return false
	}
	left, right := append([]netip.Prefix(nil), first...), append([]netip.Prefix(nil), second...)
	sortPrefixes(left)
	sortPrefixes(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneFirewallPlan(plan FirewallPlan) FirewallPlan {
	result := plan
	result.PeerPrefixes = make(map[identity.NodeID][]netip.Prefix, len(plan.PeerPrefixes))
	for node, prefixes := range plan.PeerPrefixes {
		result.PeerPrefixes[node] = append([]netip.Prefix(nil), prefixes...)
	}
	result.Rules = append([]FirewallRule(nil), plan.Rules...)
	for index := range result.Rules {
		rule, source := &result.Rules[index], &plan.Rules[index]
		rule.SourceNodes = append([]identity.NodeID(nil), source.SourceNodes...)
		rule.DestinationNodes = append([]identity.NodeID(nil), source.DestinationNodes...)
		rule.SourcePrefixes = append([]netip.Prefix(nil), source.SourcePrefixes...)
		rule.DestinationPrefixes = append([]netip.Prefix(nil), source.DestinationPrefixes...)
		rule.DestinationPorts = append([]FirewallPortRange(nil), source.DestinationPorts...)
	}
	return result
}

func (m *SecureManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), managerRollbackTimeout)
	defer cancel()
	// Remove all decrypting peers while the deny policy remains installed,
	// then delete the interface before releasing the nftables hooks.
	peerErr := m.manager.ApplyPeers(ctx, nil)
	deviceErr := m.manager.Close()
	firewallErr := m.firewall.Close()
	m.current = nil
	m.closed = true
	return errors.Join(peerErr, deviceErr, firewallErr)
}
