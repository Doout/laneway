package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"laneway.dev/laneway/internal/identity"
)

const managerRollbackTimeout = 5 * time.Second

// ManagedPeer binds a controller-authenticated NodeID to one WireGuard public
// key and its exact cryptokey-routing ownership. The relay endpoint is assigned
// locally and cannot be supplied by a controller snapshot.
type ManagedPeer struct {
	NodeID              identity.NodeID
	PublicKey           PublicKey
	AllowedIPs          []netip.Prefix
	PersistentKeepalive time.Duration
}

// ManagerConfig creates one stable kernel WireGuard device and its loopback
// encrypted-relay boundary. Device.Peers must be empty: peers are committed
// transactionally through ApplyPeers after their endpoint sockets exist.
type ManagerConfig struct {
	Device   DeviceConfig
	MaxPeers int
}

// Manager owns the stable WireGuard device and peer-to-relay endpoint mapping.
// It implements nodeservice.WireGuardRelayHandler without importing the node
// service package and keeps peer updates transactional across both resources.
type Manager struct {
	mu        sync.Mutex
	device    Device
	endpoint  *RelayEndpoint
	publicKey PublicKey
	peers     []ManagedPeer
	closed    bool
}

func OpenManager(ctx context.Context, config ManagerConfig) (*Manager, error) {
	if len(config.Device.Peers) != 0 {
		return nil, fmt.Errorf("%w: manager device peers must be applied through the managed snapshot", ErrInvalidDevice)
	}
	normalized, err := normalizeDeviceConfig(config.Device)
	if err != nil {
		return nil, err
	}
	device, err := OpenDevice(ctx, normalized)
	if err != nil {
		return nil, err
	}
	endpoint, err := NewRelayEndpoint(RelayEndpointConfig{
		KernelEndpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), device.ListenPort()),
		MaxPeers:       config.MaxPeers,
	})
	if err != nil {
		return nil, errors.Join(err, device.Close())
	}
	_, publicKey, _ := ParsePrivateKey(normalized.PrivateKey[:])
	return newManager(device, endpoint, publicKey), nil
}

func newManager(device Device, endpoint *RelayEndpoint, publicKey PublicKey) *Manager {
	return &Manager{device: device, endpoint: endpoint, publicKey: publicKey}
}

func (m *Manager) Name() string       { return m.device.Name() }
func (m *Manager) MTU() int           { return m.device.MTU() }
func (m *Manager) ListenPort() uint16 { return m.device.ListenPort() }
func (m *Manager) Addresses() []netip.Prefix {
	return m.device.Addresses()
}

func (m *Manager) Peers() []ManagedPeer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneManagedPeers(m.peers)
}

func (m *Manager) RelayMetrics() RelayEndpointMetrics { return m.endpoint.Metrics() }

// ApplyPeers commits an exact peer snapshot. It first stages the union of old
// and new loopback sockets, then replaces the kernel snapshot, then removes
// obsolete sockets. A kernel rejection leaves the old endpoints and peers
// untouched, including their exact port numbers.
func (m *Manager) ApplyPeers(ctx context.Context, peers []ManagedPeer) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidPeer)
	}
	normalized, err := normalizeManagedPeers(peers, m.publicKey)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	previous := cloneManagedPeers(m.peers)
	union := managedPeerUnion(previous, normalized)
	if err := m.endpoint.ApplyPeers(ctx, managedPeerIDs(union)); err != nil {
		return err
	}
	endpoints := m.endpoint.Endpoints()
	devicePeers := managedDevicePeers(normalized, endpoints)
	if err := m.device.ApplyPeers(ctx, devicePeers); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), managerRollbackTimeout)
		defer cancel()
		return errors.Join(err, m.endpoint.ApplyPeers(rollbackCtx, managedPeerIDs(previous)))
	}
	commitCtx, cancel := context.WithTimeout(context.Background(), managerRollbackTimeout)
	defer cancel()
	if err := m.endpoint.ApplyPeers(commitCtx, managedPeerIDs(normalized)); err != nil {
		rollbackDeviceErr := m.device.ApplyPeers(commitCtx, managedDevicePeers(previous, endpoints))
		rollbackEndpointErr := m.endpoint.ApplyPeers(commitCtx, managedPeerIDs(previous))
		return errors.Join(err, rollbackDeviceErr, rollbackEndpointErr)
	}
	m.peers = cloneManagedPeers(normalized)
	return nil
}

func normalizeManagedPeers(peers []ManagedPeer, local PublicKey) ([]ManagedPeer, error) {
	ids := make(map[identity.NodeID]struct{}, len(peers))
	devicePeers := make([]Peer, 0, len(peers))
	result := cloneManagedPeers(peers)
	for index, peer := range result {
		if peer.NodeID.IsZero() {
			return nil, fmt.Errorf("%w: peer %d has a zero node identity", ErrInvalidPeer, index)
		}
		if _, duplicate := ids[peer.NodeID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate node identity %s", ErrInvalidPeer, peer.NodeID)
		}
		ids[peer.NodeID] = struct{}{}
		devicePeers = append(devicePeers, Peer{
			PublicKey: peer.PublicKey, AllowedIPs: peer.AllowedIPs, PersistentKeepalive: peer.PersistentKeepalive,
		})
	}
	normalizedDevice, err := normalizePeers(devicePeers)
	if err != nil {
		return nil, err
	}
	if err := rejectLocalPeer(normalizedDevice, local); err != nil {
		return nil, err
	}
	// normalizePeers validates the complete ownership set. Preserve the NodeID
	// binding while using its canonical AllowedIPs ordering below.
	canonical := make(map[PublicKey]Peer, len(normalizedDevice))
	for _, peer := range normalizedDevice {
		canonical[peer.PublicKey] = peer
	}
	for index := range result {
		result[index].AllowedIPs = append([]netip.Prefix(nil), canonical[result[index].PublicKey].AllowedIPs...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].NodeID.String() < result[j].NodeID.String() })
	return result, nil
}

func managedPeerUnion(first, second []ManagedPeer) []ManagedPeer {
	union := make(map[identity.NodeID]ManagedPeer, len(first)+len(second))
	for _, peer := range first {
		union[peer.NodeID] = peer
	}
	for _, peer := range second {
		union[peer.NodeID] = peer
	}
	result := make([]ManagedPeer, 0, len(union))
	for _, peer := range union {
		result = append(result, peer)
	}
	return result
}

func managedPeerIDs(peers []ManagedPeer) []identity.NodeID {
	result := make([]identity.NodeID, 0, len(peers))
	for _, peer := range peers {
		result = append(result, peer.NodeID)
	}
	return result
}

func managedDevicePeers(peers []ManagedPeer, endpoints map[identity.NodeID]netip.AddrPort) []Peer {
	result := make([]Peer, 0, len(peers))
	for _, peer := range peers {
		result = append(result, Peer{
			PublicKey: peer.PublicKey, AllowedIPs: append([]netip.Prefix(nil), peer.AllowedIPs...),
			Endpoint: endpoints[peer.NodeID], PersistentKeepalive: peer.PersistentKeepalive,
		})
	}
	return result
}

func cloneManagedPeers(peers []ManagedPeer) []ManagedPeer {
	result := make([]ManagedPeer, len(peers))
	copy(result, peers)
	for index := range result {
		result[index].AllowedIPs = append([]netip.Prefix(nil), peers[index].AllowedIPs...)
	}
	return result
}

func (m *Manager) RunRelay(ctx context.Context, mux *RelayMux) error {
	return m.endpoint.RunRelay(ctx, mux)
}

func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.peers = nil
	m.mu.Unlock()
	// Stop userspace forwarding before clearing the kernel key and deleting the
	// interface, preventing new ciphertext from entering during teardown.
	return errors.Join(m.endpoint.Close(), m.device.Close())
}
