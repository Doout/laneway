package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"
)

const (
	DefaultInterfaceName = "lane0"
	DefaultMTU           = 1280
	MinMTU               = 1280
	MaxMTU               = 9000
	MinEphemeralPort     = 49152
	MaxEphemeralPort     = 65535
)

var (
	ErrInvalidDevice = errors.New("wireguard: invalid device configuration")
	ErrInvalidPeer   = errors.New("wireguard: invalid peer configuration")
	ErrClosed        = errors.New("wireguard: device is closed")
	ErrUnsupported   = errors.New("wireguard: kernel device is unsupported on this operating system")
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

// Peer is one controller-authorized WireGuard identity. AllowedIPs is the
// exact destination set owned by the peer; replacing a snapshot must never
// append to kernel state left by an older controller epoch.
type Peer struct {
	PublicKey           PublicKey
	AllowedIPs          []netip.Prefix
	Endpoint            netip.AddrPort
	PersistentKeepalive time.Duration
}

type DeviceConfig struct {
	Name       string
	MTU        int
	Addresses  []netip.Prefix
	PrivateKey PrivateKey
	ListenPort uint16
	Peers      []Peer
}

// Device owns one stable WireGuard interface. ApplyPeers replaces all peers as
// one controller snapshot and restores the previous snapshot if the platform
// rejects the update. Close removes only the interface created by OpenDevice.
type Device interface {
	Name() string
	MTU() int
	ListenPort() uint16
	Addresses() []netip.Prefix
	ApplyPeers(context.Context, []Peer) error
	Peers() []Peer
	Close() error
}

func ephemeralListenPort() (uint16, error) {
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0, fmt.Errorf("wireguard: generate ephemeral listen port: %w", err)
	}
	span := uint32(MaxEphemeralPort - MinEphemeralPort + 1)
	return uint16(uint32(binary.BigEndian.Uint16(random[:]))%span + MinEphemeralPort), nil
}

func normalizeDeviceConfig(config DeviceConfig) (DeviceConfig, error) {
	if config.Name == "" {
		config.Name = DefaultInterfaceName
	}
	if config.MTU == 0 {
		config.MTU = DefaultMTU
	}
	if len(config.Name) > 15 || !interfacePattern.MatchString(config.Name) {
		return DeviceConfig{}, fmt.Errorf("%w: invalid interface name %q", ErrInvalidDevice, config.Name)
	}
	if config.MTU < MinMTU || config.MTU > MaxMTU {
		return DeviceConfig{}, fmt.Errorf("%w: MTU %d is outside [%d,%d]", ErrInvalidDevice, config.MTU, MinMTU, MaxMTU)
	}
	_, localPublicKey, err := ParsePrivateKey(config.PrivateKey[:])
	if err != nil {
		return DeviceConfig{}, fmt.Errorf("%w: %v", ErrInvalidDevice, err)
	}
	addresses := make([]netip.Prefix, 0, len(config.Addresses))
	seen := make(map[netip.Prefix]struct{}, len(config.Addresses))
	for _, prefix := range config.Addresses {
		if !validAddressPrefix(prefix) {
			return DeviceConfig{}, fmt.Errorf("%w: interface address must be a unicast IPv4 /32 or IPv6 /128, got %q", ErrInvalidDevice, prefix)
		}
		prefix = netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen())
		if _, duplicate := seen[prefix]; duplicate {
			return DeviceConfig{}, fmt.Errorf("%w: duplicate interface address %s", ErrInvalidDevice, prefix)
		}
		seen[prefix] = struct{}{}
		addresses = append(addresses, prefix)
	}
	peers, err := normalizePeers(config.Peers)
	if err != nil {
		return DeviceConfig{}, err
	}
	if err := rejectLocalPeer(peers, localPublicKey); err != nil {
		return DeviceConfig{}, err
	}
	config.Addresses, config.Peers = addresses, peers
	return config, nil
}

func rejectLocalPeer(peers []Peer, localPublicKey PublicKey) error {
	for _, peer := range peers {
		if peer.PublicKey == localPublicKey {
			return fmt.Errorf("%w: local public key cannot be configured as a peer", ErrInvalidPeer)
		}
	}
	return nil
}

func normalizePeers(peers []Peer) ([]Peer, error) {
	result := make([]Peer, 0, len(peers))
	keys := make(map[PublicKey]struct{}, len(peers))
	type ownedPrefix struct {
		prefix netip.Prefix
		owner  PublicKey
	}
	var owners []ownedPrefix
	for index, peer := range peers {
		if parsed, err := ParsePublicKey(peer.PublicKey[:]); err != nil || parsed != peer.PublicKey {
			return nil, fmt.Errorf("%w: peer %d has invalid public key", ErrInvalidPeer, index)
		}
		if _, duplicate := keys[peer.PublicKey]; duplicate {
			return nil, fmt.Errorf("%w: duplicate public key at peer %d", ErrInvalidPeer, index)
		}
		keys[peer.PublicKey] = struct{}{}
		if peer.Endpoint.IsValid() && (peer.Endpoint.Addr().IsUnspecified() || peer.Endpoint.Addr().IsMulticast() || peer.Endpoint.Addr().Is4In6() || peer.Endpoint.Port() == 0) {
			return nil, fmt.Errorf("%w: peer %d has invalid endpoint %s", ErrInvalidPeer, index, peer.Endpoint)
		}
		if peer.PersistentKeepalive < 0 || peer.PersistentKeepalive > 24*time.Hour {
			return nil, fmt.Errorf("%w: peer %d has invalid keepalive %s", ErrInvalidPeer, index, peer.PersistentKeepalive)
		}
		allowed := make([]netip.Prefix, 0, len(peer.AllowedIPs))
		local := make(map[netip.Prefix]struct{}, len(peer.AllowedIPs))
		for _, prefix := range peer.AllowedIPs {
			if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Addr().IsMulticast() {
				return nil, fmt.Errorf("%w: peer %d has invalid allowed IP %q", ErrInvalidPeer, index, prefix)
			}
			if _, duplicate := local[prefix]; duplicate {
				return nil, fmt.Errorf("%w: peer %d repeats allowed IP %s", ErrInvalidPeer, index, prefix)
			}
			for _, existing := range owners {
				if existing.owner != peer.PublicKey && existing.prefix.Addr().BitLen() == prefix.Addr().BitLen() &&
					(existing.prefix.Contains(prefix.Addr()) || prefix.Contains(existing.prefix.Addr())) {
					return nil, fmt.Errorf("%w: allowed IP %s overlaps %s owned by another peer", ErrInvalidPeer, prefix, existing.prefix)
				}
			}
			local[prefix] = struct{}{}
			owners = append(owners, ownedPrefix{prefix: prefix, owner: peer.PublicKey})
			allowed = append(allowed, prefix)
		}
		sort.Slice(allowed, func(i, j int) bool { return allowed[i].String() < allowed[j].String() })
		peer.AllowedIPs = allowed
		result = append(result, peer)
	}
	sort.Slice(result, func(i, j int) bool { return string(result[i].PublicKey[:]) < string(result[j].PublicKey[:]) })
	return result, nil
}

func validAddressPrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && !prefix.Addr().Is4In6() && prefix.Bits() == prefix.Addr().BitLen() &&
		!prefix.Addr().IsUnspecified() && !prefix.Addr().IsMulticast()
}

func clonePeers(peers []Peer) []Peer {
	result := make([]Peer, len(peers))
	copy(result, peers)
	for i := range result {
		result[i].AllowedIPs = append([]netip.Prefix(nil), peers[i].AllowedIPs...)
	}
	return result
}
