//go:build linux

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type controlClient interface {
	ConfigureDevice(string, wgtypes.Config) error
	Close() error
}

type linuxDevice struct {
	name      string
	mtu       int
	addresses []netip.Prefix
	runner    commandRunner
	control   controlClient
	peers     []Peer
	mu        sync.Mutex
	close     sync.Once
	closeErr  error
	closed    bool
}

var _ Device = (*linuxDevice)(nil)

func OpenDevice(ctx context.Context, config DeviceConfig) (Device, error) {
	control, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wireguard: open kernel control client: %w", err)
	}
	device, err := openLinuxDevice(ctx, config, execRunner{}, control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	return device, nil
}

func openLinuxDevice(ctx context.Context, config DeviceConfig, runner commandRunner, control controlClient) (Device, error) {
	if ctx == nil || runner == nil || control == nil {
		return nil, fmt.Errorf("%w: missing context or platform backend", ErrInvalidDevice)
	}
	config, err := normalizeDeviceConfig(config)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if out, err := runner.Run(ctx, "ip", "link", "add", "dev", config.Name, "type", "wireguard"); err != nil {
		return nil, commandError("create interface "+config.Name, out, err)
	}
	owned := true
	cleanup := func(cause error) error {
		if !owned {
			return cause
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, removeErr := runner.Run(cleanupCtx, "ip", "link", "delete", "dev", config.Name)
		if removeErr != nil {
			return errors.Join(cause, commandError("roll back interface "+config.Name, out, removeErr))
		}
		return cause
	}
	listenPort := int(config.ListenPort)
	privateKey := wgtypes.Key(config.PrivateKey)
	peerConfigs := peersToWG(config.Peers)
	if err := control.ConfigureDevice(config.Name, wgtypes.Config{PrivateKey: &privateKey, ListenPort: &listenPort, ReplacePeers: true, Peers: peerConfigs}); err != nil {
		return nil, cleanup(fmt.Errorf("wireguard: configure interface identity: %w", err))
	}
	if out, err := runner.Run(ctx, "ip", "link", "set", "dev", config.Name, "mtu", fmt.Sprint(config.MTU), "up"); err != nil {
		return nil, cleanup(commandError("activate interface "+config.Name, out, err))
	}
	for _, prefix := range config.Addresses {
		family := "-6"
		if prefix.Addr().Is4() {
			family = "-4"
		}
		if out, err := runner.Run(ctx, "ip", family, "address", "add", prefix.String(), "dev", config.Name); err != nil {
			return nil, cleanup(commandError("assign interface address "+prefix.String(), out, err))
		}
	}
	owned = false
	return &linuxDevice{name: config.Name, mtu: config.MTU, addresses: append([]netip.Prefix(nil), config.Addresses...), runner: runner, control: control, peers: clonePeers(config.Peers)}, nil
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) MTU() int     { return d.mtu }
func (d *linuxDevice) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), d.addresses...)
}

func (d *linuxDevice) Peers() []Peer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return clonePeers(d.peers)
}

func (d *linuxDevice) ApplyPeers(ctx context.Context, peers []Peer) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidPeer)
	}
	normalized, err := normalizePeers(peers)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	previous := clonePeers(d.peers)
	if err := d.control.ConfigureDevice(d.name, wgtypes.Config{ReplacePeers: true, Peers: peersToWG(normalized)}); err != nil {
		rollbackErr := d.control.ConfigureDevice(d.name, wgtypes.Config{ReplacePeers: true, Peers: peersToWG(previous)})
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("wireguard: replace peer snapshot: %w", err), fmt.Errorf("wireguard: restore prior peer snapshot: %w", rollbackErr))
		}
		return fmt.Errorf("wireguard: replace peer snapshot: %w", err)
	}
	d.peers = clonePeers(normalized)
	return nil
}

func peersToWG(peers []Peer) []wgtypes.PeerConfig {
	result := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		allowed := make([]net.IPNet, 0, len(peer.AllowedIPs))
		for _, prefix := range peer.AllowedIPs {
			bits := prefix.Addr().BitLen()
			allowed = append(allowed, net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), bits)})
		}
		entry := wgtypes.PeerConfig{PublicKey: wgtypes.Key(peer.PublicKey), ReplaceAllowedIPs: true, AllowedIPs: allowed}
		if peer.Endpoint.IsValid() {
			entry.Endpoint = net.UDPAddrFromAddrPort(peer.Endpoint)
		}
		if peer.PersistentKeepalive != 0 {
			keepalive := peer.PersistentKeepalive
			entry.PersistentKeepaliveInterval = &keepalive
		}
		result = append(result, entry)
	}
	return result
}

func (d *linuxDevice) Close() error {
	d.close.Do(func() {
		d.mu.Lock()
		d.closed = true
		// Clear key material and peers before deleting the link. Link deletion is
		// still attempted if control cleanup fails.
		zero := wgtypes.Key{}
		controlErr := d.control.ConfigureDevice(d.name, wgtypes.Config{PrivateKey: &zero, ReplacePeers: true})
		controlCloseErr := d.control.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, linkErr := d.runner.Run(cleanupCtx, "ip", "link", "delete", "dev", d.name)
		cancel()
		if linkErr != nil {
			linkErr = commandError("delete interface "+d.name, out, linkErr)
		}
		d.peers = nil
		d.mu.Unlock()
		d.closeErr = errors.Join(controlErr, controlCloseErr, linkErr)
	})
	return d.closeErr
}

func commandError(operation string, output []byte, err error) error {
	if detail := strings.TrimSpace(string(output)); detail != "" {
		return fmt.Errorf("wireguard: %s: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("wireguard: %s: %w", operation, err)
}
