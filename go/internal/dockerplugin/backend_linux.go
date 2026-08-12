//go:build linux

package dockerplugin

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const nftFamily = "inet"

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type LinuxBackendConfig struct {
	IPCommand       string
	NFTCommand      string
	TunnelInterface string
	Runner          CommandRunner
}
type LinuxBackend struct {
	config LinuxBackendConfig
	runner CommandRunner
}

func NewLinuxBackend(config LinuxBackendConfig) (*LinuxBackend, error) {
	if config.IPCommand == "" {
		config.IPCommand = "ip"
	}
	if config.NFTCommand == "" {
		config.NFTCommand = "nft"
	}
	if config.TunnelInterface == "" {
		config.TunnelInterface = "lane0"
	}
	if len(config.TunnelInterface) > 15 {
		return nil, fmt.Errorf("%w: invalid tunnel interface", ErrInvalid)
	}
	if config.Runner == nil {
		config.Runner = execCommandRunner{}
	}
	return &LinuxBackend{config: config, runner: config.Runner}, nil
}

func (b *LinuxBackend) ApplyNetwork(ctx context.Context, n *Network, _ Authorization) error {
	if n.Policy.Egress != EgressDirect {
		if _, err := b.run(ctx, b.config.IPCommand, "link", "show", "dev", b.config.TunnelInterface); err != nil {
			return fmt.Errorf("dockerplugin: tunnel is unavailable: %w", err)
		}
	}
	created, err := b.ensureBridge(ctx, n)
	if err != nil {
		return err
	}
	if err := b.ensureNFT(ctx, n); err != nil {
		_ = b.deleteNFT(context.Background(), n)
		if created {
			_, _ = b.run(ctx, b.config.IPCommand, "link", "del", "dev", n.Bridge)
		}
		return err
	}
	if err := b.installRoutes(ctx, n); err != nil {
		_ = b.removeRoutes(context.Background(), n)
		_ = b.deleteNFT(ctx, n)
		if created {
			_, _ = b.run(ctx, b.config.IPCommand, "link", "del", "dev", n.Bridge)
		}
		return err
	}
	return nil
}

func (b *LinuxBackend) RemoveNetwork(ctx context.Context, n *Network, _ Authorization) error {
	var result error
	result = errors.Join(result, b.removeRoutes(ctx, n))
	if err := b.deleteNFT(ctx, n); err != nil {
		result = errors.Join(result, err)
	}
	if output, err := b.run(ctx, b.config.IPCommand, "-d", "link", "show", "dev", n.Bridge); err == nil {
		if !strings.Contains(string(output), "bridge") || !strings.Contains(string(output), "alias "+nftMarker(n)) {
			result = errors.Join(result, fmt.Errorf("%w: interface %s has unexpected shape", ErrConflict, n.Bridge))
		} else if _, err := b.run(ctx, b.config.IPCommand, "link", "del", "dev", n.Bridge); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (b *LinuxBackend) Join(ctx context.Context, n *Network, e *Endpoint) error {
	if _, err := b.run(ctx, b.config.IPCommand, "link", "show", "dev", e.HostVeth); err == nil {
		return fmt.Errorf("%w: endpoint interface %s already exists", ErrConflict, e.HostVeth)
	}
	if _, err := b.run(ctx, b.config.IPCommand, "link", "add", "name", e.HostVeth, "type", "veth", "peer", "name", e.PeerVeth); err != nil {
		return err
	}
	rollback := func() { _, _ = b.run(context.Background(), b.config.IPCommand, "link", "del", "dev", e.HostVeth) }
	commands := [][]string{{"link", "set", "dev", e.HostVeth, "mtu", strconv.Itoa(n.Policy.MTU)}, {"link", "set", "dev", e.PeerVeth, "mtu", strconv.Itoa(n.Policy.MTU)}, {"link", "set", "dev", e.HostVeth, "master", n.Bridge}, {"link", "set", "dev", e.HostVeth, "up"}}
	commands = append([][]string{{"link", "set", "dev", e.HostVeth, "alias", endpointMarker(n, e)}}, commands...)
	for _, args := range commands {
		if _, err := b.run(ctx, b.config.IPCommand, args...); err != nil {
			rollback()
			return err
		}
	}
	return nil
}

func (b *LinuxBackend) Leave(ctx context.Context, n *Network, e *Endpoint) error {
	output, err := b.run(ctx, b.config.IPCommand, "-d", "link", "show", "dev", e.HostVeth)
	if err != nil {
		return nil
	}
	if !strings.Contains(string(output), "alias "+endpointMarker(n, e)) {
		return fmt.Errorf("%w: refusing to delete unowned endpoint interface %s", ErrConflict, e.HostVeth)
	}
	_, err = b.run(ctx, b.config.IPCommand, "link", "del", "dev", e.HostVeth)
	return err
}

func (b *LinuxBackend) ensureBridge(ctx context.Context, n *Network) (bool, error) {
	output, err := b.run(ctx, b.config.IPCommand, "-d", "link", "show", "dev", n.Bridge)
	created := false
	if err == nil {
		if !strings.Contains(string(output), "bridge") || !strings.Contains(string(output), "alias "+nftMarker(n)) {
			return false, fmt.Errorf("%w: bridge %s does not match recorded shape", ErrConflict, n.Bridge)
		}
	} else {
		if _, err := b.run(ctx, b.config.IPCommand, "link", "add", "name", n.Bridge, "mtu", strconv.Itoa(n.Policy.MTU), "type", "bridge"); err != nil {
			return false, err
		}
		created = true
	}
	prefix := n.Gateway.String() + "/" + strconv.Itoa(n.Subnet.Bits())
	commands := [][]string{{"link", "set", "dev", n.Bridge, "alias", nftMarker(n)}, {"link", "set", "dev", n.Bridge, "mtu", strconv.Itoa(n.Policy.MTU)}, {"addr", "replace", prefix, "dev", n.Bridge}, {"link", "set", "dev", n.Bridge, "up"}}
	for _, args := range commands {
		if _, err := b.run(ctx, b.config.IPCommand, args...); err != nil {
			return created, err
		}
	}
	return created, nil
}

func (b *LinuxBackend) ensureNFT(ctx context.Context, n *Network) error {
	table := nftTable(n)
	marker := nftMarker(n)
	if output, err := b.run(ctx, b.config.NFTCommand, "list", "table", nftFamily, table); err == nil {
		if !strings.Contains(string(output), marker) {
			return fmt.Errorf("%w: nftables table %s has no ownership marker", ErrConflict, table)
		}
		return nil
	}
	commands := [][]string{{"add", "table", nftFamily, table}, {"add", "chain", nftFamily, table, "owner"}, {"add", "rule", nftFamily, table, "owner", "counter", "comment", strconv.Quote(marker)}, {"add", "chain", nftFamily, table, "forward", "{ type filter hook forward priority 0; policy accept; }"}, {"add", "chain", nftFamily, table, "postrouting", "{ type nat hook postrouting priority 100; policy accept; }"}, {"add", "rule", nftFamily, table, "forward", "oifname", n.Bridge, "ct", "state", "established,related", "accept", "comment", "laneway-established"}}
	for index, args := range commands {
		if _, err := b.run(ctx, b.config.NFTCommand, args...); err != nil {
			if index > 0 {
				_, _ = b.run(context.Background(), b.config.NFTCommand, "delete", "table", nftFamily, table)
			}
			return err
		}
	}
	if n.Policy.Egress != EgressDirect {
		mark := routeMark(n)
		markCommands := [][]string{
			{"add", "chain", nftFamily, table, "premark", "{ type filter hook prerouting priority mangle; policy accept; }"},
			{"add", "rule", nftFamily, table, "premark", "iifname", b.config.TunnelInterface, "ip", "daddr", n.Subnet.String(), "ct", "state", "new", "ct", "mark", "set", mark, "comment", "laneway-tunnel-ingress"},
			{"add", "rule", nftFamily, table, "premark", "iifname", n.Bridge, "ct", "mark", "!=", "0", "meta", "mark", "set", "ct", "mark", "comment", "laneway-symmetric-reply"},
		}
		for _, args := range markCommands {
			if _, err := b.run(ctx, b.config.NFTCommand, args...); err != nil {
				_ = b.deleteNFT(context.Background(), n)
				return err
			}
		}
	}
	if n.Policy.Ingress == IngressAllow {
		for _, source := range n.Policy.IngressSources {
			if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "oifname", n.Bridge, "ip", "saddr", source.String(), "accept", "comment", "laneway-ingress"); err != nil {
				return err
			}
		}
	}
	if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "oifname", n.Bridge, "reject", "comment", "laneway-ingress-default-deny"); err != nil {
		return err
	}
	switch n.Policy.Egress {
	case EgressDirect:
		if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "accept", "comment", "laneway-direct"); err != nil {
			return err
		}
	case EgressSelective:
		for _, prefix := range n.Policy.EgressCIDRs {
			if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "ip", "daddr", prefix.String(), "oifname", "!=", b.config.TunnelInterface, "reject", "comment", "laneway-fail-closed"); err != nil {
				return err
			}
		}
		if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "accept", "comment", "laneway-selective"); err != nil {
			return err
		}
	case EgressFullTunnel:
		for _, prefix := range n.BypassCIDRs {
			if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "ip", "daddr", prefix.String(), "accept", "comment", "laneway-bypass"); err != nil {
				return err
			}
		}
		if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "oifname", "!=", b.config.TunnelInterface, "reject", "comment", "laneway-full-fail-closed"); err != nil {
			return err
		}
	case EgressIsolated:
		for _, prefix := range n.Policy.EgressCIDRs {
			if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "ip", "daddr", prefix.String(), "oifname", b.config.TunnelInterface, "accept", "comment", "laneway-isolated-authorized"); err != nil {
				return err
			}
		}
		if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "forward", "iifname", n.Bridge, "reject", "comment", "laneway-isolated"); err != nil {
			return err
		}
	}
	if n.Policy.NAT {
		if _, err := b.run(ctx, b.config.NFTCommand, "add", "rule", nftFamily, table, "postrouting", "iifname", n.Bridge, "oifname", "!=", b.config.TunnelInterface, "masquerade", "comment", "laneway-explicit-nat"); err != nil {
			return err
		}
	}
	return nil
}

func (b *LinuxBackend) deleteNFT(ctx context.Context, n *Network) error {
	table := nftTable(n)
	output, err := b.run(ctx, b.config.NFTCommand, "list", "table", nftFamily, table)
	if err != nil {
		return nil
	}
	if !strings.Contains(string(output), nftMarker(n)) {
		return fmt.Errorf("%w: refusing to delete unowned nftables table %s", ErrConflict, table)
	}
	_, err = b.run(ctx, b.config.NFTCommand, "delete", "table", nftFamily, table)
	return err
}

func (b *LinuxBackend) installRoutes(ctx context.Context, n *Network) error {
	if n.Policy.Egress == EgressDirect {
		return nil
	}
	table := strconv.Itoa(n.Table)
	priority := n.Table
	if _, err := b.run(ctx, b.config.IPCommand, "route", "replace", "table", table, "default", "dev", b.config.TunnelInterface, "proto", "99"); err != nil {
		return err
	}
	markPriority := 10000 + n.Table - 20000
	if _, err := b.run(ctx, b.config.IPCommand, "rule", "add", "priority", strconv.Itoa(markPriority), "fwmark", routeMark(n), "lookup", table); err != nil && !strings.Contains(err.Error(), "File exists") {
		return err
	}
	if n.Policy.Egress == EgressFullTunnel {
		for _, prefix := range n.BypassCIDRs {
			if _, err := b.run(ctx, b.config.IPCommand, "rule", "add", "priority", strconv.Itoa(priority), "from", n.Subnet.String(), "to", prefix.String(), "lookup", "main"); err != nil && !strings.Contains(err.Error(), "File exists") {
				return err
			}
			priority++
		}
		_, err := b.run(ctx, b.config.IPCommand, "rule", "add", "priority", strconv.Itoa(priority), "from", n.Subnet.String(), "lookup", table)
		if err != nil && !strings.Contains(err.Error(), "File exists") {
			return err
		}
		return nil
	}
	for _, prefix := range n.Policy.EgressCIDRs {
		if _, err := b.run(ctx, b.config.IPCommand, "route", "replace", "table", table, prefix.String(), "dev", b.config.TunnelInterface, "proto", "99"); err != nil {
			return err
		}
		if _, err := b.run(ctx, b.config.IPCommand, "rule", "add", "priority", strconv.Itoa(priority), "from", n.Subnet.String(), "to", prefix.String(), "lookup", table); err != nil && !strings.Contains(err.Error(), "File exists") {
			return err
		}
		priority++
	}
	return nil
}

func (b *LinuxBackend) removeRoutes(ctx context.Context, n *Network) error {
	if n.Policy.Egress == EgressDirect {
		return nil
	}
	priority := n.Table
	var result error
	markPriority := 10000 + n.Table - 20000
	if _, err := b.run(ctx, b.config.IPCommand, "rule", "del", "priority", strconv.Itoa(markPriority)); err != nil && !isMissing(err) {
		result = errors.Join(result, err)
	}
	if n.Policy.Egress == EgressFullTunnel {
		for range n.BypassCIDRs {
			if _, err := b.run(ctx, b.config.IPCommand, "rule", "del", "priority", strconv.Itoa(priority)); err != nil && !isMissing(err) {
				result = errors.Join(result, err)
			}
			priority++
		}
		if _, err := b.run(ctx, b.config.IPCommand, "rule", "del", "priority", strconv.Itoa(priority)); err != nil && !isMissing(err) {
			result = errors.Join(result, err)
		}
	} else {
		for range n.Policy.EgressCIDRs {
			if _, err := b.run(ctx, b.config.IPCommand, "rule", "del", "priority", strconv.Itoa(priority)); err != nil && !isMissing(err) {
				result = errors.Join(result, err)
			}
			priority++
		}
	}
	if _, err := b.run(ctx, b.config.IPCommand, "route", "flush", "table", strconv.Itoa(n.Table), "proto", "99"); err != nil && !isMissing(err) {
		result = errors.Join(result, err)
	}
	return result
}
func (b *LinuxBackend) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return b.runner.Run(ctx, name, args...)
}
func nftTable(n *Network) string  { return "laneway_" + strings.TrimPrefix(n.Bridge, "lwbr") }
func nftMarker(n *Network) string { return "laneway-docker-v1:" + n.ID }
func endpointMarker(n *Network, e *Endpoint) string {
	return "laneway-docker-endpoint-v1:" + n.ID + ":" + e.ID
}
func routeMark(n *Network) string { return fmt.Sprintf("0x4c%04x", n.Table) }
func isMissing(err error) bool {
	return strings.Contains(err.Error(), "No such") || strings.Contains(err.Error(), "Cannot find") || strings.Contains(err.Error(), "not found")
}
