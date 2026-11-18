package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/pelletier/go-toml/v2"
)

type rustConnectCredentials struct {
	CA          string `toml:"ca"`
	Certificate string `toml:"certificate"`
	PrivateKey  string `toml:"private_key"`
}

type rustConnectSelection struct {
	authority   string
	routes      []netip.Prefix
	remembered  bool
	exit        identity.NodeID
	failureMode string
	dns         []netip.Addr
	localLAN    []netip.Prefix
}

func rustConnectConfig(runtimeDir string, metadata bootstrap.Metadata, node identity.NodeIdentity,
	credentials rustConnectCredentials, selection rustConnectSelection,
) (map[string]any, error) {
	if len(metadata.Relays) == 0 {
		return nil, errors.New("bootstrap metadata contains no relay")
	}
	relay := metadata.Relays[0]
	host, _, err := net.SplitHostPort(relay.Endpoint)
	if err != nil || host == "" {
		return nil, errors.New("bootstrap metadata has an invalid relay endpoint")
	}
	requested := make([]string, 0, len(selection.routes))
	for _, prefix := range selection.routes {
		requested = append(requested, prefix.String())
	}
	value := map[string]any{
		"mode":             "node",
		"socket_path":      filepath.Join(runtimeDir, "laneway.sock"),
		"exit_intent_path": filepath.Join(runtimeDir, "exit-intent.json"),
		"identity":         map[string]string{"network_id": node.NetworkID.String(), "node_id": node.NodeID.String()},
		"tls":              credentials,
		"tun":              map[string]any{"name": foregroundTunName(runtimeDir), "mtu": 1280, "configure": true},
		"relay":            map[string]string{"server_name": host, "service_id": relay.ServiceID},
		"direct":           map[string]string{"listen": "0.0.0.0:0"},
		"controller": map[string]string{
			"endpoint": metadata.Controller.EnrollmentEndpoint, "quic_endpoint": metadata.Controller.QUICEndpoint,
			"server_name": metadata.Controller.ServerName, "service_id": metadata.Controller.ServiceID, "poll_interval": "5s",
		},
		"foreground_routes": map[string]any{"policy_private": selection.remembered && len(requested) == 0, "requested": requested},
	}
	if selection.authority != "" {
		discovery, err := bootstrap.DiscoveryURL(selection.authority)
		if err != nil {
			return nil, err
		}
		origin, err := url.Parse(discovery)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSuffix(origin.Hostname(), "."), strings.TrimSuffix(host, ".")) {
			port := origin.Port()
			if port == "" {
				port = "443"
			}
			value["tcp_fallback"] = map[string]string{"address": net.JoinHostPort(host, port)}
		}
	}
	if !selection.exit.IsZero() {
		localLAN := make([]string, 0, len(selection.localLAN))
		for _, prefix := range selection.localLAN {
			localLAN = append(localLAN, prefix.String())
		}
		dns := make([]string, 0, len(selection.dns))
		for _, address := range selection.dns {
			dns = append(dns, address.String())
		}
		value["forwarding"] = map[string]any{
			"dns_state_file": filepath.Join(runtimeDir, "dns-state.json"),
			"exit_client": map[string]any{
				"enabled": true, "authorized": true, "selected_node": selection.exit.String(),
				"failure_mode": selection.failureMode, "local_lan_bypass": localLAN, "dns_servers": dns,
			},
		}
	}
	return value, nil
}

func runRustConnect(ctx context.Context, executable, runtimeDir string, metadata bootstrap.Metadata, node identity.NodeIdentity,
	credentials rustConnectCredentials, inherited []*os.File, selection rustConnectSelection,
) error {
	if ctx.Err() != nil {
		return nil
	}
	path, err := writeRustConnectConfig(runtimeDir, metadata, node, credentials, selection)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	command := exec.CommandContext(ctx, executable, "--config", path)
	command.ExtraFiles = inherited
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	defer prepareRustForegroundProcess(command)()
	// Let the daemon restore routes before the outer CLI removes its session
	// directory or rotates a saved credential. An unresponsive daemon is bounded.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 30 * time.Second
	if err := command.Run(); err != nil && !errors.Is(err, ctx.Err()) {
		return fmt.Errorf("Rust foreground runtime: %w", err)
	}
	if ctx.Err() == nil {
		return errors.New("Rust foreground runtime stopped before the session ended")
	}
	return nil
}

func writeRustConnectConfig(runtimeDir string, metadata bootstrap.Metadata, node identity.NodeIdentity,
	credentials rustConnectCredentials, selection rustConnectSelection,
) (string, error) {
	config, err := rustConnectConfig(runtimeDir, metadata, node, credentials, selection)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(runtimeDir, "rust-*.toml")
	if err != nil {
		return "", err
	}
	if err := errors.Join(toml.NewEncoder(file).Encode(config), file.Close()); err != nil {
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("write private Rust session configuration: %w", err)
	}
	return file.Name(), nil
}
