package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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

func rustConnectConfig(runtimeDir string, metadata bootstrap.Metadata, node identity.NodeIdentity,
	credentials rustConnectCredentials, routes []netip.Prefix, remembered bool,
) (map[string]any, error) {
	if len(metadata.Relays) == 0 {
		return nil, errors.New("bootstrap metadata contains no relay")
	}
	relay := metadata.Relays[0]
	host, _, err := net.SplitHostPort(relay.Endpoint)
	if err != nil || host == "" {
		return nil, errors.New("bootstrap metadata has an invalid relay endpoint")
	}
	requested := make([]string, 0, len(routes))
	for _, prefix := range routes {
		requested = append(requested, prefix.String())
	}
	return map[string]any{
		"mode":        "node",
		"socket_path": filepath.Join(runtimeDir, "laneway.sock"),
		"identity":    map[string]string{"network_id": node.NetworkID.String(), "node_id": node.NodeID.String()},
		"tls":         credentials,
		"tun":         map[string]any{"name": "utun", "mtu": 1280, "configure": true},
		"relay":       map[string]string{"server_name": host, "service_id": relay.ServiceID},
		"controller": map[string]string{
			"endpoint": metadata.Controller.EnrollmentEndpoint, "quic_endpoint": metadata.Controller.QUICEndpoint,
			"server_name": metadata.Controller.ServerName, "service_id": metadata.Controller.ServiceID, "poll_interval": "5s",
		},
		"foreground_routes": map[string]any{"policy_private": remembered && len(routes) == 0, "requested": requested},
	}, nil
}

func runRustConnect(ctx context.Context, executable, runtimeDir string, metadata bootstrap.Metadata, node identity.NodeIdentity,
	credentials rustConnectCredentials, inherited []*os.File, routes []netip.Prefix, remembered bool,
) error {
	if ctx.Err() != nil {
		return nil
	}
	path, err := writeRustConnectConfig(runtimeDir, metadata, node, credentials, routes, remembered)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	command := exec.CommandContext(ctx, executable, "--config", path)
	command.ExtraFiles = inherited
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
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
	credentials rustConnectCredentials, routes []netip.Prefix, remembered bool,
) (string, error) {
	config, err := rustConnectConfig(runtimeDir, metadata, node, credentials, routes, remembered)
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
