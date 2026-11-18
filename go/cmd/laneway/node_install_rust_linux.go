//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/pelletier/go-toml/v2"
)

const (
	managedRustBinary      = "/usr/local/sbin/lanewayd-rs"
	managedRustHealth      = "/usr/local/sbin/laneway-healthcheck-rs"
	managedRustConfig      = "/etc/laneway/node-rust.toml"
	managedRustState       = "/var/lib/laneway"
	managedRustIdentity    = managedRustState + "/identity"
	managedRustCertificate = managedRustIdentity + "/node.crt"
	managedRustExitIntent  = managedRustState + "/exit-intent-v1.json"
	managedNodeSocket      = "/run/laneway/lanewayd.sock"
)

func renderManagedRustNodeConfig(authority string, metadata bootstrap.Metadata, node identity.NodeIdentity, relay managedNodeRelay, direct bool) ([]byte, error) {
	relayHost, _, err := net.SplitHostPort(relay.endpoint)
	if err != nil || relayHost == "" {
		return nil, errors.New("controller returned an invalid managed relay endpoint")
	}
	discovery, err := bootstrap.DiscoveryURL(authority)
	if err != nil {
		return nil, err
	}
	origin, err := url.Parse(discovery)
	if err != nil {
		return nil, err
	}
	value := map[string]any{
		"mode":             "node",
		"socket_path":      managedNodeSocket,
		"exit_intent_path": managedRustExitIntent,
		"identity":         map[string]string{"network_id": node.NetworkID.String(), "node_id": node.NodeID.String()},
		"tls": rustConnectCredentials{
			CA: "/etc/laneway/ca.crt", Certificate: managedRustCertificate, PrivateKey: "/etc/laneway/node.key",
		},
		"tun":   map[string]any{"name": "lane0", "mtu": 1280, "configure": true},
		"relay": map[string]string{"server_name": relayHost, "service_id": relay.serviceID.String()},
		"controller": map[string]any{
			"endpoint": metadata.Controller.EnrollmentEndpoint, "quic_endpoint": metadata.Controller.QUICEndpoint,
			"server_name": metadata.Controller.ServerName, "service_id": metadata.Controller.ServiceID,
			"poll_interval": "30s", "auto_renew_certificate": true,
		},
		"forwarding": map[string]any{
			"exit_client": map[string]any{"authorized": true, "failure_mode": "closed"},
		},
	}
	if direct {
		value["direct"] = map[string]string{"listen": "0.0.0.0:0"}
	}
	// Compose serves discovery and fallback on the same public TLS listener.
	// Do not assume the discovery port belongs to an unrelated relay.
	if strings.EqualFold(strings.TrimSuffix(origin.Hostname(), "."), strings.TrimSuffix(relayHost, ".")) {
		port := origin.Port()
		if port == "" {
			port = "443"
		}
		value["tcp_fallback"] = map[string]string{"address": net.JoinHostPort(relayHost, port)}
	}
	return toml.Marshal(value)
}

func checkManagedRustVersions() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, path := range []string{managedRustBinary, managedRustHealth} {
		out, err := exec.CommandContext(ctx, path, "--version").Output()
		if err != nil || strings.TrimSpace(string(out)) != buildinfo.Version {
			return fmt.Errorf("%s must match Laneway %s; install the matching release", path, buildinfo.Version)
		}
	}
	return nil
}

func checkManagedRustConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, managedRustBinary, "--config", managedRustConfig, "--check-config")
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("validate managed Rust node configuration: %w", err)
	}
	return nil
}

func rejectOtherManagedNode(manifest managedNodeManifest) error {
	other := managedRustUnit
	if manifest.Runtime == managedRustRuntime {
		other = managedGoUnit
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState,UnitFileState", other).Output()
	if err != nil {
		return fmt.Errorf("cannot verify conflicting node unit %s: %w", other, err)
	}
	state := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			state[key] = value
		}
	}
	if (state["ActiveState"] != "inactive" && state["ActiveState"] != "failed") ||
		strings.HasPrefix(state["UnitFileState"], "enabled") {
		return fmt.Errorf("refusing to start alongside %s; stop and disable it first", other)
	}
	return nil
}

func waitManagedRustHealth(ctx context.Context) error {
	for {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := exec.CommandContext(probe, managedRustHealth, "-unix", managedNodeSocket).Run()
		cancel()
		if err == nil {
			return nil
		}
		if err := nodeSystemctlActive(ctx, managedRustUnit); err != nil {
			return fmt.Errorf("Rust node stopped before its local health check: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Rust node did not become healthy: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func validateManagedRustState(owner managedNodeOwner, allowMissing bool) error {
	for _, path := range []string{managedRustState, managedRustIdentity} {
		info, err := os.Lstat(path)
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return fmt.Errorf("managed Rust state path must be a private directory: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != owner.uid || int(stat.Gid) != owner.gid {
			return fmt.Errorf("managed Rust state path has unexpected ownership: %s", path)
		}
	}
	return nil
}

func prepareManagedRustState(owner managedNodeOwner) error {
	if err := validateManagedRustState(owner, true); err != nil {
		return err
	}
	for _, path := range []string{managedRustState, managedRustIdentity} {
		if err := os.Mkdir(path, 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Chown(path, owner.uid, owner.gid); err != nil {
			return err
		}
	}
	return validateManagedRustState(owner, false)
}
