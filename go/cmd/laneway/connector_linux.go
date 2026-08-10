//go:build linux

package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"laneway.dev/laneway/internal/config"
)

const connectorSetupPrefix = "st1."

type connectorSetup struct {
	Name, Code, ControllerEndpoint, ControllerQUIC, ServerName           string
	NetworkID, ControllerServiceID, RelayEndpoint, RelayServiceID, CAPEM string
}

func runConnector(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway connector <activate|configure>")
	}
	if args[0] == "configure" {
		fs := flag.NewFlagSet("connector configure", flag.ContinueOnError)
		stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || !filepath.IsAbs(*stateDir) {
			return errors.New("usage: laneway connector configure [--state-dir DIR]")
		}
		return configureConnector(*stateDir)
	}
	if args[0] != "activate" {
		return errors.New("usage: laneway connector <activate|configure>")
	}
	fs := flag.NewFlagSet("connector activate", flag.ContinueOnError)
	setupToken := fs.String("setup-token", "", "single-use Connector setup token")
	stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *setupToken == "" || !filepath.IsAbs(*stateDir) {
		return errors.New("usage: laneway connector activate --setup-token TOKEN [--state-dir DIR]")
	}
	setup, err := parseConnectorSetupToken(*setupToken)
	if err != nil {
		return err
	}
	return activateConnector(*stateDir, setup)
}

func configureConnector(stateDir string) error {
	paths := []string{"connector.toml", "ca.crt", "node.crt", "node.key", "wireguard.key"}
	for _, name := range paths {
		info, err := os.Lstat(filepath.Join(stateDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Connector identity is incomplete or unsafe: %s", name)
		}
	}
	configFile := filepath.Join(stateDir, "connector.toml")
	file, err := os.Open(configFile)
	if err != nil {
		return err
	}
	cfg, decodeErr := config.Decode(file)
	closeErr := file.Close()
	if decodeErr != nil {
		return fmt.Errorf("decode existing Connector configuration: %w", decodeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if cfg.Connector.Userspace && cfg.Direct.Enabled {
		return nil
	}
	if !cfg.Connector.Userspace && (cfg.Mode != config.ModeNode || !cfg.Direct.Enabled || cfg.Routing.OutputInterface == "" || !cfg.Routing.NAT ||
		cfg.Exit.Enabled || !cfg.Exit.Serve || cfg.WireGuard.Enabled || cfg.Controller.Endpoint == "" ||
		cfg.Controller.QUICEndpoint == "" || cfg.Controller.ServerName == "") {
		return errors.New("existing configuration is not a recognized legacy Docker Connector; refusing automatic migration")
	}
	setup := connectorSetup{
		Name: cfg.Node.Name, ControllerEndpoint: cfg.Controller.Endpoint, ControllerQUIC: cfg.Controller.QUICEndpoint,
		ServerName: cfg.Controller.ServerName, NetworkID: cfg.Controller.NetworkID, ControllerServiceID: cfg.Controller.ServiceID,
		RelayEndpoint: cfg.Node.RelayAddress, RelayServiceID: cfg.Node.RelayServiceID,
	}
	configuration := connectorConfig(stateDir, setup)
	if _, err := config.Decode(strings.NewReader(configuration)); err != nil {
		return fmt.Errorf("validate migrated Connector configuration: %w", err)
	}
	temporary, err := os.CreateTemp(stateDir, ".connector.toml-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.WriteString(configuration); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, configFile); err != nil {
		return fmt.Errorf("publish migrated Connector configuration: %w", err)
	}
	fmt.Printf("Connector %s configuration migrated to unprivileged userspace mode\n", cfg.Node.Name)
	return nil
}

func activateConnector(stateDir string, setup connectorSetup) error {
	return activateConnectorWithJoin(stateDir, setup, runJoin)
}

func activateConnectorWithJoin(stateDir string, setup connectorSetup, join func([]string) error) error {
	parent := filepath.Dir(stateDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create Connector state parent: %w", err)
	}
	if info, err := os.Lstat(stateDir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Connector state path is not a directory")
		}
		entries, err := os.ReadDir(stateDir)
		if err != nil {
			return fmt.Errorf("inspect Connector state: %w", err)
		}
		if len(entries) != 0 {
			return errors.New("Connector activation refuses to replace existing state")
		}
		if err := os.Remove(stateDir); err != nil {
			return fmt.Errorf("prepare Connector state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Connector state: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".connector-activation-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	tokenFile := filepath.Join(staging, "setup.token")
	caFile := filepath.Join(staging, "ca.crt")
	if err := os.WriteFile(tokenFile, []byte(setup.Code+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(caFile, []byte(setup.CAPEM), 0o444); err != nil {
		return err
	}
	certificate := filepath.Join(staging, "node.crt")
	privateKey := filepath.Join(staging, "node.key")
	wireGuardKey := filepath.Join(staging, "wireguard.key")
	if err := join([]string{"--token-file", tokenFile, "--controller", setup.ControllerEndpoint,
		"--ca", caFile, "--server-name", setup.ServerName, "--controller-network-id", setup.NetworkID,
		"--controller-service-id", setup.ControllerServiceID, "--name", setup.Name,
		"--out-cert", certificate, "--out-key", privateKey, "--out-wireguard-key", wireGuardKey}); err != nil {
		return err
	}
	_ = os.Remove(tokenFile)
	configFile := filepath.Join(staging, "connector.toml")
	configuration := connectorConfig(stateDir, setup)
	if _, err := config.Decode(strings.NewReader(configuration)); err != nil {
		return fmt.Errorf("validate generated Connector configuration: %w", err)
	}
	if err := os.WriteFile(configFile, []byte(configuration), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(staging, "ca.crt"), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(staging, "node.crt"), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(staging, "connector.toml"), 0o444); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(staging, "node.key"), 0o400); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(staging, "wireguard.key"), 0o400); err != nil {
		return err
	}
	if err := os.Rename(staging, stateDir); err != nil {
		return fmt.Errorf("publish Connector identity: %w", err)
	}
	staging = ""
	fmt.Printf("Connector %s activated; persistent identity: %s\n", setup.Name, stateDir)
	return nil
}

func parseConnectorSetupToken(raw string) (connectorSetup, error) {
	if !strings.HasPrefix(raw, connectorSetupPrefix) || len(raw) > 64<<10 {
		return connectorSetup{}, errors.New("SETUP_TOKEN has an unsupported format")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(raw, connectorSetupPrefix))
	if err != nil || len(payload) == 0 || len(payload) > 48<<10 || strings.ContainsRune(string(payload), '\r') {
		return connectorSetup{}, errors.New("SETUP_TOKEN payload is invalid")
	}
	fields := strings.Split(strings.TrimSuffix(string(payload), "\n"), "\n")
	if len(fields) != 10 {
		return connectorSetup{}, errors.New("SETUP_TOKEN payload has an invalid field count")
	}
	caPEM, err := base64.StdEncoding.Strict().DecodeString(fields[9])
	if err != nil || len(caPEM) == 0 || len(caPEM) > 128<<10 {
		return connectorSetup{}, errors.New("SETUP_TOKEN CA bundle is invalid")
	}
	setup := connectorSetup{
		Name: fields[0], Code: fields[1], ControllerEndpoint: fields[2], ControllerQUIC: fields[3], ServerName: fields[4],
		NetworkID: fields[5], ControllerServiceID: fields[6], RelayEndpoint: fields[7], RelayServiceID: fields[8], CAPEM: string(caPEM),
	}
	if setup.Name == "" || setup.Code == "" || setup.CAPEM == "" || strings.ContainsAny(strings.Join(fields[:9], ""), " \t") {
		return connectorSetup{}, errors.New("SETUP_TOKEN contains an empty or unsafe field")
	}
	return setup, nil
}

func connectorConfig(stateDir string, setup connectorSetup) string {
	return fmt.Sprintf(`mode = "node"
state_dir = %q
socket_path = "/run/laneway/lanewayd.sock"

[tls]
certificate = %q
private_key = %q
ca = %q
server_name = %q

[node]
name = %q
relay_address = %q
relay_network_id = %q
relay_service_id = %q
reconnect_min = "1s"
reconnect_max = "30s"

[controller]
endpoint = %q
quic_endpoint = %q
server_name = %q
network_id = %q
service_id = %q
poll_interval = "30s"

[tcp_fallback]
address = %q

[direct]
enabled = true
listen = ":0"

[connector]
userspace = true
`, stateDir, filepath.Join(stateDir, "node.crt"), filepath.Join(stateDir, "node.key"), filepath.Join(stateDir, "ca.crt"), setup.ServerName,
		setup.Name, setup.RelayEndpoint, setup.NetworkID, setup.RelayServiceID, setup.ControllerEndpoint, setup.ControllerQUIC,
		setup.ServerName, setup.NetworkID, setup.ControllerServiceID, netJoinHostPort(setup.ServerName, "443"))
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
