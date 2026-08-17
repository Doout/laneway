//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrapsecret"
	"github.com/Doout/laneway/go/internal/config"
)

const connectorSetupPrefix = "st1."

var connectorIdentityFiles = []string{"connector.toml", "ca.crt", "node.crt", "node.key", "wireguard.key"}

type connectorSetup struct {
	Name, Code, ControllerEndpoint, ControllerQUIC, ServerName           string
	NetworkID, ControllerServiceID, RelayEndpoint, RelayServiceID, CAPEM string
}

func runConnector(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway connector <activate|bootstrap-seal|bootstrap-activate|configure|run|validate>")
	}
	switch args[0] {
	case "configure":
		fs := flag.NewFlagSet("connector configure", flag.ContinueOnError)
		stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || !filepath.IsAbs(*stateDir) {
			return errors.New("usage: laneway connector configure [--state-dir DIR]")
		}
		return configureConnector(*stateDir)
	case "run":
		return runConnectorService(args[1:], activateConnector, execConnectorNode)
	case "validate":
		fs := flag.NewFlagSet("connector validate", flag.ContinueOnError)
		stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || !filepath.IsAbs(*stateDir) {
			return errors.New("usage: laneway connector validate [--state-dir DIR]")
		}
		return validateConnectorIdentity(*stateDir)
	case "activate":
		return runConnectorActivate(args[1:])
	case "bootstrap-seal":
		return runConnectorBootstrapSeal(args[1:])
	case "bootstrap-activate":
		return runConnectorBootstrapActivate(args[1:])
	default:
		return errors.New("usage: laneway connector <activate|bootstrap-seal|bootstrap-activate|configure|run|validate>")
	}
}

func runConnectorBootstrapSeal(args []string) (resultErr error) {
	fs := flag.NewFlagSet("connector bootstrap-seal", flag.ContinueOnError)
	out := fs.String("out", "", "exclusive output path for the encrypted envelope")
	expiresAtUnix := fs.Int64("expires-at", 0, "absolute payload expiry as Unix seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" || !filepath.IsAbs(*out) || *expiresAtUnix <= 0 {
		return errors.New("usage: laneway connector bootstrap-seal --out FILE --expires-at UNIX < setup-token")
	}
	contents, err := io.ReadAll(io.LimitReader(os.Stdin, bootstrapsecret.MaxTokenSize+2))
	if err != nil {
		return fmt.Errorf("read Connector setup token: %w", err)
	}
	defer clear(contents)
	if len(contents) > bootstrapsecret.MaxTokenSize+1 {
		return errors.New("Connector setup token exceeds the bootstrap limit")
	}
	tokenBytes := bytes.TrimSuffix(contents, []byte("\n"))
	token := string(tokenBytes)
	if _, err := parseConnectorSetupToken(token); err != nil {
		return err
	}
	key, envelope, err := bootstrapsecret.Seal(tokenBytes, time.Now().UTC(), time.Unix(*expiresAtUnix, 0).UTC())
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create bootstrap envelope: %w", err)
	}
	defer func() {
		if resultErr != nil {
			_ = os.Remove(*out)
		}
	}()
	if _, err := file.WriteString(envelope + "\n"); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, key)
	return nil
}

func runConnectorBootstrapActivate(args []string) error {
	fs := flag.NewFlagSet("connector bootstrap-activate", flag.ContinueOnError)
	envelopeFile := fs.String("envelope-file", "", "file containing the encrypted bootstrap envelope")
	stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *envelopeFile == "" || !filepath.IsAbs(*envelopeFile) || !filepath.IsAbs(*stateDir) {
		return errors.New("usage: laneway connector bootstrap-activate --envelope-file FILE [--state-dir DIR] < decryption-key")
	}
	info, err := os.Lstat(*envelopeFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 128<<10 {
		return errors.New("--envelope-file must be a bounded regular file")
	}
	envelopeBytes, err := os.ReadFile(*envelopeFile)
	if err != nil {
		return fmt.Errorf("read bootstrap envelope: %w", err)
	}
	defer clear(envelopeBytes)
	keyBytes, err := io.ReadAll(io.LimitReader(os.Stdin, 256))
	if err != nil {
		return fmt.Errorf("read bootstrap decryption key: %w", err)
	}
	defer clear(keyBytes)
	key := strings.TrimSpace(string(keyBytes))
	envelope := strings.TrimSpace(string(envelopeBytes))
	setup, err := openConnectorBootstrap(key, envelope, time.Now().UTC())
	if err != nil {
		return err
	}
	return activateConnector(*stateDir, setup)
}

func openConnectorBootstrap(key, envelope string, now time.Time) (connectorSetup, error) {
	plaintext, err := bootstrapsecret.Open(key, envelope, now)
	if err != nil {
		return connectorSetup{}, err
	}
	defer clear(plaintext)
	return parseConnectorSetupToken(string(plaintext))
}

func execConnectorNode(args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve Connector executable: %w", err)
	}
	argv := append([]string{executable, "node", "run"}, args...)
	return syscall.Exec(executable, argv, os.Environ())
}

func runConnectorActivate(args []string) error {
	fs := flag.NewFlagSet("connector activate", flag.ContinueOnError)
	setupToken := fs.String("setup-token", "", "single-use Connector setup token")
	stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
	if err := fs.Parse(args); err != nil {
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

func runConnectorService(args []string, activate func(string, connectorSetup) error, start func([]string) error) error {
	fs := flag.NewFlagSet("connector run", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/laneway/connector", "persistent Connector state directory")
	setupTokenFile := fs.String("setup-token-file", "", "protected file containing the single-use setup token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !filepath.IsAbs(*stateDir) || (*setupTokenFile != "" && !filepath.IsAbs(*setupTokenFile)) {
		return errors.New("usage: laneway connector run [--state-dir DIR] [--setup-token-file PATH]")
	}

	tokenFromEnvironment := os.Getenv("SETUP_TOKEN")
	tokenFileFromEnvironment := os.Getenv("SETUP_TOKEN_FILE")
	_ = os.Unsetenv("SETUP_TOKEN")
	_ = os.Unsetenv("SETUP_TOKEN_FILE")

	identityCount, err := connectorIdentityCount(*stateDir)
	if err != nil {
		return err
	}
	if identityCount != len(connectorIdentityFiles) {
		if identityCount != 0 {
			return errors.New("persistent volume contains an incomplete Connector identity")
		}
		if *setupTokenFile != "" && tokenFileFromEnvironment != "" {
			return errors.New("Connector setup token file was specified more than once")
		}
		if *setupTokenFile == "" {
			*setupTokenFile = tokenFileFromEnvironment
		}
		if *setupTokenFile != "" && !filepath.IsAbs(*setupTokenFile) {
			return errors.New("Connector setup token file path must be absolute")
		}
		if tokenFromEnvironment != "" && *setupTokenFile != "" {
			return errors.New("Connector accepts either SETUP_TOKEN or a setup token file, not both")
		}
		rawToken := tokenFromEnvironment
		if *setupTokenFile != "" {
			rawToken, err = readConnectorSetupTokenFile(*setupTokenFile)
			if err != nil {
				return err
			}
		}
		if rawToken == "" {
			return errors.New("SETUP_TOKEN or --setup-token-file is required for first start")
		}
		setup, parseErr := parseConnectorSetupToken(rawToken)
		if parseErr != nil {
			return parseErr
		}
		if err := activate(*stateDir, setup); err != nil {
			return err
		}
	}
	if err := configureConnector(*stateDir); err != nil {
		return err
	}
	return start([]string{"-config", filepath.Join(*stateDir, "connector.toml")})
}

func connectorIdentityCount(stateDir string) (int, error) {
	count := 0
	for _, name := range connectorIdentityFiles {
		_, err := os.Lstat(filepath.Join(stateDir, name))
		switch {
		case err == nil:
			count++
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return 0, fmt.Errorf("inspect Connector identity %s: %w", name, err)
		}
	}
	return count, nil
}

func readConnectorSetupTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 64<<10 {
		return "", errors.New("--setup-token-file must be a nonempty regular file no larger than 64 KiB")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("--setup-token-file must not be accessible by group or other users")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read --setup-token-file: %w", err)
	}
	token := strings.TrimSpace(string(contents))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("--setup-token-file contains an invalid setup token")
	}
	return token, nil
}

func validateConnectorIdentity(stateDir string) error {
	for _, name := range connectorIdentityFiles {
		info, err := os.Lstat(filepath.Join(stateDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("Connector identity is incomplete or unsafe: %s", name)
		}
	}
	file, err := os.Open(filepath.Join(stateDir, "connector.toml"))
	if err != nil {
		return err
	}
	_, decodeErr := config.Decode(file)
	closeErr := file.Close()
	if decodeErr != nil {
		return fmt.Errorf("decode Connector configuration: %w", decodeErr)
	}
	return closeErr
}

func configureConnector(stateDir string) error {
	if err := validateConnectorIdentity(stateDir); err != nil {
		return err
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
	tokenTemporary, err := os.CreateTemp("/tmp", ".laneway-connector-setup-")
	if err != nil {
		return fmt.Errorf("create transient Connector setup token: %w", err)
	}
	tokenFile := tokenTemporary.Name()
	defer func() { _ = os.Remove(tokenFile) }()
	if err := tokenTemporary.Chmod(0o600); err != nil {
		_ = tokenTemporary.Close()
		return err
	}
	if _, err := tokenTemporary.WriteString(setup.Code + "\n"); err != nil {
		_ = tokenTemporary.Close()
		return err
	}
	if err := tokenTemporary.Close(); err != nil {
		return err
	}
	caFile := filepath.Join(staging, "ca.crt")
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
