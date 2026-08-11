//go:build linux

package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/bootstrapsecret"
	"laneway.dev/laneway/internal/config"
)

func TestParseConnectorSetupToken(t *testing.T) {
	ca := base64.StdEncoding.EncodeToString([]byte("fixture-ca"))
	payload := strings.Join([]string{"ibmcloud", "single_use", "https://lane.example.test:8443", "lane.example.test:8443", "lane.example.test", "11111111111111111111111111111111", "22222222222222222222222222222222", "lane.example.test:4433", "33333333333333333333333333333333", ca}, "\n") + "\n"
	token := connectorSetupPrefix + base64.StdEncoding.EncodeToString([]byte(payload))
	setup, err := parseConnectorSetupToken(token)
	if err != nil || setup.Name != "ibmcloud" || setup.Code != "single_use" || setup.CAPEM != "fixture-ca" {
		t.Fatalf("parsed %#v, %v", setup, err)
	}
	for _, value := range []string{
		"opaque",
		"st1.not-base64",
		connectorSetupPrefix + base64.StdEncoding.EncodeToString([]byte("too\nfew\nfields\n")),
	} {
		if _, err := parseConnectorSetupToken(value); err == nil {
			t.Fatalf("accepted unsafe setup token %q", value)
		}
	}
}

func TestEncryptedConnectorBootstrapAuthenticatesAndExpires(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	ca := base64.StdEncoding.EncodeToString([]byte("fixture-ca"))
	payload := strings.Join([]string{"office", "single_use", "https://lane.example.test:8443", "lane.example.test:8443", "lane.example.test", "11111111111111111111111111111111", "22222222222222222222222222222222", "lane.example.test:4433", "33333333333333333333333333333333", ca}, "\n") + "\n"
	token := connectorSetupPrefix + base64.StdEncoding.EncodeToString([]byte(payload))
	key, envelope, err := bootstrapsecret.Seal([]byte(token), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	setup, err := openConnectorBootstrap(key, envelope, now)
	if err != nil || setup.Name != "office" || setup.Code != "single_use" {
		t.Fatalf("setup=%#v err=%v", setup, err)
	}
	otherKey, _, err := bootstrapsecret.Seal([]byte(token), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openConnectorBootstrap(otherKey, envelope, now); err == nil {
		t.Fatal("wrong bootstrap key was accepted")
	}
	if _, err := openConnectorBootstrap(key, envelope, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry error=%v", err)
	}
}

func TestActivateConnectorPublishesIdentityAtomically(t *testing.T) {
	setup := connectorSetup{
		Name: "ibmcloud", Code: "single_use", CAPEM: "fixture-ca", ControllerEndpoint: "https://lane.example.test:8443",
		ControllerQUIC: "lane.example.test:8443", ServerName: "lane.example.test", NetworkID: "11111111111111111111111111111111",
		ControllerServiceID: "22222222222222222222222222222222", RelayEndpoint: "lane.example.test:4433",
		RelayServiceID: "33333333333333333333333333333333",
	}
	stateDir := filepath.Join(t.TempDir(), "connector")
	joinCalls := 0
	join := func(args []string) error {
		joinCalls++
		value := func(name string) (string, error) {
			for index := 0; index+1 < len(args); index++ {
				if args[index] == name {
					return args[index+1], nil
				}
			}
			return "", errors.New("missing test join argument " + name)
		}
		tokenFile, err := value("--token-file")
		if err != nil {
			return err
		}
		token, err := os.ReadFile(tokenFile)
		if err != nil || string(token) != setup.Code+"\n" {
			return errors.New("activation did not protect and pass the one-time code")
		}
		if relative, err := filepath.Rel(filepath.Dir(stateDir), tokenFile); err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("activation staged its one-time code in the persistent volume")
		}
		for _, flagName := range []string{"--out-cert", "--out-key", "--out-wireguard-key"} {
			path, err := value(flagName)
			if err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(flagName), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	if err := activateConnectorWithJoin(stateDir, setup, join); err != nil {
		t.Fatal(err)
	}
	wantModes := map[string]os.FileMode{"connector.toml": 0o444, "ca.crt": 0o444, "node.crt": 0o444, "node.key": 0o400, "wireguard.key": 0o400}
	for name, want := range wantModes {
		info, err := os.Stat(filepath.Join(stateDir, name))
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("published %s mode = %v, err=%v; want %v", name, infoMode(info), err, want)
		}
	}
	if err := activateConnectorWithJoin(stateDir, setup, join); err == nil || !strings.Contains(err.Error(), "refuses to replace") {
		t.Fatalf("existing identity replacement error = %v", err)
	}
	if joinCalls != 1 {
		t.Fatalf("join called %d times after replacement attempt", joinCalls)
	}
}

func TestConfigureConnectorMigratesLegacyIdentityWithoutReenrollment(t *testing.T) {
	setup := connectorSetup{
		Name: "ibmcloud", ControllerEndpoint: "https://lane.example.test:8443", ControllerQUIC: "lane.example.test:8443", ServerName: "lane.example.test",
		NetworkID: "11111111111111111111111111111111", ControllerServiceID: "22222222222222222222222222222222",
		RelayEndpoint: "lane.example.test:4433", RelayServiceID: "33333333333333333333333333333333",
	}
	stateDir := t.TempDir()
	legacy := strings.Replace(connectorConfig(stateDir, setup), "[direct]\nenabled = true\nlisten = \":0\"\n\n[connector]\nuserspace = true\n", `[direct]
enabled = true
listen = "0.0.0.0:4434"

[routing]
output_interface = "eth0"
nat = true

[exit]
enabled = false
serve = true
failure_mode = "closed"
`, 1)
	if legacy == connectorConfig(stateDir, setup) {
		t.Fatal("legacy configuration fixture was not produced")
	}
	for name, contents := range map[string]string{
		"connector.toml": legacy, "ca.crt": "ca", "node.crt": "cert", "node.key": "key", "wireguard.key": "wg",
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := configureConnector(stateDir); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(stateDir, "connector.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Decode(strings.NewReader(string(contents)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Connector.Userspace || !cfg.Direct.Enabled || cfg.Direct.Listen != ":0" || cfg.Routing.OutputInterface != "" || cfg.Exit.Serve {
		t.Fatalf("legacy configuration was not migrated safely: %#v", cfg)
	}
	for name, want := range map[string]string{"node.crt": "cert", "node.key": "key", "wireguard.key": "wg"} {
		got, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil || string(got) != want {
			t.Fatalf("identity %s changed during migration: %q, %v", name, got, err)
		}
	}
	if err := configureConnector(stateDir); err != nil {
		t.Fatalf("userspace configuration is not idempotent: %v", err)
	}
}

func TestConfigureConnectorEnablesDirectTraversalForExistingUserspaceIdentity(t *testing.T) {
	setup := connectorSetup{
		Name: "ibmcloud", ControllerEndpoint: "https://lane.example.test:8443", ControllerQUIC: "lane.example.test:8443", ServerName: "lane.example.test",
		NetworkID: "11111111111111111111111111111111", ControllerServiceID: "22222222222222222222222222222222",
		RelayEndpoint: "lane.example.test:4433", RelayServiceID: "33333333333333333333333333333333",
	}
	stateDir := t.TempDir()
	oldConfig := strings.Replace(connectorConfig(stateDir, setup), "enabled = true\nlisten = \":0\"", "enabled = false", 1)
	for name, contents := range map[string]string{
		"connector.toml": oldConfig, "ca.crt": "ca", "node.crt": "cert", "node.key": "key", "wireguard.key": "wg",
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := configureConnector(stateDir); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(stateDir, "connector.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Decode(strings.NewReader(string(contents)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Connector.Userspace || !cfg.Direct.Enabled || cfg.Direct.Listen != ":0" {
		t.Fatalf("existing userspace Connector did not enable direct traversal: %#v", cfg)
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

func TestConnectorConfigSelectsUnprivilegedUserspaceMode(t *testing.T) {
	setup := connectorSetup{
		Name: "ibmcloud", ControllerEndpoint: "https://lane.example.test:8443", ControllerQUIC: "lane.example.test:8443", ServerName: "lane.example.test",
		NetworkID: "11111111111111111111111111111111", ControllerServiceID: "22222222222222222222222222222222",
		RelayEndpoint: "lane.example.test:4433", RelayServiceID: "33333333333333333333333333333333",
	}
	configuration := connectorConfig("/state", setup)
	decoded, err := config.Decode(strings.NewReader(configuration))
	if err != nil {
		t.Fatalf("generated configuration does not validate: %v", err)
	}
	if !decoded.Connector.Userspace {
		t.Fatal("generated configuration did not select userspace Connector mode")
	}
	for _, expected := range []string{"[connector]\nuserspace = true", "[direct]\nenabled = true\nlisten = \":0\"", `name = "ibmcloud"`} {
		if !strings.Contains(configuration, expected) {
			t.Fatalf("configuration lacks %q:\n%s", expected, configuration)
		}
	}
	for _, forbidden := range []string{"output_interface", "serve = true"} {
		if strings.Contains(configuration, forbidden) {
			t.Fatalf("configuration contains privileged setting %q", forbidden)
		}
	}
}

func TestRunConnectorServiceStartsFromPersistentIdentityWithoutActivation(t *testing.T) {
	setup := connectorSetup{
		Name: "ibmcloud", ControllerEndpoint: "https://lane.example.test:8443", ControllerQUIC: "lane.example.test:8443", ServerName: "lane.example.test",
		NetworkID: "11111111111111111111111111111111", ControllerServiceID: "22222222222222222222222222222222",
		RelayEndpoint: "lane.example.test:4433", RelayServiceID: "33333333333333333333333333333333",
	}
	stateDir := t.TempDir()
	for name, contents := range map[string]string{
		"connector.toml": connectorConfig(stateDir, setup), "ca.crt": "ca", "node.crt": "cert", "node.key": "key", "wireguard.key": "wg",
	} {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	activated := false
	var startArgs []string
	t.Setenv("SETUP_TOKEN", "already-consumed")
	err := runConnectorService([]string{"--state-dir", stateDir}, func(string, connectorSetup) error {
		activated = true
		return nil
	}, func(args []string) error {
		if _, exists := os.LookupEnv("SETUP_TOKEN"); exists {
			t.Fatal("setup token remained in the node runtime environment")
		}
		startArgs = append([]string(nil), args...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if activated {
		t.Fatal("persistent identity triggered activation")
	}
	wantConfig := filepath.Join(stateDir, "connector.toml")
	if len(startArgs) != 2 || startArgs[0] != "-config" || startArgs[1] != wantConfig {
		t.Fatalf("node start arguments = %q, want [-config %s]", startArgs, wantConfig)
	}
}

func TestRunConnectorServiceReadsProtectedSetupTokenFile(t *testing.T) {
	ca := base64.StdEncoding.EncodeToString([]byte("fixture-ca"))
	payload := strings.Join([]string{"ibmcloud", "single_use", "https://lane.example.test:8443", "lane.example.test:8443", "lane.example.test", "11111111111111111111111111111111", "22222222222222222222222222222222", "lane.example.test:4433", "33333333333333333333333333333333", ca}, "\n") + "\n"
	token := connectorSetupPrefix + base64.StdEncoding.EncodeToString([]byte(payload))
	tokenFile := filepath.Join(t.TempDir(), "setup.token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SETUP_TOKEN_FILE", tokenFile)
	sentinel := errors.New("activation fixture complete")
	activationCalls := 0
	err := runConnectorService([]string{"--state-dir", filepath.Join(t.TempDir(), "connector")}, func(_ string, setup connectorSetup) error {
		activationCalls++
		if setup.Name != "ibmcloud" || setup.Code != "single_use" || setup.CAPEM != "fixture-ca" {
			t.Fatalf("activation setup = %#v", setup)
		}
		return sentinel
	}, func([]string) error {
		t.Fatal("node runtime started after failed activation")
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("run error = %v, want activation sentinel", err)
	}
	if activationCalls != 1 {
		t.Fatalf("activation calls = %d, want 1", activationCalls)
	}
	if _, exists := os.LookupEnv("SETUP_TOKEN_FILE"); exists {
		t.Fatal("setup token file environment variable remained in the process environment")
	}
}

func TestRunConnectorServiceRejectsPartialIdentity(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "ca.crt"), []byte("ca"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SETUP_TOKEN", "not-consumed")
	activated := false
	err := runConnectorService([]string{"--state-dir", stateDir}, func(string, connectorSetup) error {
		activated = true
		return nil
	}, func([]string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "incomplete Connector identity") {
		t.Fatalf("partial identity error = %v", err)
	}
	if activated {
		t.Fatal("partial identity triggered activation")
	}
}
