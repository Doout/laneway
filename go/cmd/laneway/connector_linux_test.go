//go:build linux

package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, expected := range []string{"[connector]\nuserspace = true", "[direct]\nenabled = false", `name = "ibmcloud"`} {
		if !strings.Contains(configuration, expected) {
			t.Fatalf("configuration lacks %q:\n%s", expected, configuration)
		}
	}
	for _, forbidden := range []string{"output_interface", "serve = true", "enabled = true"} {
		if strings.Contains(configuration, forbidden) {
			t.Fatalf("configuration contains privileged setting %q", forbidden)
		}
	}
}
