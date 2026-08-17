//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/identity"
)

func TestRenderEphemeralExitConfigIsRAMCredentialBound(t *testing.T) {
	var network identity.NetworkID
	var controllerID, relayID identity.ID
	for index := range network {
		network[index] = byte(index + 1)
		controllerID[index] = byte(index + 33)
		relayID[index] = byte(index + 65)
	}
	metadata := bootstrap.Metadata{NetworkID: network.String(), Controller: bootstrap.Controller{
		EnrollmentEndpoint: "https://controller.example.test:8443", QUICEndpoint: "controller.example.test:8443",
		ServerName: "controller.example.test", ServiceID: controllerID.String(),
	}}
	contents, err := renderEphemeralExitConfig(metadata, "borrowed-egress", managedNodeRelay{
		serviceID: relayID, endpoint: "relay.example.test:4433",
	}, "laneway-ephemeral-exit-0123456789abcdef", 9)
	if err != nil {
		t.Fatal(err)
	}
	value, err := config.Decode(bytes.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if value.StateDir != "/run/laneway-ephemeral-exit-0123456789abcdef/state" || value.Exit.LeaseGeneration != 9 ||
		!value.Exit.Serve || value.Exit.Enabled || value.Exit.FailureMode != "closed" || value.Direct.Enabled ||
		value.Controller.PollInterval != config.Duration(10_000_000_000) || value.Routing.OutputInterface != "uplink0" ||
		!value.WireGuard.Enabled || value.WireGuard.PrivateKeyFile != "@credential/wireguard.key" ||
		value.WireGuard.InterfaceName != "lane0" || value.WireGuard.MTU != 1280 {
		t.Fatalf("rendered runtime config=%+v", value)
	}
	for _, path := range []string{value.TLS.CAFile, value.TLS.CertificateFile, value.TLS.PrivateKeyFile} {
		if len(path) < len("@credential/") || path[:len("@credential/")] != "@credential/" {
			t.Fatalf("credential escaped systemd credential directory: %q", path)
		}
	}
}

func TestEphemeralExitPrepareIsHiddenNodeCommand(t *testing.T) {
	command, _, err := newRootCommand().Find([]string{"node", "ephemeral-exit-prepare"})
	if err != nil || command == nil || !command.Hidden {
		t.Fatalf("hidden command=%v err=%v", command, err)
	}
	err = run([]string{"node", "ephemeral-exit-prepare", "--authority", "controller.example.test:8443",
		"--runtime-dir", "/run/laneway-ephemeral-exit-0123456789abcdef", "--runtime-name", "laneway-ephemeral-exit-0123456789abcdef",
		"--name", "borrowed-egress", "--token-fd", "3"})
	if err == nil || strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unknown node command") {
		t.Fatalf("prepare dispatch error=%v", err)
	}
}

func TestWriteEphemeralExitFileIsExclusiveAndProtected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	secret := []byte("one-use-secret")
	if err := writeEphemeralExitFile(path, secret); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o400 || !info.Mode().IsRegular() {
		t.Fatalf("credential mode=%v err=%v", info, err)
	}
	if err := writeEphemeralExitFile(path, []byte("replacement")); err == nil {
		t.Fatal("credential was overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("credential contents=%q err=%v", got, err)
	}
}
