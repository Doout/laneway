package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/localapi"
	"github.com/Doout/laneway/go/internal/pki"
)

func TestWritePairExclusiveAndPermissions(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "node.crt")
	keyPath := filepath.Join(dir, "private", "node.key")
	if err := writePair(certPath, []byte("cert"), keyPath, []byte("key")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %o, want 600", got)
	}
	if err := writePair(certPath, []byte("replacement"), keyPath, []byte("replacement")); err == nil {
		t.Fatal("existing pair overwritten")
	}
	contents, err := os.ReadFile(keyPath)
	if err != nil || string(contents) != "key" {
		t.Fatalf("existing key changed: %q, %v", contents, err)
	}
}

func TestJoinTokenFileMustBeProtectedAndExclusive(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "join.token")
	if err := os.WriteFile(tokenPath, []byte("one-time-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"join", "--token-file", tokenPath, "--controller", "https://controller.example:8443",
		"--controller-network-id", "000102030405060708090a0b0c0d0e0f",
		"--controller-service-id", "101112131415161718191a1b1c1d1e1f", "--name", "node",
	}
	if err := run(arguments); err == nil || !strings.Contains(err.Error(), "must not be accessible") {
		t.Fatalf("unprotected token file error = %v", err)
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	withToken := append([]string{"join", "literal-token"}, arguments[1:]...)
	if err := run(withToken); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("token and token-file error = %v", err)
	}
}

func TestNodeRunCommandSurface(t *testing.T) {
	if err := run([]string{"node"}); err != nil {
		t.Fatalf("node help: %v", err)
	}
	if err := run([]string{"node", "start"}); err == nil || !strings.Contains(err.Error(), "unknown node command") {
		t.Fatalf("unknown node command error = %v", err)
	}
	if err := run([]string{"node", "run", "-version"}); err != nil {
		t.Fatalf("node run version: %v", err)
	}
	if err := run([]string{"node", "run", "unexpected"}); err == nil || !strings.Contains(err.Error(), "unexpected node run argument") {
		t.Fatalf("unexpected node argument error = %v", err)
	}
}

func TestPKICommands(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"pki", "init", "--out-dir", dir, "--validity", "48h"}); err != nil {
		t.Fatal(err)
	}
	intermediateCert := filepath.Join(dir, "intermediate.crt")
	intermediateKey := filepath.Join(dir, "intermediate.key")
	if err := run([]string{
		"pki", "intermediate",
		"--ca-cert", filepath.Join(dir, "ca.crt"),
		"--ca-key", filepath.Join(dir, "ca.key"),
		"--out-cert", intermediateCert,
		"--out-key", intermediateKey,
		"--validity", "24h",
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"pki", "verify-authority", "--root", filepath.Join(dir, "ca.crt"),
		"--issuer", intermediateCert, "--key", intermediateKey,
	}); err != nil {
		t.Fatal(err)
	}
	otherRoot := filepath.Join(dir, "other-root")
	if err := run([]string{"pki", "init", "--out-dir", otherRoot, "--validity", "48h"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"pki", "verify-authority", "--root", filepath.Join(otherRoot, "ca.crt"),
		"--issuer", intermediateCert, "--key", intermediateKey,
	}); err == nil || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("mismatched offline root verification error = %v", err)
	}
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	if err := run([]string{
		"pki", "node",
		"--ca-cert", intermediateCert,
		"--ca-key", intermediateKey,
		"--network-id", "000102030405060708090a0b0c0d0e0f",
		"--node-id", "101112131415161718191a1b1c1d1e1f",
		"--out-cert", certPath,
		"--out-key", keyPath,
		"--validity", "1h",
	}); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(certificate), "-----BEGIN CERTIFICATE-----") {
		t.Fatal("node certificate is not PEM")
	}
	chain, err := pki.ParseCertificatesPEM(certificate)
	if err != nil || len(chain) != 2 {
		t.Fatalf("node certificate chain length = %d, err=%v", len(chain), err)
	}
	rootBundle, err := pki.ParseCertificatesPEM(mustRead(t, filepath.Join(dir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootBundle[0])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify CLI-issued node through intermediate: %v", err)
	}
	if _, _, err := pki.ParseAuthority(certificate, mustRead(t, keyPath)); err == nil {
		t.Fatal("leaf accepted as an authority")
	}
	if err := run([]string{
		"pki", "controller",
		"--ca-cert", intermediateCert,
		"--ca-key", intermediateKey,
		"--network-id", "000102030405060708090a0b0c0d0e0f",
		"--service-id", "202122232425262728292a2b2c2d2e2f",
		"--dns", "controller.example.test",
		"--out-cert", filepath.Join(dir, "controller.crt"),
		"--out-key", filepath.Join(dir, "controller.key"),
		"--validity", "1h",
	}); err != nil {
		t.Fatal(err)
	}
	controllerChain, err := pki.ParseCertificatesPEM(mustRead(t, filepath.Join(dir, "controller.crt")))
	if err != nil || len(controllerChain) != 2 {
		t.Fatalf("controller certificate chain length = %d, err=%v", len(controllerChain), err)
	}
}

func TestExitCommandValidation(t *testing.T) {
	if err := run([]string{"exit", "use", "bad-id"}); err == nil {
		t.Fatal("invalid exit node ID accepted")
	}
	if err := run([]string{"exit", "disable", "unexpected"}); err == nil {
		t.Fatal("unexpected exit argument accepted")
	}
	if err := run([]string{"exit", "enable", "--family", "ipx"}); err == nil || !strings.Contains(err.Error(), "--family") {
		t.Fatalf("invalid exit family error = %v", err)
	}
	if err := run([]string{"exit", "enable", "--family", "ipv4"}); err == nil || !strings.Contains(err.Error(), "open configuration") {
		t.Fatalf("valid exit enable was not parsed before connection validation: %v", err)
	}
}

func TestJoinParsesDocumentedTokenBeforeFlags(t *testing.T) {
	err := runJoin([]string{
		"single-use-secret",
		"--controller", "https://controller.example.test:8443",
		"--ca", filepath.Join(t.TempDir(), "missing-ca.crt"),
		"--controller-network-id", "000102030405060708090a0b0c0d0e0f",
		"--controller-service-id", "101112131415161718191a1b1c1d1e1f",
		"--name", "documented-order",
	})
	if err == nil || strings.Contains(err.Error(), "usage:") || !strings.Contains(err.Error(), "read CA") {
		t.Fatalf("documented join order was not parsed before client setup: %v", err)
	}
	if err := runJoin([]string{"first", "--controller", "https://controller.example.test:8443", "--name", "duplicate", "second"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("duplicate enrollment token accepted: %v", err)
	}
}

func TestBootstrapJoinRefusesSecretsInArgvAndMetadataOverrides(t *testing.T) {
	err := runJoin([]string{"literal-token", "--bootstrap", "lane.example.test", "--name", "laptop"})
	if err == nil || !strings.Contains(err.Error(), "refuses a code in argv") {
		t.Fatalf("bootstrap argv secret error = %v", err)
	}
	err = runJoin([]string{"--bootstrap", "lane.example.test", "--name", "laptop", "--controller", "https://attacker.example.test"})
	if err == nil || !strings.Contains(err.Error(), "cannot override") {
		t.Fatalf("bootstrap metadata override error = %v", err)
	}
	err = runInvite([]string{"--name", "laptop", "--ephemeral", "--remembered"})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("conflicting invite class error = %v", err)
	}
	err = runInvite([]string{"--name", "laptop", "--expires-in", "2h"})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("unbounded invite expiry error = %v", err)
	}
}

func TestControllerInvitePinsLocalDialWithoutChangingTLSIdentity(t *testing.T) {
	for input, want := range map[string]string{
		":8443":        "127.0.0.1:8443",
		"0.0.0.0:8443": "127.0.0.1:8443",
		"[::]:8443":    "127.0.0.1:8443",
		"127.0.0.2:9":  "127.0.0.2:9",
	} {
		if got := controllerLoopbackDialAddress(input); got != want {
			t.Errorf("controllerLoopbackDialAddress(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveExitSelectorExactUniqueName(t *testing.T) {
	first := "000102030405060708090a0b0c0d0e0f"
	second := "101112131415161718191a1b1c1d1e1f"
	peers := []localapi.Peer{
		{Name: "homelab-gateway", NodeID: first},
		// A duplicate directory entry for the same authenticated identity is
		// harmless; ambiguity is about distinct identities.
		{Name: "homelab-gateway", NodeID: first},
		{Name: "Homelab-Gateway", NodeID: second},
	}
	resolved, err := resolveExitSelector("homelab-gateway", peers)
	if err != nil || resolved.String() != first {
		t.Fatalf("resolve exact name = %s, %v", resolved, err)
	}
	if _, err := resolveExitSelector("HOMELAB-GATEWAY", peers); err == nil || !strings.Contains(err.Error(), "no peer") {
		t.Fatalf("inexact name accepted: %v", err)
	}
	peers = append(peers, localapi.Peer{Name: "homelab-gateway", NodeID: second})
	if _, err := resolveExitSelector("homelab-gateway", peers); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous name accepted: %v", err)
	}
	if _, err := resolveExitSelector("broken", []localapi.Peer{{Name: "broken", NodeID: "not-an-id"}}); err == nil || !strings.Contains(err.Error(), "invalid node identity") {
		t.Fatalf("malformed directory identity accepted: %v", err)
	}
}

func TestExitUseResolvesNameThenSubmitsNodeID(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "lanewayd.sock")
	configPath := filepath.Join(dir, "laneway.toml")
	configuration := fmt.Sprintf(`
mode = "node"
state_dir = %q
socket_path = %q
[tls]
certificate = "/tmp/node.crt"
private_key = "/tmp/node.key"
ca = "/tmp/ca.crt"
server_name = "relay.example.test"
[node]
name = "client"
relay_address = "relay.example.test:4433"
relay_network_id = "000102030405060708090a0b0c0d0e0f"
relay_service_id = "202122232425262728292a2b2c2d2e2f"
overlay_addresses = ["100.96.0.1/32"]
`, dir, socket)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "101112131415161718191a1b1c1d1e1f"
	selected := make(chan localapi.ExitSelection, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := localapi.Server{
		SocketPath: socket,
		Snapshot: func() (localapi.Status, []localapi.Peer, []localapi.Route) {
			return localapi.Status{}, []localapi.Peer{{Name: "homelab-gateway", NodeID: want}}, nil
		},
		SetExit: func(_ context.Context, value localapi.ExitSelection) error {
			selected <- value
			return nil
		},
	}
	go func() { done <- server.Serve(ctx) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		if _, err := os.Lstat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local API socket did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	missingConfig := filepath.Join(dir, "rust-node.toml")
	if err := runLocal("up", []string{"--socket", socket, "--config", missingConfig, "--json"}); err != nil {
		t.Fatalf("local command did not bypass configuration loading: %v", err)
	}
	if err := runExit([]string{"use", "homelab-gateway", "--socket", socket, "--config", missingConfig}); err != nil {
		t.Fatal(err)
	}
	if got := <-selected; !got.Enabled || got.SelectedNodeID != want {
		t.Fatalf("selection = %#v", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("local API stopped with %v", err)
	}
}

func TestExitEnableUsesConfiguredGatewayIdentity(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "laneway.toml")
	configuration := fmt.Sprintf(`
mode = "node"
state_dir = %q
socket_path = %q
[tls]
certificate = %q
private_key = %q
ca = %q
server_name = "relay.example.test"
[node]
name = "gateway"
relay_address = "relay.example.test:4433"
relay_network_id = "000102030405060708090a0b0c0d0e0f"
relay_service_id = "202122232425262728292a2b2c2d2e2f"
[controller]
endpoint = "https://controller.example.test:8443"
quic_endpoint = "controller.example.test:8443"
server_name = "controller.example.test"
network_id = "000102030405060708090a0b0c0d0e0f"
service_id = "303132333435363738393a3b3c3d3e3f"
[routing]
output_interface = "eth0"
[exit]
serve = true
`, dir, filepath.Join(dir, "lanewayd.sock"), filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key"), filepath.Join(dir, "ca.crt"))
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runExit([]string{"enable", "--family", "ipv4", "--config", configPath})
	if err == nil || strings.Contains(err.Error(), "--controller is required") || strings.Contains(err.Error(), "exit.serve") {
		t.Fatalf("configured controller/gateway values were not used: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
