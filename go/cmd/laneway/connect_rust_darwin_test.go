package main

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/pelletier/go-toml/v2"
)

func rustForegroundFixture(t *testing.T) (bootstrap.Metadata, identity.NodeIdentity) {
	t.Helper()
	network, err := identity.ParseNetworkID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	node := connectTestNodeID(t, "101112131415161718191a1b1c1d1e1f")
	return bootstrap.Metadata{
		NetworkID: network.String(),
		Controller: bootstrap.Controller{EnrollmentEndpoint: "https://controller.example:443",
			QUICEndpoint: "controller.example:443", ServerName: "controller.example", ServiceID: "202122232425262728292a2b2c2d2e2f"},
		Relays: []bootstrap.Relay{{Endpoint: "relay.example:443", ServiceID: "303132333435363738393a3b3c3d3e3f"}},
	}, identity.NodeIdentity{NetworkID: network, NodeID: node}
}

func TestMacRustRuntimeCandidateRequiresNativeExecutable(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The Go test executable has the same thin native Mach-O contract as the
	// Rust executable. The archive gate separately runs the actual Rust binary.
	if err := inspectMacRustCandidate(path, runtime.GOARCH); err != nil {
		t.Fatal(err)
	}
	wrongArch := "amd64"
	if runtime.GOARCH == wrongArch {
		wrongArch = "arm64"
	}
	if err := inspectMacRustCandidate(path, wrongArch); err == nil {
		t.Fatal("accepted executable for a different architecture")
	}
	link := filepath.Join(t.TempDir(), "lanewayd-rs")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := inspectMacRustCandidate(link, runtime.GOARCH); err == nil {
		t.Fatal("accepted a symlink as the packaged Rust binary")
	}
}

func TestRustForegroundSessionConfigAndCredentialHandoff(t *testing.T) {
	metadata, node := rustForegroundFixture(t)
	directory, err := os.MkdirTemp("", "lnw-rust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	credentials := rustConnectCredentials{"/dev/fd/3", "/dev/fd/4", "/dev/fd/5"}
	path, err := writeRustConnectConfig(directory, metadata, node, credentials, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("expected a private config file, got info=%v err=%v", info, err)
	}
	var session struct {
		Routes struct {
			PolicyPrivate bool     `toml:"policy_private"`
			Requested     []string `toml:"requested"`
		} `toml:"foreground_routes"`
		TLS rustConnectCredentials `toml:"tls"`
	}
	readSession := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := toml.Unmarshal(data, &session); err != nil {
			t.Fatal(err)
		}
	}
	readSession(path)
	if session.Routes.PolicyPrivate || len(session.Routes.Requested) != 0 || session.TLS != credentials {
		t.Fatalf("unexpected ephemeral session: %+v", session)
	}

	remembered, err := writeRustConnectConfig(directory, metadata, node, credentials, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	readSession(remembered)
	if !session.Routes.PolicyPrivate || len(session.Routes.Requested) != 0 {
		t.Fatalf("unexpected remembered session: %+v", session)
	}
	explicit, err := writeRustConnectConfig(directory, metadata, node, credentials, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, true)
	if err != nil {
		t.Fatal(err)
	}
	readSession(explicit)
	if session.Routes.PolicyPrivate || len(session.Routes.Requested) != 1 || session.Routes.Requested[0] != "10.20.0.0/16" {
		t.Fatalf("unexpected explicit scope: %+v", session)
	}

	binary := os.Getenv("LANEWAY_RUST_TEST_BINARY")
	if binary == "" {
		return // The scope and permission checks above do not require a Rust build.
	}
	now := time.Now()
	caMaterial, ca, err := pki.NewAuthority("Test CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := pki.IssueNode(ca, caMaterial.PrivateKey, node, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	files := new(runtimeCredentialFiles)
	t.Cleanup(func() { _ = files.close() })
	key, err := pki.PrivateKeyPEM(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{pki.CertificatePEM(caMaterial.CertificateDER), pki.CertificatePEM(leaf.CertificateDER), key} {
		if _, err := files.add(directory, "credential", data); err != nil {
			t.Fatal(err)
		}
	}
	for _, config := range []string{path, remembered, explicit} {
		cmd := exec.Command(binary, "--config", config, "--check-config")
		cmd.ExtraFiles = files.files
		if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "configuration is valid") {
			t.Fatalf("Rust did not read the Go-generated configuration and inherited credentials: %v\n%s", err, output)
		}
	}
}

func TestRustForegroundWaitsForProcessCleanupOnCancellation(t *testing.T) {
	metadata, node := rustForegroundFixture(t)
	directory := t.TempDir()
	program := filepath.Join(directory, "daemon")
	ready := filepath.Join(directory, "ready")
	cleaned := filepath.Join(directory, "cleaned")
	t.Setenv("TEST_READY_FILE", ready)
	t.Setenv("TEST_CLEANED_FILE", cleaned)
	const script = `#!/bin/sh
set -eu
trap 'test -f "$2" && : > "$TEST_CLEANED_FILE"; exit 0' TERM
: > "$TEST_READY_FILE"
while :; do sleep 0.1; done
`
	if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runRustConnect(ctx, program, directory, metadata, node, rustConnectCredentials{}, nil, nil, false)
	}()
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("process exited before cleanup could be requested: %v", err)
		case <-ctx.Done():
			t.Fatal("process did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("launcher did not reap process after graceful shutdown")
	}
	if _, err := os.Stat(cleaned); err != nil {
		t.Fatalf("process did not complete cleanup before returning: %v", err)
	}
	if configs, _ := filepath.Glob(filepath.Join(directory, "rust-*.toml")); len(configs) != 0 {
		t.Fatalf("launcher left session configuration files: %v", configs)
	}
}
