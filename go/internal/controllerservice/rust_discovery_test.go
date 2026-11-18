//go:build rustinterop

package controllerservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
)

func TestRustControllerDiscovery(t *testing.T) {
	f := newFixture(t, 0, nil)
	const serverName = "controller.bootstrap.test"
	const enrol = "https://relay.bootstrap.test:443"
	const quic = "controller.bootstrap.test:8443"
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	leaf, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleController,
	}, []string{serverName}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	pemFile := func(name, prefix string, der []byte) string {
		return write(name, pem.EncodeToMemory(&pem.Block{Type: prefix, Bytes: der}))
	}
	keyFile := func(name string, key any) string {
		t.Helper()
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pemFile(name, "PRIVATE KEY", data)
	}
	cert := pemFile("controller.crt", "CERTIFICATE", leaf.CertificateDER)
	key := keyFile("controller.key", leaf.PrivateKey)
	ca := pemFile("ca.crt", "CERTIFICATE", f.service.ca.Raw)
	issuerKey := keyFile("ca.key", f.service.caKey)
	artifact := bootstrap.Artifact{OS: "linux", Arch: "arm64", URL: "https://release.bootstrap.test/laneway",
		SHA256: strings.Repeat("12", 32), SizeBytes: 512}
	profile := func(name, filename string) string {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"enrollment_endpoint": enrol, "quic_endpoint": quic, "server_name": name, "artifacts": []bootstrap.Artifact{artifact},
		})
		if err != nil {
			t.Fatal(err)
		}
		return write(filename, data)
	}
	command := func(ctx context.Context, profile string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", f.dbPath, "127.0.0.1:0",
			cert, key, "--node-issuer", ca, issuerKey, "86400", "--node-client-ca", ca, "--bootstrap-profile", profile)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if out, err := command(ctx, profile("wrong.bootstrap.test", "bad.json")).CombinedOutput(); err == nil ||
		ctx.Err() != nil || !strings.Contains(string(out), "bootstrap trust and name do not verify") {
		t.Fatal("listener did not reject a profile inconsistent with its controller certificate")
	}
	cmd := command(t.Context(), profile(serverName, "good.json"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	announce := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); announce <- strings.TrimSpace(line) }()
	var base string
	select {
	case line := <-announce:
		if !strings.HasPrefix(line, "listening https://127.0.0.1:") {
			t.Fatal("bootstrap listener failed to start")
		}
		base = strings.TrimPrefix(line, "listening ")
	case <-time.After(10 * time.Second):
		t.Fatal("bootstrap listener startup timed out")
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13},
	}}
	defer client.CloseIdleConnections()
	call := func(method, path string, want int) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "unrelated-request.bootstrap.test"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		if resp.StatusCode != want || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s returned %d, expected %d or missing cache protection", method, path, resp.StatusCode, want)
		}
		return resp
	}
	health := call("GET", "/v1/health", 200)
	if got, err := io.ReadAll(health.Body); err != nil || string(got) != `{"status":"ok"}` {
		t.Fatal("readiness payload differs from Go")
	}
	call("HEAD", "/v1/health", 200)
	call("POST", "/v1/health", 405)
	call("GET", bootstrap.WellKnownPath, 503)
	foreign, err := f.store.CreateNetwork(t.Context(), "discovery-unrelated", netip.MustParsePrefix("10.80.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.RegisterRelay(t.Context(), foreign.ID, identity.ID{4}, nil, "unrelated",
		"unrelated.bootstrap.test:443"); err != nil {
		t.Fatal(err)
	}
	relay, _, err := f.store.RegisterRelay(t.Context(), f.network.ID, identity.ID{3}, nil, "expected",
		"relay.bootstrap.test:443")
	if err != nil {
		t.Fatal(err)
	}
	resp := call("GET", bootstrap.WellKnownPath, 200)
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("bootstrap document is missing its media or content policy")
	}
	doc, err := bootstrap.Decode(resp.Body, time.Now().UTC())
	if err != nil {
		t.Fatalf("Go could not consume public Rust bootstrap metadata: %v", err)
	}
	if doc.NetworkID != f.network.ID.String() || doc.Controller.ServiceID != serviceID.String() ||
		doc.Controller.EnrollmentEndpoint != enrol || doc.Controller.QUICEndpoint != quic ||
		doc.Controller.ServerName != serverName || len(doc.Relays) != 1 || doc.Relays[0].ServiceID != relay.ServiceID.String() ||
		doc.Relays[0].Endpoint != relay.Endpoint || doc.ValidUntil-doc.GeneratedAt != 300 ||
		doc.Protocol.Capabilities != uint64(protocol.KnownCapabilities) || len(doc.Artifacts) != 1 || doc.Artifacts[0] != artifact {
		t.Fatal("metadata did not preserve its pinned network, trust, relay, and artifact profile")
	}
	call("GET", bootstrap.WellKnownPath+"?unexpected=1", 404)
	call("HEAD", bootstrap.WellKnownPath, 404)
	if _, err := f.store.DisableRelay(t.Context(), relay.ID); err != nil {
		t.Fatal(err)
	}
	call("GET", bootstrap.WellKnownPath, 503)
}
