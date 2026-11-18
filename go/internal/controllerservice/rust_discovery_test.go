//go:build rustinterop

package controllerservice

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
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
	console := rustConsoleDir(t)
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
			cert, key, "--node-issuer", ca, issuerKey, "86400", "--node-client-ca", ca, "--bootstrap-profile", profile,
			"--console-dir", console)
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
	testRustConsole(t, client, base, serverName)
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
	if relayBinary := os.Getenv("LANEWAY_RUST_RELAY"); relayBinary != "" {
		const publicName = "relay.bootstrap.test"
		const workloadName = "workload.bootstrap.test"
		now := time.Now()
		workload, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
			NetworkID: f.network.ID, ServiceID: relay.ServiceID, Role: pki.RoleRelay,
		}, []string{workloadName}, nil, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		workloadCert := pemFile("relay.crt", "CERTIFICATE", workload.CertificateDER)
		workloadKey := keyFile("relay.key", workload.PrivateKey)
		publicCA, publicRoot, err := pki.NewAuthority("Separate test public CA", now.Add(-time.Hour), time.Hour*24)
		if err != nil {
			t.Fatal(err)
		}
		httpsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(23), DNSNames: []string{publicName},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, publicRoot, httpsKey.Public(), publicCA.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicCert := pemFile("public.crt", "CERTIFICATE", leafDER)
		publicKey := keyFile("public.key", httpsKey)
		cfg := fmt.Sprintf(`mode = "relay"
[tls]
certificate = %q
private_key = %q
ca = %q
[relay]
listen = "127.0.0.1:0"
max_sessions = 4
[tcp_fallback]
listen = "127.0.0.1:0"
[controller]
endpoint = %q
allow_legacy_https = true
network_id = %q
service_id = %q
[public_https]
server_name = %q
certificate = %q
private_key = %q
`, workloadCert, workloadKey, ca, base, f.network.ID.String(), serviceID.String(), publicName, publicCert, publicKey)
		// A same-CA, valid-host controller with the wrong service identity
		// must not see even the preflight HTTP request.
		var requests atomic.Int32
		wrong := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		}))
		wrong.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ClientCAs: roots,
			ClientAuth: tls.RequireAndVerifyClientCert, Certificates: []tls.Certificate{{
				Certificate: [][]byte{leaf.CertificateDER}, PrivateKey: leaf.PrivateKey,
			}}}
		wrong.StartTLS()
		defer wrong.Close()
		badConfig := strings.Replace(cfg, base, wrong.URL, 1)
		badConfig = strings.Replace(badConfig, "service_id = "+fmt.Sprintf("%q", serviceID),
			"service_id = "+fmt.Sprintf("%q", identity.ID{33}), 1)
		badCtx, badCancel := context.WithTimeout(t.Context(), 5*time.Second)
		wrongCmd := exec.CommandContext(badCtx, relayBinary, "--config", write("wrong-controller.toml", []byte(badConfig)))
		out, badErr := wrongCmd.CombinedOutput()
		timedOut := badCtx.Err() != nil
		badCancel()
		if badErr == nil || timedOut || requests.Load() != 0 || !strings.Contains(string(out), "request relay configuration") {
			t.Fatal("wrong controller identity was not rejected before the relay sent HTTP")
		}
		tcp, _ := startRustPublicRelay(t, relayBinary, write("relay.toml", []byte(cfg)))
		publicRoots := x509.NewCertPool()
		publicRoots.AddCert(publicRoot)
		https := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: publicRoots, ServerName: publicName, MinVersion: tls.VersionTLS13},
		}}
		defer https.CloseIdleConnections()
		testRustConsole(t, https, "https://"+tcp, publicName)
		request := func(method, path string, body io.Reader, headers http.Header, want int) *http.Response {
			t.Helper()
			req, err := http.NewRequestWithContext(t.Context(), method, "https://"+tcp+path, body)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = publicName
			if headers != nil {
				req.Header = headers.Clone()
			}
			resp, err := https.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = resp.Body.Close() })
			if resp.StatusCode != want {
				t.Fatalf("public %s %s returned %d, want %d", method, path, resp.StatusCode, want)
			}
			return resp
		}
		public := request("GET", bootstrap.WellKnownPath, nil, nil, 200)
		metadata, err := bootstrap.Decode(public.Body, time.Now())
		if err != nil || metadata.NetworkID != f.network.ID.String() || public.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("public relay did not serve usable, non-cacheable bootstrap discovery")
		}
		const authState = "/v1/admin/auth/state"
		request("GET", authState, nil, http.Header{"X-Laneway-Public-Client-Ip": {"not-an-ip"}}, 200)
		_, wireToken, csrf, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "relay-owner", "local relay fixture password")
		if wireToken == "" {
			t.Fatal("test browser session is empty")
		}
		browser := http.Header{"Cookie": {adminauth.SessionCookieName + "=" + wireToken + "; " + adminauth.CSRFCookieName + "=" + csrf},
			"Origin": {"https://" + publicName}, "X-Laneway-Csrf": {csrf}, "Content-Type": {"application/json"}}
		request("GET", "/v1/admin/networks", nil, browser, 200)
		const script = "#!/bin/bash\n# local encrypted-wrapper fixture\n:\n"
		bundle := request("POST", "/v1/admin/bootstrap-bundles",
			strings.NewReader(fmt.Sprintf(`{"payload":%q,"expires_at_unix_seconds":%d}`, script, now.Add(5*time.Minute).Unix())),
			browser, 201)
		var envelope struct {
			ID   string `json:"bundle_id"`
			Path string `json:"public_path"`
		}
		if err := json.NewDecoder(bundle.Body).Decode(&envelope); err != nil || len(envelope.ID) != 43 {
			t.Fatal("bootstrap bundle was not created through public browser session")
		}
		request("GET", "/v1/bootstrap-bundles/"+envelope.ID, nil, nil, 404)
		request("GET", envelope.Path+"?unexpected=1", nil, nil, 404)
		request("HEAD", envelope.Path, nil, nil, 404)
		download := request("GET", envelope.Path, nil, nil, 200)
		if data, err := io.ReadAll(download.Body); err != nil || string(data) != script ||
			download.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("public bundle differs from the stored one-use wrapper")
		}
		request("GET", envelope.Path, nil, nil, 404)
		request("POST", "/v1/enroll", nil, nil, 404)
		request("GET", "/v1/admin/%2e%2e/configuration", nil, nil, 404)
		request("GET", authState, nil, http.Header{"Authorization": {"Bearer test"}}, 401)
		oauth := request("POST", "/oauth/token", strings.NewReader("grant_type=authorization_code"),
			http.Header{"Authorization": {"Basic dGVzdDp0ZXN0"}, "Content-Type": {"application/x-www-form-urlencoded"}}, 401)
		if !strings.HasPrefix(oauth.Header.Get("Www-Authenticate"), "Basic ") {
			t.Fatal("OAuth client authentication was blocked by the relay instead of reaching the controller")
		}
		// Node fallback chooses the Laneway certificate even if HTTP is also
		// offered, and does not finish a working session without a client key.
		nodeTLS := &tls.Config{RootCAs: roots, ServerName: workloadName, MinVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1", "laneway-fallback/1"}}
		dial := &net.Dialer{Timeout: 3 * time.Second}
		noCert, err := tls.DialWithDialer(dial, "tcp", tcp, nodeTLS)
		if err == nil {
			_ = noCert.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := noCert.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "certificate required") {
				t.Fatal("node listener did not demand a client certificate")
			}
			_ = noCert.Close()
		}
		node, _, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{
			NetworkID: f.network.ID, NodeID: identity.NodeID{12},
		}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		nodeTLS.Certificates = []tls.Certificate{{Certificate: [][]byte{node.CertificateDER}, PrivateKey: node.PrivateKey}}
		work, err := tls.DialWithDialer(dial, "tcp", tcp, nodeTLS)
		if err != nil {
			t.Fatal(err)
		}
		if work.ConnectionState().NegotiatedProtocol != "laneway-fallback/1" {
			t.Fatal("public listener accepted node transport with the wrong ALPN")
		}
		_ = work.Close()
		if pebble := os.Getenv("LANEWAY_RUST_PEBBLE"); pebble != "" {
			testRustAcme(t, pebble, relayBinary, cfg, roots, cert, key, ca)
		}
		if _, err := f.store.DisableRelay(t.Context(), relay.ID); err != nil {
			t.Fatal(err)
		}
		request("GET", authState, nil, nil, 401)
		request("GET", bootstrap.WellKnownPath, nil, nil, 503)
	} else {
		t.Log("shared public port test requires LANEWAY_RUST_RELAY; run make rust-controller-interop")
		if _, err := f.store.DisableRelay(t.Context(), relay.ID); err != nil {
			t.Fatal(err)
		}
	}
	call("GET", bootstrap.WellKnownPath, 503)
}

func startRustPublicRelay(t *testing.T, binary, cfg string) (string, func()) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binary, "--config", cfg)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	addr := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if _, tail, found := strings.Cut(scanner.Text(), "tcp_fallback=Some("); found {
				value, _, _ := strings.Cut(tail, ")")
				select {
				case addr <- value:
				default:
				}
			}
		}
		close(addr)
	}()
	select {
	case address := <-addr:
		if _, _, err := net.SplitHostPort(address); err != nil {
			t.Fatal("Rust relay did not announce its shared TCP listener")
		}
		return address, stop
	case <-time.After(10 * time.Second):
		t.Fatal("Rust relay did not start")
		return "", nil
	}
}
