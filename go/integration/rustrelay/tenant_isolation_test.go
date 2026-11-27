//go:build rustinterop

package rustrelay_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/platform"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
)

type tenantLab struct {
	slug, host, udp, root, caFile, https string
	network                              identity.NetworkID
	service, relay                       identity.ID
	client                               *controllerclient.Client
	config                               map[string]string
}

func TestSharedTenantIsolation(t *testing.T) {
	controllerBinary, relayBinary := os.Getenv("LANEWAY_RUST_CONTROLLER"), os.Getenv("LANEWAY_RUST_RELAY")
	if controllerBinary == "" || relayBinary == "" {
		t.Skip("set LANEWAY_RUST_CONTROLLER and LANEWAY_RUST_RELAY or run make rust-tenant-interop")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	const domain = "lane.test"
	dir := t.TempDir()
	publicAddress := tenantTCPAddress(t)
	_, publicPort, err := net.SplitHostPort(publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	webRoot, webCA, err := pki.NewAuthority("Local HTTPS root", now.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	create := func(slug, host, pool string) tenantLab {
		t.Helper()
		cell := tenantLab{slug: slug, host: host, udp: availableUDPAddress(t), https: tenantTCPAddress(t),
			network: identity.NetworkID(randomID(t)), service: randomID(t), relay: randomID(t)}
		quic := availableUDPAddress(t)
		_, httpsPort, _ := net.SplitHostPort(cell.https)
		_, quicPort, _ := net.SplitHostPort(quic)
		cell.root = filepath.Join(dir, slug+".root")
		writeFile(t, cell.root, []byte(randomID(t).String()+randomID(t).String()+"\n"), 0600)
		root, ca, err := pki.NewAuthority(slug, now.Add(-time.Minute), 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		caFile, caKey := writeLeaf(t, dir, slug+"-ca", root)
		cell.caFile = caFile
		issue := func(name string, role pki.ServiceRole, service identity.ID) (string, string) {
			t.Helper()
			cert, _, err := pki.IssueService(ca, root.PrivateKey, pki.ServiceIdentity{
				NetworkID: cell.network, Role: role, ServiceID: service,
			}, []string{host}, nil, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			return writeLeaf(t, dir, slug+"-"+name, cert)
		}
		controllerCert, controllerKey := issue("controller", pki.RoleController, cell.service)
		relayCert, relayKey := issue("relay", pki.RoleRelay, cell.relay)
		db := filepath.Join(dir, slug+".db")
		if output, err := exec.CommandContext(ctx, controllerBinary, "init", db, controllerCert, slug, pool).CombinedOutput(); err != nil {
			t.Fatalf("initialize %s: %v: %s", slug, err, output)
		}
		publicKey, publicPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(int64(publicKey[0]) + 1), DNSNames: []string{host},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, webCA, publicKey, webRoot.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicCert, publicKeyPath := writeLeaf(t, dir, slug+"-public", pki.Material{CertificateDER: der, PrivateKey: publicPrivate})
		relayConfig := filepath.Join(dir, slug+".toml")
		writeFile(t, relayConfig, []byte(fmt.Sprintf(`mode = "relay"
[tls]
certificate = %q
private_key = %q
ca = %q
[relay]
listen = %q
queue_depth = 16
max_sessions = 8
max_routes = 8
handshake_timeout = "5s"
idle_timeout = "15s"
metrics_interval = "0s"
[controller]
endpoint = %q
dial_address = %q
quic_endpoint = %q
network_id = %q
service_id = %q
server_name = %q
poll_interval = "100ms"
[tcp_fallback]
listen = %q
[public_https]
server_name = %q
certificate = %q
private_key = %q
`, relayCert, relayKey, cell.caFile, cell.udp, "https://"+host+":"+httpsPort, cell.https, quic,
			cell.network.String(), cell.service.String(), host, publicAddress, host, publicCert, publicKeyPath)), 0600)
		profile := filepath.Join(dir, slug+".bootstrap.json")
		writeFile(t, profile, []byte(fmt.Sprintf(`{"enrollment_endpoint":"https://%s:%s","quic_endpoint":"%s:%s","server_name":"%s"}`,
			host, httpsPort, host, quicPort, host)), 0600)
		cell.config = map[string]string{"database": db, "controller_https": cell.https, "controller_quic": quic,
			"controller_certificate": controllerCert, "controller_key": controllerKey, "root_token": cell.root,
			"issuer_chain": cell.caFile, "issuer_key": caKey, "client_ca": cell.caFile, "relay_config": relayConfig, "bootstrap_profile": profile}
		cell.client, err = controllerclient.New(controllerclient.Options{
			Endpoint: "https://" + host + ":" + httpsPort, DialAddress: cell.https, CAFile: cell.caFile,
			ServerName: host, ExpectedNetworkID: cell.network, ExpectedServiceID: cell.service,
			AdminTokenFile: cell.root, Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cell.client.Close() })
		return cell
	}
	a := create("alpha", "alpha."+domain, "100.96.31.0/24")
	b := create("beta", "beta."+domain, "100.96.32.0/24")
	baseCell := create("platform", domain, "100.96.30.0/24")
	manifest := filepath.Join(dir, "tenants.json")
	writeManifest := func(path string, beta map[string]string) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"domain": domain, "public_listen": publicAddress, "platform": baseCell.config, "tenants": []map[string]any{
				{"slug": a.slug, "deployment": a.config}, {"slug": b.slug, "deployment": beta},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, raw, 0600)
	}
	invalid := filepath.Join(dir, "invalid.json")
	sharedDatabase := maps.Clone(b.config)
	sharedDatabase["database"] = a.config["database"]
	writeManifest(invalid, sharedDatabase)
	if output, err := exec.CommandContext(ctx, controllerBinary, "serve-tenants", invalid).CombinedOutput(); err == nil ||
		!bytes.Contains(output, []byte("duplicate tenant database")) {
		t.Fatalf("controller did not reject duplicate database: %v: %s", err, output)
	}
	writeManifest(manifest, b.config)
	roots := x509.NewCertPool()
	roots.AddCert(webCA)
	web := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, publicAddress)
		},
	}}
	t.Cleanup(web.CloseIdleConnections)
	base := func(c tenantLab) string { return "https://" + c.host + ":" + publicPort }
	discovered := func(cell tenantLab) bool {
		r, err := web.Get(base(cell) + "/.well-known/laneway/bootstrap.json")
		if err != nil {
			return false
		}
		defer r.Body.Close()
		var body struct {
			NetworkID string `json:"network_id"`
		}
		return r.StatusCode == 200 && json.NewDecoder(r.Body).Decode(&body) == nil && body.NetworkID == cell.network.String()
	}
	t.Run("operator directory stages a separate instance", func(t *testing.T) {
		// Stage and start the candidate only inside this subtest.
		defer web.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		state := filepath.Join(dir, "platform-state")
		run := func(args ...string) {
			t.Helper()
			if output, err := exec.CommandContext(ctx, controllerBinary, append([]string{"platform"}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("platform %s: %v: %s", args[0], err, output)
			}
		}
		run("init", state)
		password, err := os.ReadFile(filepath.Join(state, "operator.password"))
		if err != nil {
			t.Fatal(err)
		}
		address := tenantTCPAddress(t)
		origin := "http://" + address
		startTenantProcess(t, controllerBinary, "platform", "serve", state, manifest, address)
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		var session *http.Cookie
		request := func(method, path, from, body string, authenticated bool) (int, string) {
			t.Helper()
			req, err := http.NewRequestWithContext(ctx, method, origin+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			if method == "POST" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", from)
			}
			if authenticated && session != nil {
				req.AddCookie(session)
			}
			resp, err := client.Do(req)
			if err != nil {
				return 0, ""
			}
			defer resp.Body.Close()
			if path == "/platform/sign-in" && resp.StatusCode == http.StatusSeeOther && method == "POST" {
				cookies := resp.Cookies()
				if len(cookies) != 1 || cookies[0].Name != "__Host-laneway-platform" ||
					!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" ||
					cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge != 28800 {
					t.Fatal("missing protected Platform session cookie")
				}
				session = cookies[0]
			}
			value, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			return resp.StatusCode, string(value)
		}
		waitFor(t, ctx, "platform listener", func() bool {
			status, _ := request("GET", "/", "", "", false)
			return status == http.StatusSeeOther
		})
		if status, page := request("GET", "/platform/sign-in", "", "", false); status != 200 || !strings.Contains(page, "Sign in · Laneway Platform") {
			t.Fatal("Platform sign-in page is missing")
		}
		if status, _ := request("POST", "/platform/sign-in", origin, "username=operator&password=wrong", false); status != 401 {
			t.Fatalf("invalid Platform password: HTTP %d", status)
		}
		if status, _ := request("POST", "/platform/sign-in", origin, "username=operator&password="+strings.TrimSpace(string(password)), false); status != 303 {
			t.Fatalf("Platform sign-in: HTTP %d", status)
		}
		for _, check := range []struct {
			path, from, body string
			want             int
		}{
			{"/tenants", "http://other.test", "slug=gamma", http.StatusForbidden},
			{"/tenants", origin, "slug=alpha", http.StatusConflict},
			{"/tenants", origin, "slug=platform", http.StatusConflict},
			{"/tenants", origin, "slug=gamma", http.StatusSeeOther},
			{"/tenants", origin, "slug=gamma", http.StatusConflict},
		} {
			if status, _ := request("POST", check.path, check.from, check.body, true); status != check.want {
				t.Fatalf("reserve %q: HTTP %d, want %d", check.body, status, check.want)
			}
		}
		status, page := request("GET", "/", "", "", true)
		if status != http.StatusOK || !strings.Contains(page, "alpha.lane.test") ||
			!strings.Contains(page, "beta.lane.test") || !strings.Contains(page, "Reserved · awaiting staging") ||
			strings.Contains(page, strings.TrimSpace(string(password))) || strings.Contains(page, a.root) {
			t.Fatal("platform must show tenant metadata and no credentials or paths")
		}
		if status, _ := request("GET", "/v1/admin/networks", "", "", true); status != http.StatusNotFound {
			t.Fatalf("instance API exposed on platform: HTTP %d", status)
		}
		gamma := create("gamma", "gamma."+domain, "100.96.33.0/24")
		gamma.config["database"] = filepath.Join(dir, "gamma-staged.db")
		gammaInput := filepath.Join(dir, "gamma-deployment.json")
		_, gammaRelayPort, err := net.SplitHostPort(gamma.udp)
		if err != nil {
			t.Fatal(err)
		}
		provision := map[string]any{
			"deployment":        gamma.config,
			"ipv4_pool":         "100.96.33.0/24",
			"relay_certificate": filepath.Join(dir, "gamma-relay.crt"),
			"relay_endpoint":    gamma.host + ":" + gammaRelayPort,
		}
		raw, err := json.Marshal(provision)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, gammaInput, raw, 0600)
		before, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		unsafeInput := filepath.Join(dir, "gamma-duplicate-credential.json")
		unsafeConfig := maps.Clone(gamma.config)
		unsafeConfig["root_token"] = a.root
		unsafeProvision := maps.Clone(provision)
		unsafeProvision["deployment"] = unsafeConfig
		unsafeJSON, err := json.Marshal(unsafeProvision)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, unsafeInput, unsafeJSON, 0600)
		if output, err := exec.CommandContext(ctx, controllerBinary, "platform", "stage", state, manifest,
			"gamma", unsafeInput).CombinedOutput(); err == nil ||
			!bytes.Contains(output, []byte("duplicate root credential")) {
			t.Fatalf("staging accepted shared credentials: %v: %s", err, output)
		}
		if _, err := os.Stat(gamma.config["database"]); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected staging published a database")
		}
		run("stage", state, manifest, "gamma", gammaInput)
		after, err := os.ReadFile(manifest)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("staging changed the active manifest")
		}
		candidatePath := filepath.Join(state, "gamma.manifest.json")
		candidate, err := os.ReadFile(candidatePath)
		if err != nil || !bytes.Contains(candidate, []byte("gamma-staged.db")) {
			t.Fatal("missing staged deployment")
		}
		status, page = request("GET", "/", "", "", true)
		if status != http.StatusOK || !strings.Contains(page, "Staged · awaiting activation") {
			t.Fatal("platform did not show the staged tenant")
		}
		if status, _ := request("POST", "/platform/sign-out", "http://other.test", "", true); status != 403 {
			t.Fatalf("cross-origin sign-out: HTTP %d", status)
		}
		if status, _ := request("POST", "/platform/sign-out", origin, "", true); status != 303 {
			t.Fatalf("Platform sign-out: HTTP %d", status)
		}
		if status, _ := request("GET", "/", "", "", true); status != 303 {
			t.Fatalf("signed-out cookie was still accepted: HTTP %d", status)
		}
		// Only start gamma here; the other fixture tenants bootstrap below.
		var config struct {
			Domain       string            `json:"domain"`
			PublicListen string            `json:"public_listen"`
			Tenants      []json.RawMessage `json:"tenants"`
		}
		if err := json.Unmarshal(candidate, &config); err != nil || len(config.Tenants) != 3 {
			t.Fatal("candidate did not preserve existing tenant entries")
		}
		config.Tenants = config.Tenants[2:]
		gammaManifest := filepath.Join(dir, "gamma-test-manifest.json")
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, gammaManifest, raw, 0600)
		startTenantProcess(t, controllerBinary, "serve-tenants", gammaManifest)
		waitFor(t, ctx, "staged tenant controller", func() bool {
			_, err := gamma.client.Networks(ctx, 2)
			return err == nil
		})
		startTenantProcess(t, relayBinary, "--tenants", gammaManifest)
		waitFor(t, ctx, "staged tenant public HTTPS", func() bool { return discovered(gamma) })
	})
	startTenantProcess(t, controllerBinary, "serve-tenants", manifest)
	for _, cell := range []tenantLab{a, b, baseCell} {
		waitFor(t, ctx, "tenant controller "+cell.slug, func() bool {
			_, err := cell.client.Networks(ctx, 2)
			return err == nil
		})
		if err := cell.client.BootstrapFirstAdministrator(ctx, cell.slug+"-owner", []byte(cell.slug+"-local-fixture-admin-password")); err != nil {
			t.Fatalf("bootstrap %s: %v", cell.slug, err)
		}
		_, udpPort, _ := net.SplitHostPort(cell.udp)
		if _, err := cell.client.RegisterRelay(ctx, cell.network, cell.relay, nil, "tenant relay", cell.host+":"+udpPort); err != nil {
			t.Fatalf("register %s relay: %v", cell.slug, err)
		}
		if _, err := cell.client.AddACLRule(ctx, cell.network, 1, "accept", json.RawMessage(`{"ipProtocol":"IP_PROTOCOL_ANY"}`), "allow lab peers"); err != nil {
			t.Fatalf("authorize %s peers: %v", cell.slug, err)
		}
	}
	socketDir, err := os.MkdirTemp("/tmp", "lnw-platform-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "p.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	operator := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:4177" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		session, err := r.Cookie("__Host-laneway-platform")
		if err != nil || session.Value != "fixture-session" {
			http.Redirect(w, r, "/platform/sign-in", http.StatusSeeOther)
			return
		}
		if r.Header.Get("Authorization") != "" || len(r.Cookies()) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			if r.Header.Get("Origin") != "http://127.0.0.1:4177" || r.FormValue("slug") != "test" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		_, _ = io.WriteString(w, "Platform fixture")
	})}
	go func() { _ = operator.Serve(listener) }()
	t.Cleanup(func() { _ = operator.Close() })
	rootRelay := baseCell.config["relay_config"]
	relayBytes, err := os.ReadFile(rootRelay)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, rootRelay, bytes.Replace(relayBytes, []byte("[public_https]\n"),
		[]byte(fmt.Sprintf("[public_https]\nplatform_socket = %q\n", socket)), 1), 0600)
	startTenantProcess(t, relayBinary, "--tenants", manifest)
	for _, cell := range []tenantLab{a, b, baseCell} {
		waitFor(t, ctx, "tenant HTTPS discovery "+cell.slug, func() bool { return discovered(cell) })
		if cell.slug != baseCell.slug && os.Getenv("LANEWAY_CONSOLE_DIR") != "" {
			response, err := web.Get(base(cell) + "/")
			if err != nil {
				t.Fatal(err)
			}
			html, err := io.ReadAll(io.LimitReader(response.Body, 65536))
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(html, []byte("<title>Laneway</title>")) {
				t.Fatalf("%s did not serve the built browser console: status %d: %v", cell.host, response.StatusCode, err)
			}
		}
	}
	t.Run("root HTTPS has separate Platform sign-in", func(t *testing.T) {
		client := *web
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		for _, test := range []struct {
			method, path, from string
			auth               bool
			status             int
		}{
			{"GET", "/", "", false, 303},
			{"GET", "/", "", true, 200},
			{"POST", "/tenants", "https://" + a.host, true, 403},
			{"POST", "/tenants", "https://" + baseCell.host, true, 303},
		} {
			req, err := http.NewRequestWithContext(ctx, test.method, base(baseCell)+test.path, strings.NewReader("slug=test"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: "unrelated", Value: "ignored"})
			if test.auth {
				req.AddCookie(&http.Cookie{Name: "__Host-laneway-platform", Value: "fixture-session"})
			}
			if test.from != "" {
				req.Header.Set("Origin", test.from)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
			res.Body.Close()
			if err != nil || res.StatusCode != test.status {
				t.Fatalf("%s %s: got %d, want %d (%v)", test.method, test.path, res.StatusCode, test.status, err)
			}
			if test.status == 200 && string(body) != "Platform fixture" {
				t.Fatal("root response did not come from Platform")
			}
		}
	})
	badHost, _ := http.NewRequestWithContext(ctx, http.MethodGet, base(a)+"/v1/admin/auth/state", nil)
	badHost.Host = b.host + ":" + publicPort
	if response, err := web.Do(badHost); err != nil {
		t.Fatal(err)
	} else {
		response.Body.Close()
		if response.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("wrong authority: status %d", response.StatusCode)
		}
	}
	if response, err := web.Get("https://unknown." + domain + ":" + publicPort + "/v1/admin/auth/state"); err == nil {
		response.Body.Close()
		t.Fatal("unknown SNI reached an HTTPS backend")
	}

	nodes := make(map[string][]tenantNode)
	for _, pair := range [][2]tenantLab{{a, b}, {b, a}} {
		nodes[pair[0].slug] = []tenantNode{
			enrollTenantLabNode(t, ctx, pair[0], pair[1], "first"),
			enrollTenantLabNode(t, ctx, pair[0], pair[1], "second"),
		}
	}
	tenantAdminChecks(t, web, base, nodes, a, b, baseCell)
	tenantAdminChecks(t, web, base, nodes, b, a, baseCell)
	tenantAdminChecks(t, web, base, nodes, baseCell, a, b)
	for _, pair := range [][2]tenantLab{{a, b}, {b, a}} {
		own, other := nodes[pair[0].slug], nodes[pair[1].slug]
		var fallback string
		carrier := "relay-quic"
		if pair[0].slug == a.slug {
			fallback = publicAddress
			carrier = "tcp-fallback"
		}
		source := startTenantNode(t, ctx, pair[0].udp, fallback, own[0], own[1], other[1])
		target := startTenantNode(t, ctx, pair[0].udp, "", own[1], own[0])
		packet, err := nodeservice.IPv4Packet(own[0].ip, own[1].ip, []byte("authorized tenant packet"))
		if err != nil {
			t.Fatal(err)
		}
		packetCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		waitFor(t, packetCtx, pair[0].slug+" node relay sessions", func() bool {
			return source.SelectedCarrier() == carrier && target.SelectedCarrier() == "relay-quic" &&
				source.PathAvailable(own[1].id.NodeID) && target.PathAvailable(own[0].id.NodeID)
		})
		if source.PathAvailable(other[1].id.NodeID) {
			t.Fatalf("%s relay supplied a route to a %s node", pair[0].slug, pair[1].slug)
		}
		waitForPacket(t, packetCtx, own[0].tun, own[1].tun, packet)
		cancel()
	}
	for _, pair := range [][2]tenantLab{{a, b}, {b, a}} {
		own, other := nodes[pair[0].slug], nodes[pair[1].slug]
		cross, err := nodeservice.IPv4Packet(own[0].ip, other[1].ip, []byte("must not cross tenants"))
		if err != nil {
			t.Fatal(err)
		}
		probeCtx, done := context.WithTimeout(ctx, 800*time.Millisecond)
		for i := 0; i < 3; i++ {
			if err := own[0].tun.Inject(probeCtx, cross); err != nil {
				t.Fatal(err)
			}
		}
		for {
			packet, err := other[1].tun.Receive(probeCtx)
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			if err != nil || bytes.Equal(packet, cross) {
				t.Fatalf("%s to %s: unexpected packet or error: %v", pair[0].slug, pair[1].slug, err)
			}
		}
		done()
		crossTLS := own[0].tls.Clone()
		crossTLS.RootCAs, crossTLS.ServerName = other[0].tls.RootCAs, pair[1].host
		foreign := newNode(t, own[0].id, crossTLS, pair[1].udp, own[0].tun, other[1].id.NodeID, other[1].ip)
		probeCtx, done = context.WithTimeout(ctx, 3*time.Second)
		err = foreign.RunSession(probeCtx)
		done()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s relay did not reject %s node credentials: %v", pair[1].slug, pair[0].slug, err)
		}
		probeCtx, done = context.WithTimeout(ctx, 3*time.Second)
		tcp, err := tcpfallback.Dial(probeCtx, publicAddress, crossTLS, nil)
		done()
		if err == nil {
			_ = tcp.Close()
			t.Fatalf("shared fallback accepted %s credentials for %s", pair[0].slug, pair[1].slug)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shared fallback timed out instead of rejecting %s credentials for %s", pair[0].slug, pair[1].slug)
		}
	}
	t.Log("Platform and tenant sign-in and inventory, discovery, enrollment, QUIC and TCP fallback verified; cross-tenant access and packets denied in both directions")
}

func tenantAdminChecks(t *testing.T, web *http.Client, base func(tenantLab) string, nodes map[string][]tenantNode, own tenantLab, others ...tenantLab) {
	t.Helper()
	requestTenant := func(method, base, path string, body []byte, cookies []*http.Cookie, want int) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			request.Header.Set("Origin", base)
			request.Header.Set("Content-Type", "application/json")
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
			if cookie.Name == "__Host-laneway_admin_csrf" && body != nil {
				request.Header.Set("X-Laneway-CSRF", cookie.Value)
			}
		}
		response, err := web.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s: status %d, want %d: %v", method, path, response.StatusCode, want, err)
		}
		return response, raw
	}
	call := func(base, path string, body []byte, cookies []*http.Cookie, want int) (*http.Response, []byte) {
		t.Helper()
		method := http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
		return requestTenant(method, base, path, body, cookies, want)
	}
	login := []byte(fmt.Sprintf(`{"username":%q,"password":%q}`, own.slug+"-owner", own.slug+"-local-fixture-admin-password"))
	ownURL := base(own)
	response, loginBody := call(ownURL, "/v1/admin/auth/login", login, nil, http.StatusOK)
	cookies := response.Cookies()
	if len(cookies) == 0 {
		t.Fatal("tenant login did not set session cookies")
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.Domain != "" {
			t.Fatal("tenant session cookies must be secure and host-only")
		}
	}
	_, sessionBody := call(ownURL, "/v1/admin/auth/session", nil, cookies, http.StatusOK)
	for _, body := range [][]byte{loginBody, sessionBody} {
		var session struct {
			Permissions []string `json:"permissions"`
		}
		if err := json.Unmarshal(body, &session); err != nil || len(session.Permissions) == 0 {
			t.Fatalf("tenant session did not return permissions: %v", err)
		}
		for _, permission := range session.Permissions {
			if permission == "network.create" {
				t.Fatal("tenant console offered a second workload network")
			}
		}
	}
	const twingatePath = "/v1/admin/integrations/twingate"
	_, twingateStatus := call(ownURL, twingatePath, nil, cookies, http.StatusOK)
	if string(twingateStatus) != `{"tenant":null,"verified_at_unix_seconds":null}` {
		t.Fatal("unexpected disconnected Twingate connection")
	}
	call(ownURL, twingatePath, nil, nil, http.StatusUnauthorized)
	requestTenant(http.MethodDelete, ownURL, twingatePath, nil, cookies, http.StatusForbidden)
	requestTenant(http.MethodPut, ownURL, twingatePath, []byte(`{"tenant":"acme.example","api_token":"fixture-only-token"}`), cookies, http.StatusBadRequest)
	call(ownURL, twingatePath+"/test", []byte{}, cookies, http.StatusConflict)
	call(ownURL, twingatePath+"/resources", nil, nil, http.StatusUnauthorized)
	call(ownURL, twingatePath+"/resources", nil, cookies, http.StatusConflict)
	call(ownURL, "/v1/admin/networks", []byte(`{"name":"another","ipv4_pool":"100.96.99.0/24"}`), cookies, http.StatusForbidden)
	_, raw := call(ownURL, "/v1/admin/networks", nil, cookies, http.StatusOK)
	var networks struct {
		Networks []struct {
			ID string `json:"network_id"`
		}
	}
	if err := json.Unmarshal(raw, &networks); err != nil || len(networks.Networks) != 1 ||
		networks.Networks[0].ID != own.network.String() {
		t.Fatalf("tenant received an incorrect network list: %v", err)
	}
	_, inventory := call(ownURL, "/v1/admin/networks/"+own.network.String()+"/nodes", nil, cookies, http.StatusOK)
	var listed struct {
		Nodes []struct {
			ID string `json:"node_id"`
		}
	}
	wantNodes := make(map[string]bool, len(nodes[own.slug]))
	for _, node := range nodes[own.slug] {
		wantNodes[node.id.NodeID.String()] = true
	}
	if err := json.Unmarshal(inventory, &listed); err != nil || len(listed.Nodes) != len(wantNodes) {
		t.Fatalf("%s received an incorrect node list: %v", own.slug, err)
	}
	for _, node := range listed.Nodes {
		if !wantNodes[node.ID] {
			t.Fatalf("%s node list contained an unexpected node", own.slug)
		}
		delete(wantNodes, node.ID)
	}
	for _, other := range others {
		call(base(other), "/v1/admin/auth/login", login, nil, http.StatusUnauthorized)
		call(base(other), "/v1/admin/auth/session", nil, cookies, http.StatusUnauthorized)
		call(base(other), twingatePath, nil, cookies, http.StatusUnauthorized)
		call(base(other), twingatePath+"/resources", nil, cookies, http.StatusUnauthorized)
		call(ownURL, "/v1/admin/networks/"+other.network.String(), nil, cookies, http.StatusNotFound)
		call(ownURL, "/v1/admin/networks/"+other.network.String()+"/nodes", nil, cookies, http.StatusNotFound)
	}
}

type tenantNode struct {
	id  identity.NodeIdentity
	ip  netip.Addr
	tls *tls.Config
	tun *platform.MemoryTUN
}

func enrollTenantLabNode(t *testing.T, ctx context.Context, own, other tenantLab, name string) tenantNode {
	t.Helper()
	wireguard, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, signer)
	if err != nil {
		t.Fatal(err)
	}
	token, err := own.client.IssueEnrollmentToken(ctx, own.network, name, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	key := wireguard.PublicKey().Bytes()
	if _, err := other.client.EnrollForNetwork(ctx, token.EnrollmentToken, name, csr, key, other.network); err == nil {
		t.Fatal("a tenant accepted the other tenant's enrollment token")
	}
	enrolled, err := own.client.EnrollForNetwork(ctx, token.EnrollmentToken, name, csr, key, own.network)
	if err != nil {
		t.Fatal(err)
	}
	if len(enrolled.GetOverlayAddresses()) != 1 {
		t.Fatal("expected one enrolled overlay address")
	}
	ip, ok := netip.AddrFromSlice(enrolled.GetOverlayAddresses()[0])
	if !ok || !ip.Is4() || len(enrolled.GetNodeId()) != 16 {
		t.Fatal("enrollment did not allocate IPv4 and a node identity")
	}
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(own.caFile)
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatal("could not load tenant root")
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: own.host, MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: enrolled.GetCertificateChain().GetCertificatesDer(), PrivateKey: signer}}}
	tun := memoryTUN(t, own.slug+"-"+name, ip)
	t.Cleanup(func() { _ = tun.Close() })
	return tenantNode{identity.NodeIdentity{NetworkID: own.network, NodeID: identity.NodeID(enrolled.GetNodeId())}, ip, cfg, tun}
}

func startTenantNode(t *testing.T, ctx context.Context, udp, fallback string, node tenantNode, peers ...tenantNode) *nodeservice.Service {
	t.Helper()
	routes := make([]routing.Route, 0, len(peers))
	for _, peer := range peers {
		routes = append(routes, routing.Route{Prefix: netip.PrefixFrom(peer.ip, 32), NextHop: peer.id.NodeID})
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		t.Fatal(err)
	}
	config := nodeservice.Config{Identity: node.id, BootID: randomID(t),
		RelayAddress: udp, TLSConfig: node.tls, Routes: routing.NewTable(snapshot), Packets: tunAdapter{node.tun},
		MaxControlPayload: 64 * 1024, MaxRoutes: 8}
	if fallback != "" {
		config.TCPFallbackAddress = fallback
		config.RelayAddress = availableUDPAddress(t)
		config.Transport = &transport.Config{HandshakeIdleTimeout: 150 * time.Millisecond}
	}
	service, err := nodeservice.New(config)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = service.Run(ctx) }()
	return service
}

func tenantTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func startTenantProcess(t *testing.T, binary string, args ...string) {
	t.Helper()
	var logs lockedBuffer
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	})
}
