//go:build rustinterop

package controllerservice

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

// Run both HTTP implementations with the same lab TLS identity and DB.
// The production cookie middleware remains in the Go reference path.
func TestRustControllerHTTPS(t *testing.T) {
	f := newFixture(t, 0, nil)
	material, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: f.network.ID, ServiceID: identity.ID(f.network.ID), Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	goServer := httptest.NewUnstartedServer(f.service.Handler())
	goServer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}}, MinVersion: tls.VersionTLS13}
	goServer.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	goServer.TLS.ClientCAs = x509.NewCertPool()
	goServer.TLS.ClientCAs.AddCert(f.service.ca)
	goServer.StartTLS()
	defer goServer.Close()
	dir := t.TempDir()
	write := func(name, kind string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pair := goServer.TLS.Certificates[0]
	pk, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := write("tls.crt", "CERTIFICATE", pair.Certificate[0])
	key := write("tls.key", "PRIVATE KEY", pk)
	ca := write("ca.crt", "CERTIFICATE", f.service.ca.Raw)
	rootFile := filepath.Join(dir, "root.token")
	if err := os.WriteFile(rootFile, []byte(testRootBearer+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	caPK, err := x509.MarshalPKCS8PrivateKey(f.service.caKey)
	if err != nil {
		t.Fatal(err)
	}
	caKey := write("issuer.key", "PRIVATE KEY", caPK)
	cmd := exec.CommandContext(t.Context(), os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", f.dbPath, "127.0.0.1:0", cert, key, "--root-token-file", rootFile, "--node-issuer", ca, caKey, "86400", "--node-client-ca", ca)
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
	var rustURL string
	select {
	case line := <-announce:
		if !strings.HasPrefix(line, "listening https://127.0.0.1:") {
			t.Fatalf("listener did not start: %q", line)
		}
		rustURL = strings.TrimPrefix(line, "listening ")
	case <-time.After(10 * time.Second):
		t.Fatal("listener startup timed out")
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	defer client.CloseIdleConnections()
	probe := filepath.Join(filepath.Dir(os.Getenv("LANEWAY_RUST_CONTROLLER")), "laneway-healthcheck")
	for _, pc := range []struct {
		name string
		ok   bool
	}{{"127.0.0.1", true}, {"wrong-name.invalid", false}} {
		cmd := exec.CommandContext(t.Context(), probe, "-tcp", strings.TrimPrefix(rustURL, "https://"), "-tls-ca", ca, "-tls-server-name", pc.name)
		if out, err := cmd.CombinedOutput(); (err == nil) != pc.ok {
			t.Fatalf("TLS healthcheck %s: %v %s", pc.name, err, out)
		}
	}
	client.Timeout = 5 * time.Second
	type result struct {
		status int
		body   map[string]any
		header http.Header
	}
	request := func(t *testing.T, base, method, path string, cookies []string, bearer bool, headers ...http.Header) result {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range cookies {
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: v})
		}
		if bearer {
			r.Header.Set("Authorization", "Bearer unrecognized-fixture")
		}
		for _, fields := range headers {
			for k, values := range fields {
				for _, v := range values {
					r.Header.Add(k, v)
				}
			}
		}
		r.Header.Set(AdministratorRequestIDHeader, "untrusted-id")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || resp.TLS.Version != tls.VersionTLS13 {
			t.Fatal("expected verified TLS 1.3")
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		out := result{status: resp.StatusCode, header: resp.Header}
		if method == "HEAD" || resp.StatusCode == http.StatusNoContent {
			if len(data) != 0 {
				t.Fatal("unexpected response body")
			}
		} else {
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			if err := dec.Decode(&out.body); err != nil {
				t.Fatalf("expected JSON response: %v", err)
			}
		}
		id := resp.Header.Get(AdministratorRequestIDHeader)
		if !administratorRequestIDPattern.MatchString(id) {
			t.Fatal("missing or malformed request ID")
		}
		if out.status >= 400 && method != "HEAD" {
			if out.body["request_id"] != id {
				t.Fatal("uncorrelated error")
			}
			delete(out.body, "request_id")
		}
		return out
	}
	const networks = "/v1/admin/networks"
	pairRequest := func(path string, cookies []string, fields http.Header, status int) (result, result) {
		t.Helper()
		a := request(t, goServer.URL, "GET", path, cookies, false, fields)
		b := request(t, rustURL, "GET", path, cookies, false, fields)
		if a.status != status || b.status != status {
			t.Fatalf("%s: Go %d, Rust %d, want %d", path, a.status, b.status, status)
		}
		if status >= 400 && !reflect.DeepEqual(a.body, b.body) {
			t.Fatalf("%s: error envelopes differ", path)
		}
		return a, b
	}
	const statePath = "/v1/admin/auth/state"
	a, b := pairRequest(statePath, nil, nil, 200)
	if a.body["state"] != "bootstrap_required" || !reflect.DeepEqual(a.body, b.body) {
		t.Fatal("bootstrap state mismatch")
	}
	session, cookie, csrf, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "web-owner", "local browser fixture password")
	a, b = pairRequest(statePath, nil, nil, 200)
	if a.body["state"] != "sign_in" || !reflect.DeepEqual(a.body, b.body) {
		t.Fatal("initialized state mismatch")
	}
	pairRequest(statePath, nil, http.Header{adminauth.PublicClientAddressHeader: {"192.0.2.8"}}, 401)
	for i := 2; i < 30; i++ {
		pairRequest(statePath, nil, nil, 200)
	}
	a, b = pairRequest(statePath, nil, nil, 429)
	for _, h := range []http.Header{a.header, b.header} {
		n, err := strconv.Atoi(h.Get("Retry-After"))
		if err != nil || n < 1 || n > 60 {
			t.Fatal("invalid discovery retry deadline")
		}
	}

	const sessionPath = "/v1/admin/auth/session"
	testSession := func(token, csrf, role string) {
		t.Helper()
		a, b := pairRequest(sessionPath, []string{token}, http.Header{"Cookie": {adminauth.CSRFCookieName + "=" + csrf}}, 200)
		for _, resp := range []result{a, b} {
			if resp.body["role"] != role || resp.body["csrf_token"] != csrf || resp.body["session_id"] != resp.header.Get(administratorSessionIDHeader) || resp.body["idle_expires_at_unix_seconds"] != json.Number(resp.header.Get(administratorSessionIdleHeader)) || resp.body["absolute_expires_at_unix_seconds"] != json.Number(resp.header.Get(administratorSessionAbsoluteHeader)) {
				t.Fatal("invalid browser session metadata")
			}
			delete(resp.body, "idle_expires_at_unix_seconds") // Two successful reads can straddle a second.
		}
		if !reflect.DeepEqual(a.body, b.body) {
			t.Fatalf("%s session properties or ordered permissions differ", role)
		}
	}
	testSession(cookie, csrf, "owner")
	testRustSessionRejection(t, f, func(token, csrf string) {
		r := request(t, rustURL, "GET", sessionPath, []string{token}, false, http.Header{"Cookie": {adminauth.CSRFCookieName + "=" + csrf}})
		if r.status != 401 || r.header.Get(administratorSessionIDHeader) != "" {
			t.Fatal("rejected session returned privileged metadata")
		}
	})
	for _, role := range []string{"operator", "auditor"} {
		token, c := rustScopedBrowserFixture(t, f, role)
		testSession(token, c, role)
	}
	pairRequest(sessionPath, nil, nil, 401)
	pairRequest(sessionPath, []string{cookie}, nil, 401)
	pairRequest(sessionPath, []string{cookie}, http.Header{"Cookie": {adminauth.CSRFCookieName + "=" + cookie}}, 401)
	pairRequest(sessionPath, []string{cookie}, http.Header{"Cookie": {adminauth.CSRFCookieName + "=" + csrf, adminauth.CSRFCookieName + "=" + csrf}}, 401)
	pairRequest(sessionPath, nil, http.Header{"Authorization": {"Bearer " + testRootBearer}}, 401)
	for _, tc := range []struct {
		name, method, path string
		cookies            []string
		bearer             bool
		want               int
	}{
		{"networks", "GET", networks + "?limit=1", []string{cookie}, false, 200},
		{"nodes", "GET", networks + "/" + f.network.ID.String() + "/nodes", []string{cookie}, false, 200},
		{"network-detail", "GET", networks + "/" + f.network.ID.String() + "?limit=ignored", []string{cookie}, false, 200},
		{"head-network-detail", "HEAD", networks + "/" + f.network.ID.String(), []string{cookie}, false, 200},
		{"invalid-network-detail", "GET", networks + "/invalid", []string{cookie}, false, 400},
		{"missing-network-detail", "GET", networks + "/ffffffffffffffffffffffffffffffff", []string{cookie}, false, 404},
		{"head", "HEAD", networks, []string{cookie}, false, 200},
		{"missing-cookie", "GET", networks, nil, false, 401},
		{"invalid-session-before-invalid-query", "GET", networks + "?limit=no", []string{"invalid"}, false, 401},
		{"duplicate-cookie", "GET", networks, []string{cookie, cookie}, false, 401},
		{"mixed-credentials", "GET", networks, []string{cookie}, true, 401},
		{"unknown-bearer", "GET", networks, nil, true, 401},
		{"invalid-limit", "GET", networks + "?limit=0", []string{cookie}, false, 400},
		{"malformed-escape-skipped", "GET", networks + "?limit=%ZZ&limit=1", []string{cookie}, false, 200},
		{"semicolon-field-skipped", "GET", networks + "?limit=0;unused", []string{cookie}, false, 200},
		{"first-decoded-limit", "GET", networks + "?%6cimit=0&limit=1", []string{cookie}, false, 400},
		{"invalid-id", "GET", networks + "/invalid/nodes", []string{cookie}, false, 400},
		{"missing-network", "GET", networks + "/ffffffffffffffffffffffffffffffff/nodes", []string{cookie}, false, 404},
		{"noncanonical", "GET", networks + "//nodes", []string{cookie}, false, 400},
		{"unknown-route", "GET", "/v1/admin/missing", []string{cookie}, false, 404},
		{"method", "DELETE", networks, []string{cookie}, false, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := request(t, goServer.URL, tc.method, tc.path, tc.cookies, tc.bearer)
			got := request(t, rustURL, tc.method, tc.path, tc.cookies, tc.bearer)
			if got.status != tc.want || got.status != want.status || !reflect.DeepEqual(got.body, want.body) {
				t.Fatalf("HTTP mismatch: Rust %d %v, Go %d %v", got.status, got.body, want.status, want.body)
			}
			for _, h := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options", administratorSessionIDHeader, administratorSessionAbsoluteHeader} {
				if got.header.Get(h) != want.header.Get(h) {
					t.Fatalf("%s mismatch", h)
				}
			}
			if got.status == 200 {
				s, _, err := f.store.AuthenticateAdministratorSession(t.Context(), cookie)
				if err != nil || s.ID != session.ID || got.header.Get(administratorSessionIdleHeader) != strconv.FormatInt(s.IdleExpiresAt.Unix(), 10) {
					t.Fatal("incorrect response idle deadline")
				}
			} else if got.header.Get(administratorSessionIdleHeader) != "" {
				t.Fatal("session metadata on error")
			}
		})
	}
	check := func(label, path string, h http.Header, status int, cookies ...string) map[string]any {
		t.Helper()
		a := request(t, goServer.URL, "GET", path, cookies, false, h)
		b := request(t, rustURL, "GET", path, cookies, false, h)
		if a.status != status || b.status != status || !reflect.DeepEqual(a.body, b.body) {
			t.Fatalf("%s: reference=%d %v Rust=%d %v", label, a.status, a.body, b.status, b.body)
		}
		for _, hdr := range []string{administratorSessionIDHeader, administratorSessionAbsoluteHeader, administratorSessionIdleHeader} {
			if b.header.Get(hdr) != "" {
				t.Fatalf("%s: bearer received session metadata", label)
			}
		}
		return b.body
	}
	testRustBearerInventory(t, f, cookie, check)
	t.Run("network-management", func(t *testing.T) { testRustNetworkManagement(t, f, client, goServer.URL, rustURL, cookie, csrf) })
	t.Run("access-management", func(t *testing.T) { testRustAccessManagement(t, f, client, goServer.URL, rustURL) })
	t.Run("enrollment-issuance", func(t *testing.T) { testRustEnrollmentIssuance(t, f, client, goServer.URL, rustURL, cookie, csrf) })
	t.Run("enrollment-redemption", func(t *testing.T) { testRustRedemption(t, f, client, rustURL, goServer.URL) })
	t.Run("node-renewal", func(t *testing.T) { testRustRenewal(t, f, client, rustURL, goServer.URL) })
	if err := f.store.LogoutAdministratorSession(t.Context(), adminauth.SessionSubject(session.PrincipalID, session.ID)); err != nil {
		t.Fatal(err)
	}
	if r := request(t, rustURL, "GET", networks, []string{cookie}, false); r.status != 401 {
		t.Fatal("logged-out session still had access")
	}
	pairRequest(sessionPath, []string{cookie}, http.Header{"Cookie": {adminauth.CSRFCookieName + "=" + csrf}}, 401)
	testRustSessionMutations(t, f, goServer.URL, rustURL, func(server, path, token string, fields http.Header) (int, map[string]any, http.Header) {
		r := request(t, server, "POST", path, []string{token}, false, fields)
		return r.status, r.body, r.header
	})
	testRustLogoutRotationRace(t, f, client, goServer.URL, rustURL)
	testRustBrowserLogin(t, f, client, goServer.URL, rustURL)
}
