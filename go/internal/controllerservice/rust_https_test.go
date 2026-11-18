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
	session, cookie, _, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "web-owner", "local browser fixture password")
	material, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: f.network.ID, ServiceID: identity.ID(f.network.ID), Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	goServer := httptest.NewUnstartedServer(f.service.Handler())
	goServer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}}, MinVersion: tls.VersionTLS13}
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
	cmd := exec.CommandContext(t.Context(), os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", f.dbPath, "127.0.0.1:0", cert, key)
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
	request := func(t *testing.T, base, method, path string, cookies []string, bearer bool) result {
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
		if method == "HEAD" {
			if len(data) != 0 {
				t.Fatal("HEAD returned a body")
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
	for _, tc := range []struct {
		name, method, path string
		cookies            []string
		bearer             bool
		want               int
	}{
		{"networks", "GET", networks + "?limit=1", []string{cookie}, false, 200},
		{"nodes", "GET", networks + "/" + f.network.ID.String() + "/nodes", []string{cookie}, false, 200},
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
	if err := f.store.LogoutAdministratorSession(t.Context(), adminauth.SessionSubject(session.PrincipalID, session.ID)); err != nil {
		t.Fatal(err)
	}
	if r := request(t, rustURL, "GET", networks, []string{cookie}, false); r.status != 401 {
		t.Fatal("logged-out session still had access")
	}
}
