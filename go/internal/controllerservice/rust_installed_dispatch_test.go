//go:build rustinterop

package controllerservice

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

// Run only against the disposable deployment made by installer-fresh.sh.
// All database mutations go through the Rust APIs, including test setup.
func TestRustInstalledDispatch(t *testing.T) {
	deployment := os.Getenv("LANEWAY_INSTALLED_DISPATCH_DEPLOY")
	if deployment == "" {
		t.Skip("requires the isolated Rust Compose installer fixture")
	}
	probeBin := os.Getenv("LANEWAY_DISPATCH_PROBE")
	if probeBin == "" {
		t.Fatal("requires the compiled Dispatch client probe")
	}
	read := func(relative string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(deployment, relative))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	settings := map[string]string{}
	for line := range strings.SplitSeq(string(read(".env")), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			settings[key] = value
		}
	}
	if settings["LANEWAY_CONTROL_RUNTIME"] != "rust" || settings["LANEWAY_BIND_ADDRESS"] != "127.0.0.1" ||
		settings["LANEWAY_CONTROLLER_SERVER_NAME"] != "installer.fresh.test" || settings["LANEWAY_RELAY_TCP_PORT"] != "443" {
		t.Fatal("requires the loopback-only installer fixture with HTTPS on port 443")
	}
	network, err := identity.ParseID(settings["LANEWAY_NETWORK_ID"])
	if err != nil {
		t.Fatal(err)
	}
	name := settings["LANEWAY_CONTROLLER_SERVER_NAME"]
	controllerAddress := net.JoinHostPort("127.0.0.1", settings["LANEWAY_CONTROLLER_PORT"])
	controllerOrigin := "https://" + net.JoinHostPort(name, settings["LANEWAY_CONTROLLER_PORT"])
	publicOrigin, publicAddress := "https://"+name, "127.0.0.1:443"
	controllerCA := read("generated/pki/ca.crt")
	publicCA := read("generated/pki/public.crt")
	newClient := func(ca []byte, address string) *http.Client {
		t.Helper()
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("could not load lab trust bundle")
		}
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		client := &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, address)
				},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		t.Cleanup(client.CloseIdleConnections)
		return client
	}
	direct, https := newClient(controllerCA, controllerAddress), newClient(publicCA, publicAddress)
	call := func(client *http.Client, origin, method, path string, body io.Reader, headers http.Header, want int) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, origin+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if headers != nil {
			req.Header = headers.Clone()
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		if resp.StatusCode != want {
			t.Fatalf("installed service: %s %s returned %d, want %d", method, path, resp.StatusCode, want)
		}
		return resp
	}
	public := func(method, path string, body io.Reader, headers http.Header, want int) *http.Response {
		t.Helper()
		return call(https, publicOrigin, method, path, body, headers, want)
	}
	root := strings.TrimSpace(string(read("generated/secrets/admin.token")))
	private := labManagementHTTP(t, direct)
	admin := labCredentials{bearer: root}
	requiredField := func(value map[string]any, field string) string {
		t.Helper()
		s, _ := value[field].(string)
		if s == "" {
			t.Fatalf("missing %s in Rust controller response", field)
		}
		return s
	}
	const username, password = "dispatch-owner", "isolated dispatch test password"
	grant := requiredField(private(controllerOrigin, "POST", "/v1/admin/auth/bootstrap-grants", "", admin, 201), "grant")
	call(direct, controllerOrigin, "POST", "/v1/admin/auth/bootstrap",
		strings.NewReader(fmt.Sprintf(`{"grant":%q,"username":%q,"password":%q}`, grant, username, password)),
		http.Header{"Origin": {controllerOrigin}, "Content-Type": {"application/json"}}, 204).Body.Close()
	browser := http.Header{"Origin": {publicOrigin}, "Content-Type": {"application/json"}}
	login := public("POST", "/v1/admin/auth/login", strings.NewReader(
		`{"username":"`+username+`","password":"`+password+`"}`), browser, 200)
	login.Body.Close()
	var session, csrf string
	for _, cookie := range login.Cookies() {
		switch cookie.Name {
		case adminauth.SessionCookieName:
			session = cookie.Value
		case adminauth.CSRFCookieName:
			csrf = cookie.Value
		}
	}
	if session == "" || csrf == "" {
		t.Fatal("HTTPS login did not issue the browser session and CSRF cookies")
	}
	browser.Set("Cookie", adminauth.SessionCookieName+"="+session+"; "+adminauth.CSRFCookieName+"="+csrf)
	browser.Set(adminauth.CSRFHeaderName, csrf)
	foreign := private(controllerOrigin, "POST", "/v1/admin/networks",
		`{"name":"other-lab-network","ipv4_pool":"100.97.0.0/16"}`, admin, 201)
	foreignID, err := identity.ParseID(requiredField(foreign, "network_id"))
	if err != nil {
		t.Fatal(err)
	}
	makeRouter := func(id identity.NetworkID, label string) identity.NodeID {
		t.Helper()
		token := requiredField(private(controllerOrigin, "POST", "/v1/admin/enrollment-tokens",
			fmt.Sprintf(`{"network_id":%q,"label":%q,"enrollment_class":"durable","expires_at_unix_seconds":%d,"enabled_capabilities":%d}`,
				id, label, time.Now().Add(time.Hour).Unix(), protocol.CapabilitySubnetRouterV1), admin, 201), "enrollment_token")
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
		if err != nil {
			t.Fatal(err)
		}
		wireguard, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := proto.Marshal(&v1.EnrollmentRequest{
			EnrollmentToken: token, RequestedName: label, Pkcs10CsrDer: csr, WireguardPublicKey: wireguard.PublicKey().Bytes(),
			ExpectedNetworkId: id[:], ExpectedEnrollmentClass: v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE,
		})
		if err != nil {
			t.Fatal(err)
		}
		reply := call(direct, controllerOrigin, "POST", "/v1/enroll", bytes.NewReader(wire),
			http.Header{"Content-Type": {"application/x-protobuf"}}, 201)
		defer reply.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(reply.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		response := new(v1.EnrollmentResponse)
		if err := proto.Unmarshal(payload, response); err != nil {
			t.Fatal(err)
		}
		if len(response.GetNodeId()) != identity.IDSize {
			t.Fatal("Rust enrollment returned an invalid node ID")
		}
		return identity.NodeID(response.GetNodeId())
	}
	testRustPublicApplication(t, identity.NetworkID(network), identity.NetworkID(foreignID), makeRouter, public, direct, controllerOrigin, browser,
		root, dispatchClientProbe{
			binary: probeBin, address: publicAddress, authority: publicOrigin, caPEM: string(publicCA),
		})
}
