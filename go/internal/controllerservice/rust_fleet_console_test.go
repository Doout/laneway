//go:build rustinterop

package controllerservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

// Run a supplied private live build through Chromium, the Rust public relay,
// and the Rust controller.
// The Go store only prepares a throwaway database; it does not serve requests.
func TestRustControllerFleetConsole(t *testing.T) {
	assets := os.Getenv("LANEWAY_RUST_FLEET_CONSOLE_ASSETS")
	if assets == "" {
		t.Skip("set LANEWAY_RUST_FLEET_CONSOLE_ASSETS to a private live console build")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("LANEWAY_RUST_FLEET_CONSOLE_ASSETS must be an absolute path")
	}
	if _, err := os.Stat(filepath.Join(assets, "index.html")); err != nil {
		t.Fatal(err)
	}
	relayBinary := os.Getenv("LANEWAY_RUST_RELAY")
	if relayBinary == "" {
		t.Fatal("set LANEWAY_RUST_RELAY to the Rust relay binary")
	}

	f := newFixture(t, 0, nil)
	const username = "fleet-console-owner"
	const password = "isolated fleet console fixture password"
	bootstrapAdministratorSessionForHTTPTest(t, f, username, password)
	ctx, now := t.Context(), time.Now()
	network := f.network.ID
	const publicName = "laneway-fleet.test"
	relayID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.RegisterRelay(ctx, network, relayID, nil, "fleet-relay", publicName+":443"); err != nil {
		t.Fatal(err)
	}
	enroll := func(name string) controller.Node {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, network, name, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		node, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, cert, err := pki.IssueNode(f.service.ca, f.service.caKey,
			identity.NodeIdentity{NetworkID: network, NodeID: node.ID}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AddCertificate(ctx, network, node.ID, cert.SerialNumber.Bytes(), cert.Raw, cert.NotBefore, cert.NotAfter); err != nil {
			t.Fatal(err)
		}
		return node
	}
	source := enroll("console-source")
	destination := enroll("console-destination")
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath).CombinedOutput(); err != nil {
		t.Fatalf("migrate fleet console database: %v %s", err, out)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	observed := now.Add(-5 * time.Minute).Unix()
	if _, err := db.ExecContext(ctx, `INSERT INTO endpoint_status_latest
		(node_id,network_id,observed_at,expires_at,valid_for_seconds,product_version,platform,
		certificate_state,configuration_state,carrier_state,route_state,selected_exit_state,cleanup_failure_count,configuration_epoch)
		VALUES(?,?,?,?,30,'lab','linux','healthy','current','relay_quic','ready','not_selected',0,1)`,
		source.ID[:], network[:], observed, observed+30); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	material, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: identity.ID(network), Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ca := write("ca.crt", pki.CertificatePEM(f.service.ca.Raw))
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := pki.PrivateKeyPEM(f.service.caKey)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, stop := startRustAdministratorLab(t, f.dbPath, write("tls.crt", pki.CertificatePEM(material.CertificateDER)),
		write("tls.key", key), write("root.token", []byte(testRootBearer+"\n")),
		"--console-dir", assets, "--node-client-ca", ca, "--node-issuer", ca, write("issuer.key", issuerKey), "3600")
	defer stop()

	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	api := "/v1/admin/networks/" + network.String()
	labManagementHTTP(t, client)(endpoint, http.MethodPost, api+"/acl-rules",
		`{"priority":10,"action":"accept","selector":{"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":443,"last":443}]}}`,
		labCredentials{bearer: testRootBearer}, http.StatusCreated)

	workload, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workloadKey, err := pki.PrivateKeyPEM(workload.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	// Browsers reach the public ECDSA listener, not the internal service TLS
	// listener. The test never weakens the relay's upstream verification.
	httpsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	httpsDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{publicName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, f.service.ca, httpsKey.Public(), f.service.caKey)
	if err != nil {
		t.Fatal(err)
	}
	httpsPEM, err := pki.PrivateKeyPEM(httpsKey)
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`mode = "relay"
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
`, write("relay.crt", pki.CertificatePEM(workload.CertificateDER)), write("relay.key", workloadKey), ca,
		endpoint, network, network, publicName, write("https.crt", pki.CertificatePEM(httpsDER)), write("https.key", httpsPEM))
	addr, stopRelay := startRustPublicRelay(t, relayBinary, write("relay.toml", []byte(config)))
	defer stopRelay()
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("expected a loopback relay, got %q", addr)
	}
	browserContext, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(browserContext, "node", "../../../web/scripts/check-fleet-console.mjs")
	cmd.Env = append(os.Environ(),
		"LANEWAY_FLEET_LAB_ORIGIN=https://"+net.JoinHostPort(publicName, port),
		"LANEWAY_FLEET_LAB_USERNAME="+username, "LANEWAY_FLEET_LAB_PASSWORD="+password,
		"LANEWAY_FLEET_LAB_NETWORK="+network.String(), "LANEWAY_FLEET_LAB_DESTINATION_IP="+destination.IPv4Address.String(),
	)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("fleet console browser gate: %v", err)
	}
}
