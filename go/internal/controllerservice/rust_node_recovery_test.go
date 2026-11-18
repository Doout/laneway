//go:build rustinterop && unix

package controllerservice

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

func TestRustNodeCredentialRecovery(t *testing.T) {
	f := newFixture(t, 0, nil)
	useProductionRootAccess(t, f)
	ctx := t.Context()
	_, session, csrf, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "node-recovery-owner", "recovery fixture owner password")
	now := time.Now().UTC()
	foreign, err := f.store.CreateNetwork(ctx, "foreign recovery", netip.MustParsePrefix("10.197.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	nodeKey := func(netID identity.NetworkID, name string, expiry time.Time, opts controller.EnrollmentTokenOptions) (controller.Node, pki.Material, *x509.Certificate) {
		t.Helper()
		token, err := f.store.IssueEnrollmentTokenWithOptions(ctx, netID, name, now.Add(time.Hour), opts)
		if err != nil {
			t.Fatal(err)
		}
		node, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		key, cert, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: netID, NodeID: node.ID}, expiry.Add(-10*time.Minute), 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AddCertificate(ctx, netID, node.ID, cert.SerialNumber.Bytes(), cert.Raw, cert.NotBefore, cert.NotAfter); err != nil {
			t.Fatal(err)
		}
		return node, key, cert
	}
	create := httptest.NewRequest("POST", "/v1/admin/networks/"+f.network.ID.String()+"/users", strings.NewReader(`{"name":"remembered-recovery-user"}`))
	create.Header.Set("Authorization", "Bearer "+testRootBearer)
	create.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("create managed user: status=%d", created.Code)
	}
	var user struct {
		ID string `json:"user_id"`
	}
	decodeJSONResponse(t, created, &user)
	managed, err := identity.ParseID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	node, oldKey, old := nodeKey(f.network.ID, "remembered recovery", now.Add(-time.Minute),
		controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassRemembered, UserID: &managed})
	active, wrongKey, current := nodeKey(f.network.ID, "still valid", now.Add(time.Hour), controller.EnrollmentTokenOptions{})
	outside, outsideKey, outerCert := nodeKey(foreign.ID, "outside", now.Add(-time.Minute), controller.EnrollmentTokenOptions{})
	leased, _, leaseCert := nodeKey(f.network.ID, "leased", now.Add(-time.Minute),
		controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassEphemeral, SessionLifetime: controller.MinEphemeralLifetime})
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate fleet: %v %s", err, out)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{
		NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyPEM := func(key crypto.Signer) []byte {
		t.Helper()
		b, err := pki.PrivateKeyPEM(key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ca := write("ca.crt", pki.CertificatePEM(f.service.ca.Raw))
	key := write("ca.key", keyPEM(f.service.caKey))
	rootFile := write("root.token", []byte(testRootBearer+"\n"))
	endpoint, quic, stop := startControllerTLSLab(t, f.dbPath, write("controller.crt", pki.CertificatePEM(server.CertificateDER)), write("controller.key", keyPEM(server.PrivateKey)),
		"--root-token-file", rootFile, "--node-issuer", ca, key, "3600", "--node-client-ca", ca, "--node-quic")
	defer stop()
	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	owner := labCredentials{session: session, csrf: csrf}
	net := "/v1/admin/networks/" + f.network.ID.String()
	bot := func(permission string) labCredentials {
		t.Helper()
		principal := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, "recovery-"+permission, permission, f.network.ID.String()), root, 201)["principal_id"].(string)
		token := send(endpoint, "POST", "/v1/admin/service-principals/"+principal+"/tokens", fmt.Sprintf(`{"label":"test","expires_at_unix_seconds":%d}`, now.Add(time.Hour).Unix()), root, 201)["access_token"].(string)
		return labCredentials{bearer: token}
	}
	manager, reader := bot("node.manage"), bot("node.read")
	approve := func(nodeID identity.NodeID, cert *x509.Certificate, cred labCredentials, status int) string {
		t.Helper()
		path := "/v1/admin/nodes/" + nodeID.String() + "/credential-recovery-grants"
		body := fmt.Sprintf(`{"certificate_serial":%q,"reason":"Verified fixture identity"}`, hex.EncodeToString(cert.SerialNumber.Bytes()))
		reply := send(endpoint, "POST", path, body, cred, status)
		if status != 201 {
			return ""
		}
		token, ok := reply["recovery_token"].(string)
		if !ok || len(token) != 43 || reply["expires_at_unix_seconds"].(float64) > float64(time.Now().Add(10*time.Minute).Unix()) {
			t.Fatal("invalid recovery approval envelope")
		}
		return token
	}
	approve(node.ID, old, reader, 403)
	approve(node.ID, old, labCredentials{session: session}, 403)
	approve(outside.ID, outerCert, manager, 404)
	approve(active.ID, current, root, 404)
	approve(leased.ID, leaseCert, root, 404)
	send(endpoint, "PATCH", "/v1/admin/users/"+managed.String(), `{"enabled":false}`, root, 200)
	approve(node.ID, old, root, 404)
	send(endpoint, "PATCH", "/v1/admin/users/"+managed.String(), `{"enabled":true}`, root, 200)
	before := send(endpoint, "GET", net, "", root, 200)["configuration_epoch"]
	superseded := approve(node.ID, old, owner, 201)
	approved := approve(node.ID, old, manager, 201)
	proof := func(token string, signer any, bound bool) []byte {
		t.Helper()
		subject := pkix.Name{CommonName: "unbound"}
		if bound {
			digest := sha256.Sum256([]byte(token))
			subject.CommonName = "laneway-recovery:" + hex.EncodeToString(digest[:])
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	redeem := func(token string, csr []byte, status int) map[string]any {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"recovery_token": token, "pkcs10_csr_der": csr})
		return send(endpoint, "POST", "/v1/node-credential-recovery", string(payload), labCredentials{}, status)
	}
	redeem(superseded, proof(superseded, oldKey.PrivateKey, true), 403)
	redeem(approved, proof(approved, oldKey.PrivateKey, false), 403)
	redeem(approved, proof(approved, wrongKey.PrivateKey, true), 403)
	broken := proof(approved, oldKey.PrivateKey, true)
	broken[len(broken)-1] ^= 1
	redeem(approved, broken, 403)
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER lab_reject_recovery BEFORE INSERT ON audit_events
		WHEN NEW.action='node.credential_recovery.consume' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	redeem(approved, proof(approved, oldKey.PrivateKey, true), 500)
	if _, err := db.Exec("DROP TRIGGER lab_reject_recovery"); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(approved))
	var stillAvailable int
	if err := db.QueryRow("SELECT count(*) FROM node_credential_recovery_grants WHERE token_hash=? AND consumed_at IS NULL", digest[:]).Scan(&stillAvailable); err != nil || stillAvailable != 1 {
		t.Fatal("failed recovery consumed its approval")
	}

	var newDER []byte
	if binary := os.Getenv("LANEWAY_RUST_NODE"); binary != "" {
		original := pki.CertificatePEM(old.Raw)
		certificate := write("node.crt", original)
		private := keyPEM(oldKey.PrivateKey)
		keyPath := write("node.key", private)
		tokenPath := write("approval.token", []byte(approved+"\n"))
		run := func(service string, want bool) {
			t.Helper()
			cfg := write("node.toml", []byte(fmt.Sprintf(`
mode = "node"
[identity]
network_id = %q
node_id = %q
[tls]
certificate = %q
private_key = %q
ca = %q
[controller]
endpoint = %q
quic_endpoint = %q
server_name = "127.0.0.1"
service_id = %q
[tun]
name = "lane0"
[relay]
address = "127.0.0.1:4433"
server_name = "relay.example"
service_id = "44444444444444444444444444444444"
`, f.network.ID.String(), node.ID.String(), certificate, keyPath, ca, endpoint, quic, service)))
			cmd := exec.CommandContext(ctx, binary, "recover", "--config", cfg, "--recovery-token-file", tokenPath)
			out, err := cmd.CombinedOutput()
			if bytes.Contains(out, []byte(approved)) {
				t.Fatal("native recovery disclosed an approval in its output")
			}
			if (err == nil) != want {
				t.Fatalf("native recovery returned unexpected result (expected success=%t, err=%v): %s", want, err, out)
			}
		}
		run("66666666666666666666666666666666", false)
		if oldPEM, err := os.ReadFile(certificate); err != nil || !bytes.Equal(oldPEM, original) {
			t.Fatal("controller identity mismatch modified the certificate")
		}
		run(serviceID.String(), true)
		b, err := os.ReadFile(certificate)
		if err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(b, private)
		if key, keyErr := os.ReadFile(keyPath); err != nil || keyErr != nil || !bytes.Equal(key, private) {
			t.Fatal("native recovery did not preserve the existing private key")
		}
		newDER = pair.Certificate[0]
	} else {
		t.Log("native recovery command check requires LANEWAY_RUST_NODE")
		reply := redeem(approved, proof(approved, oldKey.PrivateKey, true), 200)
		chain, _ := json.Marshal(reply["certificates_der"])
		var ders [][]byte
		if err := json.Unmarshal(chain, &ders); err != nil || len(ders) == 0 {
			t.Fatal("missing recovered certificate")
		}
		newDER = ders[0]
	}
	leaf, err := x509.ParseCertificate(newDER)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := identity.IdentityFromCertificate(leaf)
	if err != nil || recovered.NodeID != node.ID || recovered.NetworkID != f.network.ID ||
		!bytes.Equal(leaf.RawSubjectPublicKeyInfo, old.RawSubjectPublicKeyInfo) || !leaf.NotAfter.After(now) ||
		leaf.SerialNumber.Cmp(old.SerialNumber) == 0 {
		t.Fatal("recovered certificate did not preserve identity and key")
	}
	redeem(approved, proof(approved, oldKey.PrivateKey, true), 403)
	stale := approve(outside.ID, outerCert, root, 201)
	staleHash := sha256.Sum256([]byte(stale))
	if _, err := db.Exec("UPDATE node_credential_recovery_grants SET expires_at=unixepoch()-1 WHERE token_hash=?", staleHash[:]); err != nil {
		t.Fatal(err)
	}
	redeem(stale, proof(stale, outsideKey.PrivateKey, true), 403)
	revoked := approve(outside.ID, outerCert, root, 201)
	serial := hex.EncodeToString(outerCert.SerialNumber.Bytes())
	send(endpoint, "POST", "/v1/admin/networks/"+foreign.ID.String()+"/certificates/"+serial+"/revoke", `{"reason":"node recovery test"}`, root, 200)
	redeem(revoked, proof(revoked, outsideKey.PrivateKey, true), 403)
	withCertificate := transport.Clone()
	withCertificate.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{newDER}, PrivateKey: oldKey.PrivateKey}}
	reconnected := &http.Client{Transport: withCertificate, Timeout: 5 * time.Second}
	defer reconnected.CloseIdleConnections()
	report := fmt.Sprintf(`{"valid_for_seconds":30,"product_version":"recovered","platform":"linux",
		"certificate_state":"healthy","configuration_state":"current","carrier_state":"unknown",
		"route_state":"unknown","selected_exit_state":"not_selected","cleanup_failure_count":0,"configuration_epoch":%.0f}`, before)
	labManagementHTTP(t, reconnected)(endpoint, "PUT", "/v1/status", report, labCredentials{}, 204)
	if after := send(endpoint, "GET", net, "", root, 200)["configuration_epoch"]; after != before {
		t.Fatal("credential recovery changed network configuration")
	}
	var nodeClass string
	var approvals, consumed, certificates int
	if err := db.QueryRow(`SELECT enrollment_class, (SELECT count(*) FROM audit_events WHERE target_id=? AND action='node.credential_recovery.approve'),
		(SELECT count(*) FROM audit_events WHERE target_id=? AND action='node.credential_recovery.consume' AND actor_kind='node'),
		(SELECT count(*) FROM certificates WHERE node_id=?) FROM nodes WHERE id=?`, node.ID[:], node.ID[:], node.ID[:], node.ID[:]).Scan(&nodeClass, &approvals, &consumed, &certificates); err != nil ||
		!strings.EqualFold(nodeClass, "remembered") || approvals != 2 || consumed != 1 || certificates != 2 {
		t.Fatalf("wrong persisted recovery state: class=%s approvals=%d consumed=%d certificates=%d err=%v", nodeClass, approvals, consumed, certificates, err)
	}
}
