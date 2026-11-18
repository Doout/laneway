//go:build rustinterop && unix

package controllerservice

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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

func TestRustControllerTopology(t *testing.T) {
	f := newFixture(t, 0, nil)
	bootstrapAdministratorSessionForHTTPTest(t, f, "topology-owner", "topology fixture owner password")
	ctx := t.Context()
	now := time.Now()
	other, err := f.store.CreateNetwork(ctx, "foreign topology", netip.MustParsePrefix("10.214.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(net identity.NetworkID, name string) (identity.NodeID, tls.Certificate) {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, net, name, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var client tls.Certificate
		node, err := f.store.EnrollNodeWithCertificate(ctx, token.Secret, name, 0, func(_ context.Context, n controller.Node) (controller.CertificateMaterial, error) {
			material, leaf, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: net, NodeID: n.ID}, now, time.Hour)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			client = tls.Certificate{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return node.Node.ID, client
	}
	a, aTLS := enroll(f.network.ID, "topology-a")
	b, bTLS := enroll(f.network.ID, "topology-b")
	empty, emptyTLS := enroll(f.network.ID, "topology-empty")
	foreign, _ := enroll(other.ID, "topology-foreign")
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	migrate := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath)
	if out, err := migrate.CombinedOutput(); err != nil {
		t.Fatalf("migrate fleet: %v %s", err, out)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("INSERT INTO node_topology VALUES(?,unixepoch()-180,unixepoch()-60,'[]')", empty[:]); err != nil {
		t.Fatal(err)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleController},
		nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
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
		data, err := pki.PrivateKeyPEM(key)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ca := write("ca.crt", pki.CertificatePEM(f.service.ca.Raw))
	endpoint, _, stop := startControllerTLSLab(t, f.dbPath, write("controller.crt", pki.CertificatePEM(server.CertificateDER)), write("controller.key", keyPEM(server.PrivateKey)),
		"--root-token-file", write("root.token", []byte(testRootBearer+"\n")), "--node-issuer", ca, write("ca.key", keyPEM(f.service.caKey)), "3600", "--node-client-ca", ca, "--node-quic")
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM node_topology").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle expiration worker did not remove stored report")
		}
		time.Sleep(25 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	client := func(c ...tls.Certificate) *http.Client {
		h := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: c, MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
		t.Cleanup(h.CloseIdleConnections)
		return h
	}
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client())
	put := func(c *http.Client, body string, want int) {
		t.Helper()
		labManagementHTTP(t, c)(endpoint, "PUT", "/v1/topology", body, labCredentials{}, want)
	}
	aClient, bClient := client(aTLS), client(bTLS)
	observed := func(peer identity.NodeID, path string, stamp int64) string {
		return fmt.Sprintf(`{"enabled":true,"peers":[{"peer_id":%q,"path":%q,"last_contact_unix_seconds":%d}]}`, peer.String(), path, stamp)
	}
	base := "/v1/admin/networks/" + f.network.ID.String()
	path := base + "/topology"
	before := send(endpoint, "GET", base, "", root, 200)["configuration_epoch"]
	put(client(), `{"enabled":true,"peers":[]}`, 401)
	put(client(emptyTLS), `{"enabled":true,"peers":null}`, 204)
	put(aClient, observed(foreign, "relay", now.Unix()), 404)
	put(aClient, observed(a, "relay", now.Unix()), 400)
	put(aClient, observed(b, "relay", now.Add(-120*time.Second).Unix()), 400)
	put(aClient, observed(b, "relay", now.Add(time.Hour).Unix()), 400)
	put(aClient, observed(b, "configured", now.Unix()), 400)
	put(aClient, `{"enabled":true,"peers":[],"source_node_id":"unexpected"}`, 400)
	put(aClient, `{"enabled":true,"peers":[]}`+strings.Repeat(" ", 32768), 413)
	aReport := observed(b, "direct", now.Unix())
	put(aClient, aReport, 204)
	put(aClient, aReport, 409)
	put(bClient, observed(a, "relay", now.Unix()), 204)
	bot := func(permission string) labCredentials {
		t.Helper()
		id := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, "topology-"+permission, permission, f.network.ID.String()), root, 201)["principal_id"].(string)
		token := send(endpoint, "POST", "/v1/admin/service-principals/"+id+"/tokens", fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)
		return labCredentials{bearer: token}
	}
	reader := bot("node.read")
	send(endpoint, "GET", path, "", bot("acl.read"), 403)
	send(endpoint, "GET", "/v1/admin/networks/"+other.ID.String()+"/topology", "", reader, 403)
	send(endpoint, "GET", path+"?limit=0", "", reader, 400)
	check := func(query string, n int, limited bool) []any {
		t.Helper()
		result := send(endpoint, "GET", path+query, "", reader, 200)
		edges := result["edges"].([]any)
		if len(edges) != n || result["limited"] != limited || result["retention_seconds"] != float64(120) {
			t.Fatalf("unexpected topology page: %#v", result)
		}
		return edges
	}
	check("?limit=1", 1, true)
	for _, raw := range check("?limit=2", 2, false) {
		edge := raw.(map[string]any)
		wanted := map[string]string{a.String(): b.String(), b.String(): a.String()}
		if edge["network_id"] != f.network.ID.String() || wanted[edge["node_id"].(string)] != edge["peer_id"] ||
			edge["latency_ms"] != nil || edge["expires_at_unix_seconds"].(float64) <= float64(now.Unix()) {
			t.Fatalf("unexpected observed edge: %#v", edge)
		}
	}
	put(bClient, `{"enabled":false,"peers":[]}`, 204)
	check("", 1, false)
	var stale struct {
		Peers []map[string]any `json:"peers"`
	}
	if err := json.Unmarshal([]byte(observed(b, "direct", now.Add(-121*time.Second).Unix())), &stale); err != nil {
		t.Fatal(err)
	}
	peers, _ := json.Marshal(stale.Peers)
	if _, err := db.Exec("UPDATE node_topology SET peers_json=? WHERE node_id=?", string(peers), a[:]); err != nil {
		t.Fatal(err)
	}
	check("", 0, false)
	if after := send(endpoint, "GET", base, "", root, 200)["configuration_epoch"]; after != before {
		t.Fatal("topology reporting changed configuration authority")
	}
	put(bClient, observed(a, "relay", now.Unix()), 204)
	send(endpoint, "POST", "/v1/admin/nodes/"+a.String()+"/revoke", `{"reason":"test topology revocation"}`, root, 200)
	check("", 0, false)
	put(aClient, aReport, 403)
}
