//go:build rustinterop

package controllerservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

func TestRustControllerFresh(t *testing.T) {
	const name = "controller.fresh.test"
	dir := t.TempDir()
	now := time.Now()
	root, ca, err := pki.NewAuthority("fresh lab root", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyPEM := func(material pki.Material) []byte {
		t.Helper()
		key, err := pki.PrivateKeyPEM(material.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	newID := func() identity.ID {
		t.Helper()
		id, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	network, service := identity.NetworkID(newID()), newID()
	issue := func(prefix string, id identity.ID) (string, string) {
		t.Helper()
		leaf, _, err := pki.IssueService(ca, root.PrivateKey, pki.ServiceIdentity{
			NetworkID: network, ServiceID: id, Role: pki.RoleController,
		}, []string{name}, nil, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return write(prefix+".crt", pki.CertificatePEM(leaf.CertificateDER)),
			write(prefix+".key", keyPEM(leaf))
	}
	cert, key := issue("controller", service)
	caPath := write("ca.crt", pki.CertificatePEM(ca.Raw))
	issuer := write("issuer.key", keyPEM(root))
	profile := write("bootstrap.json", []byte(`{"enrollment_endpoint":"https://controller.fresh.test","quic_endpoint":"controller.fresh.test:8443","server_name":"controller.fresh.test"}`))
	token := write("root.token", []byte(testRootBearer+"\n"))
	db := filepath.Join(dir, "controller.db")
	binary := os.Getenv("LANEWAY_RUST_CONTROLLER")
	initArgs := []string{"init", db, cert, "fresh", "100.96.0.0/16"}
	if out, err := exec.CommandContext(t.Context(), binary, initArgs...).CombinedOutput(); err != nil {
		t.Fatalf("initialize an empty directory: %v: %s", err, out)
	}
	if out, err := exec.CommandContext(t.Context(), binary, initArgs...).CombinedOutput(); err == nil ||
		!strings.Contains(string(out), "already exists") {
		t.Fatalf("init must refuse an existing database: %v: %s", err, out)
	}
	wrongCert, wrongKey := issue("wrong-service", newID())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "serve", db, "127.0.0.1:0", wrongCert, wrongKey).CombinedOutput(); err == nil ||
		!strings.Contains(string(out), "does not match the database identity") {
		t.Fatalf("TLS identity mismatch did not prevent startup: %v: %s", err, out)
	}
	base, _, stop := startControllerTLSLab(t, db, cert, key, "--root-token-file", token,
		"--node-issuer", caPath, issuer, "3600", "--node-client-ca", caPath, "--node-quic",
		"--bootstrap-profile", profile)
	defer stop()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13},
	}}
	defer client.CloseIdleConnections()
	relayID := newID().String()
	payload := fmt.Sprintf(`{"service_id":"%s","name":"relay","endpoint":"relay.fresh.test:4433"}`, relayID)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		base+"/v1/admin/networks/"+network.String()+"/relays", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testRootBearer)
	request.Header.Set("Content-Type", "application/json")
	registered, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	registered.Body.Close()
	if registered.StatusCode != http.StatusCreated {
		t.Fatalf("register the first relay: %s", registered.Status)
	}
	response, err := client.Get(base + "/.well-known/laneway/bootstrap.json")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var discovery struct {
		NetworkID  string `json:"network_id"`
		Controller struct {
			ServiceID string `json:"service_id"`
		}
		Relays []struct {
			ServiceID string `json:"service_id"`
			Endpoint  string
		}
	}
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || discovery.NetworkID != network.String() ||
		discovery.Controller.ServiceID != service.String() || len(discovery.Relays) != 1 ||
		discovery.Relays[0].ServiceID != relayID || discovery.Relays[0].Endpoint != "relay.fresh.test:4433" {
		t.Fatalf("unexpected fresh discovery: status=%d document=%+v", response.StatusCode, discovery)
	}
}
