package controllerservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"google.golang.org/protobuf/proto"
)

// This exercises the actual TLS verifier instead of fabricating an
// http.Request.VerifiedChains value. In particular, it proves the relay leaf
// emitted by the supported PKI command is valid for controller client auth.
func TestIssuedRelayCertificateAuthenticatesOverRealTLS(t *testing.T) {
	store, err := controller.Open(context.Background(), filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	network, err := store.CreateNetwork(context.Background(), "tls-test", netip.MustParsePrefix("10.66.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caMaterial, ca, err := pki.NewAuthority("Laneway TLS test", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		Store: store, CACertificate: ca, CAKey: caMaterial.PrivateKey,
		LeafValidity: time.Hour, MaxBodyBytes: DefaultMaxBodyBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	controllerID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	controllerMaterial, controllerLeaf, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: controllerID, Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterRelay(context.Background(), network.ID, relayID, nil, "tls-relay", "127.0.0.1:443"); err != nil {
		t.Fatal(err)
	}
	relayMaterial, relayLeaf, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server := httptest.NewUnstartedServer(service.Handler())
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{controllerMaterial.CertificateDER}, PrivateKey: controllerMaterial.PrivateKey, Leaf: controllerLeaf}},
		ClientCAs:    pool, ClientAuth: tls.VerifyClientCertIfGiven,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{relayMaterial.CertificateDER}, PrivateKey: relayMaterial.PrivateKey, Leaf: relayLeaf}},
	}}}
	payload, err := proto.Marshal(&lanewayv1.RelayConfigurationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/v1/relay/configuration", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-protobuf")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("relay mTLS request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("relay mTLS status = %d", response.StatusCode)
	}
}
