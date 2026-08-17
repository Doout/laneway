package controllerservice_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/controllerservice"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/wireguard"
)

func TestGoClientAndControllerReliableQUICInterop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store, err := controller.Open(ctx, filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	network, err := store.CreateNetwork(ctx, "quic-test", netip.MustParsePrefix("10.77.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caMaterial, ca, err := pki.NewAuthority("Laneway QUIC test", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerID, _ := identity.NewID()
	controllerMaterial, controllerLeaf, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: controllerID, Role: pki.RoleController,
	}, nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayID, _ := identity.NewID()
	if _, _, err := store.RegisterRelay(ctx, network.ID, relayID, nil, "quic-relay", "127.0.0.1:4433"); err != nil {
		t.Fatal(err)
	}
	relayMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var controllerNow atomic.Int64
	controllerNow.Store(now.Unix())
	service, err := controllerservice.New(controllerservice.Options{
		Store: store, CACertificate: ca, CAKey: caMaterial.PrivateKey,
		LeafValidity: time.Hour, SnapshotValidity: time.Minute,
		Now: func() time.Time { return time.Unix(controllerNow.Load(), 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	server, err := service.ListenQUIC("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{controllerMaterial.CertificateDER}, PrivateKey: controllerMaterial.PrivateKey, Leaf: controllerLeaf}},
		ClientCAs:    pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()

	directory := t.TempDir()
	caFile := filepath.Join(directory, "ca.crt")
	certFile := filepath.Join(directory, "relay.crt")
	keyFile := filepath.Join(directory, "relay.key")
	keyPEM, err := pki.PrivateKeyPEM(relayMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string][]byte{
		caFile: pki.CertificatePEM(ca.Raw), certFile: pki.CertificatePEM(relayMaterial.CertificateDER), keyFile: keyPEM,
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: "https://127.0.0.1:1", QUICEndpoint: server.Addr().String(),
		CAFile: caFile, CertificateFile: certFile, PrivateKeyFile: keyFile,
		ExpectedNetworkID: network.ID, ExpectedServiceID: controllerID, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, unchanged, err := client.RelayConfiguration(ctx, 0)
	if err != nil || unchanged {
		t.Fatalf("initial QUIC configuration: unchanged=%t err=%v", unchanged, err)
	}
	if configuration.GetConfigurationEpoch() == 0 || configuration.GetCertificateHealth() == nil {
		t.Fatal("QUIC snapshot omitted epoch or certificate health")
	}
	lease, unchanged, err := client.RelayConfiguration(ctx, configuration.GetConfigurationEpoch())
	if err != nil || !unchanged || lease.GetValidUntilUnixSeconds() == 0 {
		t.Fatalf("conditional QUIC configuration: unchanged=%t lease=%v err=%v", unchanged, lease, err)
	}
	// A response frame must be followed through its FIN so the single-stream
	// transport credit is returned before the next serialized poll.
	// Exceed quic-go's normal initial stream window several times. Each request
	// and response FIN must be consumed explicitly or this serialized connection
	// will eventually stall while opening a new stream.
	for i := 0; i < 256; i++ {
		if _, unchanged, err := client.RelayConfiguration(ctx, configuration.GetConfigurationEpoch()); err != nil || !unchanged {
			t.Fatalf("persistent QUIC poll %d: unchanged=%t err=%v", i, unchanged, err)
		}
	}

	// Enrollment remains HTTPS-only, but the first issued node credential can
	// renew over the same language-neutral QUIC protocol without sending either
	// old or new private key to the controller.
	token, err := store.IssueEnrollmentToken(ctx, network.ID, "quic-node", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var nodeMaterial pki.Material
	_, err = store.EnrollNodeWithCertificate(ctx, token.Secret, "quic-node", 0, func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
		issued, leaf, issueErr := pki.IssueNode(ca, caMaterial.PrivateKey, identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}, now, time.Hour)
		if issueErr != nil {
			return controller.CertificateMaterial{}, issueErr
		}
		nodeMaterial = issued
		return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeCertFile := filepath.Join(directory, "node.crt")
	nodeKeyFile := filepath.Join(directory, "node.key")
	nodeKeyPEM, _ := pki.PrivateKeyPEM(nodeMaterial.PrivateKey)
	if err := os.WriteFile(nodeCertFile, pki.CertificatePEM(nodeMaterial.CertificateDER), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeKeyFile, nodeKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	nodeClient, err := controllerclient.New(controllerclient.Options{
		Endpoint: "https://127.0.0.1:1", QUICEndpoint: server.Addr().String(),
		CAFile: caFile, CertificateFile: nodeCertFile, PrivateKeyFile: nodeKeyFile,
		ExpectedNetworkID: network.ID, ExpectedServiceID: controllerID, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, replacementKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "quic-node-renewal"}}, replacementKey)
	if err != nil {
		t.Fatal(err)
	}
	_, wireGuardPublicKey, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := nodeClient.Renew(ctx, csr, wireGuardPublicKey.Bytes())
	if err != nil || renewal.GetCertificateChain() == nil || len(renewal.GetCertificateChain().GetCertificatesDer()) == 0 {
		t.Fatalf("node QUIC renewal failed: response=%v err=%v", renewal, err)
	}
	// Keep the same QUIC connection alive past the relay leaf's NotAfter. The
	// server must re-check the certificate on this request, not trust the old
	// TLS handshake indefinitely.
	controllerNow.Store(now.Add(2 * time.Hour).Unix())
	if _, _, err := client.RelayConfiguration(ctx, configuration.GetConfigurationEpoch()); err == nil {
		t.Fatal("persistent QUIC connection accepted an expired client certificate")
	}
	cancel()
	_ = server.Close()
	<-serveDone
}
