package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/wireguard"
)

func TestControllerCommandValidation(t *testing.T) {
	validNetwork := "000102030405060708090a0b0c0d0e0f"
	validObject := "101112131415161718191a1b1c1d1e1f"
	for name, args := range map[string][]string{
		"missing group":                 nil,
		"unknown group":                 {"wat"},
		"network missing operation":     {"network"},
		"network create missing values": {"network", "create"},
		"network noncanonical pool":     {"network", "create", "--name", "n", "--ipv4-pool", "10.0.0.1/24"},
		"network list bad ID":           {"network", "list", "--network-id", "bad"},
		"token bad expiry":              {"enrollment-token", "issue", "--network-id", validNetwork, "--label", "x", "--expires-in", "0s"},
		"token bad class":               {"enrollment-token", "issue", "--network-id", validNetwork, "--label", "x", "--class", "root"},
		"durable token with lease":      {"enrollment-token", "issue", "--network-id", validNetwork, "--label", "x", "--session-lifetime", "1h"},
		"route bad kind":                {"route", "advertise", "--prefix", "192.0.2.0/24", "--kind", "overlay"},
		"route bad ID":                  {"route", "withdraw", "--route-id", "bad"},
		"route bad limit":               {"route", "list", "--network-id", validNetwork, "--limit", "0"},
		"ACL missing selector":          {"acl", "add", "--network-id", validNetwork, "--action", "deny"},
		"ACL two selectors":             {"acl", "add", "--network-id", validNetwork, "--action", "deny", "--selector", "{}", "--selector-file", "x"},
		"ACL bad action":                {"acl", "add", "--network-id", validNetwork, "--action", "log", "--selector", "{}"},
		"ACL bad delete ID":             {"acl", "delete", "--rule-id", "bad"},
		"node missing reason":           {"node", "revoke", "--node-id", validObject},
		"certificate bad serial":        {"certificate", "revoke", "--network-id", validNetwork, "--serial", "ABC", "--reason", "x"},
		"relay missing operation":       {"relay"},
		"relay register missing values": {"relay", "register", "--network-id", validNetwork, "--service-id", validObject},
		"relay disable bad ID":          {"relay", "disable", "--relay-id", "bad"},
		"audit bad limit":               {"audit", "--network-id", validNetwork, "--limit", "1001"},
		"unexpected argument":           {"audit", "extra", "--network-id", validNetwork},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runController(args); err == nil {
				t.Fatal("invalid command accepted")
			}
		})
	}
}

func TestRouteAdvertiseAcceptsPositionalPrefix(t *testing.T) {
	for _, args := range [][]string{
		{"advertise", "192.168.50.0/24"},
		{"advertise", "192.168.50.0/24", "--mode", "routed"},
		{"advertise", "--mode", "routed", "192.168.50.0/24"},
	} {
		err := runControllerRoute(args)
		if err == nil || !strings.Contains(err.Error(), "--controller is required") {
			t.Fatalf("%v did not reach connection validation: %v", args, err)
		}
	}
	if err := runControllerRoute([]string{"advertise", "192.168.50.0/24", "--prefix", "192.168.50.0/24"}); err == nil || !strings.Contains(err.Error(), "either positional") {
		t.Fatalf("positional/flag ambiguity accepted: %v", err)
	}
}

func TestReadBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selector.json")
	if err := os.WriteFile(path, []byte(`{"ip_protocol":"IP_PROTOCOL_ANY"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := readBounded(path, 100); err != nil || len(contents) == 0 {
		t.Fatalf("readBounded = %q, %v", contents, err)
	}
	if _, err := readBounded(path, 2); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestRenewUsesCSRAndWritesDistinctCredentialPair(t *testing.T) {
	now := time.Now().UTC()
	caMaterial, ca, err := pki.NewAuthority("test CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	networkID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	nodeID, _ := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	serviceID, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	node := identity.NodeIdentity{NetworkID: networkID, NodeID: nodeID}
	nodeMaterial, _, err := pki.IssueNode(ca, caMaterial.PrivateKey, node, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleController,
	}, []string{"controller.test"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := pki.PrivateKeyPEM(controllerMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(pki.CertificatePEM(controllerMaterial.CertificateDER), controllerKey)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/renew" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("renewal did not authenticate with the current node credential")
		}
		body, _ := io.ReadAll(r.Body)
		request := new(lanewayv1.RenewalRequest)
		if err := proto.Unmarshal(body, request); err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(string(body), "PRIVATE KEY") {
			t.Error("private key appeared in renewal request")
		}
		csr, err := x509.ParseCertificateRequest(request.GetPkcs10CsrDer())
		if err != nil || csr.CheckSignature() != nil {
			t.Errorf("invalid CSR: %v", err)
			return
		}
		uri, _ := node.URI()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(999), Subject: pkix.Name{CommonName: "renewed"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri},
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, csr.PublicKey, caMaterial.PrivateKey)
		if err != nil {
			t.Error(err)
			return
		}
		payload, _ := proto.Marshal(&lanewayv1.RenewalResponse{CertificateChain: &lanewayv1.CertificateChain{CertificatesDer: [][]byte{der, caMaterial.CertificateDER}}, WireguardPublicKey: request.GetWireguardPublicKey()})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(payload)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	outCert := filepath.Join(dir, "node.next.crt")
	outKey := filepath.Join(dir, "node.next.key")
	outWireGuardKey := filepath.Join(dir, "wireguard.next.key")
	currentKey, _ := pki.PrivateKeyPEM(nodeMaterial.PrivateKey)
	if err := os.WriteFile(caPath, pki.CertificatePEM(caMaterial.CertificateDER), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, append(pki.CertificatePEM(nodeMaterial.CertificateDER), pki.CertificatePEM(caMaterial.CertificateDER)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, currentKey, 0o600); err != nil {
		t.Fatal(err)
	}
	oldCert, _ := os.ReadFile(certPath)
	oldKey, _ := os.ReadFile(keyPath)
	if err := runRenew([]string{"--controller", server.URL, "--allow-legacy-controller-https", "--server-name", "controller.test", "--controller-network-id", networkID.String(), "--controller-service-id", serviceID.String(), "--ca", caPath, "--cert", certPath, "--key", keyPath, "--out-cert", outCert, "--out-key", outKey, "--out-wireguard-key", outWireGuardKey}); err != nil {
		t.Fatal(err)
	}
	if current, _ := os.ReadFile(certPath); string(current) != string(oldCert) {
		t.Fatal("active certificate was modified")
	}
	if current, _ := os.ReadFile(keyPath); string(current) != string(oldKey) {
		t.Fatal("active key was modified")
	}
	if _, err := tls.LoadX509KeyPair(outCert, outKey); err != nil {
		t.Fatalf("new credential pair: %v", err)
	}
	if info, err := os.Stat(outKey); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("new key permissions: %v, %v", info, err)
	}
	if raw, err := os.ReadFile(outWireGuardKey); err != nil || len(raw) != wireguard.KeySize {
		t.Fatalf("new WireGuard key: length=%d error=%v", len(raw), err)
	}
	wrongServiceID, _ := identity.NewID()
	if err := runRenew([]string{"--controller", server.URL, "--allow-legacy-controller-https", "--server-name", "controller.test", "--controller-network-id", networkID.String(), "--controller-service-id", wrongServiceID.String(), "--ca", caPath, "--cert", certPath, "--key", keyPath, "--out-cert", outCert + ".wrong", "--out-key", outKey + ".wrong", "--out-wireguard-key", outWireGuardKey + ".wrong"}); err == nil {
		t.Fatal("renewal accepted an unexpected controller service identity")
	}
	if err := runRenew([]string{"--controller", server.URL, "--ca", caPath, "--cert", certPath, "--key", keyPath, "--out-cert", certPath, "--out-key", outKey + ".other"}); err == nil {
		t.Fatal("renewal accepted active certificate as output")
	}
}

func TestFirstCertificatePEMRejectsNonCertificate(t *testing.T) {
	if _, err := firstCertificatePEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})); err == nil {
		t.Fatal("private key accepted as certificate")
	}
}
