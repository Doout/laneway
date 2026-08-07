package pki

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
)

func TestIssueNodeAndService(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	material, ca, err := NewAuthority("Laneway test CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	network := identity.NetworkID(mustID(t, "000102030405060708090a0b0c0d0e0f"))
	nodeID := identity.NodeID(mustID(t, "101112131415161718191a1b1c1d1e1f"))
	nodeMaterial, nodeCert, err := IssueNode(ca, material.PrivateKey, identity.NodeIdentity{NetworkID: network, NodeID: nodeID}, now, DefaultLeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.IdentityFromCertificate(nodeCert); err != nil {
		t.Fatalf("extract node identity: %v", err)
	}
	verify(t, ca, nodeCert, x509.ExtKeyUsageClientAuth, "")
	if keyPEM, err := PrivateKeyPEM(nodeMaterial.PrivateKey); err != nil || len(keyPEM) == 0 {
		t.Fatalf("private key PEM: %v", err)
	}
	caKeyPEM, err := PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedCA, parsedKey, err := ParseAuthority(CertificatePEM(material.CertificateDER), caKeyPEM)
	if err != nil || parsedCA.SerialNumber.Cmp(ca.SerialNumber) != 0 || parsedKey == nil {
		t.Fatalf("parse authority: %v", err)
	}

	serviceID := mustID(t, "202122232425262728292a2b2c2d2e2f")
	_, serviceCert, err := IssueService(ca, material.PrivateKey, ServiceIdentity{
		NetworkID: network,
		ServiceID: serviceID,
		Role:      RoleRelay,
	}, []string{"relay.example.test"}, []net.IP{net.ParseIP("127.0.0.1")}, now, DefaultLeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, ca, serviceCert, x509.ExtKeyUsageServerAuth, "relay.example.test")
	verify(t, ca, serviceCert, x509.ExtKeyUsageClientAuth, "")

	_, controllerCert, err := IssueService(ca, material.PrivateKey, ServiceIdentity{
		NetworkID: network,
		ServiceID: mustID(t, "303132333435363738393a3b3c3d3e3f"),
		Role:      RoleController,
	}, []string{"controller.example.test"}, nil, now, DefaultLeafValidity)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, ca, controllerCert, x509.ExtKeyUsageServerAuth, "controller.example.test")
	if _, err := controllerCert.Verify(x509.VerifyOptions{
		Roots:       func() *x509.CertPool { pool := x509.NewCertPool(); pool.AddCert(ca); return pool }(),
		CurrentTime: controllerCert.NotBefore.Add(time.Minute), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Fatal("controller certificate unexpectedly valid for client authentication")
	}
}

func TestRejectInvalidInputs(t *testing.T) {
	now := time.Now()
	if _, _, err := NewAuthority("", now, time.Hour); err == nil {
		t.Fatal("empty CA name accepted")
	}
	material, ca, err := NewAuthority("test", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := IssueNode(ca, material.PrivateKey, identity.NodeIdentity{}, now, time.Minute); err == nil {
		t.Fatal("zero node identity accepted")
	}
	if _, _, err := IssueService(ca, material.PrivateKey, ServiceIdentity{}, nil, nil, now, time.Minute); err == nil {
		t.Fatal("invalid service identity accepted")
	}
}

func TestIntermediateIssuesLeafVerifiedByRootOnlyTrust(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rootMaterial, root, err := NewAuthority("offline root", now, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := IssueIntermediate(root, rootMaterial.PrivateKey, "online issuer", now, 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !issuer.IsCA || !issuer.MaxPathLenZero || issuer.MaxPathLen != 0 {
		t.Fatalf("intermediate constraints = IsCA:%t MaxPathLen:%d Zero:%t", issuer.IsCA, issuer.MaxPathLen, issuer.MaxPathLenZero)
	}
	network := identity.NetworkID(mustID(t, "000102030405060708090a0b0c0d0e0f"))
	nodeID := identity.NodeID(mustID(t, "101112131415161718191a1b1c1d1e1f"))
	_, leaf, err := IssueNode(issuer, issuerMaterial.PrivateKey, identity.NodeIdentity{NetworkID: network, NodeID: nodeID}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now.Add(time.Minute),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify intermediate-issued leaf with root-only trust: %v", err)
	}

	issuerKey, err := PrivateKeyPEM(issuerMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(CertificatePEM(issuer.Raw), CertificatePEM(root.Raw)...)
	parsedIssuer, _, chain, err := ParseAuthorityBundle(bundle, issuerKey)
	if err != nil || parsedIssuer.SerialNumber.Cmp(issuer.SerialNumber) != 0 || len(chain) != 2 {
		t.Fatalf("ParseAuthorityBundle issuer=%v chain=%d err=%v", parsedIssuer, len(chain), err)
	}
	if got := len(IssuerChainDER(chain)); got != 1 {
		t.Fatalf("non-root issuer chain length = %d, want 1", got)
	}
}

func verify(t *testing.T, ca, leaf *x509.Certificate, usage x509.ExtKeyUsage, dnsName string) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: leaf.NotBefore.Add(time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{usage},
		DNSName:     dnsName,
	}); err != nil {
		t.Fatal(err)
	}
}

func mustID(t *testing.T, value string) identity.ID {
	t.Helper()
	id, err := identity.ParseID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
