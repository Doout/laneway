package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerservice"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

func TestAdminBearerCredentialFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credential, err := adminBearerCredentialFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.clear()

	// Binding the database-backed identity must not reread a credential that
	// may have changed after startup validation.
	replacement := strings.Repeat("b", 48)
	if err := os.WriteFile(path, []byte(replacement+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	servicePrincipal := identity.ID{1}
	authorize, err := credential.authorizer(servicePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://controller/v1/admin/enrollment-tokens", nil)
	if _, err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("missing credential error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	actor, err := authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	if actor.Kind != adminauth.ActorServicePrincipal || actor.ID == nil || *actor.ID != servicePrincipal {
		t.Fatalf("authenticated actor = %+v", actor)
	}
	request.Header.Set("Authorization", "Bearer "+replacement)
	if _, err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestAdminBearerCredentialRejectsWeakAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminBearerCredentialFromFile(weak); err == nil {
		t.Fatal("weak token accepted")
	}
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxAdminTokenFile+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminBearerCredentialFromFile(large); err == nil {
		t.Fatal("oversized token accepted")
	}
}

func TestRunRejectsInvalidAdminTokenBeforeCreatingDatabase(t *testing.T) {
	tests := []struct {
		name  string
		write bool
		value string
	}{
		{name: "missing"},
		{name: "weak", write: true, value: "short"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			database := filepath.Join(directory, "state", "controller.db")
			tokenFile := filepath.Join(directory, "admin.token")
			if test.write {
				if err := os.WriteFile(tokenFile, []byte(test.value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := writeControllerConfigWithAdminToken(t, database, tokenFile)
			if err := run(configPath, "", "", "", "", ""); err == nil {
				t.Fatal("run accepted an invalid administrator token")
			}
			if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid administrator token created controller database: %v", err)
			}
		})
	}
}

func TestControllerTLSConfigVerifiesChainAndIdentity(t *testing.T) {
	now := time.Now().UTC()
	rootMaterial, root, err := pki.NewAuthority("test root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediateMaterial, intermediate, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"test issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	serviceID := identity.ID{2}
	serviceMaterial, _, err := pki.IssueService(intermediate, intermediateMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile, privateKeyFile := writeServicePair(t, directory, "controller", serviceMaterial, intermediate.Raw)
	caPEM := pki.CertificatePEM(root.Raw)
	tlsConfig, authenticated, err := controllerTLSConfig(config.TLS{
		CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
	}, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.NetworkID != networkID || authenticated.SubjectID != serviceID ||
		authenticated.Role != identity.IdentityRoleController || tlsConfig.Certificates[0].Leaf == nil {
		t.Fatalf("authenticated controller=%+v TLS=%+v", authenticated, tlsConfig)
	}

	if _, _, err := controllerTLSConfig(config.TLS{
		CertificateFile: writeServicePairCertificateOnly(t, directory, "missing-intermediate", serviceMaterial),
		PrivateKeyFile:  privateKeyFile,
	}, caPEM); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("missing intermediate error=%v", err)
	}
	otherRootMaterial, otherRoot, err := pki.NewAuthority("other root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil || otherRootMaterial.PrivateKey == nil {
		t.Fatal(err)
	}
	if _, _, err := controllerTLSConfig(config.TLS{
		CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
	}, pki.CertificatePEM(otherRoot.Raw)); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("untrusted controller error=%v", err)
	}
}

func TestControllerTLSConfigRejectsExpiredWrongRoleAndKey(t *testing.T) {
	now := time.Now().UTC()
	rootMaterial, root, err := pki.NewAuthority("test root", now.Add(-4*time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	serviceID := identity.ID{2}
	directory := t.TempDir()
	expired, _, err := pki.IssueService(root, rootMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now.Add(-2*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expiredCertificate, expiredKey := writeServicePair(t, directory, "expired", expired)
	if _, _, err := controllerTLSConfig(config.TLS{CertificateFile: expiredCertificate, PrivateKeyFile: expiredKey},
		pki.CertificatePEM(root.Raw)); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("expired controller error=%v", err)
	}

	relay, _, err := pki.IssueService(root, rootMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleRelay,
	}, []string{"relay.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate, relayKey := writeServicePair(t, directory, "relay", relay)
	if _, _, err := controllerTLSConfig(config.TLS{CertificateFile: relayCertificate, PrivateKeyFile: relayKey},
		pki.CertificatePEM(root.Raw)); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("relay-role controller error=%v", err)
	}

	controllerMaterial, _, err := pki.IssueService(root, rootMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerCertificate := writeServicePairCertificateOnly(t, directory, "mismatched-key", controllerMaterial)
	if _, _, err := controllerTLSConfig(config.TLS{CertificateFile: controllerCertificate, PrivateKeyFile: relayKey},
		pki.CertificatePEM(root.Raw)); err == nil || !strings.Contains(err.Error(), "load controller certificate and key") {
		t.Fatalf("mismatched controller key error=%v", err)
	}
}

func TestConfiguredControllerInitialNetwork(t *testing.T) {
	configured, err := configuredControllerInitialNetwork(config.ControllerInitialNetwork{
		NetworkID: "000102030405060708090a0b0c0d0e0f", Name: "production",
		IPv4Pool: "100.96.0.0/16", IPv6Pool: "fd00:96::/64",
	})
	if err != nil || configured.Name != "production" || configured.IPv4Pool.String() != "100.96.0.0/16" ||
		configured.IPv6Pool.String() != "fd00:96::/64" {
		t.Fatalf("configured initial network=%+v err=%v", configured, err)
	}
	if empty, err := configuredControllerInitialNetwork(config.ControllerInitialNetwork{}); err != nil || !empty.NetworkID.IsZero() {
		t.Fatalf("empty initial network=%+v err=%v", empty, err)
	}
}

func TestVerifyControllerIssuer(t *testing.T) {
	now := time.Now().UTC()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	intermediateMaterial, intermediate, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil || intermediateMaterial.PrivateKey == nil {
		t.Fatal(err)
	}
	if err := verifyControllerIssuer(intermediate, []*x509.Certificate{intermediate, root},
		pki.CertificatePEM(root.Raw), now); err != nil {
		t.Fatalf("valid issuer rejected: %v", err)
	}
	_, otherRoot, err := pki.NewAuthority("other root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyControllerIssuer(intermediate, []*x509.Certificate{intermediate, root},
		pki.CertificatePEM(otherRoot.Raw), now); err == nil || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("untrusted issuer error=%v", err)
	}
	if err := verifyControllerIssuer(intermediate, []*x509.Certificate{intermediate},
		pki.CertificatePEM(root.Raw), now); err == nil || !strings.Contains(err.Error(), "not anchored") {
		t.Fatalf("incomplete issuer chain error=%v", err)
	}
	if err := verifyControllerIssuer(intermediate, []*x509.Certificate{intermediate, root},
		pki.CertificatePEM(root.Raw), intermediate.NotAfter.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "verify controller issuing authority") {
		t.Fatalf("expired issuer error=%v", err)
	}
	if err := verifyControllerIssuer(root, []*x509.Certificate{root}, pki.CertificatePEM(root.Raw), now); err != nil {
		t.Fatalf("direct-root issuer rejected: %v", err)
	}
}

func TestRunRejectsInitialNetworkCertificateMismatchBeforeCreatingDatabase(t *testing.T) {
	now := time.Now().UTC()
	directory := t.TempDir()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificateNetwork := identity.NetworkID{1}
	configuredNetwork := identity.NetworkID{9}
	controllerMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: certificateNetwork, ServiceID: identity.ID{2}, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	paths := writeControllerRunPKI(t, directory, root, issuer, issuerMaterial, controllerMaterial)
	database := filepath.Join(directory, "state", "controller.db")
	configPath := writeRunnableControllerConfig(t, directory, database, configuredNetwork, paths)
	if err := run(configPath, "", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "does not match the verified controller certificate") {
		t.Fatalf("initial-network/certificate mismatch error=%v", err)
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity mismatch created database: %v", err)
	}
}

func TestRunRejectsLegacyBootstrapCertificateMismatchBeforeMigratingV9Database(t *testing.T) {
	now := time.Now().UTC()
	directory := t.TempDir()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificateNetwork := identity.NetworkID{1}
	bootstrapNetwork := identity.NetworkID{9}
	controllerMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: certificateNetwork, ServiceID: identity.ID{2}, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	paths := writeControllerRunPKI(t, directory, root, issuer, issuerMaterial, controllerMaterial)
	database := filepath.Join(directory, "controller-v9.db")
	createDowngradedV9Database(t, database)
	before := mustFileDigest(t, database)
	configPath := writeRunnableLegacyBootstrapConfig(t, directory, database, bootstrapNetwork, paths)
	if err := run(configPath, "", "", "", "", ""); err == nil ||
		!strings.Contains(err.Error(), "bootstrap network does not match the verified controller certificate") {
		t.Fatalf("bootstrap/certificate mismatch error=%v", err)
	}
	if after := mustFileDigest(t, database); after != before {
		t.Fatalf("bootstrap identity mismatch mutated v9 database: before=%x after=%x", before, after)
	}
	db, err := sql.Open("sqlite", "file:"+database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version, v10Tables int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema
		WHERE type='table' AND name='controller_identity_state'`).Scan(&v10Tables); err != nil {
		t.Fatal(err)
	}
	if version != 9 || v10Tables != 0 {
		t.Fatalf("bootstrap identity mismatch database version=%d v10 tables=%d", version, v10Tables)
	}
}

func TestRunRejectsInvalidIssuerBeforeMigratingV9Database(t *testing.T) {
	for _, test := range []struct {
		name    string
		expired bool
	}{
		{name: "untrusted"},
		{name: "expired", expired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			directory := t.TempDir()
			trustedMaterial, trustedRoot, err := pki.NewAuthority("trusted root", now.Add(-4*time.Hour), 96*time.Hour)
			if err != nil || trustedMaterial.PrivateKey == nil {
				t.Fatal(err)
			}
			issuerRootMaterial, issuerRoot := trustedMaterial, trustedRoot
			if !test.expired {
				issuerRootMaterial, issuerRoot, err = pki.NewAuthority("untrusted root", now.Add(-4*time.Hour), 96*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
			}
			issuerAt, issuerValidity := now.Add(-time.Hour), 24*time.Hour
			if test.expired {
				issuerAt, issuerValidity = now.Add(-2*time.Hour), time.Hour
			}
			issuerMaterial, issuer, err := pki.IssueIntermediate(issuerRoot, issuerRootMaterial.PrivateKey,
				"issuer", issuerAt, issuerValidity)
			if err != nil {
				t.Fatal(err)
			}
			networkID := identity.NetworkID{1}
			leafAt, leafValidity := now, time.Hour
			if test.expired {
				leafAt, leafValidity = now.Add(-90*time.Minute), 20*time.Minute
			}
			controllerMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
				NetworkID: networkID, ServiceID: identity.ID{2}, Role: pki.RoleController,
			}, []string{"controller.example"}, nil, leafAt, leafValidity)
			if err != nil {
				t.Fatal(err)
			}
			paths := writeControllerRunPKI(t, directory, trustedRoot, issuer, issuerMaterial, controllerMaterial, issuerRoot)
			database := filepath.Join(directory, "controller-v9.db")
			createDowngradedV9Database(t, database)
			before := mustFileDigest(t, database)
			configPath := writeRunnableControllerConfig(t, directory, database, networkID, paths)
			if err := run(configPath, "", "", "", "", ""); err == nil {
				t.Fatal("invalid controller issuer reached database migration")
			}
			if after := mustFileDigest(t, database); after != before {
				t.Fatalf("invalid issuer mutated v9 database: before=%x after=%x", before, after)
			}
			db, err := sql.Open("sqlite", "file:"+database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, v10Tables int
			if err := db.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema
				WHERE type='table' AND name='controller_identity_state'`).Scan(&v10Tables); err != nil {
				t.Fatal(err)
			}
			if version != 9 || v10Tables != 0 {
				t.Fatalf("invalid issuer database version=%d v10 tables=%d", version, v10Tables)
			}
		})
	}
}

func writeServicePair(t *testing.T, directory, name string, material pki.Material, chain ...[]byte) (string, string) {
	t.Helper()
	certificateFile := writeServicePairCertificateOnly(t, directory, name, material, chain...)
	privateKey, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyFile := filepath.Join(directory, name+".key")
	if err := os.WriteFile(privateKeyFile, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, privateKeyFile
}

func writeServicePairCertificateOnly(t *testing.T, directory, name string, material pki.Material, chain ...[]byte) string {
	t.Helper()
	contents := pki.CertificatePEM(material.CertificateDER)
	for _, certificate := range chain {
		contents = append(contents, pki.CertificatePEM(certificate)...)
	}
	certificateFile := filepath.Join(directory, name+".crt")
	if err := os.WriteFile(certificateFile, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile
}

type controllerRunPKIPaths struct {
	rootCertificate   string
	issuerCertificate string
	issuerPrivateKey  string
	serverCertificate string
	serverPrivateKey  string
	adminToken        string
}

func writeControllerRunPKI(t *testing.T, directory string, trustedRoot, issuer *x509.Certificate,
	issuerMaterial, controllerMaterial pki.Material, issuerAnchor ...*x509.Certificate) controllerRunPKIPaths {
	t.Helper()
	anchor := trustedRoot
	if len(issuerAnchor) == 1 {
		anchor = issuerAnchor[0]
	} else if len(issuerAnchor) > 1 {
		t.Fatal("at most one issuer anchor is supported")
	}
	paths := controllerRunPKIPaths{
		rootCertificate:   filepath.Join(directory, "ca.crt"),
		issuerCertificate: filepath.Join(directory, "issuer.crt"),
		issuerPrivateKey:  filepath.Join(directory, "issuer.key"),
		adminToken:        filepath.Join(directory, "admin.token"),
	}
	if err := os.WriteFile(paths.rootCertificate, pki.CertificatePEM(trustedRoot.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	issuerPEM := append(pki.CertificatePEM(issuer.Raw), pki.CertificatePEM(anchor.Raw)...)
	if err := os.WriteFile(paths.issuerCertificate, issuerPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	issuerKey, err := pki.PrivateKeyPEM(issuerMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.issuerPrivateKey, issuerKey, 0o600); err != nil {
		t.Fatal(err)
	}
	paths.serverCertificate, paths.serverPrivateKey = writeServicePair(t, directory, "controller", controllerMaterial, issuer.Raw)
	if err := os.WriteFile(paths.adminToken, []byte(strings.Repeat("a", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths
}

func writeRunnableControllerConfig(t *testing.T, directory, database string, networkID identity.NetworkID,
	paths controllerRunPKIPaths) string {
	t.Helper()
	path := filepath.Join(directory, "controller.toml")
	contents := fmt.Sprintf(`mode = "controller"
state_dir = %q
socket_path = %q

[tls]
certificate = %q
private_key = %q
ca = %q

[controller]
listen = "127.0.0.1:0"
quic_listen = "127.0.0.1:0"
database = %q
ca_private_key = %q
issuer_certificate = %q
admin_token_file = %q
leaf_validity = "1h"

[controller.initial_network]
network_id = %q
name = "production"
ipv4_pool = "100.96.0.0/16"
`, filepath.Join(directory, "state"), filepath.Join(directory, "controller.sock"),
		paths.serverCertificate, paths.serverPrivateKey, paths.rootCertificate, database,
		paths.issuerPrivateKey, paths.issuerCertificate, paths.adminToken, networkID.String())
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRunnableLegacyBootstrapConfig(t *testing.T, directory, database string, networkID identity.NetworkID,
	paths controllerRunPKIPaths) string {
	t.Helper()
	path := filepath.Join(directory, "controller.toml")
	contents := fmt.Sprintf(`mode = "controller"
state_dir = %q
socket_path = %q

[tls]
certificate = %q
private_key = %q
ca = %q

[controller]
listen = "127.0.0.1:0"
quic_listen = "127.0.0.1:0"
database = %q
ca_private_key = %q
issuer_certificate = %q
admin_token_file = %q
leaf_validity = "1h"

[bootstrap]
network_id = %q
controller_endpoint = "https://controller.example:8443"
controller_quic_endpoint = "controller.example:8444"
controller_server_name = "controller.example"
`, filepath.Join(directory, "state"), filepath.Join(directory, "controller.sock"),
		paths.serverCertificate, paths.serverPrivateKey, paths.rootCertificate, database,
		paths.issuerPrivateKey, paths.issuerCertificate, paths.adminToken, networkID.String())
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func createDowngradedV9Database(t *testing.T, path string) {
	t.Helper()
	store, err := controller.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TRIGGER controller_identity_state_immutable;
		DROP TRIGGER controller_identity_state_undeletable;
		DROP TABLE controller_identity_state;
		DELETE FROM schema_versions WHERE version=10;
		VACUUM`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustFileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(contents)
}

func TestAddConsoleCertificate(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile, privateKeyFile := writeConsoleCertificate(t, privateKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	base := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}}
	config := base.Clone()
	if err := addConsoleCertificate(config, certificateFile, privateKeyFile, "controller.example"); err != nil {
		t.Fatal(err)
	}
	if len(base.Certificates) != 1 {
		t.Fatalf("base controller certificate count = %d, want 1", len(base.Certificates))
	}
	if len(config.Certificates) != 2 || config.Certificates[1].Leaf == nil {
		t.Fatalf("console certificate count = %d, leaf = %v", len(config.Certificates), config.Certificates[1].Leaf)
	}
	if got := config.Certificates[1].Leaf.PublicKeyAlgorithm; got != x509.ECDSA {
		t.Fatalf("console public key algorithm = %s, want ECDSA", got)
	}
}

func TestAddConsoleCertificateRejectsEd25519AndClientOnly(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Certificate, ed25519PrivateKey := writeConsoleCertificate(t, ed25519Key, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{{1}}}}}
	if err := addConsoleCertificate(config, ed25519Certificate, ed25519PrivateKey, "controller.example"); err == nil || !strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("Ed25519 console certificate error = %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, clientPrivateKey := writeConsoleCertificate(t, ecdsaKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := addConsoleCertificate(config, clientCertificate, clientPrivateKey, "controller.example"); err == nil || !strings.Contains(err.Error(), "server authentication") {
		t.Fatalf("client-only console certificate error = %v", err)
	}
	if err := addConsoleCertificate(config, clientCertificate, clientPrivateKey, "wrong.example"); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("wrong-hostname console certificate error = %v", err)
	}
}

func TestConsoleCertificateSelectionBySignatureScheme(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed25519CertificateFile, ed25519PrivateKeyFile := writeConsoleCertificate(t, ed25519Key, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	ed25519Certificate, err := tls.LoadX509KeyPair(ed25519CertificateFile, ed25519PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaCertificateFile, ecdsaPrivateKeyFile := writeConsoleCertificate(t, ecdsaKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config := &tls.Config{Certificates: []tls.Certificate{ed25519Certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if err := addConsoleCertificate(config, ecdsaCertificateFile, ecdsaPrivateKeyFile, "controller.example"); err != nil {
		t.Fatal(err)
	}

	ecdsaOnly := &tls.ClientHelloInfo{
		ServerName:        "controller.example",
		SupportedVersions: []uint16{tls.VersionTLS13},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
	}
	if err := ecdsaOnly.SupportsCertificate(&config.Certificates[0]); err == nil {
		t.Fatal("ECDSA-only ClientHello accepted the Ed25519 controller certificate")
	}
	if err := ecdsaOnly.SupportsCertificate(&config.Certificates[1]); err != nil {
		t.Fatalf("ECDSA-only ClientHello rejected the console certificate: %v", err)
	}

	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	serverTLS := tls.Server(serverConnection, config)
	clientTLS := tls.Client(clientConnection, &tls.Config{
		ServerName: "controller.example", MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true, // The test asserts selection, not trust.
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := clientTLS.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm; got != x509.Ed25519 {
		t.Fatalf("ordinary Go client received %s certificate, want Ed25519 controller identity", got)
	}
}

func writeConsoleCertificate(t *testing.T, privateKey crypto.Signer, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "controller.example"},
		DNSNames:              []string{"controller.example"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "console.crt")
	privateKeyFile := filepath.Join(directory, "console.key")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, privateKeyFile
}

func TestMaintenanceBackupAndFreshRestore(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.db")
	store, err := controller.Open(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(directory, "backup.db")
	if err := runBackup(writeControllerConfig(t, source), backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(directory, "restored.db")
	err = runRestore(writeControllerConfig(t, restored), backup)
	if runtime.GOOS != "linux" {
		if err == nil || !strings.Contains(err.Error(), "restore requires a stopped controller: controller lifecycle locking is not supported on this platform") {
			t.Fatalf("runRestore error = %v, want lifecycle lock refusal", err)
		}
		if _, err := os.Stat(restored); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restore refusal created or opened database: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := controller.Open(context.Background(), restored)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if version, err := reopened.SchemaVersion(context.Background()); err != nil || version == 0 {
		t.Fatalf("restored schema version = %d, %v", version, err)
	}
}

func TestMaintenanceBackupRefusesMissingSource(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.db")
	destination := filepath.Join(directory, "backup.db")
	if err := runBackup(writeControllerConfig(t, missing), destination); err == nil {
		t.Fatal("runBackup accepted a missing source database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created missing source database: %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created destination after source failure: %v", err)
	}
}

func TestMaintenanceRestoreRefusesActiveController(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("lifecycle lock is Linux-specific")
	}
	directory := t.TempDir()
	database := filepath.Join(directory, "controller.db")
	lock, err := acquireControllerDatabaseLock(database)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	err = runRestore(writeControllerConfig(t, database), filepath.Join(directory, "unused-backup.db"))
	if err == nil || !strings.Contains(err.Error(), "requires a stopped controller") {
		t.Fatalf("runRestore error = %v, want active-controller refusal", err)
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active-controller refusal created database: %v", err)
	}
}

func writeControllerConfig(t *testing.T, database string) string {
	return writeControllerConfigWithAdminToken(t, database, "unused-token")
}

func writeControllerConfigWithAdminToken(t *testing.T, database, adminTokenFile string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.toml")
	contents := fmt.Sprintf(`mode = "controller"
state_dir = %q
socket_path = %q

[tls]
certificate = "unused.crt"
private_key = "unused.key"
ca = "unused-ca.crt"

[controller]
listen = ":8443"
quic_listen = ":8443"
database = %q
ca_private_key = "unused-ca.key"
admin_token_file = %q
leaf_validity = "720h"
`, filepath.Dir(database), filepath.Join(filepath.Dir(database), "controller.sock"), database, adminTokenFile)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
