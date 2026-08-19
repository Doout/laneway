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
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/controllerservice"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
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
	tlsConfig, authenticated, err := controllerTLSConfigAt(config.TLS{
		CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
	}, caPEM, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.NetworkID != networkID || authenticated.SubjectID != serviceID ||
		authenticated.Role != identity.IdentityRoleController || tlsConfig.Certificates[0].Leaf == nil {
		t.Fatalf("authenticated controller=%+v TLS=%+v", authenticated, tlsConfig)
	}

	missingIntermediate := writeServicePairCertificateOnly(t, directory, "missing-intermediate", serviceMaterial)
	if _, _, err := controllerTLSConfigAt(config.TLS{
		CertificateFile: missingIntermediate, PrivateKeyFile: privateKeyFile,
	}, caPEM, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("missing intermediate error=%v", err)
	}
	_, otherRoot, err := pki.NewAuthority("other root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := controllerTLSConfigAt(config.TLS{
		CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
	}, pki.CertificatePEM(otherRoot.Raw), now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("untrusted controller error=%v", err)
	}
	if _, _, err := controllerTLSConfigAt(config.TLS{
		CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
	}, caPEM, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "verify controller certificate chain") {
		t.Fatalf("expired controller error=%v", err)
	}
	relayMaterial, _, err := pki.IssueService(intermediate, intermediateMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: serviceID, Role: pki.RoleRelay,
	}, []string{"relay.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate, relayKey := writeServicePair(t, directory, "relay", relayMaterial, intermediate.Raw)
	if _, _, err := controllerTLSConfigAt(config.TLS{
		CertificateFile: relayCertificate, PrivateKeyFile: relayKey,
	}, caPEM, now.Add(time.Minute)); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("relay-role controller error=%v", err)
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
	if err := verifyControllerIssuer(root, []*x509.Certificate{root}, pki.CertificatePEM(root.Raw), now); err != nil {
		t.Fatalf("direct-root issuer rejected: %v", err)
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

func TestRunRejectsInitialNetworkCertificateMismatchBeforeCreatingDatabase(t *testing.T) {
	now := time.Now().UTC()
	directory := t.TempDir()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerMaterial, _, err := pki.IssueService(root, rootMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: identity.NetworkID{1}, ServiceID: identity.ID{2}, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate := filepath.Join(directory, "ca.crt")
	rootPrivateKey := filepath.Join(directory, "ca.key")
	if err := os.WriteFile(rootCertificate, pki.CertificatePEM(root.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	rootKeyPEM, err := pki.PrivateKeyPEM(rootMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPrivateKey, rootKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	controllerCertificate, controllerKey := writeServicePair(t, directory, "controller", controllerMaterial)
	adminToken := filepath.Join(directory, "admin.token")
	if err := os.WriteFile(adminToken, []byte(strings.Repeat("a", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "state", "controller.db")
	configPath := filepath.Join(directory, "controller.toml")
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
admin_token_file = %q
leaf_validity = "1h"
[controller.initial_network]
network_id = "09000000000000000000000000000000"
name = "production"
ipv4_pool = "100.96.0.0/16"
`, filepath.Join(directory, "state"), filepath.Join(directory, "controller.sock"),
		controllerCertificate, controllerKey, rootCertificate, database, rootPrivateKey, adminToken)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(configPath, "", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "does not match the verified controller certificate") {
		t.Fatalf("initial-network/certificate mismatch error=%v", err)
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity mismatch created database: %v", err)
	}
	store, err := controller.Open(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TRIGGER controller_identity_state_immutable;
		DROP TRIGGER controller_identity_state_undeletable;
		DROP TABLE controller_identity_state;
		DELETE FROM schema_versions WHERE version=12;
		VACUUM`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run(configPath, "", "", "", "", ""); err == nil || !strings.Contains(err.Error(), "does not match the verified controller certificate") {
		t.Fatalf("existing-v11 initial-network/certificate mismatch error=%v", err)
	}
	raw, err = sql.Open("sqlite", database)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var version, identityTables int
	if err := raw.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='controller_identity_state'`).Scan(&identityTables); err != nil {
		t.Fatal(err)
	}
	if version != 11 || identityTables != 0 {
		t.Fatalf("pre-open mismatch migrated database: version=%d identity tables=%d", version, identityTables)
	}
}

type runPreflightFixture struct {
	directory             string
	database              string
	stateDirectory        string
	controllerCertificate string
	controllerKey         string
	rootCertificate       string
	rootPrivateKey        string
	adminToken            string
	networkID             identity.NetworkID
}

func newRunPreflightFixture(t *testing.T) runPreflightFixture {
	t.Helper()
	now := time.Now().UTC()
	directory := t.TempDir()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	networkID := identity.NetworkID{1}
	controllerMaterial, _, err := pki.IssueService(root, rootMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: identity.ID{2}, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate := filepath.Join(directory, "ca.crt")
	rootPrivateKey := filepath.Join(directory, "ca.key")
	if err := os.WriteFile(rootCertificate, pki.CertificatePEM(root.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	rootKeyPEM, err := pki.PrivateKeyPEM(rootMaterial.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPrivateKey, rootKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	controllerCertificate, controllerKey := writeServicePair(t, directory, "controller", controllerMaterial)
	adminToken := filepath.Join(directory, "admin.token")
	if err := os.WriteFile(adminToken, []byte(strings.Repeat("a", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	return runPreflightFixture{
		directory: directory, database: filepath.Join(stateDirectory, "controller.db"), stateDirectory: stateDirectory,
		controllerCertificate: controllerCertificate, controllerKey: controllerKey,
		rootCertificate: rootCertificate, rootPrivateKey: rootPrivateKey,
		adminToken: adminToken, networkID: networkID,
	}
}

func (fixture runPreflightFixture) writeConfig(t *testing.T, controllerListen, quicListen, bootstrap string) string {
	t.Helper()
	if controllerListen == "" {
		controllerListen = "127.0.0.1:0"
	}
	if quicListen == "" {
		quicListen = "127.0.0.1:0"
	}
	configPath := filepath.Join(fixture.directory, fmt.Sprintf("controller-%d.toml", time.Now().UnixNano()))
	contents := fmt.Sprintf(`mode = "controller"
state_dir = %q
socket_path = %q
[tls]
certificate = %q
private_key = %q
ca = %q
[controller]
listen = %q
quic_listen = %q
database = %q
ca_private_key = %q
admin_token_file = %q
leaf_validity = "1h"
[controller.initial_network]
network_id = %q
name = "production"
ipv4_pool = "100.96.0.0/16"
%s`, fixture.stateDirectory, filepath.Join(fixture.directory, "controller.sock"),
		fixture.controllerCertificate, fixture.controllerKey, fixture.rootCertificate,
		controllerListen, quicListen, fixture.database, fixture.rootPrivateKey, fixture.adminToken,
		fixture.networkID.String(), bootstrap)
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func TestRunPreflightRejectsV11TopologyDriftWithoutMigration(t *testing.T) {
	fixture := newRunPreflightFixture(t)
	store, err := controller.Open(context.Background(), fixture.database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateNetworkDualStackWithID(context.Background(), fixture.networkID, "legacy-production", netip.MustParsePrefix("100.97.0.0/16"), netip.Prefix{}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", fixture.database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DROP TRIGGER controller_identity_state_immutable;
		DROP TRIGGER controller_identity_state_undeletable;
		DROP TABLE controller_identity_state;
		DELETE FROM schema_versions WHERE version=12;
		VACUUM`); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	before := fileDigest(t, fixture.database)
	err = run(fixture.writeConfig(t, "", "", ""), "", "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "existing initial network differs from configuration") {
		t.Fatalf("topology drift error = %v", err)
	}
	after := fileDigest(t, fixture.database)
	if before != after {
		t.Fatal("read-only topology preflight changed the v11 database bytes")
	}
	raw, err = sql.Open("sqlite", fixture.database)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var version, identityTables int
	if err := raw.QueryRow(`SELECT MAX(version) FROM schema_versions`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='controller_identity_state'`).Scan(&identityTables); err != nil {
		t.Fatal(err)
	}
	if version != 11 || identityTables != 0 {
		t.Fatalf("topology preflight migrated database: version=%d identity tables=%d", version, identityTables)
	}
}

func TestRunPreflightFailuresLeaveFreshDatabaseAbsent(t *testing.T) {
	t.Run("missing console certificate", func(t *testing.T) {
		fixture := newRunPreflightFixture(t)
		err := run(fixture.writeConfig(t, "", "", ""), "", "", filepath.Join(fixture.directory, "missing.crt"), filepath.Join(fixture.directory, "missing.key"), "controller.example")
		assertFreshDatabaseAbsent(t, fixture.database, err)
	})
	t.Run("missing console assets", func(t *testing.T) {
		fixture := newRunPreflightFixture(t)
		err := run(fixture.writeConfig(t, "", "", ""), "", filepath.Join(fixture.directory, "missing-console"), "", "", "")
		assertFreshDatabaseAbsent(t, fixture.database, err)
	})
	t.Run("invalid bootstrap certificate", func(t *testing.T) {
		fixture := newRunPreflightFixture(t)
		bootstrap := fmt.Sprintf(`[bootstrap]
listen = "127.0.0.1:0"
certificate = %q
private_key = %q
network_id = %q
controller_endpoint = "https://controller.example:8443"
controller_quic_endpoint = "controller.example:8443"
controller_server_name = "controller.example"
`, filepath.Join(fixture.directory, "missing-bootstrap.crt"), filepath.Join(fixture.directory, "missing-bootstrap.key"), fixture.networkID.String())
		err := run(fixture.writeConfig(t, "", "", bootstrap), "", "", "", "", "")
		assertFreshDatabaseAbsent(t, fixture.database, err)
	})
	t.Run("controller listener collision", func(t *testing.T) {
		fixture := newRunPreflightFixture(t)
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		err = run(fixture.writeConfig(t, occupied.Addr().String(), "", ""), "", "", "", "", "")
		assertFreshDatabaseAbsent(t, fixture.database, err)
	})
}

func assertFreshDatabaseAbsent(t *testing.T, database string, runErr error) {
	t.Helper()
	if runErr == nil {
		t.Fatal("startup preflight unexpectedly succeeded")
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed startup preflight created database: %v (run error: %v)", err, runErr)
	}
}

func fileDigest(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(contents)
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
	if err := runRestore(writeControllerConfig(t, restored), backup); err != nil {
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
