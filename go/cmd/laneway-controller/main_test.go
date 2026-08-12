package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerservice"
)

func TestBearerAuthorizerFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorize, err := bearerAuthorizerFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://controller/v1/admin/enrollment-tokens", nil)
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("missing credential error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if err := authorize(request); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token+"x")
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestBearerAuthorizerRejectsWeakAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(weak); err == nil {
		t.Fatal("weak token accepted")
	}
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxAdminTokenFile+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(large); err == nil {
		t.Fatal("oversized token accepted")
	}
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
admin_token_file = "unused-token"
leaf_validity = "720h"
`, filepath.Dir(database), filepath.Join(filepath.Dir(database), "controller.sock"), database)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
