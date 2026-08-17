package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/revocation"
	"github.com/quic-go/quic-go"
)

const testNetworkID = "000102030405060708090a0b0c0d0e0f"

type testPKI struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string
	serverIdentity identity.AuthenticatedIdentity
	clientIdentity identity.AuthenticatedIdentity
	caCertificate  *x509.Certificate
	caPrivateKey   ed25519.PrivateKey
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Laneway test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	serverIdentity := parseTestIdentity(t, "101112131415161718191a1b1c1d1e1f", identity.IdentityRoleRelay)
	clientIdentity := parseTestIdentity(t, "202122232425262728292a2b2c2d2e2f", identity.IdentityRoleNode)
	serverCert, serverKey := issueTestCertificate(t, dir, "server", 2, serverIdentity, caCert, caKey)
	clientCert, clientKey := issueTestCertificate(t, dir, "client", 3, clientIdentity, caCert, caKey)
	return testPKI{
		caFile:         caFile,
		serverCertFile: serverCert,
		serverKeyFile:  serverKey,
		clientCertFile: clientCert,
		clientKeyFile:  clientKey,
		serverIdentity: serverIdentity,
		clientIdentity: clientIdentity,
		caCertificate:  caCert,
		caPrivateKey:   caKey,
	}
}

func parseTestIdentity(t *testing.T, subject string, role identity.IdentityRole) identity.AuthenticatedIdentity {
	t.Helper()
	networkID, err := identity.ParseNetworkID(testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := identity.ParseID(subject)
	if err != nil {
		t.Fatal(err)
	}
	return identity.AuthenticatedIdentity{NetworkID: networkID, Role: role, SubjectID: subjectID}
}

func issueTestCertificate(t *testing.T, dir, name string, serial int64, authenticated identity.AuthenticatedIdentity, ca *x509.Certificate, caKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	return issueTestCertificateForPeriod(t, dir, name, serial, authenticated, ca, caKey,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func issueTestCertificateForPeriod(t *testing.T, dir, name string, serial int64, authenticated identity.AuthenticatedIdentity, ca *x509.Certificate, caKey ed25519.PrivateKey, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURI, err := authenticated.URI()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{identityURI},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, name+".pem")
	keyFile := filepath.Join(dir, name+"-key.pem")
	writePEM(t, certFile, "CERTIFICATE", certDER)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadTestConfigs(t *testing.T, pki testPKI) (*tlsConfigs, error) {
	t.Helper()
	server, err := LoadServerTLSConfig(pki.caFile, pki.serverCertFile, pki.serverKeyFile)
	if err != nil {
		return nil, err
	}
	client, err := LoadClientTLSConfig(pki.caFile, pki.clientCertFile, pki.clientKeyFile)
	if err != nil {
		return nil, err
	}
	return &tlsConfigs{server: server, client: client}, nil
}

type tlsConfigs struct {
	server *tls.Config
	client *tls.Config
}

func TestLoopbackControlDatagramsAndIdentity(t *testing.T) {
	pki := newTestPKI(t)
	configs, err := loadTestConfigs(t, pki)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", configs.server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type acceptResult struct {
		conn *Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	client, err := Dial(ctx, listener.Addr().String(), configs.client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatal(result.err)
	}
	server := result.conn
	defer server.Close()

	if got := client.PeerIdentity(); got != pki.serverIdentity {
		t.Fatalf("client peer identity = %#v, want %#v", got, pki.serverIdentity)
	}
	if got := server.PeerIdentity(); got != pki.clientIdentity {
		t.Fatalf("server peer identity = %#v, want %#v", got, pki.clientIdentity)
	}
	if _, ok := client.PeerNodeIdentity(); ok {
		t.Fatal("relay peer converted to a node identity")
	}
	if node, ok := server.PeerNodeIdentity(); !ok || identity.ID(node.NodeID) != pki.clientIdentity.SubjectID {
		t.Fatalf("server node peer = %#v, %v", node, ok)
	}
	if client.LocalAddr() == nil || client.RemoteAddr() == nil || client.Context() == nil {
		t.Fatal("connection metadata is incomplete")
	}

	if _, err := client.ControlStream().Write([]byte("control request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("control request"))
	if _, err := io.ReadFull(server.ControlStream(), request); err != nil {
		t.Fatal(err)
	}
	if string(request) != "control request" {
		t.Fatalf("control request = %q", request)
	}
	if _, err := server.ControlStream().Write([]byte("control response")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("control response"))
	if _, err := io.ReadFull(client.ControlStream(), response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "control response" {
		t.Fatalf("control response = %q", response)
	}

	if err := client.SendDatagram([]byte("client datagram")); err != nil {
		t.Fatal(err)
	}
	datagram, err := server.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(datagram) != "client datagram" {
		t.Fatalf("server datagram = %q", datagram)
	}
	if err := server.SendDatagram([]byte("server datagram")); err != nil {
		t.Fatal(err)
	}
	datagram, err = client.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(datagram) != "server datagram" {
		t.Fatalf("client datagram = %q", datagram)
	}

	receiveCtx, receiveCancel := context.WithCancel(context.Background())
	receiveCancel()
	if _, err := client.ReceiveDatagram(receiveCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ReceiveDatagram error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("connection context was not canceled by Close")
	}
}

func TestAcceptHonorsContext(t *testing.T) {
	pki := newTestPKI(t)
	configs, err := loadTestConfigs(t, pki)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", configs.server, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := listener.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept error = %v", err)
	}
}

func TestDatagramNegotiationIsRequired(t *testing.T) {
	pki := newTestPKI(t)
	configs, err := loadTestConfigs(t, pki)
	if err != nil {
		t.Fatal(err)
	}
	rawListener, err := quic.ListenAddr("127.0.0.1:0", strictTLSConfig(configs.server), &quic.Config{
		EnableDatagrams:       false,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rawListener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := rawListener.Accept(ctx)
		if acceptErr == nil {
			_ = conn.CloseWithError(0, "test complete")
		}
	}()
	_, err = Dial(ctx, rawListener.Addr().String(), configs.client, nil)
	if !errors.Is(err, ErrDatagramsNotNegotiated) {
		t.Fatalf("Dial error = %v", err)
	}
	cancel()
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("raw server did not shut down")
	}
}

func TestMutualTLSRejectsClientFromUntrustedCA(t *testing.T) {
	trusted := newTestPKI(t)
	untrusted := newTestPKI(t)
	serverTLS, err := LoadServerTLSConfig(trusted.caFile, trusted.serverCertFile, trusted.serverKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Trust the real server CA while presenting a client certificate issued by
	// a different CA. This isolates the server-side half of mutual TLS.
	clientTLS, err := LoadClientTLSConfig(trusted.caFile, untrusted.clientCertFile, untrusted.clientKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	acceptResult := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept(ctx)
		acceptResult <- acceptErr
	}()
	// In TLS 1.3 the client can transiently consider its side of the handshake
	// complete before the server's certificate alert arrives, so the listener's
	// result is authoritative here.
	client, _ := Dial(ctx, listener.Addr().String(), clientTLS, nil)
	if client != nil {
		defer client.Close()
	}
	select {
	case err := <-acceptResult:
		// quic-go silently discards failed handshakes and continues waiting for
		// another connection, so expiration proves that no Conn was accepted.
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Accept error = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after its context deadline")
	}
}

func TestMutualTLSRejectsExpiredClientCertificate(t *testing.T) {
	trusted := newTestPKI(t)
	expiredCert, expiredKey := issueTestCertificateForPeriod(t, t.TempDir(), "expired-client", 9,
		trusted.clientIdentity, trusted.caCertificate, trusted.caPrivateKey,
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	serverTLS, err := LoadServerTLSConfig(trusted.caFile, trusted.serverCertFile, trusted.serverKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := LoadClientTLSConfig(trusted.caFile, expiredCert, expiredKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept(ctx)
		accepted <- acceptErr
	}()
	client, _ := Dial(ctx, listener.Addr().String(), clientTLS, nil)
	if client != nil {
		defer client.Close()
	}
	select {
	case err := <-accepted:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Accept error = %v, want deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired client handshake did not terminate")
	}
}

func TestTLSLoadersRejectInvalidInputs(t *testing.T) {
	pki := newTestPKI(t)
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientTLSConfig(badCA, pki.clientCertFile, pki.clientKeyFile); err == nil || !strings.Contains(err.Error(), "no valid certificates") {
		t.Fatalf("bad CA error = %v", err)
	}
	if _, err := LoadServerTLSConfig(pki.caFile, pki.serverCertFile, pki.clientKeyFile); err == nil {
		t.Fatal("mismatched certificate and key accepted")
	}
	if _, err := LoadClientTLSConfig(filepath.Join(t.TempDir(), "missing"), pki.clientCertFile, pki.clientKeyFile); err == nil {
		t.Fatal("missing CA accepted")
	}
	if _, err := LoadServerTLSConfig(pki.caFile, pki.clientCertFile, pki.clientKeyFile); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("node certificate accepted as local relay: %v", err)
	}
	if _, err := LoadClientTLSConfig(pki.caFile, pki.serverCertFile, pki.serverKeyFile); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("relay certificate accepted as local node: %v", err)
	}
}

func TestTLSCallbacksRejectWrongPeerRole(t *testing.T) {
	pki := newTestPKI(t)
	configs, err := loadTestConfigs(t, pki)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf := readTestCertificate(t, pki.serverCertFile)
	clientLeaf := readTestCertificate(t, pki.clientCertFile)
	if err := configs.client.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientLeaf}}); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("node certificate accepted as relay server: %v", err)
	}
	if err := configs.server.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{serverLeaf}}); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("relay certificate accepted as node client: %v", err)
	}
}

func TestTLSCallbacksRejectRevokedAndUnexpectedServiceCertificates(t *testing.T) {
	pki := newTestPKI(t)
	serverLeaf := readTestCertificate(t, pki.serverCertFile)
	revoked := new(revocation.Set)
	client, err := LoadClientTLSConfigWithRevocations(pki.caFile, pki.clientCertFile, pki.clientKeyFile, revoked)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{serverLeaf}}
	if err := client.VerifyConnection(state); err != nil {
		t.Fatalf("valid relay rejected: %v", err)
	}
	if err := revoked.Replace([][]byte{serverLeaf.SerialNumber.Bytes()}); err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyConnection(state); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked relay error=%v", err)
	}
	if err := revoked.Replace(nil); err != nil {
		t.Fatal(err)
	}
	wrong := pki.serverIdentity
	wrong.SubjectID[0] ^= 0xff
	if err := RequirePeerService(client, wrong); err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyConnection(state); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected relay service error=%v", err)
	}
}

func readTestCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("certificate PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestConfigurationValidation(t *testing.T) {
	for _, config := range []*Config{
		{HandshakeIdleTimeout: -time.Second},
		{MaxIdleTimeout: -time.Second},
		{KeepAlivePeriod: -time.Second},
		{MaxIdleTimeout: time.Second, KeepAlivePeriod: time.Second},
	} {
		if _, err := config.quicConfig(); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("config %#v error = %v", config, err)
		}
	}
	config, err := (*Config)(nil).quicConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.EnableDatagrams || config.Allow0RTT || config.MaxIncomingStreams != 1 || config.MaxIncomingUniStreams != -1 {
		t.Fatalf("unsafe default QUIC config: %#v", config)
	}
}
