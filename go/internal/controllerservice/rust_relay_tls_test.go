//go:build rustinterop

package controllerservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/agent"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
)

func TestRustControllerRelayTLS(t *testing.T) {
	relayBinary := os.Getenv("LANEWAY_RUST_RELAY")
	if relayBinary == "" {
		t.Skip("LANEWAY_RUST_RELAY is required")
	}
	f := newFixture(t, 0, nil)
	const relayName = "relay.renewal.test"
	ca, caKey := f.service.ca, f.service.caKey
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyPEM := func(material pki.Material) []byte {
		t.Helper()
		data, err := pki.PrivateKeyPEM(material.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	issue := func(role pki.ServiceRole, id identity.ID, start time.Time, duration time.Duration) (pki.Material, *x509.Certificate) {
		t.Helper()
		m, c, err := pki.IssueService(ca, caKey, pki.ServiceIdentity{
			NetworkID: f.network.ID, ServiceID: id, Role: role,
		}, []string{relayName}, []net.IP{net.ParseIP("127.0.0.1")}, start, duration)
		if err != nil {
			t.Fatal(err)
		}
		return m, c
	}
	controllerID, relayID := identity.ID{1}, identity.ID{2}
	issuer, _ := issue(pki.RoleController, controllerID, time.Now(), time.Hour)
	crt := write("controller.crt", pki.CertificatePEM(issuer.CertificateDER))
	key := write("controller.key", keyPEM(issuer))
	root := write("ca.crt", pki.CertificatePEM(ca.Raw))
	issuerKey := write("ca.key", keyPEM(pki.Material{PrivateKey: caKey}))
	if _, _, err := f.store.RegisterRelay(t.Context(), f.network.ID, relayID, nil, "relay", relayName+":443"); err != nil {
		t.Fatal(err)
	}
	token, err := f.store.IssueEnrollmentTokenWithOptions(t.Context(), f.network.ID, "node", time.Now().Add(time.Hour),
		controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable})
	if err != nil {
		t.Fatal(err)
	}
	var nodeTLS tls.Certificate
	node, err := f.store.EnrollNodeWithCertificate(t.Context(), token.Secret, "node", 0,
		func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
			m, leaf, err := pki.IssueNode(ca, caKey, identity.NodeIdentity{NetworkID: f.network.ID, NodeID: node.ID},
				time.Now(), time.Hour)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			nodeTLS = tls.Certificate{Certificate: [][]byte{m.CertificateDER}, PrivateKey: m.PrivateKey}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw,
				NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	base, endpoint, stopController := startControllerTLSLab(t, f.dbPath, crt, key,
		"--node-issuer", root, issuerKey, "86400", "--node-client-ca", root, "--node-quic")
	defer stopController()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	checkDenied := func(want int, certs ...tls.Certificate) {
		t.Helper()
		config := clientTLS.Clone()
		config.Certificates = certs
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
			TLSClientConfig: config, DisableKeepAlives: true,
		}}
		req, err := http.NewRequestWithContext(t.Context(), "POST", base+"/v1/relay/renew", bytes.NewReader(nil))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("relay renewal returned %d, want %d", resp.StatusCode, want)
		}
	}
	unknown, _ := issue(pki.RoleRelay, identity.ID{3}, time.Now().Add(-time.Minute), 90*time.Second)
	checkDenied(http.StatusUnauthorized)
	checkDenied(http.StatusUnauthorized, nodeTLS)
	checkDenied(http.StatusForbidden, tls.Certificate{Certificate: [][]byte{unknown.CertificateDER}, PrivateKey: unknown.PrivateKey})

	// Go backdates these service certificates one minute. A 39-second
	// lifetime from now means the two-thirds threshold is six seconds away.
	original, leaf := issue(pki.RoleRelay, relayID, time.Now(), 39*time.Second)
	seedCert, seedKey := pki.CertificatePEM(original.CertificateDER), keyPEM(original)
	relayCert, relayKey := write("relay.crt", seedCert), write("relay.key", seedKey)
	state := filepath.Join(dir, "renewal")
	udp := unusedLocalAddr(t)
	cfg := fmt.Sprintf(`mode = "relay"
[tls]
certificate = %q
private_key = %q
ca = %q
renewal_dir = %q
[relay]
listen = %q
[tcp_fallback]
listen = "127.0.0.1:0"
[controller]
endpoint = %q
quic_endpoint = %q
network_id = %q
service_id = %q
poll_interval = "250ms"
`, relayCert, relayKey, root, state, udp, base, endpoint, f.network.ID.String(), controllerID.String())
	cfgPath := write("relay.toml", []byte(cfg))
	tcp, stopRelay := startRustPublicRelay(t, relayBinary, cfgPath)
	defer stopRelay()
	nodeTLSConfig := &tls.Config{
		RootCAs: roots, ServerName: relayName, MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{nodeTLS},
	}
	dialTCP := func(address string) *tcpfallback.Session {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		session, err := tcpfallback.Dial(ctx, address, nodeTLSConfig, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	register := func(session *tcpfallback.Session) {
		t.Helper()
		startRelayTLSNodeSession(t, session, identity.NodeIdentity{NetworkID: f.network.ID, NodeID: node.Node.ID})
	}
	old := dialTCP(tcp)
	if !bytes.Equal(old.PeerCertificateSerial(), leaf.SerialNumber.Bytes()) {
		t.Fatal("TCP listener did not start with the seed certificate")
	}
	register(old)
	quicConfig := nodeTLSConfig.Clone()
	quicConfig.NextProtos = []string{"laneway-relay/1"}
	quicPeer := func() *x509.Certificate {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, udp, quicConfig, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseWithError(0, "probe complete")
		return conn.ConnectionState().TLS.PeerCertificates[0]
	}
	if quicPeer().SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("QUIC listener did not start with the seed certificate")
	}
	var renewed *x509.Certificate
	deadline := time.Now().Add(15 * time.Second)
	for {
		candidate := quicPeer()
		if candidate.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			renewed = candidate
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("relay did not renew its workload certificate")
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !time.Now().Before(leaf.NotAfter) || !renewed.NotAfter.After(leaf.NotAfter.Add(24*time.Hour)) ||
		!reflect.DeepEqual(renewed.URIs, leaf.URIs) || !reflect.DeepEqual(renewed.DNSNames, leaf.DNSNames) ||
		!reflect.DeepEqual(renewed.IPAddresses, leaf.IPAddresses) ||
		bytes.Equal(renewed.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("relay renewal did not preserve its identity and names while rotating the key before expiry")
	}
	if probe := dialTCP(tcp); !bytes.Equal(probe.PeerCertificateSerial(), renewed.SerialNumber.Bytes()) {
		t.Fatal("TCP did not adopt the replacement certificate")
	} else {
		_ = probe.Close()
	}
	for path, original := range map[string][]byte{relayCert: seedCert, relayKey: seedKey} {
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
			t.Fatal("renewal modified the seed files")
		}
	}
	info, err := os.Stat(filepath.Join(state, "relay-service.pem"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("renewed relay bundle is missing or not private")
	}
	events, err := f.store.AuditEvents(t.Context(), f.network.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	var renewals int
	for _, event := range events {
		if event.Action == "relay.certificate_renew" && event.TargetID != nil && *event.TargetID == relayID {
			renewals++
		}
	}
	if renewals != 1 {
		t.Fatalf("expected one relay renewal audit event, got %d", renewals)
	}
	if wait := time.Until(leaf.NotAfter) + 150*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	// Old relay-to-controller leases cannot outlive the original leaf.
	// The original node session must survive, and a new node must still
	// be able to register using the relay's renewed controller authority.
	select {
	case <-old.Done():
		t.Fatalf("live node TCP session was interrupted: %v", old.Err())
	default:
	}
	_ = old.Close()
	fresh := dialTCP(tcp)
	register(fresh)
	_ = fresh.Close()
	stopRelay()
	tcp, stopRestarted := startRustPublicRelay(t, relayBinary, cfgPath)
	defer stopRestarted()
	restarted := dialTCP(tcp)
	if !bytes.Equal(restarted.PeerCertificateSerial(), renewed.SerialNumber.Bytes()) {
		t.Fatal("relay restart did not recover the cached replacement after seed expiration")
	}
	register(restarted)
}

func startRelayTLSNodeSession(t *testing.T, session *tcpfallback.Session, node identity.NodeIdentity) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	boot, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := agent.NewClientHandshake(node, boot, protocol.Version{Major: protocol.ProtocolMajor1},
		agent.RequiredTCPFallbackCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	send := func(msg proto.Message) {
		t.Helper()
		wire, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := session.WriteControl(ctx, wire); err != nil {
			t.Fatal(err)
		}
	}
	hello, err := handshake.HelloEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	send(hello)
	wire, err := session.ReadControl(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var welcome v1.ControlEnvelope
	if err := proto.Unmarshal(wire, &welcome); err != nil {
		t.Fatal(err)
	}
	params, err := handshake.AcceptWelcome(&welcome, protocol.DefaultMaxControlFrame)
	if err != nil {
		t.Fatal(err)
	}
	send(&v1.RelayEnvelope{
		SchemaVersion: 1, Sequence: 1,
		Body: &v1.RelayEnvelope_Register{Register: &v1.RelayRegister{
			SessionId: params.SessionID[:], RequestedMaxRoutes: 1,
		}},
	})
}
