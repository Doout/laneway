//go:build rustinterop

package controllerservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
)

func TestRustControllerServiceTLS(t *testing.T) {
	f := newFixture(t, 0, nil)
	const name = "controller.renewal.test"
	names := []string{"alternate.renewal.test", name}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.RegisterRelay(t.Context(), f.network.ID, relayID, nil, "renewal relay", "relay.renewal.test:443"); err != nil {
		t.Fatal(err)
	}
	inter, ca, err := pki.IssueIntermediate(f.service.ca, f.service.caKey, "lab online service issuer",
		time.Now().Add(-10*time.Minute), 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relay, _, err := pki.IssueService(ca, inter.PrivateKey, pki.ServiceIdentity{
		NetworkID: f.network.ID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(filename string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	keyPEM := func(material pki.Material) []byte {
		t.Helper()
		pem, err := pki.PrivateKeyPEM(material.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem
	}
	caPEM := pki.CertificatePEM(f.service.ca.Raw)
	interPEM := pki.CertificatePEM(inter.CertificateDER)
	issuerChain := write("issuer.crt", append(bytes.Clone(interPEM), caPEM...))
	issuerKey := write("issuer.key", keyPEM(inter))
	trust := write("root.crt", caPEM)
	profile, err := json.Marshal(map[string]string{
		"enrollment_endpoint": "https://relay.renewal.test",
		"quic_endpoint":       name + ":8443",
		"server_name":         name,
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPath := write("profile.json", profile)
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(f.service.ca)
	public := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{RootCAs: tlsRoots, ServerName: name, MinVersion: tls.VersionTLS13},
	}}
	defer public.CloseIdleConnections()
	quicConfig := &tls.Config{
		RootCAs: tlsRoots, ServerName: name, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"laneway-control/1"},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{relay.CertificateDER, inter.CertificateDER}, PrivateKey: relay.PrivateKey,
		}},
	}
	service := pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleController}
	original, leaf, err := pki.IssueService(ca, inter.PrivateKey, service, names, ips, time.Now(), 9*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	seedChain := append(pki.CertificatePEM(original.CertificateDER), interPEM...)
	seedKey := keyPEM(original)
	cert := write("controller.crt", seedChain)
	key := write("controller.key", seedKey)
	start := func(state string) (string, string, func()) {
		t.Helper()
		return startControllerTLSLab(t, f.dbPath, cert, key,
			"--node-issuer", issuerChain, issuerKey, "86400", "--node-client-ca", trust, "--node-quic",
			"--bootstrap-profile", bootstrapPath, "--renew-controller-tls", state, "--controller-renew-before", "3")
	}
	state := filepath.Join(dir, "renewal")
	base, endpoint, stop := start(state)
	peer := func(url string) *x509.Certificate {
		t.Helper()
		resp, err := public.Get(url + "/v1/health")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 ||
			len(resp.TLS.PeerCertificates) != 2 {
			t.Fatal("unverified controller peer or missing intermediate")
		}
		return resp.TLS.PeerCertificates[0]
	}
	if c := peer(base); c.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("controller replaced a certificate before its renewal window")
	}
	dial := func(endpoint string) *quic.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, endpoint, quicConfig, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.CloseWithError(0, "done") })
		return conn
	}
	oldConn := dial(endpoint)
	if oldConn.ConnectionState().TLS.PeerCertificates[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("initial QUIC and HTTPS certificates differ")
	}
	exchangeControllerTLSProbe(t, oldConn)

	var renewed *x509.Certificate
	deadline := time.Now().Add(12 * time.Second)
	for {
		candidate := peer(base)
		if candidate.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			renewed = candidate
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller did not rotate before expiry")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !time.Now().Before(leaf.NotAfter) || !renewed.NotAfter.After(leaf.NotAfter.Add(24*time.Hour)) ||
		!reflect.DeepEqual(renewed.URIs, leaf.URIs) ||
		!reflect.DeepEqual(renewed.DNSNames, leaf.DNSNames) || !reflect.DeepEqual(renewed.IPAddresses, leaf.IPAddresses) ||
		bytes.Equal(renewed.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal did not preserve identity and names while rotating the key before expiry")
	}
	exchangeControllerTLSProbe(t, oldConn)
	fresh := dial(endpoint)
	if fresh.ConnectionState().TLS.PeerCertificates[0].SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Fatal("new QUIC handshakes did not adopt the rotated certificate")
	}
	exchangeControllerTLSProbe(t, fresh)
	checkDiscovery := func(base string) {
		t.Helper()
		resp, err := public.Get(base + bootstrap.WellKnownPath)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		doc, err := bootstrap.Decode(resp.Body, time.Now())
		if err != nil || resp.StatusCode != 200 || doc.Controller.ServiceID != serviceID.String() ||
			doc.NetworkID != f.network.ID.String() || doc.Controller.ServerName != name {
			t.Fatal("bootstrap discovery no longer matches the controller identity")
		}
	}
	checkDiscovery(base)
	cache := filepath.Join(state, "controller-service.pem")
	info, err := os.Stat(cache)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("last-good controller TLS bundle is missing or not private")
	}
	aliasCtx, cancelAlias := context.WithTimeout(t.Context(), 5*time.Second)
	alias := exec.CommandContext(aliasCtx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", f.dbPath, "127.0.0.1:0",
		cache, cache, "--node-issuer", issuerChain, issuerKey, "86400", "--node-client-ca", trust,
		"--renew-controller-tls", state)
	out, aliasErr := alias.CombinedOutput()
	timedOut := aliasCtx.Err() != nil
	cancelAlias()
	if aliasErr == nil || timedOut || !strings.Contains(string(out), "must not replace a configured seed file") {
		t.Fatal("renewal did not reject a cache path that aliases the configured seed")
	}
	for path, expected := range map[string][]byte{cert: seedChain, key: seedKey} {
		if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, expected) {
			t.Fatal("renewal changed the operator's original TLS files")
		}
	}
	stop()
	if wait := time.Until(leaf.NotAfter) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	base, _, stop = start(state)
	if peer(base).SerialNumber.Cmp(renewed.SerialNumber) != 0 {
		t.Fatal("restart did not reuse the valid cached leaf after the original expired")
	}
	checkDiscovery(base)
	stop()

	// Even a CA-signed local bundle cannot change the pinned service identity.
	service.ServiceID = relayID
	wrong, wrongLeaf, err := pki.IssueService(ca, inter.PrivateKey, service, names, ips, time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(keyPEM(wrong), pki.CertificatePEM(wrong.CertificateDER)...)
	bundle = append(bundle, interPEM...)
	if err := os.WriteFile(cache, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	base, _, stop = start(state)
	defer stop()
	recovered := peer(base)
	if recovered.SerialNumber.Cmp(wrongLeaf.SerialNumber) == 0 ||
		recovered.SerialNumber.Cmp(renewed.SerialNumber) == 0 || !reflect.DeepEqual(recovered.URIs, leaf.URIs) {
		t.Fatal("expired bootstrap did not replace an unusable cache under the original identity")
	}
	checkDiscovery(base)
}

func startControllerTLSLab(t *testing.T, db, cert, key string, opts ...string) (string, string, func()) {
	t.Helper()
	args := append([]string{"serve", db, "127.0.0.1:0", cert, key}, opts...)
	cmd := exec.CommandContext(t.Context(), os.Getenv("LANEWAY_RUST_CONTROLLER"), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	announced := make(chan [2]string, 1)
	go func() {
		out := bufio.NewReader(stdout)
		tcp, _ := out.ReadString('\n')
		udp, _ := out.ReadString('\n')
		announced <- [2]string{strings.TrimSpace(tcp), strings.TrimSpace(udp)}
	}()
	select {
	case lines := <-announced:
		if !strings.HasPrefix(lines[0], "listening https://127.0.0.1:") || !strings.HasPrefix(lines[1], "listening quic://127.0.0.1:") {
			t.Fatal("renewal lab controller failed to start both listeners")
		}
		return strings.TrimPrefix(lines[0], "listening "), strings.TrimPrefix(lines[1], "listening quic://"), stop
	case <-time.After(10 * time.Second):
		t.Fatal("renewal lab controller startup timed out")
		return "", "", nil
	}
}

func exchangeControllerTLSProbe(t *testing.T, conn *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	request, err := proto.Marshal(&v1.ControllerEnvelope{
		SchemaVersion: 1, RequestId: 1,
		Body: &v1.ControllerEnvelope_RelayConfigurationRequest{RelayConfigurationRequest: &v1.RelayConfigurationRequest{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(request)))
	if _, err := stream.Write(append(frame, request...)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(io.LimitReader(stream, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	var parsed v1.ControllerEnvelope
	if len(reply) < 4 || int(binary.BigEndian.Uint32(reply)) != len(reply)-4 ||
		proto.Unmarshal(reply[4:], &parsed) != nil || parsed.GetRelayConfiguration() == nil {
		t.Fatalf("mTLS QUIC stream did not return a configuration (%d bytes)", len(reply))
	}
}
