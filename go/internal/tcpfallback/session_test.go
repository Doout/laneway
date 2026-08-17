package tcpfallback

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/packetbuffer"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/transport"
)

const testNetwork = "000102030405060708090a0b0c0d0e0f"

type testCredentials struct {
	serverTLS, clientTLS *tls.Config
	server, client       identity.AuthenticatedIdentity
	ca                   *x509.Certificate
	caKey                ed25519.PrivateKey
	dir, caFile          string
}

func newTestCredentials(t *testing.T) testCredentials {
	t.Helper()
	dir := t.TempDir()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Laneway TCP fallback test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)
	network := mustNetworkID(t, testNetwork)
	server := authenticated(t, network, identity.IdentityRoleRelay, "101112131415161718191a1b1c1d1e1f")
	client := authenticated(t, network, identity.IdentityRoleNode, "202122232425262728292a2b2c2d2e2f")
	serverCert, serverKey := issueCertificate(t, dir, "server", 2, server, ca, caKey)
	clientCert, clientKey := issueCertificate(t, dir, "client", 3, client, ca, caKey)
	serverTLS, err := transport.LoadServerTLSConfig(caFile, serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := transport.LoadClientTLSConfig(caFile, clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	return testCredentials{serverTLS: serverTLS, clientTLS: clientTLS, server: server, client: client, ca: ca, caKey: caKey, dir: dir, caFile: caFile}
}

func authenticated(t *testing.T, network identity.NetworkID, role identity.IdentityRole, subject string) identity.AuthenticatedIdentity {
	t.Helper()
	id, err := identity.ParseID(subject)
	if err != nil {
		t.Fatal(err)
	}
	return identity.AuthenticatedIdentity{NetworkID: network, Role: role, SubjectID: id}
}

func mustNetworkID(t *testing.T, value string) identity.NetworkID {
	t.Helper()
	id, err := identity.ParseNetworkID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func issueCertificate(t *testing.T, dir, name string, serial int64, id identity.AuthenticatedIdentity, ca *x509.Certificate, caKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := id.URI()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

type sessionPair struct{ server, client *Session }

func openPair(t *testing.T, config *Config) sessionPair {
	t.Helper()
	credentials := newTestCredentials(t)
	listener, err := Listen("127.0.0.1:0", credentials.serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *Session, 1)
	errorsChannel := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			errorsChannel <- acceptErr
			return
		}
		accepted <- session
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Dial(ctx, listener.Addr().String(), credentials.clientTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	var server *Session
	select {
	case server = <-accepted:
	case err := <-errorsChannel:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return sessionPair{server: server, client: client}
}

func TestHTTPSAndFallbackShareListenerByALPN(t *testing.T) {
	credentials := newTestCredentials(t)
	publicTLS := credentials.serverTLS.Clone()
	publicTLS.ClientAuth = tls.NoClientCert
	publicTLS.ClientCAs = nil
	publicTLS.VerifyConnection = nil
	publicTLS.NextProtos = []string{"http/1.1"}
	listener, err := ListenWithHTTPS("127.0.0.1:0", credentials.serverTLS, nil, HTTPSOptions{
		TLSConfig: publicTLS,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/bootstrap" {
				http.NotFound(writer, request)
				return
			}
			_, _ = io.WriteString(writer, "public")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- session
	}()
	transport := &http.Transport{TLSClientConfig: &tls.Config{ //nolint:gosec -- test certificate
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
	}}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "public" {
		t.Fatalf("public HTTPS response status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	clientSession, err := Dial(context.Background(), listener.Addr().String(), credentials.clientTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	select {
	case serverSession := <-accepted:
		defer serverSession.Close()
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("fallback session was not accepted after public HTTPS")
	}
}

func TestPacketReceiveReusesBoundedOwnedBuffer(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	// sync.Pool is intentionally permitted to discard cached storage at a GC
	// boundary. Disable GC while measuring the warmed packet loop so this test
	// detects per-packet allocation rather than the runtime's cache policy.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	pair := openPair(t, &Config{QueueDepth: 4, MaxPacketPayload: 1205})
	packet := ipv4Packet(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), make([]byte, 1180))
	frame, err := protocol.EncodePacket(nil, protocol.PacketHeader{Version: protocol.PacketVersion1, RouteHandle: 7}, packet)
	if err != nil {
		t.Fatal(err)
	}
	writeReadRelease := func() {
		if err := pair.server.WritePacket(context.Background(), frame); err != nil {
			t.Fatal(err)
		}
		owned, err := pair.client.ReadPacketBuffer(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if string(owned.Bytes()) != string(frame) || cap(owned.Bytes()) != pair.client.config.maxPacket {
			t.Fatalf("owned frame len/cap = %d/%d", len(owned.Bytes()), cap(owned.Bytes()))
		}
		owned.Release()
	}
	writeReadRelease()
	created := pair.client.packetPool.Created()
	const measuredPackets = 100
	for range measuredPackets {
		writeReadRelease()
	}
	// The race runtime deliberately drops sync.Pool entries at random, so an
	// exact zero-allocation assertion is not portable to `go test -race`.
	// Requiring reuse for at least half the frames still catches the original
	// allocate-on-every-frame implementation, while ordinary builds retain a
	// much stronger result (normally no additional backing buffers at all).
	if got := pair.client.packetPool.Created(); got-created >= measuredPackets/2 {
		t.Fatalf("warm packet receive created %d new backing buffers for %d packets", got-created, measuredPackets)
	}
}

func TestSessionCarriesStructurallyValidOpaqueWireGuardFrame(t *testing.T) {
	pair := openPair(t, &Config{QueueDepth: 4, MaxPacketPayload: 1205})
	ciphertext := make([]byte, 148)
	binary.LittleEndian.PutUint32(ciphertext, 1)
	frame, err := protocol.EncodeWireGuardPacket(nil, 7, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pair.client.WritePacket(ctx, frame); err != nil {
		t.Fatal(err)
	}
	got, err := pair.server.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(frame) {
		t.Fatalf("opaque frame differs: got=%x want=%x", got, frame)
	}
	// The TCP record layer validates public framing only. A plaintext consumer
	// must still reject the encrypted flag unless its authenticated session
	// negotiated e2e-packet-v1.
	if _, _, err := protocol.DecodePacket(got); !errors.Is(err, protocol.ErrInvalidPacketFlags) {
		t.Fatalf("plaintext decoder accepted opaque frame: %v", err)
	}
}

func TestLoopbackControlAndPacketPathExchange(t *testing.T) {
	pair := openPair(t, nil)
	if pair.client.PeerIdentity().Role != identity.IdentityRoleRelay || pair.server.PeerIdentity().Role != identity.IdentityRoleNode {
		t.Fatalf("identities: client=%+v server=%+v", pair.client.PeerIdentity(), pair.server.PeerIdentity())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pair.client.WriteControl(ctx, []byte("hello relay")); err != nil {
		t.Fatal(err)
	}
	if got, err := pair.server.ReadControl(ctx); err != nil || string(got) != "hello relay" {
		t.Fatalf("server control = %q, %v", got, err)
	}
	if err := pair.server.WriteControl(ctx, []byte("welcome node")); err != nil {
		t.Fatal(err)
	}
	if got, err := pair.client.ReadControl(ctx); err != nil || string(got) != "welcome node" {
		t.Fatalf("client control = %q, %v", got, err)
	}

	clientPath, err := NewPacketPath("tcp-client", pair.client)
	if err != nil {
		t.Fatal(err)
	}
	serverPath, err := NewPacketPath("tcp-server", pair.server)
	if err != nil {
		t.Fatal(err)
	}
	clientPeer, serverPeer := testNodeID(0xa1), testNodeID(0xb2)
	if err := clientPath.ReplaceBindings([]Binding{{Peer: serverPeer, SendHandle: 11, ReceiveHandle: 22}}); err != nil {
		t.Fatal(err)
	}
	if err := serverPath.ReplaceBindings([]Binding{{Peer: clientPeer, SendHandle: 22, ReceiveHandle: 11}}); err != nil {
		t.Fatal(err)
	}
	packet := ipv4Packet(netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("100.96.0.2"), []byte{1, 2, 3})
	if err := clientPath.Send(ctx, serverPeer, packet); err != nil {
		t.Fatal(err)
	}
	received, err := serverPath.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if received.Peer != clientPeer || string(received.Packet) != string(packet) {
		t.Fatalf("received peer=%s packet=%x", received.Peer, received.Packet)
	}
	if got := clientPath.MaxPayload(serverPeer); got != maxPacketFramePayload-5 {
		t.Fatalf("max payload = %d", got)
	}
	if got := clientPath.Health(serverPeer); got.State != pathmanager.HealthHealthy {
		t.Fatalf("health = %+v", got)
	}
}

func TestControlStreamCarriesInnerFramesWithQueueDepthOne(t *testing.T) {
	pair := openPair(t, &Config{QueueDepth: 1})
	payload := []byte("one logical protobuf frame")
	framer := protocol.ControlFramer{MaxPayload: protocol.DefaultMaxControlFrame}
	if err := framer.Write(pair.client.ControlStream(), payload); err != nil {
		t.Fatal(err)
	}
	got, err := framer.Read(pair.server.ControlStream())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("control payload = %q", got)
	}
	var empty [4]byte
	if _, err := pair.client.ControlStream().Write(empty[:]); !errors.Is(err, ErrProtocol) {
		t.Fatalf("zero inner frame = %v", err)
	}
}

func TestConcurrentWritersRemainFramed(t *testing.T) {
	pair := openPair(t, &Config{QueueDepth: 256})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const writers, perWriter = 8, 20
	var wait sync.WaitGroup
	for writer := range writers {
		wait.Add(1)
		go func(writer int) {
			defer wait.Done()
			for sequence := range perWriter {
				if err := pair.client.WriteControl(ctx, []byte(fmt.Sprintf("%d:%d", writer, sequence))); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(writer)
	}
	seen := make(map[string]bool, writers*perWriter)
	for range writers * perWriter {
		payload, err := pair.server.ReadControl(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(payload)] = true
	}
	wait.Wait()
	if len(seen) != writers*perWriter {
		t.Fatalf("received %d unique frames", len(seen))
	}
}

func TestReceiveBackpressureClosesSession(t *testing.T) {
	pair := openPair(t, &Config{QueueDepth: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pair.client.WriteControl(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := pair.client.WriteControl(ctx, []byte("two")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pair.server.Done():
		if !errors.Is(pair.server.Err(), ErrBackpressure) {
			t.Fatalf("session error = %v", pair.server.Err())
		}
	case <-ctx.Done():
		t.Fatal("server did not enforce receive backpressure")
	}
}

func TestSlowPeerCannotBlockWriterIndefinitely(t *testing.T) {
	server, _ := openRawPair(t, &Config{
		WriteTimeout:      25 * time.Millisecond,
		MaxControlPayload: maxControlPayloadLimit,
	})
	started := time.Now()
	err := server.WriteControl(context.Background(), make([]byte, maxControlPayloadLimit))
	if err == nil {
		t.Fatal("write to non-reading peer unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded write took %s: %v", elapsed, err)
	}
	select {
	case <-server.Done():
	case <-time.After(time.Second):
		t.Fatal("write failure did not terminate session")
	}
}

func TestPacketPathRejectsInvalidBindingsAndPackets(t *testing.T) {
	pair := openPair(t, nil)
	path, err := NewPacketPath("tcp", pair.client)
	if err != nil {
		t.Fatal(err)
	}
	peer := testNodeID(1)
	if path.MaxPayload(peer) != 0 {
		t.Fatal("unbound peer has a payload allowance")
	}
	if err := path.Send(context.Background(), peer, ipv4Packet(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), nil)); !errors.Is(err, ErrRouteNotBound) {
		t.Fatalf("unbound send = %v", err)
	}
	if err := path.ReplaceBindings([]Binding{{Peer: peer, SendHandle: 1, ReceiveHandle: 2}, {Peer: testNodeID(2), SendHandle: 3, ReceiveHandle: 2}}); !errors.Is(err, ErrDuplicateRouteHandle) {
		t.Fatalf("duplicate handle = %v", err)
	}
	if err := path.ReplaceBindings([]Binding{{Peer: peer, SendHandle: 1, ReceiveHandle: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := path.Send(context.Background(), peer, []byte("not IP")); err == nil {
		t.Fatal("invalid IP packet accepted")
	}
}

func TestTCPPacketFramingReusesLargeBuffer(t *testing.T) {
	path := &PacketPath{frames: packetbuffer.NewPool(1205)}
	packet := ipv4Packet(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), make([]byte, 1180))
	encodeAndRelease := func() bool {
		buffer, frame, err := path.encodePacket(7, packet)
		if err != nil || len(frame) != 1205 {
			return false
		}
		buffer.Release()
		return true
	}
	if !encodeAndRelease() {
		t.Fatal("warm encode failed")
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if !encodeAndRelease() {
			t.Fatal("encode failed")
		}
	}); allocations != 0 {
		t.Fatalf("warm TCP packet framing allocations = %v, want zero", allocations)
	}
}

func BenchmarkTCPPacketFraming(b *testing.B) {
	path := &PacketPath{frames: packetbuffer.NewPool(1205)}
	packet := ipv4Packet(netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2"), make([]byte, 1180))
	buffer, _, _ := path.encodePacket(7, packet)
	buffer.Release()
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for range b.N {
		buffer, _, _ := path.encodePacket(7, packet)
		buffer.Release()
	}
}

func testNodeID(last byte) identity.NodeID {
	var id identity.NodeID
	id[len(id)-1] = last
	return id
}

func ipv4Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	sourceBytes, destinationBytes := source.As4(), destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	copy(packet[20:], payload)
	return packet
}

func TestConfigAndLocalCertificateRoleRejection(t *testing.T) {
	credentials := newTestCredentials(t)
	if _, err := Listen("127.0.0.1:0", credentials.clientTLS, nil); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("node used as server = %v", err)
	}
	dialer := &Dialer{Address: "127.0.0.1:1", TLSConfig: credentials.serverTLS}
	if _, err := dialer.Dial(context.Background()); !errors.Is(err, identity.ErrUnexpectedIdentityRole) {
		t.Fatalf("relay used as client = %v", err)
	}
	bad := credentials.clientTLS.Clone()
	bad.VerifyConnection = nil
	if _, _, err := prepareTLS(bad, identity.IdentityRoleNode, false); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("unsafe client TLS = %v", err)
	}
	if _, err := normalizeConfig(&Config{KeepAlivePeriod: time.Second, IdleTimeout: time.Second}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("invalid liveness config = %v", err)
	}
}

func TestHandshakeRejectsWrongPeerRole(t *testing.T) {
	credentials := newTestCredentials(t)
	listener, err := Listen("127.0.0.1:0", credentials.serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relayID := authenticated(t, credentials.server.NetworkID, identity.IdentityRoleRelay, "303132333435363738393a3b3c3d3e3f")
	wrongCert, wrongKey := issueCertificate(t, credentials.dir, "wrong-client", 9, relayID, credentials.ca, credentials.caKey)
	certificate, err := tls.LoadX509KeyPair(wrongCert, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(credentials.caFile)
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("CA pool: %v", err)
	}
	rawClient := &tls.Config{
		Certificates: []tls.Certificate{certificate}, RootCAs: pool, InsecureSkipVerify: true, // verified by callback below
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{ALPN},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
	acceptResult := make(chan error, 1)
	go func() {
		_, acceptErr := listener.Accept(context.Background())
		acceptResult <- acceptErr
	}()
	conn, dialErr := tls.Dial("tcp", listener.Addr().String(), rawClient)
	if dialErr == nil {
		_ = conn.Close()
	}
	select {
	case acceptErr := <-acceptResult:
		if acceptErr == nil {
			t.Fatal("server accepted relay-role client")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accept did not reject wrong role")
	}
}

func TestMalformedAndOversizeFramesCloseSession(t *testing.T) {
	tests := []struct {
		name   string
		header [frameHeaderSize]byte
		want   error
	}{
		{name: "empty", header: wireHeader(0, frameControl), want: ErrProtocol},
		{name: "unknown", header: wireHeader(1, frameType(99)), want: ErrProtocol},
		{name: "oversize control", header: wireHeader(DefaultMaxControlPayload+2, frameControl), want: ErrFrameTooLarge},
		{name: "oversize packet", header: wireHeader(maxPacketFramePayload+2, framePacket), want: ErrFrameTooLarge},
		{name: "ping payload", header: wireHeader(2, framePing), want: ErrFrameTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, raw := openRawPair(t, nil)
			if _, err := raw.Write(test.header[:]); err != nil {
				t.Fatal(err)
			}
			select {
			case <-server.Done():
				if !errors.Is(server.Err(), test.want) {
					t.Fatalf("error = %v, want %v", server.Err(), test.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("malformed frame did not close session")
			}
		})
	}
}

func wireHeader(length int, kind frameType) [frameHeaderSize]byte {
	var header [frameHeaderSize]byte
	binary.BigEndian.PutUint32(header[:4], uint32(length))
	header[4] = byte(kind)
	return header
}

func openRawPair(t *testing.T, config *Config) (*Session, *tls.Conn) {
	t.Helper()
	credentials := newTestCredentials(t)
	listener, err := Listen("127.0.0.1:0", credentials.serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *Session, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- session
	}()
	clientTLS, _, err := prepareTLS(credentials.clientTLS, identity.IdentityRoleNode, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tls.Dial("tcp", listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	select {
	case server := <-accepted:
		t.Cleanup(func() { _ = server.Close() })
		return server, raw
	case err := <-acceptErrors:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("accept timeout")
	}
	return nil, nil
}

func TestKeepaliveAndIdleDetection(t *testing.T) {
	config := &Config{KeepAlivePeriod: 20 * time.Millisecond, IdleTimeout: 100 * time.Millisecond, WriteTimeout: 50 * time.Millisecond}
	pair := openPair(t, config)
	time.Sleep(180 * time.Millisecond)
	select {
	case <-pair.client.Done():
		t.Fatalf("client died while keepalives were exchanged: %v", pair.client.Err())
	case <-pair.server.Done():
		t.Fatalf("server died while keepalives were exchanged: %v", pair.server.Err())
	default:
	}

	server, raw := openRawPair(t, config)
	_ = raw.SetReadDeadline(time.Now().Add(time.Second))
	// Drain server pings without answering them.
	go func() {
		buffer := make([]byte, 64)
		for {
			if _, err := raw.Read(buffer); err != nil {
				return
			}
		}
	}()
	select {
	case <-server.Done():
		if server.Err() == nil {
			t.Fatal("idle server ended without a cause")
		}
	case <-time.After(time.Second):
		t.Fatal("unresponsive peer did not time out")
	}
}

func TestDialerRunRetriesUntilCanceled(t *testing.T) {
	credentials := newTestCredentials(t)
	listener, err := Listen("127.0.0.1:0", credentials.serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	accepted := make(chan struct{})
	go func() {
		session, acceptErr := listener.Accept(context.Background())
		if acceptErr != nil {
			return
		}
		close(accepted)
		_ = session.Close()
	}()
	dialer := &Dialer{Address: listener.Addr().String(), TLSConfig: credentials.clientTLS}
	runDone := make(chan error, 1)
	go func() {
		runDone <- dialer.Run(ctx, ReconnectConfig{Initial: time.Millisecond, Maximum: 5 * time.Millisecond}, func(_ context.Context, session *Session) error {
			cancel()
			return session.Err()
		})
	}()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("connection not accepted")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run ignored cancellation")
	}
}
