//go:build rustinterop

package controllerservice_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
)

func TestRustControllerQUIC(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	db := filepath.Join(dir, "lab.db")
	store, err := controller.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	net1, err := store.CreateNetwork(ctx, "quic", netip.MustParsePrefix("10.77.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	net2, err := store.CreateNetwork(ctx, "other", netip.MustParsePrefix("10.78.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	signer, ca, err := pki.NewAuthority("lab", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := pki.IssueService(ca, signer.PrivateKey, pki.ServiceIdentity{NetworkID: net1.ID, ServiceID: sid, Role: pki.RoleController}, nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	pair := func(name string, m pki.Material) (string, string) {
		t.Helper()
		key, err := pki.PrivateKeyPEM(m.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".crt", pki.CertificatePEM(m.CertificateDER)), write(name+".key", key)
	}
	cert, key := pair("controller", server)
	root, caKey := pair("ca", signer)
	cmd := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "serve", db, "127.0.0.1:0", cert, key, "--node-issuer", root, caKey, "3600", "--node-client-ca", root, "--node-quic")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	var endpoint string
	select {
	case line := <-ready:
		var ok bool
		endpoint, ok = strings.CutPrefix(line, "listening https://")
		if !ok {
			t.Fatalf("unexpected readiness: %q", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("controller startup timeout")
	}
	newClient := func(name string, m pki.Material) *controllerclient.Client {
		t.Helper()
		cert, key := pair(name, m)
		// Deliberately unreachable HTTPS: this test only passes over UDP.
		cl, err := controllerclient.New(controllerclient.Options{Endpoint: "https://127.0.0.1:1", QUICEndpoint: endpoint, CAFile: root, CertificateFile: cert, PrivateKeyFile: key, ExpectedNetworkID: net1.ID, ExpectedServiceID: sid, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cl.Close() })
		return cl
	}
	enroll := func(network identity.NetworkID, name string, exit bool) (pki.Material, *x509.Certificate) {
		t.Helper()
		opts := controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable}
		lifetime := time.Hour
		if exit {
			opts = controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassEphemeral, RequestedName: name, EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1), SessionLifetime: 10 * time.Minute}
			lifetime = 5 * time.Minute
		}
		token, err := store.IssueEnrollmentTokenWithOptions(ctx, network, name, now.Add(time.Hour), opts)
		if err != nil {
			t.Fatal(err)
		}
		var material pki.Material
		var leaf *x509.Certificate
		_, err = store.EnrollNodeWithCertificate(ctx, token.Secret, name, 0, func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
			var err error
			material, leaf, err = pki.IssueNode(ca, signer.PrivateKey, identity.NodeIdentity{NetworkID: network, NodeID: node.ID}, now, lifetime)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return material, leaf
	}
	keyPub, keyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, keyPriv)
	if err != nil {
		t.Fatal(err)
	}
	old, oldLeaf := enroll(net1.ID, "old", false)
	client := newClient("old", old)
	for i := 0; i < 64; i++ {
		if _, err := client.Renew(ctx, []byte{1}, nil); err == nil || !strings.Contains(err.Error(), "ERROR_CODE_MALFORMED") {
			t.Fatalf("framed response %d: %v", i, err)
		}
	}
	result, err := client.Renew(ctx, csr, nil)
	if err != nil {
		t.Fatal(err)
	}
	der := result.GetCertificateChain().GetCertificatesDer()
	if len(der) == 0 {
		t.Fatal("missing new certificate")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || !bytes.Equal(pub, keyPub) || leaf.SerialNumber.Cmp(oldLeaf.SerialNumber) == 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != oldLeaf.URIs[0].String() || leaf.CheckSignatureFrom(ca) != nil {
		t.Fatal("renewal changed identity or signer")
	}
	if _, err := store.RevokeCertificateBySerial(ctx, net1.ID, oldLeaf.SerialNumber.Bytes(), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Renew(ctx, csr, nil); err == nil || !strings.Contains(err.Error(), "ERROR_CODE_PERMISSION_DENIED") {
		t.Fatalf("persistent connection revocation: %v", err)
	}
	renewed := newClient("replacement", pki.Material{CertificateDER: der[0], PrivateKey: keyPriv})
	if _, err := renewed.Renew(ctx, csr, nil); err != nil {
		t.Fatal(err)
	}
	outsider, _ := enroll(net2.ID, "foreign", false)
	if _, err := newClient("foreign", outsider).Renew(ctx, csr, nil); err == nil {
		t.Fatal("registered node from another network renewed")
	}
	relay, _, err := pki.IssueService(ca, signer.PrivateKey, pki.ServiceIdentity{NetworkID: net1.ID, ServiceID: sid, Role: pki.RoleRelay}, nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newClient("relay", relay).Renew(ctx, csr, nil); err == nil {
		t.Fatal("relay certificate authorized for node renewal")
	}
	subject, err := identity.IdentityFromCertificate(oldLeaf)
	if err != nil {
		t.Fatal(err)
	}
	unrecorded, _, err := pki.IssueNode(ca, signer.PrivateKey, subject, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newClient("unrecorded", unrecorded).Renew(ctx, csr, nil); err == nil {
		t.Fatal("unrecorded node certificate authorized by CA signature alone")
	}
	t.Run("framing and handshake", func(t *testing.T) {
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		frame := func(schema uint32, id uint64) []byte {
			msg, err := proto.Marshal(&v1.ControllerEnvelope{SchemaVersion: schema, RequestId: id, Body: &v1.ControllerEnvelope_RenewalRequest{RenewalRequest: &v1.RenewalRequest{Pkcs10CsrDer: csr}}})
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := protocol.WriteControlFrame(&buf, msg, protocol.DefaultMaxControlFrame); err != nil {
				t.Fatal(err)
			}
			return buf.Bytes()
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, NextProtos: []string{"laneway-control/1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der[0]}, PrivateKey: keyPriv}}}
		for _, tc := range []struct {
			name    string
			config  *tls.Config
			payload []byte
		}{
			{"oversized", cfg, []byte{0, 0x10, 0, 1}}, {"empty", cfg, []byte{0, 0, 0, 0}},
			{"trailing", cfg, append(frame(1, 1), 0)}, {"zero request id", cfg, frame(1, 0)}, {"wrong schema", cfg, frame(2, 1)},
			{"wrong protocol", func() *tls.Config { x := cfg.Clone(); x.NextProtos = []string{"h3"}; return x }(), nil},
			{"no client certificate", func() *tls.Config { x := cfg.Clone(); x.Certificates = nil; return x }(), nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				conn, err := quic.DialAddr(ctx, endpoint, tc.config, nil)
				if err != nil {
					if tc.payload != nil {
						t.Fatal(err)
					}
					return
				}
				defer conn.CloseWithError(0, "done")
				if tc.payload != nil {
					s, err := conn.OpenStreamSync(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = s.Write(tc.payload); err != nil {
						t.Fatal(err)
					}
					_ = s.Close()
				}
				select {
				case <-conn.Context().Done():
				case <-ctx.Done():
					t.Fatal("invalid connection remained open")
				}
			})
		}
	})
	t.Run("ephemeral exit session", func(t *testing.T) {
		m, l := enroll(net1.ID, "lab-exit", true)
		a := newClient("exit-a", m)
		b := newClient("exit-b", m)
		if _, err := a.Renew(ctx, csr, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Renew(ctx, csr, nil); err == nil {
			t.Fatal("duplicate control session accepted")
		}
		if _, err := a.Renew(ctx, csr, nil); err != nil {
			t.Fatalf("duplicate displaced live owner: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := b.Renew(ctx, csr, nil); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("released exit was never reclaimed")
			}
			time.Sleep(20 * time.Millisecond)
		}
		// A terminated heartbeat lease is independent of the client leaf's
		// absolute expiry and must be rechecked on the established session.
		id, err := identity.IdentityFromCertificate(l)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := sql.Open("sqlite", db)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		if _, err = raw.Exec("UPDATE ephemeral_exit_sessions SET terminated_at=unixepoch() WHERE node_id=?", id.NodeID[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Renew(ctx, csr, nil); err == nil || !strings.Contains(err.Error(), "ERROR_CODE_PERMISSION_DENIED") {
			t.Fatalf("terminated exit session: %v", err)
		}
	})
}
