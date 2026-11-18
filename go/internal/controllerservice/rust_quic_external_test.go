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
	"github.com/Doout/laneway/go/internal/controllerservice"
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
	net1, err := store.CreateNetworkDualStack(ctx, "quic", netip.MustParsePrefix("10.77.0.0/24"), netip.MustParsePrefix("fd12:b584:14c0::/64"))
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
	clientFor := func(name string, m pki.Material, address string, generation uint64) *controllerclient.Client {
		t.Helper()
		cert, key := pair(name, m)
		https, quicAddress := "https://127.0.0.1:1", address
		if strings.HasPrefix(address, "https://") {
			https, quicAddress = address, ""
		}
		cl, err := controllerclient.New(controllerclient.Options{Endpoint: https, QUICEndpoint: quicAddress, CAFile: root, CertificateFile: cert, PrivateKeyFile: key, ExpectedNetworkID: net1.ID, ExpectedServiceID: sid, Timeout: 2 * time.Second, EphemeralExitLeaseGeneration: generation})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cl.Close() })
		return cl
	}
	newClient := func(name string, m pki.Material) *controllerclient.Client { return clientFor(name, m, endpoint, 0) }
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
	t.Run("node configuration", func(t *testing.T) {
		connector, connectorLeaf := enroll(net1.ID, "connector", false)
		cid, err := identity.IdentityFromCertificate(connectorLeaf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.SetNodeCapabilities(ctx, cid.NodeID, protocol.CapabilitySubnetRouterV1); err != nil {
			t.Fatal(err)
		}
		exp := time.Now().Add(5 * time.Second).Truncate(time.Second)
		subnet, err := store.AdvertiseRoute(ctx, cid.NodeID, netip.MustParsePrefix("172.21.0.0/16"), controller.RouteKindSubnet, controller.RouteModeNAT, 10, &exp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.ApproveRoute(ctx, subnet.ID); err != nil {
			t.Fatal(err)
		}
		selector := `{"ip_protocol":"IP_PROTOCOL_TCP","destination_prefixes":[{"address":"rBUAAA==","prefix_length":16}],"destination_ports":[{"first":443,"last":443}]}`
		rule, _, err := store.AddACLRule(ctx, net1.ID, 50, controller.ACLActionAccept, selector, "Allow HTTPS only")
		if err != nil {
			t.Fatal(err)
		}
		relayID, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		registration, _, err := store.RegisterRelay(ctx, net1.ID, relayID, nil, "relay", "127.0.0.1:4433")
		if err != nil {
			t.Fatal(err)
		}
		relayMaterial, _, err := pki.IssueService(ca, signer.PrivateKey, pki.ServiceIdentity{NetworkID: net1.ID, ServiceID: relayID, Role: pki.RoleRelay}, nil, nil, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		goService, err := controllerservice.New(controllerservice.Options{Store: store, CACertificate: ca, CAKey: signer.PrivateKey, LeafValidity: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		goServer, err := goService.ListenQUIC("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{server.CertificateDER}, PrivateKey: server.PrivateKey}}, ClientCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		serve := make(chan error, 1)
		go func() { serve <- goServer.Serve(ctx) }()
		defer func() { _ = goServer.Close(); <-serve }()
		m := pki.Material{CertificateDER: der[0], PrivateKey: keyPriv}
		reference := clientFor("reference", m, goServer.Addr().String(), 0)
		oracle, unchanged, err := reference.Configuration(ctx, 0)
		if err != nil || unchanged {
			t.Fatalf("Go snapshot: unchanged=%t err=%v", unchanged, err)
		}
		rust, unchanged, err := renewed.Configuration(ctx, 0)
		if err != nil || unchanged {
			t.Fatalf("Rust snapshot: unchanged=%t err=%v", unchanged, err)
		}
		if len(rust.OverlayAddresses) != 2 || len(rust.Routes.Routes) != 5 || len(rust.Policy.Rules) != 1 || len(rust.RevokedCertificateSerials) != 1 || len(rust.Relays) != 1 {
			t.Fatalf("fixture did not exercise dual-stack peers, route, ACL, revocation and relay: %v", rust)
		}
		if rust.ValidUntilUnixSeconds != uint64(exp.Unix()) || rust.ValidUntilUnixSeconds > oracle.ValidUntilUnixSeconds {
			t.Fatalf("invalid route-clamped lease: %v", rust.ValidUntilUnixSeconds)
		}
		oracle.ValidUntilUnixSeconds = rust.ValidUntilUnixSeconds
		if !proto.Equal(oracle, rust) {
			t.Fatalf("snapshot mismatch\nGo: %v\nRust: %v", oracle, rust)
		}
		relayOracle := clientFor("relay-reference", relayMaterial, goServer.Addr().String(), 0)
		relayReference, unchanged, err := relayOracle.RelayConfiguration(ctx, 0)
		if err != nil || unchanged {
			t.Fatalf("Go relay snapshot: unchanged=%t err=%v", unchanged, err)
		}
		relayClients := []*controllerclient.Client{
			clientFor("relay-quic", relayMaterial, endpoint, 0),
			clientFor("relay-https", relayMaterial, "https://"+endpoint, 0),
		}
		if len(relayReference.Peers) != 2 || len(relayReference.RevokedCertificateSerials) != 1 || len(relayReference.Policy.Rules) != 1 {
			t.Fatalf("fixture did not exercise relay policy: %v", relayReference)
		}
		relayReference.ValidUntilUnixSeconds = uint64(exp.Unix())
		for i, cl := range relayClients {
			cfg, unchanged, err := cl.RelayConfiguration(ctx, 0)
			if err != nil || unchanged || !proto.Equal(cfg, relayReference) {
				t.Fatalf("relay transport %d snapshot mismatch (%t, %v)\nGo: %v\nRust: %v", i, unchanged, err, relayReference, cfg)
			}
			lease, unchanged, err := cl.RelayConfiguration(ctx, cfg.ConfigurationEpoch)
			if err != nil || !unchanged || lease.GetValidUntilUnixSeconds() != cfg.ValidUntilUnixSeconds {
				t.Fatalf("relay transport %d conditional snapshot: %v %t %v", i, lease, unchanged, err)
			}
			// Registered relay certificates cannot access a node operation.
			if _, _, err := cl.Configuration(ctx, 0); err == nil {
				t.Fatalf("relay transport %d accepted as a node", i)
			}
			// Re-establish the QUIC connection after the role mismatch, so
			// disabling the service below tests a live established session.
			if _, _, err := cl.RelayConfiguration(ctx, cfg.ConfigurationEpoch); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := renewed.RelayConfiguration(ctx, 0); err == nil {
			t.Fatal("node accepted as a relay")
		}
		httpsNode := clientFor("https-node", m, "https://"+endpoint, 0)
		if _, _, err := httpsNode.RelayConfiguration(ctx, 0); err == nil {
			t.Fatal("node certificate authorized for relay configuration over HTTPS")
		}
		disabledEpoch, err := store.DisableRelay(ctx, registration.ID)
		if err != nil {
			t.Fatal(err)
		}
		for i, cl := range relayClients {
			if _, _, err := cl.RelayConfiguration(ctx, disabledEpoch); err == nil {
				t.Fatalf("disabled relay accepted on transport %d", i)
			}
		}
		// Disabling a relay changes the node epoch and removes discovery.
		rust, unchanged, err = renewed.Configuration(ctx, rust.ConfigurationEpoch)
		if err != nil || unchanged || len(rust.GetRelays()) != 0 || rust.GetConfigurationEpoch() != disabledEpoch {
			t.Fatalf("relay disable not reflected in node snapshot: %v %t %v", rust, unchanged, err)
		}
		epoch := rust.ConfigurationEpoch
		lease, unchanged, err := renewed.Configuration(ctx, epoch)
		if err != nil || !unchanged || lease.ValidUntilUnixSeconds != rust.ValidUntilUnixSeconds {
			t.Fatalf("conditional lease: %v %t %v", lease, unchanged, err)
		}
		if _, _, err := renewed.Configuration(ctx, epoch+100); err == nil || !strings.Contains(err.Error(), "ERROR_CODE_STALE_EPOCH") {
			t.Fatalf("future epoch: %v", err)
		}
		if _, err = store.DeleteACLRule(ctx, rule.ID); err != nil {
			t.Fatal(err)
		}
		noRule, unchanged, err := renewed.Configuration(ctx, epoch)
		if err != nil || unchanged || len(noRule.GetPolicy().GetRules()) != 0 || noRule.GetPolicy().GetDefaultAction() != v1.PolicyAction_POLICY_ACTION_DENY {
			t.Fatalf("ACL removal: %v %t %v", noRule, unchanged, err)
		}
		raw, err := sql.Open("sqlite", db)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		time.Sleep(time.Until(exp) + 100*time.Millisecond)
		after, unchanged, err := renewed.Configuration(ctx, noRule.ConfigurationEpoch)
		if err != nil || unchanged || after.ConfigurationEpoch != noRule.ConfigurationEpoch+1 || len(after.GetRoutes().GetRoutes()) != 4 {
			t.Fatalf("route expiry: %v %t %v", after, unchanged, err)
		}
		var state string
		if err = raw.QueryRow("SELECT state FROM routes WHERE id=?", subnet.ID[:]).Scan(&state); err != nil || state != "withdrawn" {
			t.Fatalf("route expiry was not durable: %s %v", state, err)
		}
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)) + 100*time.Millisecond)
		fresh, unchanged, err := renewed.Configuration(ctx, after.ConfigurationEpoch)
		if err != nil || !unchanged || fresh.GetConfigurationEpoch() != after.ConfigurationEpoch || fresh.GetValidUntilUnixSeconds() <= after.GetValidUntilUnixSeconds() {
			t.Fatalf("lease did not advance without an epoch change: %v %t %v", fresh, unchanged, err)
		}
		// Bind the connector to a managed user and prove the ordinary ACL
		// snapshot path cannot bypass unported managed grants.
		user, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = raw.Exec("INSERT INTO access_users(id,network_id,name,enabled,created_at,updated_at) VALUES(?,?,?,1,unixepoch(),unixepoch())", user[:], net1.ID[:], "managed"); err != nil {
			t.Fatal(err)
		}
		if _, err = raw.Exec("UPDATE nodes SET user_id=? WHERE id=?", user[:], cid.NodeID[:]); err != nil {
			t.Fatal(err)
		}
		if _, _, err = newClient("managed", connector).Configuration(ctx, after.ConfigurationEpoch); err == nil || !strings.Contains(err.Error(), "ERROR_CODE_PERMISSION_DENIED") {
			t.Fatalf("managed node was not denied: %v", err)
		}
	})
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
		id, err := identity.IdentityFromCertificate(l)
		if err != nil {
			t.Fatal(err)
		}
		session, err := store.EphemeralExitSession(ctx, id.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		a := clientFor("exit-a", m, endpoint, session.Generation)
		b := clientFor("exit-b", m, endpoint, session.Generation)
		conf, unchanged, err := a.Configuration(ctx, 0)
		if err != nil || unchanged || conf.GetEphemeralExitLeaseGeneration() != session.Generation || conf.GetEphemeralExitSuspectAtUnixSeconds() != conf.GetValidUntilUnixSeconds() || conf.GetEphemeralExitRevokeAtUnixSeconds() < conf.GetValidUntilUnixSeconds() {
			t.Fatalf("ephemeral Exit heartbeat: %v %t %v", conf, unchanged, err)
		}
		if conf, unchanged, err = a.Configuration(ctx, conf.ConfigurationEpoch); err != nil || unchanged || conf.GetEphemeralExitLeaseGeneration() != session.Generation {
			t.Fatalf("ephemeral Exit did not get a fresh heartbeat: %v %t %v", conf, unchanged, err)
		}
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
