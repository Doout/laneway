//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/controllerservice"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/wireguard"
)

const quicControllerName = "controller.example"

type quicControllerFixture struct {
	ctx               context.Context
	directory, backup string
	paths             controllerRunPKIPaths
	network, foreign  identity.NetworkID
	service, relay    identity.ID
	relayAddress      string
	nativeToken       string
	relays            map[string][2]string
}

type quicWorkload struct {
	id        identity.NodeID
	cert, key string
	leaf      *x509.Certificate
	expires   uint64
}

func TestControllerQUICCandidateCompatibility(t *testing.T) {
	goBinary, candidate := os.Getenv("LANEWAY_GO_CONTROLLER_BIN"), os.Getenv("LANEWAY_CONTROLLER_QUIC_BIN")
	if goBinary == "" || candidate == "" {
		t.Skip("set LANEWAY_GO_CONTROLLER_BIN and LANEWAY_CONTROLLER_QUIC_BIN")
	}
	if !filepath.IsAbs(goBinary) || !filepath.IsAbs(candidate) {
		t.Fatal("controller binaries must be absolute paths")
	}
	f := setupQUICControllerFixture(t, goBinary)
	var snapshots [2]*lanewayv1.ControllerEnvelope
	for _, server := range []struct {
		name, binary string
		args         []string
	}{
		{"go-reference", goBinary, nil},
		{"rust-candidate", candidate, []string{"-serve-controller-candidate"}},
	} {
		t.Run(server.name, func(t *testing.T) {
			dir := t.TempDir()
			database := filepath.Join(dir, "controller.db")
			config := writeRunnableControllerConfig(t, dir, database, f.network, f.paths)
			if output, err := exec.CommandContext(f.ctx, server.binary, "-config", config, "-restore", f.backup).CombinedOutput(); err != nil {
				t.Fatalf("restore Go backup: %v\n%s", err, output)
			}
			https, quicAddr := startContractController(t, f.ctx, server.binary, config, server.args...)
			writer, err := controller.Open(f.ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = writer.Close() })
			node, ephemeral := readQUICWorkload(t, f.directory, "durable"), readQUICWorkload(t, f.directory, "ephemeral")
			nodeClient := f.client(t, https, quicAddr, node.cert, node.key)
			relayClient := f.client(t, https, quicAddr, f.relays["registered"][0], f.relays["registered"][1])
			fromNode, unchanged, err := nodeClient.Configuration(f.ctx, 0)
			if err != nil || unchanged || len(fromNode.GetOverlayAddresses()) != 1 ||
				fromNode.GetCertificateHealth() == nil || len(fromNode.GetPeers()) != 2 || len(fromNode.GetRelays()) != 1 {
				t.Fatalf("node configuration: unchanged=%v, %v, %v", unchanged, fromNode, err)
			}
			requireQUICLease(t, fromNode.GetValidUntilUnixSeconds(), ephemeral.expires)
			fromRelay, unchanged, err := relayClient.RelayConfiguration(f.ctx, 0)
			if err != nil || unchanged || fromRelay.GetConfigurationEpoch() != fromNode.GetConfigurationEpoch() ||
				fromRelay.GetCertificateHealth() == nil || len(fromRelay.GetPeers()) != 2 {
				t.Fatalf("relay configuration: unchanged=%v, %v, %v", unchanged, fromRelay, err)
			}
			requireQUICLease(t, fromRelay.GetValidUntilUnixSeconds(), ephemeral.expires)
			initialEpoch := fromNode.GetConfigurationEpoch()
			requireConfigurationParity(t, &snapshots, fromNode, fromRelay)

			rawNode := f.dial(t, quicAddr, node.cert, node.key)
			rawRelay := f.dial(t, quicAddr, f.relays["registered"][0], f.relays["registered"][1])
			for i := uint64(1); i <= 48; i++ {
				lease := rawQUICExchange(t, f.ctx, rawNode, nodeRequest(i, initialEpoch)).GetConfigurationLease()
				if lease.GetConfigurationEpoch() != initialEpoch {
					t.Fatalf("same-connection lease %d: %v", i, lease)
				}
				requireQUICLease(t, lease.GetValidUntilUnixSeconds(), ephemeral.expires)
			}
			lease := rawQUICExchange(t, f.ctx, rawRelay, relayRequest(1, initialEpoch)).GetConfigurationLease()
			if lease.GetConfigurationEpoch() != initialEpoch {
				t.Fatalf("conditional relay lease: %v", lease)
			}
			requireQUICLease(t, lease.GetValidUntilUnixSeconds(), ephemeral.expires)
			ahead := rawQUICExchange(t, f.ctx, rawNode, nodeRequest(49, initialEpoch+1)).GetError()
			if ahead.GetCode() != lanewayv1.ErrorCode_ERROR_CODE_STALE_EPOCH || ahead.GetRetryable() {
				t.Fatalf("future epoch: %v", ahead)
			}

			prefix := netip.MustParsePrefix("192.0.2.88/32")
			routeExpiry := time.Now().Add(time.Minute).Truncate(time.Second)
			route, err := writer.AdvertiseRoute(f.ctx, node.id, prefix, controller.RouteKindSubnet, controller.RouteModeNAT, 7, &routeExpiry)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.ApproveRoute(f.ctx, route.ID); err != nil {
				t.Fatal(err)
			}
			admin := f.client(t, https, quicAddr, "", "")
			rule, err := admin.AddACLRule(f.ctx, f.network, 80, "accept", []byte(`{"ip_protocol":"IP_PROTOCOL_ANY"}`), "fixture live policy")
			if err != nil {
				t.Fatal(err)
			}
			ruleID, err := identity.ParseID(rule.RuleID)
			if err != nil {
				t.Fatal(err)
			}
			epoch := rule.ConfigurationEpoch
			updatedNode := rawQUICExchange(t, f.ctx, rawNode, nodeRequest(50, initialEpoch)).GetNodeConfiguration()
			updatedRelay := rawQUICExchange(t, f.ctx, rawRelay, relayRequest(2, initialEpoch)).GetRelayConfiguration()
			if updatedNode.GetConfigurationEpoch() != epoch || updatedRelay.GetConfigurationEpoch() != epoch ||
				len(updatedNode.GetRoutes().GetRoutes()) != len(fromNode.GetRoutes().GetRoutes())+1 ||
				len(updatedNode.GetPolicy().GetRules()) != len(fromNode.GetPolicy().GetRules())+1 ||
				!proto.Equal(updatedNode.GetPolicy(), updatedRelay.GetPolicy()) ||
				proto.Equal(fromRelay, updatedRelay) {
				t.Fatalf("live route/policy change: node %v relay %v", updatedNode, updatedRelay)
			}
			requireQUICRouteAndRule(t, updatedNode, updatedRelay, route, ruleID, rule.Priority)
			if server.name == "rust-candidate" {
				// The candidate also caps lease reuse at the next approved route expiry.
				requireQUICLease(t, updatedNode.GetValidUntilUnixSeconds(), uint64(routeExpiry.Unix()))
				requireQUICLease(t, updatedRelay.GetValidUntilUnixSeconds(), uint64(routeExpiry.Unix()))
			}
			if _, err := writer.WithdrawRoute(f.ctx, route.ID, &node.id); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.DeleteACLRule(f.ctx, ruleID); err != nil {
				t.Fatal(err)
			}
			withdrawn := rawQUICExchange(t, f.ctx, rawNode, nodeRequest(51, epoch)).GetNodeConfiguration()
			if withdrawn.GetConfigurationEpoch() <= epoch ||
				len(withdrawn.GetRoutes().GetRoutes()) != len(fromNode.GetRoutes().GetRoutes()) ||
				len(withdrawn.GetPolicy().GetRules()) != len(fromNode.GetPolicy().GetRules()) {
				t.Fatalf("live route/policy withdrawal: %v", withdrawn)
			}
			checkQUICRenewal(t, f, dir, https, quicAddr, writer, nodeClient, rawRelay, node, ephemeral, withdrawn.GetConfigurationEpoch())

			for _, name := range []string{"unregistered", "foreign"} {
				paths := f.relays[name]
				unknown := f.client(t, https, quicAddr, paths[0], paths[1])
				if _, _, err := unknown.RelayConfiguration(f.ctx, 0); err == nil {
					t.Fatalf("accepted %s relay", name)
				}
			}
			checkQUICRequestRejection(t, f, quicAddr, node, f.relays["registered"])
			if server.name == "rust-candidate" {
				t.Run("native-node-and-relay", func(t *testing.T) {
					checkNativeQUICClients(t, f, https, quicAddr)
				})
			}
		})
	}
}

func setupQUICControllerFixture(t *testing.T, goBinary string) quicControllerFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	dir := t.TempDir()
	f := quicControllerFixture{ctx: ctx, directory: dir, backup: filepath.Join(dir, "backup.db"),
		network: identity.NetworkID{11}, foreign: identity.NetworkID{12}, service: identity.ID{13}, relay: identity.ID{14},
		relays: make(map[string][2]string)}
	now := time.Now()
	rootMaterial, root, err := pki.NewAuthority("QUIC fixture root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey, "QUIC fixture issuer", now.Add(-time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{NetworkID: f.network, ServiceID: f.service, Role: pki.RoleController}, []string{quicControllerName}, nil, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.paths = writeControllerRunPKI(t, dir, root, issuer, issuerMaterial, service)
	for _, entry := range []struct {
		name    string
		network identity.NetworkID
		service identity.ID
	}{
		{"registered", f.network, f.relay}, {"unregistered", f.network, identity.ID{16}}, {"foreign", f.foreign, f.relay},
	} {
		material, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{NetworkID: entry.network, ServiceID: entry.service, Role: pki.RoleRelay}, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cert, key := writeServicePair(t, dir, entry.name, material, issuer.Raw)
		f.relays[entry.name] = [2]string{cert, key}
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f.relayAddress = listener.LocalAddr().String()
	_ = listener.Close()
	if !t.Run("go-seed", func(t *testing.T) {
		db := filepath.Join(dir, "seed.db")
		config := writeRunnableControllerConfig(t, dir, db, f.network, f.paths)
		https, quicAddr := startContractController(t, ctx, goBinary, config)
		admin := f.client(t, https, quicAddr, "", "")
		if _, err := admin.RegisterRelay(ctx, f.network, f.relay, nil, "registered", f.relayAddress); err != nil {
			t.Fatal(err)
		}
		for _, class := range []string{"durable", "ephemeral"} {
			opt := controllerclient.EnrollmentTokenOptions{Class: class, RequestedName: class}
			if class == "durable" {
				opt.EnabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
			} else {
				opt.SessionLifetime = controller.MinEphemeralLifetime
			}
			token, err := admin.IssueEnrollmentTokenWithOptions(ctx, f.network, class, time.Now().Add(time.Minute), opt)
			if err != nil {
				t.Fatal(err)
			}
			csr, key := makeQUICCSR(t)
			_, wg, err := wireguard.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			enrollmentClass := lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
			if class == "ephemeral" {
				enrollmentClass = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
			}
			identity, err := admin.EnrollForNetworkAndClass(ctx, token.EnrollmentToken, class, csr, wg[:], f.network, enrollmentClass)
			if err != nil {
				t.Fatal(err)
			}
			persistQUICCredential(t, dir, class, key, identity.GetCertificateChain())
		}
		nativeToken, err := admin.IssueEnrollmentToken(ctx, f.network, "native-process", time.Now().Add(2*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		f.nativeToken = nativeToken.EnrollmentToken
		if output, err := exec.CommandContext(ctx, goBinary, "-config", config, "-backup", f.backup).CombinedOutput(); err != nil {
			t.Fatalf("Go backup: %v\n%s", err, output)
		}
	}) {
		t.FailNow()
	}
	return f
}

func (f quicControllerFixture) client(t *testing.T, https, quicAddr, cert, key string) *controllerclient.Client {
	t.Helper()
	opts := controllerclient.Options{Endpoint: "https://" + quicControllerName, DialAddress: https, CAFile: f.paths.rootCertificate,
		ServerName: quicControllerName, ExpectedNetworkID: f.network, ExpectedServiceID: f.service, CertificateFile: cert, PrivateKeyFile: key, Timeout: 4 * time.Second}
	if cert == "" {
		opts.AdminTokenFile = f.paths.adminToken
	} else {
		opts.QUICEndpoint = quicAddr
	}
	client, err := controllerclient.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func makeQUICCSR(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func persistQUICCredential(t *testing.T, dir, name string, key ed25519.PrivateKey, chain *lanewayv1.CertificateChain) quicWorkload {
	t.Helper()
	ders := chain.GetCertificatesDer()
	if len(ders) != 2 {
		t.Fatalf("expected leaf and intermediate, got %d", len(ders))
	}
	writeServicePair(t, dir, name, pki.Material{CertificateDER: ders[0], PrivateKey: key}, ders[1])
	return readQUICWorkload(t, dir, name)
}

func readQUICWorkload(t *testing.T, dir, name string) quicWorkload {
	t.Helper()
	cert, key := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.IdentityFromCertificate(pair.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	return quicWorkload{id: id.NodeID, cert: cert, key: key, leaf: pair.Leaf, expires: uint64(pair.Leaf.NotAfter.Unix())}
}

func (f quicControllerFixture) dial(t *testing.T, address, cert, key string) *quic.Conn {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(f.paths.rootCertificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid root certificate")
	}
	conn, err := quic.DialAddr(f.ctx, address, &tls.Config{ServerName: quicControllerName,
		RootCAs: roots, Certificates: []tls.Certificate{pair}, NextProtos: []string{controllerservice.ControllerALPN}, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "fixture complete") })
	return conn
}

func rawQUICExchange(t *testing.T, parent context.Context, conn *quic.Conn, req *lanewayv1.ControllerEnvelope) *lanewayv1.ControllerEnvelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteControlFrame(stream, data, protocol.DefaultMaxControlFrame); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := protocol.ReadControlFrame(stream, protocol.DefaultMaxControlFrame)
	if err != nil {
		t.Fatal(err)
	}
	var trailing [1]byte
	if n, err := stream.Read(trailing[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("QUIC response FIN: %d/%v", n, err)
	}
	env := new(lanewayv1.ControllerEnvelope)
	if err := proto.Unmarshal(result, env); err != nil {
		t.Fatal(err)
	}
	if env.GetSchemaVersion() != 1 || env.GetRequestId() != req.GetRequestId() {
		t.Fatalf("invalid QUIC envelope: %v", env)
	}
	return env
}

func checkQUICRequestRejection(t *testing.T, f quicControllerFixture, address string, node quicWorkload, relay [2]string) {
	t.Helper()
	for _, fixture := range []struct {
		name, cert, key string
		request         *lanewayv1.ControllerEnvelope
		trailing        bool
	}{
		{"node-as-relay", node.cert, node.key, relayRequest(1, 0), false},
		{"relay-as-node", relay[0], relay[1], nodeRequest(1, 0), false},
		{"zero-request-id", relay[0], relay[1], relayRequest(0, 0), false},
		{"trailing-request-data", relay[0], relay[1], relayRequest(1, 0), true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			conn := f.dial(t, address, fixture.cert, fixture.key)
			ctx, cancel := context.WithTimeout(f.ctx, 4*time.Second)
			defer cancel()
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			deadline, _ := ctx.Deadline()
			_ = stream.SetDeadline(deadline)
			data, err := proto.Marshal(fixture.request)
			if err != nil {
				t.Fatal(err)
			}
			if err := protocol.WriteControlFrame(stream, data, protocol.DefaultMaxControlFrame); err != nil {
				t.Fatal(err)
			}
			if fixture.trailing {
				if _, err := stream.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			_ = stream.Close()
			select {
			case <-conn.Context().Done():
				var closed *quic.ApplicationError
				if err := context.Cause(conn.Context()); !errors.As(err, &closed) || !closed.Remote || closed.ErrorCode != 0x103 {
					t.Fatalf("invalid request close error: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("controller left an invalid QUIC connection open")
			}
		})
	}
}

func nodeRequest(id, epoch uint64) *lanewayv1.ControllerEnvelope {
	return &lanewayv1.ControllerEnvelope{SchemaVersion: 1, RequestId: id, Body: &lanewayv1.ControllerEnvelope_ConfigurationRequest{ConfigurationRequest: &lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: epoch}}}
}

func relayRequest(id, epoch uint64) *lanewayv1.ControllerEnvelope {
	return &lanewayv1.ControllerEnvelope{SchemaVersion: 1, RequestId: id, Body: &lanewayv1.ControllerEnvelope_RelayConfigurationRequest{RelayConfigurationRequest: &lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: epoch}}}
}

func requireQUICLease(t *testing.T, got, bound uint64) {
	t.Helper()
	if got != bound || got <= uint64(time.Now().Unix()) {
		t.Fatalf("lease deadline %d did not match authorization bound %d", got, bound)
	}
}

func requireConfigurationParity(t *testing.T, prior *[2]*lanewayv1.ControllerEnvelope, node *lanewayv1.NodeConfiguration, relay *lanewayv1.RelayConfiguration) {
	t.Helper()
	for i, message := range [2]*lanewayv1.ControllerEnvelope{
		{Body: &lanewayv1.ControllerEnvelope_NodeConfiguration{NodeConfiguration: node}},
		{Body: &lanewayv1.ControllerEnvelope_RelayConfiguration{RelayConfiguration: relay}},
	} {
		if prior[i] == nil {
			prior[i] = message
			continue
		}
		if !proto.Equal(prior[i], message) {
			t.Fatalf("configuration %d differs from the Go reference:\nGo: %v\nRust: %v", i, prior[i], message)
		}
	}
}

func requireQUICRouteAndRule(t *testing.T, node *lanewayv1.NodeConfiguration, relay *lanewayv1.RelayConfiguration, route controller.Route, ruleID identity.ID, priority uint32) {
	t.Helper()
	prefixMatches := func(prefix *lanewayv1.IpPrefix) bool {
		return bytes.Equal(prefix.GetAddress(), route.Prefix.Addr().AsSlice()) && int(prefix.GetPrefixLength()) == route.Prefix.Bits()
	}
	if !slices.ContainsFunc(node.GetRoutes().GetRoutes(), func(entry *lanewayv1.Route) bool {
		return bytes.Equal(entry.GetRouteId(), route.ID[:]) && bytes.Equal(entry.GetViaNodeId(), route.NodeID[:]) &&
			entry.GetMetric() == route.Metric && prefixMatches(entry.GetDestination()) &&
			entry.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_SUBNET && entry.GetMode() == lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT
	}) {
		t.Fatalf("node snapshot omitted the new approved subnet %s", route.Prefix)
	}
	if !slices.ContainsFunc(relay.GetPeers(), func(peer *lanewayv1.RelayPeerAuthorization) bool {
		return bytes.Equal(peer.GetNodeId(), route.NodeID[:]) && slices.ContainsFunc(peer.GetAuthorizedPrefixes(), prefixMatches)
	}) {
		t.Fatalf("relay snapshot omitted %s from its owner's authorized prefixes", route.Prefix)
	}
	if !slices.ContainsFunc(node.GetPolicy().GetRules(), func(entry *lanewayv1.PolicyRule) bool {
		return bytes.Equal(entry.GetRuleId(), ruleID[:]) && entry.GetPriority() == priority &&
			entry.GetAction() == lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT
	}) {
		t.Fatalf("snapshots omitted the added ACL rule %s", ruleID)
	}
}

func checkQUICRenewal(t *testing.T, f quicControllerFixture, dir, https, quicAddr string, writer *controller.Store,
	client *controllerclient.Client, relay *quic.Conn, node, ephemeral quicWorkload, initialEpoch uint64) {
	t.Helper()
	csr, key := makeQUICCSR(t)
	_, replacement, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := client.Renew(f.ctx, csr, replacement[:])
	if err != nil || !bytes.Equal(renewed.GetWireguardPublicKey(), replacement[:]) {
		t.Fatalf("WireGuard key replacement: %v", err)
	}
	persisted, err := writer.Node(f.ctx, node.id)
	if err != nil || !bytes.Equal(persisted.WireGuardPublicKey[:], replacement[:]) {
		t.Fatalf("Go could not read the renewed WireGuard binding from SQLite: %v", err)
	}
	newNode := persistQUICCredential(t, dir, "renewed", key, renewed.GetCertificateChain())
	if newNode.id != node.id || newNode.leaf.SerialNumber.Cmp(node.leaf.SerialNumber) == 0 {
		t.Fatal("renewal changed identity or reused old serial")
	}
	newClient := f.client(t, https, quicAddr, newNode.cert, newNode.key)
	newSnapshot, unchanged, err := newClient.Configuration(f.ctx, 0)
	if err != nil || unchanged || newSnapshot.GetConfigurationEpoch() != initialEpoch+1 {
		t.Fatalf("renewal did not advance epoch once: %v, %v", newSnapshot, err)
	}
	if _, _, err := client.Configuration(f.ctx, 0); err != nil {
		t.Fatalf("previous certificate rejected before revocation: %v", err)
	}
	csr, _ = makeQUICCSR(t)
	repeat, err := newClient.Renew(f.ctx, csr, nil)
	if err != nil || !bytes.Equal(repeat.GetWireguardPublicKey(), replacement[:]) {
		t.Fatalf("omitted WireGuard key did not keep stored key: %v", err)
	}
	_, unchanged, err = newClient.Configuration(f.ctx, newSnapshot.GetConfigurationEpoch())
	if err != nil || !unchanged {
		t.Fatalf("preserving key changed epoch: %v", err)
	}
	ephemeralClient := f.client(t, https, quicAddr, ephemeral.cert, ephemeral.key)
	csr, _ = makeQUICCSR(t)
	bounded, err := ephemeralClient.Renew(f.ctx, csr, nil)
	if err != nil || bounded.GetCertificateChain().GetNotAfterUnixSeconds() != ephemeral.expires {
		t.Fatalf("renewal exceeded ephemeral lease: %v", err)
	}
	serial := node.leaf.SerialNumber.Bytes()
	revokedEpoch, err := writer.RevokeCertificateBySerial(f.ctx, f.network, serial, "fixture old certificate")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Configuration(f.ctx, 0); err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("expected old certificate rejection on its existing client: %v", err)
	}
	fresh := rawQUICExchange(t, f.ctx, relay, relayRequest(3, newSnapshot.GetConfigurationEpoch())).GetRelayConfiguration()
	if fresh.GetConfigurationEpoch() != revokedEpoch || len(fresh.GetRevokedCertificateSerials()) != 1 ||
		!bytes.Equal(fresh.GetRevokedCertificateSerials()[0], serial) {
		t.Fatalf("live relay revocation snapshot: %v", fresh)
	}
	if _, _, err := newClient.Configuration(f.ctx, 0); err != nil {
		t.Fatalf("unrevoked replacement lost access: %v", err)
	}
}

func checkNativeQUICClients(t *testing.T, f quicControllerFixture, https, quicAddr string) {
	t.Helper()
	node, relay := os.Getenv("LANEWAY_CONTROLLER_QUIC_NODE_BIN"), os.Getenv("LANEWAY_CONTROLLER_QUIC_RELAY_BIN")
	if node == "" && relay == "" {
		t.Skip("set LANEWAY_CONTROLLER_QUIC_NODE_BIN and LANEWAY_CONTROLLER_QUIC_RELAY_BIN")
	}
	if !filepath.IsAbs(node) || !filepath.IsAbs(relay) {
		t.Fatal("native node and relay binaries must be absolute paths")
	}
	dir := t.TempDir()
	relayConfig := filepath.Join(dir, "relay.toml")
	registered := f.relays["registered"]
	config := fmt.Sprintf(`mode = "relay"
state_dir = %q
socket_path = %q
[tls]
certificate = %q
private_key = %q
ca = %q
[relay]
listen = %q
[controller]
endpoint = %q
quic_endpoint = %q
server_name = %q
network_id = %q
service_id = %q
poll_interval = "100ms"
`, filepath.Join(dir, "relay"), filepath.Join(dir, "relay.sock"), registered[0], registered[1],
		f.paths.rootCertificate, f.relayAddress, "https://"+https, quicAddr, quicControllerName, f.network, f.service)
	if err := os.WriteFile(relayConfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	diagnostics := reserve.Addr().String()
	_ = reserve.Close()
	relayLog := startNativeQUICFixture(t, f.ctx, dir, "relay", relay, "--config", relayConfig, "--diagnostics", diagnostics)

	ca, err := os.ReadFile(f.paths.rootCertificate)
	if err != nil {
		t.Fatal(err)
	}
	setup := strings.Join([]string{
		"native-process", f.nativeToken, "https://" + https, quicAddr, quicControllerName,
		f.network.String(), f.service.String(), f.relayAddress, f.relay.String(),
		base64.StdEncoding.EncodeToString(ca),
	}, "\n") + "\n"
	token := "st1." + base64.StdEncoding.EncodeToString([]byte(setup))
	state := filepath.Join(dir, "node")
	enroll := exec.CommandContext(f.ctx, node, "enroll", "--state-dir", state)
	enroll.Stdin = strings.NewReader(token + "\n")
	if output, err := enroll.CombinedOutput(); err != nil {
		t.Fatalf("Rust node enrollment: %v\n%s", err, output)
	}

	nodeLog := startNativeQUICFixture(t, f.ctx, dir, "node", node, "run", "--state-dir", state, "--no-proxy")
	httpClient := &http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{},
	}
	t.Cleanup(httpClient.CloseIdleConnections)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && f.ctx.Err() == nil {
		response, err := httpClient.Get("http://" + diagnostics + "/metrics")
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK &&
				bytes.Contains(data, []byte("\nlaneway_relay_sessions 1\n")) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	nodeOutput, _ := os.ReadFile(nodeLog)
	relayOutput, _ := os.ReadFile(relayLog)
	t.Fatalf("native Rust node never established a controller-authorized Rust relay session\nnode: %s\nrelay: %s", nodeOutput, relayOutput)
}

func startNativeQUICFixture(t *testing.T, ctx context.Context, dir, name, binary string, args ...string) string {
	t.Helper()
	log := filepath.Join(dir, name+".log")
	file, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout, command.Stderr = file, file
	err = command.Start()
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		_ = command.Wait()
	})
	return log
}
