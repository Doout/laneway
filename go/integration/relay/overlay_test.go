package relay_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nodeservice"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/relay"
	"laneway.dev/laneway/internal/relayservice"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/transport"
)

func TestTwoNodesExchangePacketThroughRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	network := identity.NetworkID(fixedID(1))
	nodeA := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(2))}
	nodeB := identity.NodeIdentity{NetworkID: network, NodeID: identity.NodeID(fixedID(3))}
	addressA := netip.MustParseAddr("100.96.0.1")
	addressB := netip.MustParseAddr("100.96.0.2")
	serverTLS, clientATLS, clientBTLS := testTLS(t, network, nodeA, nodeB)

	listener, err := transport.Listen("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := relayservice.New(relayservice.Config{
		Authorizer: relayservice.StaticAuthorizer{
			nodeA: {OverlayAddresses: []netip.Addr{addressA}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressA, 32)}},
			nodeB: {OverlayAddresses: []netip.Addr{addressB}, AuthorizedPrefixes: []netip.Prefix{netip.PrefixFrom(addressB, 32)}},
		},
		Registry: relay.Config{
			MaxSessions: 8, MaxHandlesPerSession: 8, OutboundQueueCapacity: 8,
			MaxPacketPayload: 1200, DuplicatePolicy: relay.RejectDuplicate, QueuePolicy: relay.DropNewest,
		},
		MaxPacketPayload: 1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(ctx, listener) }()

	tunA, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "laneA", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressA, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunA.Close()
	tunB, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "laneB", MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(addressB, 32)}}, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer tunB.Close()

	serviceA := newNode(t, nodeA, clientATLS, listener.Addr().String(), tunA, nodeB.NodeID, addressB)
	serviceB := newNode(t, nodeB, clientBTLS, listener.Addr().String(), tunB, nodeA.NodeID, addressA)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(ctx) }()
	go func() { nodeDone <- serviceB.RunSession(ctx) }()
	bindingsReady := time.NewTicker(10 * time.Millisecond)
	defer bindingsReady.Stop()
	for server.Registry().Metrics().Bindings != 2 {
		select {
		case err := <-nodeDone:
			t.Fatalf("node session stopped before binding: %v", err)
		case err := <-serverDone:
			t.Fatalf("relay stopped before binding: %v", err)
		case <-bindingsReady.C:
		case <-ctx.Done():
			t.Fatalf("bindings not established: metrics=%#v", server.Registry().Metrics())
		}
	}

	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("laneway integration"))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		payload, receiveErr := tunB.Receive(ctx)
		if receiveErr == nil {
			received <- payload
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := tunA.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-received:
			if string(got) != string(packet) {
				t.Fatalf("received packet differs: %x", got)
			}
			if server.Registry().Metrics().ForwardedPackets == 0 {
				t.Fatal("relay did not count forwarded packet")
			}
			cancel()
			waitDone(t, serverDone)
			waitDone(t, nodeDone)
			waitDone(t, nodeDone)
			return
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("timed out waiting for relayed packet")
		}
	}
}

type tunAdapter struct{ platform.TUNDevice }

func (t tunAdapter) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	return t.Read(ctx, buffer)
}

func (t tunAdapter) WritePacket(ctx context.Context, packet []byte) error {
	_, err := t.Write(ctx, packet)
	return err
}

func newNode(t *testing.T, id identity.NodeIdentity, tlsConfig *tls.Config, relayAddress string, tun platform.TUNDevice, peer identity.NodeID, peerAddress netip.Addr) *nodeservice.Service {
	t.Helper()
	snapshot, err := routing.NewSnapshot([]routing.Route{{Prefix: netip.PrefixFrom(peerAddress, 32), NextHop: peer}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity: id, BootID: randomID(t), RelayAddress: relayAddress, TLSConfig: tlsConfig,
		Routes: routing.NewTable(snapshot), Packets: tunAdapter{tun},
		MaxControlPayload: protocol.DefaultMaxControlFrame, MaxRoutes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testTLS(t *testing.T, network identity.NetworkID, nodes ...identity.NodeIdentity) (*tls.Config, *tls.Config, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	caMaterial, ca, err := pki.NewAuthority("Laneway integration CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	write(t, caPath, pki.CertificatePEM(caMaterial.CertificateDER), 0o644)
	serviceID := fixedID(4)
	relayMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: serviceID, Role: pki.RoleRelay,
	}, []string{"relay.test"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCert, relayKey := writeLeaf(t, dir, "relay", relayMaterial)
	serverTLS, err := transport.LoadServerTLSConfig(caPath, relayCert, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]*tls.Config, 0, len(nodes))
	for i, node := range nodes {
		material, _, err := pki.IssueNode(ca, caMaterial.PrivateKey, node, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := writeLeaf(t, dir, "node"+string(rune('A'+i)), material)
		clientTLS, err := transport.LoadClientTLSConfig(caPath, certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, clientTLS)
	}
	return serverTLS, clients[0], clients[1]
}

func writeLeaf(t *testing.T, dir, name string, material pki.Material) (string, string) {
	t.Helper()
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	write(t, certPath, pki.CertificatePEM(material.CertificateDER), 0o644)
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	write(t, keyPath, key, 0o600)
	return certPath, keyPath
}

func write(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func fixedID(last byte) identity.ID {
	var id identity.ID
	id[len(id)-1] = last
	return id
}

func randomID(t *testing.T) identity.ID {
	t.Helper()
	id, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func eventually(t *testing.T, ctx context.Context, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("condition not met before timeout")
		}
	}
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("service did not stop after cancellation")
	}
}
