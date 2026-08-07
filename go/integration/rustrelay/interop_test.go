//go:build rustinterop

package rustrelay_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nodeservice"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/transport"
)

func TestGoNodesExchangePacketThroughRustRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "laneway-relay")
	build := exec.CommandContext(ctx, "cargo", "build", "--quiet", "--manifest-path", filepath.Join(repository, "rust", "Cargo.toml"), "-p", "laneway-relay")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Rust relay: %v\n%s", err, output)
	}
	if err := copyFile(filepath.Join(repository, "rust", "target", "debug", "laneway-relay"), binary, 0o755); err != nil {
		t.Fatal(err)
	}

	networkID := identity.NetworkID(fixedID(1))
	nodeA := identity.NodeIdentity{NetworkID: networkID, NodeID: identity.NodeID(fixedID(2))}
	nodeB := identity.NodeIdentity{NetworkID: networkID, NodeID: identity.NodeID(fixedID(3))}
	addressA := netip.MustParseAddr("100.96.0.1")
	addressB := netip.MustParseAddr("100.96.0.2")
	directory := t.TempDir()
	caPath, relayCert, relayKey, clientATLS, clientBTLS := credentials(t, directory, networkID, nodeA, nodeB)
	listen := availableUDPAddress(t)
	configPath := filepath.Join(directory, "relay.toml")
	config := fmt.Sprintf(`mode = "relay"
state_dir = %q
socket_path = %q

[tls]
certificate = %q
private_key = %q
ca = %q

[relay]
listen = %q
queue_depth = 16
max_sessions = 8
max_routes = 8
handshake_timeout = "5s"
idle_timeout = "15s"
metrics_interval = "0s"

[[peers]]
network_id = %q
node_id = %q
prefixes = ["100.96.0.1/32"]

[[peers]]
network_id = %q
node_id = %q
prefixes = ["100.96.0.2/32"]
`, directory, filepath.Join(directory, "relay.sock"), relayCert, relayKey, caPath, listen,
		networkID.String(), nodeA.NodeID.String(), networkID.String(), nodeB.NodeID.String())
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	var logs lockedBuffer
	process := exec.Command(binary, "--config", configPath)
	process.Stdout, process.Stderr = &logs, &logs
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	defer func() {
		if process.ProcessState == nil || !process.ProcessState.Exited() {
			_ = process.Process.Kill()
			<-processDone
		}
	}()
	select {
	case err := <-processDone:
		t.Fatalf("Rust relay exited during startup: %v\n%s", err, logs.String())
	case <-time.After(150 * time.Millisecond):
	}

	tunA := memoryTUN(t, "laneA", addressA)
	defer tunA.Close()
	tunB := memoryTUN(t, "laneB", addressB)
	defer tunB.Close()
	serviceA := newNode(t, nodeA, clientATLS, listen, tunA, nodeB.NodeID, addressB)
	serviceB := newNode(t, nodeB, clientBTLS, listen, tunB, nodeA.NodeID, addressA)
	nodeCtx, stopNodes := context.WithCancel(ctx)
	nodeDone := make(chan error, 2)
	go func() { nodeDone <- serviceA.RunSession(nodeCtx) }()
	go func() { nodeDone <- serviceB.RunSession(nodeCtx) }()

	packet, err := nodeservice.IPv4Packet(addressA, addressB, []byte("go-rust-laneway-interoperability"))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		payload, receiveErr := tunB.Receive(nodeCtx)
		if receiveErr == nil {
			received <- payload
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := tunA.Inject(nodeCtx, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-received:
			if !bytes.Equal(got, packet) {
				t.Fatalf("received packet differs: %x", got)
			}
			stopNodes()
			waitResult(t, nodeDone, 2*time.Second)
			waitResult(t, nodeDone, 2*time.Second)
			if err := process.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-processDone:
				if err != nil {
					t.Fatalf("Rust relay shutdown: %v\n%s", err, logs.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("Rust relay did not stop\n%s", logs.String())
			}
			return
		case err := <-nodeDone:
			t.Fatalf("Go node stopped before forwarding: %v\n%s", err, logs.String())
		case err := <-processDone:
			t.Fatalf("Rust relay stopped before forwarding: %v\n%s", err, logs.String())
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for Go→Rust→Go packet: %v\n%s", ctx.Err(), logs.String())
		}
	}
}

type tunAdapter struct{ platform.TUNDevice }

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(data)
}

// ReadFrom prevents os/exec from reaching the embedded bytes.Buffer's
// promoted ReaderFrom implementation without taking the lock.
func (b *lockedBuffer) ReadFrom(reader io.Reader) (int64, error) {
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			written, writeErr := b.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

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

func credentials(t *testing.T, directory string, network identity.NetworkID, nodes ...identity.NodeIdentity) (string, string, string, *tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caMaterial, ca, err := pki.NewAuthority("Laneway Rust interop CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.crt")
	writeFile(t, caPath, pki.CertificatePEM(caMaterial.CertificateDER), 0o644)
	relayMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: fixedID(4), Role: pki.RoleRelay,
	}, []string{"relay.test"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCert, relayKey := writeLeaf(t, directory, "relay", relayMaterial)
	clients := make([]*tls.Config, 0, len(nodes))
	for index, node := range nodes {
		material, _, issueErr := pki.IssueNode(ca, caMaterial.PrivateKey, node, now, time.Hour)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		certPath, keyPath := writeLeaf(t, directory, fmt.Sprintf("node%d", index), material)
		client, loadErr := transport.LoadClientTLSConfig(caPath, certPath, keyPath)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		clients = append(clients, client)
	}
	return caPath, relayCert, relayKey, clients[0], clients[1]
}

func memoryTUN(t *testing.T, name string, address netip.Addr) *platform.MemoryTUN {
	t.Helper()
	tun, err := platform.NewMemoryTUN(platform.TUNConfig{
		Name: name, MTU: 1200, Addresses: []netip.Prefix{netip.PrefixFrom(address, 32)},
	}, 16)
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

func writeLeaf(t *testing.T, directory, name string, material pki.Material) (string, string) {
	t.Helper()
	certificate, key := filepath.Join(directory, name+".crt"), filepath.Join(directory, name+".key")
	writeFile(t, certificate, pki.CertificatePEM(material.CertificateDER), 0o644)
	keyPEM, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, key, keyPEM, 0o600)
	return certificate, key
}

func writeFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func copyFile(source, destination string, mode os.FileMode) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, contents, mode)
}

func availableUDPAddress(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().String()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate interoperability test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
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

func waitResult(t *testing.T, done <-chan error, maximum time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(maximum):
		t.Fatal("service did not stop")
	}
}
