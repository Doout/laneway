//go:build rustinterop

package rustrelay_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/controllerservice"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/platform"
	"github.com/Doout/laneway/go/internal/transport"
	"google.golang.org/protobuf/proto"
)

type relayPollObservation struct {
	known  uint64
	status int
	epoch  uint64
}

type relayPollRecorder struct {
	handler  http.Handler
	mu       sync.Mutex
	polls    []relayPollObservation
	oversize atomic.Bool
}

// This is the cross-language control-transport gate: a production Rust relay
// cannot finish startup until it has authenticated the Go controller over
// QUIC and compiled the returned protobuf RelayConfiguration.
func TestGoControllerQUICBootstrapsLiveRustRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository := repositoryRoot(t)
	directory := t.TempDir()
	relayBinary := buildRustRelay(t, ctx, repository, directory)
	store, err := controller.Open(ctx, filepath.Join(directory, "controller-quic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	network, err := store.CreateNetwork(ctx, "rust-quic", netip.MustParsePrefix("100.98.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caMaterial, ca, err := pki.NewAuthority("Rust QUIC controller CA", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "quic-ca.crt")
	writeFile(t, caPath, pki.CertificatePEM(caMaterial.CertificateDER), 0o644)
	controllerID := randomID(t)
	controllerMaterial, controllerLeaf, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: controllerID, Role: pki.RoleController,
	}, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayID := randomID(t)
	relayMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterRelay(ctx, network.ID, relayID, nil, "rust-quic", "127.0.0.1:4433"); err != nil {
		t.Fatal(err)
	}
	service, err := controllerservice.New(controllerservice.Options{
		Store: store, CACertificate: ca, CAKey: caMaterial.PrivateKey,
		LeafValidity: time.Hour, SnapshotValidity: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	quicServer, err := service.ListenQUIC("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{controllerMaterial.CertificateDER}, PrivateKey: controllerMaterial.PrivateKey, Leaf: controllerLeaf}},
		ClientCAs:    roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- quicServer.Serve(ctx) }()
	defer func() { _ = quicServer.Close() }()
	relayCert, relayKey := writeLeaf(t, directory, "quic-controller-relay", relayMaterial)
	listen := availableUDPAddress(t)
	configPath := filepath.Join(directory, "controller-quic-relay.toml")
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
[controller]
endpoint = "https://127.0.0.1:1"
quic_endpoint = %q
network_id = %q
service_id = %q
server_name = "127.0.0.1"
poll_interval = "100ms"
timeout = "3s"
`, directory, filepath.Join(directory, "relay.sock"), relayCert, relayKey, caPath,
		listen, quicServer.Addr().String(), network.ID.String(), controllerID.String())
	writeFile(t, configPath, []byte(config), 0o600)
	var logs lockedBuffer
	process := exec.Command(relayBinary, "--config", configPath)
	process.Stdout, process.Stderr = &logs, &logs
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	defer stopRustRelay(process, processDone)
	waitFor(t, ctx, "Rust relay QUIC controller bootstrap", func() bool {
		select {
		case err := <-processDone:
			t.Fatalf("Rust relay exited before QUIC bootstrap: %v\n%s", err, logs.String())
		default:
		}
		return bytes.Contains([]byte(logs.String()), []byte("laneway Rust relay listening"))
	})
}

func (r *relayPollRecorder) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/relay/configuration" {
		r.handler.ServeHTTP(response, request)
		return
	}
	if r.oversize.Load() {
		response.Header().Set("Content-Length", "16777217")
		response.WriteHeader(http.StatusOK)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, controllerservice.DefaultMaxBodyBytes+1))
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	input := new(lanewayv1.RelayConfigurationRequest)
	_ = proto.Unmarshal(body, input)
	recorded := httptest.NewRecorder()
	r.handler.ServeHTTP(recorded, request)
	for name, values := range recorded.Header() {
		response.Header()[name] = append([]string(nil), values...)
	}
	response.WriteHeader(recorded.Code)
	_, _ = response.Write(recorded.Body.Bytes())
	observation := relayPollObservation{known: input.GetKnownConfigurationEpoch(), status: recorded.Code}
	if recorded.Code == http.StatusOK {
		configuration := new(lanewayv1.RelayConfiguration)
		if proto.Unmarshal(recorded.Body.Bytes(), configuration) == nil {
			observation.epoch = configuration.GetConfigurationEpoch()
		}
	}
	r.mu.Lock()
	r.polls = append(r.polls, observation)
	r.mu.Unlock()
}

func (r *relayPollRecorder) observed(match func(relayPollObservation) bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, poll := range r.polls {
		if match(poll) {
			return true
		}
	}
	return false
}

func TestGoControllerDrivesLiveRustRelaySnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	repository := repositoryRoot(t)
	directory := t.TempDir()
	relayBinary := buildRustRelay(t, ctx, repository, directory)

	store, err := controller.Open(ctx, filepath.Join(directory, "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	network, err := store.CreateNetwork(ctx, "rust-live", netip.MustParsePrefix("100.97.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caMaterial, ca, err := pki.NewAuthority("Rust live controller CA", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.crt")
	writeFile(t, caPath, pki.CertificatePEM(caMaterial.CertificateDER), 0o644)

	nodeA, materialA, certificateA := enrollControllerNode(t, ctx, store, ca, caMaterial, network.ID, "node-a")
	nodeB, materialB, _ := enrollControllerNode(t, ctx, store, ca, caMaterial, network.ID, "node-b")
	if _, _, err := store.AddACLRule(ctx, network.ID, 1, controller.ACLActionAccept,
		`{"ipProtocol":"IP_PROTOCOL_ANY"}`, "allow live interop"); err != nil {
		t.Fatal(err)
	}

	controllerID := randomID(t)
	controllerMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: controllerID, Role: pki.RoleController,
	}, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayID := randomID(t)
	relayMaterial, _, err := pki.IssueService(ca, caMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network.ID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterRelay(ctx, network.ID, relayID, nil, "rust-live", "127.0.0.1:4433"); err != nil {
		t.Fatal(err)
	}

	service, err := controllerservice.New(controllerservice.Options{
		Store: store, CACertificate: ca, CAKey: caMaterial.PrivateKey,
		LeafValidity: time.Hour, SnapshotValidity: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	polls := &relayPollRecorder{handler: service.Handler()}
	controllerServer := startMTLSController(t, polls, ca, controllerMaterial)

	relayCert, relayKey := writeLeaf(t, directory, "controller-relay", relayMaterial)
	listen := availableUDPAddress(t)
	configPath := filepath.Join(directory, "controller-relay.toml")
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
[controller]
endpoint = %q
allow_legacy_https = true
network_id = %q
service_id = %q
server_name = "127.0.0.1"
poll_interval = "100ms"
`, directory, filepath.Join(directory, "relay.sock"), relayCert, relayKey, caPath,
		listen, controllerServer.URL, network.ID.String(), controllerID.String())
	writeFile(t, configPath, []byte(config), 0o600)

	var logs lockedBuffer
	process := exec.Command(relayBinary, "--config", configPath)
	process.Stdout, process.Stderr = &logs, &logs
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	defer stopRustRelay(process, processDone)
	waitForRustRelayPoll(t, ctx, processDone, &logs, "Rust relay initial 200", func() bool {
		return polls.observed(func(p relayPollObservation) bool { return p.status == http.StatusOK && p.epoch > 0 })
	})
	var initialEpoch uint64
	polls.mu.Lock()
	for _, poll := range polls.polls {
		if poll.status == http.StatusOK && poll.epoch > initialEpoch {
			initialEpoch = poll.epoch
		}
	}
	polls.mu.Unlock()
	waitFor(t, ctx, "Rust relay conditional 304", func() bool {
		return polls.observed(func(p relayPollObservation) bool {
			return p.status == http.StatusNotModified && p.known == initialEpoch
		})
	})

	clientATLS := nodeClientTLS(t, directory, caPath, "live-a", materialA)
	clientBTLS := nodeClientTLS(t, directory, caPath, "live-b", materialB)
	tunA := memoryTUN(t, "liveA", nodeA.Node.IPv4Address)
	tunB := memoryTUN(t, "liveB", nodeB.Node.IPv4Address)
	defer tunA.Close()
	defer tunB.Close()
	serviceA := newNode(t, identity.NodeIdentity{NetworkID: network.ID, NodeID: nodeA.Node.ID}, clientATLS, listen, tunA, nodeB.Node.ID, nodeB.Node.IPv4Address)
	serviceB := newNode(t, identity.NodeIdentity{NetworkID: network.ID, NodeID: nodeB.Node.ID}, clientBTLS, listen, tunB, nodeA.Node.ID, nodeA.Node.IPv4Address)
	nodeCtx, stopNodes := context.WithCancel(ctx)
	defer stopNodes()
	nodeADone, nodeBDone := make(chan error, 1), make(chan error, 1)
	go func() { nodeADone <- serviceA.RunSession(nodeCtx) }()
	go func() { nodeBDone <- serviceB.RunSession(nodeCtx) }()
	packet, err := nodeservice.IPv4Packet(nodeA.Node.IPv4Address, nodeB.Node.IPv4Address, []byte("controller-backed Rust relay"))
	if err != nil {
		t.Fatal(err)
	}
	waitForPacket(t, ctx, tunA, tunB, packet)

	revokedEpoch, err := store.RevokeCertificate(ctx, nodeA.Certificate.ID, "live Rust relay revocation")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, ctx, "Rust relay monotonic revocation snapshot", func() bool {
		return polls.observed(func(p relayPollObservation) bool {
			return p.status == http.StatusOK && p.known == initialEpoch && p.epoch == revokedEpoch
		})
	})
	waitFor(t, ctx, "Rust relay revocation 304", func() bool {
		return polls.observed(func(p relayPollObservation) bool {
			return p.status == http.StatusNotModified && p.known == revokedEpoch
		})
	})
	waitChannel(t, nodeADone, 4*time.Second, "revoked Rust relay session")
	if certificateA.SerialNumber.Sign() <= 0 {
		t.Fatal("issued node certificate has invalid serial")
	}
	polls.oversize.Store(true)
	waitFor(t, ctx, "pre-allocation controller response bound", func() bool {
		return bytes.Contains([]byte(logs.String()), []byte("controller response exceeds limit"))
	})

	// With the controller unavailable, a renewed 304 lease cannot be fetched.
	// The Rust relay must fail closed and terminate the remaining live session
	// once the last bounded snapshot validity deadline passes.
	controllerServer.Close()
	waitChannel(t, nodeBDone, 5*time.Second, "expired Rust relay snapshot session")

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
}

func buildRustRelay(t *testing.T, ctx context.Context, repository, directory string) string {
	t.Helper()
	binary := filepath.Join(directory, "laneway-relay")
	command := exec.CommandContext(ctx, "cargo", "build", "--quiet", "--locked", "--manifest-path", filepath.Join(repository, "rust", "Cargo.toml"), "-p", "laneway-relay")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Rust relay: %v\n%s", err, output)
	}
	if err := copyFile(filepath.Join(repository, "rust", "target", "debug", "laneway-relay"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	return binary
}

func enrollControllerNode(t *testing.T, ctx context.Context, store *controller.Store, ca *x509.Certificate, caMaterial pki.Material, network identity.NetworkID, name string) (controller.Enrollment, pki.Material, *x509.Certificate) {
	t.Helper()
	token, err := store.IssueEnrollmentToken(ctx, network, name, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var material pki.Material
	var certificate *x509.Certificate
	enrollment, err := store.EnrollNodeWithCertificate(ctx, token.Secret, name, 0, func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
		issued, leaf, issueErr := pki.IssueNode(ca, caMaterial.PrivateKey, identity.NodeIdentity{NetworkID: network, NodeID: node.ID}, time.Now(), time.Hour)
		if issueErr != nil {
			return controller.CertificateMaterial{}, issueErr
		}
		material, certificate = issued, leaf
		return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return enrollment, material, certificate
}

func startMTLSController(t *testing.T, handler http.Handler, ca *x509.Certificate, material pki.Material) *httptest.Server {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(func() { server.Close() })
	return server
}

func nodeClientTLS(t *testing.T, directory, caPath, name string, material pki.Material) *tls.Config {
	t.Helper()
	certificate, key := writeLeaf(t, directory, name, material)
	config, err := transport.LoadClientTLSConfig(caPath, certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func waitForPacket(t *testing.T, ctx context.Context, source, destination *platform.MemoryTUN, packet []byte) {
	t.Helper()
	received := make(chan []byte, 1)
	go func() {
		value, err := destination.Receive(ctx)
		if err == nil {
			received <- value
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := source.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case value := <-received:
			if !bytes.Equal(value, packet) {
				t.Fatalf("packet differs: %x", value)
			}
			return
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func waitFor(t *testing.T, ctx context.Context, description string, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
		}
	}
}

func waitForRustRelayPoll(t *testing.T, ctx context.Context, processDone <-chan error, logs *lockedBuffer, description string, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case err := <-processDone:
			t.Fatalf("Rust relay exited waiting for %s: %v\n%s", description, err, logs.String())
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s: %v\n%s", description, ctx.Err(), logs.String())
		}
	}
}

func waitChannel(t *testing.T, channel <-chan error, timeout time.Duration, description string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func stopRustRelay(process *exec.Cmd, done <-chan error) {
	if process.ProcessState != nil && process.ProcessState.Exited() {
		return
	}
	_ = process.Process.Kill()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}
