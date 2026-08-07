package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/protocol"
)

func validMetadata(t *testing.T, now time.Time) Metadata {
	t.Helper()
	material, _, err := pki.NewAuthority("bootstrap test", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified release")
	digest := sha256.Sum256(payload)
	return Metadata{
		SchemaVersion: SchemaVersion, GeneratedAt: now.Unix(), ValidUntil: now.Add(5 * time.Minute).Unix(),
		NetworkID: "000102030405060708090a0b0c0d0e0f",
		Controller: Controller{
			EnrollmentEndpoint: "https://controller.example.test:8443",
			QUICEndpoint:       "controller.example.test:8443", ServerName: "controller.example.test",
			ServiceID: "101112131415161718191a1b1c1d1e1f",
		},
		Relays:   []Relay{{Name: "relay", Endpoint: "relay.example.test:4433", ServiceID: "202122232425262728292a2b2c2d2e2f"}},
		Trust:    Trust{CAPEM: string(pki.CertificatePEM(material.CertificateDER))},
		Protocol: Protocol{ControlMajor: 1, Packet: []uint32{1}, Capabilities: uint64(protocol.KnownCapabilities)},
		Artifacts: []Artifact{
			{OS: "linux", Arch: "amd64", URL: "https://downloads.example.test/laneway-amd64.tar.gz", SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(payload))},
			{OS: "linux", Arch: "arm64", URL: "https://downloads.example.test/laneway-arm64.tar.gz", SHA256: strings.Repeat("0", 64), SizeBytes: 1},
		},
	}
}

func TestMetadataValidationAndStrictDecode(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	metadata := validMetadata(t, now)
	if err := metadata.Validate(now); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bytes.NewReader(encoded), now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Metadata){
		"expired":             func(value *Metadata) { value.ValidUntil = now.Add(-time.Second).Unix() },
		"controller identity": func(value *Metadata) { value.Controller.ServiceID = strings.Repeat("0", 32) },
		"relay endpoint":      func(value *Metadata) { value.Relays[0].Endpoint = "https://relay.example.test" },
		"artifact digest":     func(value *Metadata) { value.Artifacts[0].SHA256 = strings.Repeat("A", 64) },
		"unknown capability":  func(value *Metadata) { value.Protocol.Capabilities |= 1 << 63 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := metadata
			candidate.Relays = append([]Relay(nil), metadata.Relays...)
			candidate.Artifacts = append([]Artifact(nil), metadata.Artifacts...)
			mutate(&candidate)
			if err := candidate.Validate(now); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
	withUnknown := append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
	if _, err := Decode(bytes.NewReader(withUnknown), now); err == nil {
		t.Fatal("unknown metadata field accepted")
	}
	if _, err := Decode(io.LimitReader(strings.NewReader(strings.Repeat("x", MaxDocumentBytes+1)), MaxDocumentBytes+1), now); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

func TestArtifactVerification(t *testing.T) {
	payload := []byte("verified release")
	digest := sha256.Sum256(payload)
	artifact := Artifact{SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	if err := VerifyArtifact(bytes.NewReader(payload), artifact); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(strings.NewReader("tampered release"), artifact); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if err := VerifyArtifact(bytes.NewReader(append(payload, 0)), artifact); err == nil {
		t.Fatal("oversized artifact accepted")
	}
}

func TestArtifactDownloadIsWebPKIVerifiedAndNeverOverwrites(t *testing.T) {
	payload := []byte("verified release")
	digest := sha256.Sum256(payload)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	artifact := Artifact{URL: server.URL + "/release", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
	destination := filepath.Join(t.TempDir(), "laneway.tar.gz")
	if err := downloadArtifact(context.Background(), server.Client(), artifact, destination); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(contents, payload) {
		t.Fatalf("downloaded artifact = %q, %v", contents, err)
	}
	if err := downloadArtifact(context.Background(), server.Client(), artifact, destination); err == nil {
		t.Fatal("existing artifact was overwritten")
	}
	tampered := artifact
	tampered.SHA256 = strings.Repeat("0", 64)
	tamperedDestination := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := downloadArtifact(context.Background(), server.Client(), tampered, tamperedDestination); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if _, err := os.Lstat(tamperedDestination); !os.IsNotExist(err) {
		t.Fatalf("failed verification published output: %v", err)
	}
}

func TestDiscoveryURLRequiresWebPKIDNSOrigin(t *testing.T) {
	if got, err := DiscoveryURL("lane.example.test:443"); err != nil || got != "https://lane.example.test:443"+WellKnownPath {
		t.Fatalf("discovery URL = %q, %v", got, err)
	}
	for _, value := range []string{"http://lane.example.test", "https://127.0.0.1", "https://user@lane.example.test", "https://lane.example.test/path"} {
		if _, err := DiscoveryURL(value); err == nil {
			t.Fatalf("invalid discovery authority %q accepted", value)
		}
	}
}

type relayFixture struct {
	relays []controller.Relay
	err    error
}

func (f relayFixture) ActiveRelays(context.Context, identity.NetworkID) ([]controller.Relay, error) {
	return append([]controller.Relay(nil), f.relays...), f.err
}

func TestPublicServerAndWebPKIAuthenticatedFetch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	metadata := validMetadata(t, now)
	networkID, _ := identity.ParseNetworkID(metadata.NetworkID)
	controllerService, _ := identity.ParseID(metadata.Controller.ServiceID)
	relayService, _ := identity.ParseID(metadata.Relays[0].ServiceID)
	server, err := NewServer(ServerOptions{
		Relays:    relayFixture{relays: []controller.Relay{{Name: "relay", Endpoint: metadata.Relays[0].Endpoint, ServiceID: relayService}}},
		NetworkID: networkID, ControllerEndpoint: metadata.Controller.EnrollmentEndpoint,
		ControllerQUIC: metadata.Controller.QUICEndpoint, ControllerServerName: metadata.Controller.ServerName,
		ControllerServiceID: controllerService, CAPEM: metadata.Trust.CAPEM, Artifacts: metadata.Artifacts,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewTLSServer(server.Handler())
	defer tlsServer.Close()
	result, err := fetch(context.Background(), tlsServer.Client(), tlsServer.URL+WellKnownPath, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.NetworkID != metadata.NetworkID || len(result.Relays) != 1 {
		t.Fatalf("metadata = %+v", result)
	}
	notFound, err := tlsServer.Client().Get(tlsServer.URL + "/other")
	if err != nil {
		t.Fatal(err)
	}
	defer notFound.Body.Close()
	if notFound.StatusCode != http.StatusNotFound {
		t.Fatalf("unrelated path status = %d", notFound.StatusCode)
	}
}
