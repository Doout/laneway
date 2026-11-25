//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/wireguard"
)

func TestConnectSessionFrameRejectsMalformedSecretWithoutEcho(t *testing.T) {
	frame := func(contents string) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(contents))), contents...)
	}
	for _, invalid := range [][]byte{
		{0, 0, 0},
		binary.BigEndian.AppendUint32(nil, connectSessionMaxBytes+1),
		frame(`{"private_key_pem":"SECRET", "unknown":"must stay private"}`),
		frame(`{} {"token":"SECRET"}`),
	} {
		_, err := readConnectSession(bytes.NewReader(invalid))
		if err == nil || err.Error() != "invalid private connect session frame" {
			t.Fatalf("invalid frame error = %v", err)
		}
	}
	payload := frame(`{"private_key_pem":"Y3JlZGVudGlhbC1maXh0dXJl","saved_login":true}`)
	got, err := readConnectSession(bytes.NewReader(payload))
	if err != nil || !got.SavedLogin || string(got.PrivateKeyPEM) != "credential-fixture" {
		t.Fatalf("base64 private frame did not decode: %v", err)
	}
}

func TestConnectSessionChecksCredentialsBeforeStartingRuntime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	caMaterial, ca, err := pki.NewAuthority("fixture CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	network, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	node, _ := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	material, _, err := pki.IssueNode(ca, caMaterial.PrivateKey, identity.NodeIdentity{
		NetworkID: network, NodeID: node,
	}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	wg, _, err := wireguard.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pki.CertificatePEM(caMaterial.CertificateDER)
	session := connectSession{
		Metadata: bootstrap.Metadata{
			SchemaVersion: bootstrap.SchemaVersion, GeneratedAt: now.Unix(),
			ValidUntil: now.Add(time.Minute).Unix(), NetworkID: network.String(),
			Controller: bootstrap.Controller{EnrollmentEndpoint: "https://lane.example:8443",
				QUICEndpoint: "lane.example:8443", ServerName: "lane.example",
				ServiceID: "202122232425262728292a2b2c2d2e2f"},
			Relays: []bootstrap.Relay{{Name: "relay", Endpoint: "relay.example:4433",
				ServiceID: "303132333435363738393a3b3c3d3e3f"}},
			Trust:    bootstrap.Trust{CAPEM: string(caPEM)},
			Protocol: bootstrap.Protocol{ControlMajor: 1, Packet: []uint32{1}},
			Artifacts: []bootstrap.Artifact{{OS: runtime.GOOS, Arch: runtime.GOARCH,
				URL: "https://example.test/release", SHA256: strings.Repeat("0", 64), SizeBytes: 1}},
		},
		CAPEM: caPEM, CertificatePEM: pki.CertificatePEM(material.CertificateDER),
		PrivateKeyPEM: key, WireguardPrivateKey: wg.Bytes(),
		NetworkID: network.String(), NodeID: node.String(), SavedLogin: true,
	}
	bytes, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := readConnectSession(bytesReader(bytes))
	if err != nil {
		t.Fatal(err)
	}
	if enrolled, err := decoded.validateCredentials(now); err != nil || enrolled.identity.NodeID != node {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	decoded.NodeID = "404142434445464748494a4b4c4d4e4f"
	if _, err := decoded.validateCredentials(now); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("arbitrary payload identity accepted: %v", err)
	}
	decoded.NodeID = node.String()
	decoded.PrivateKeyPEM, _ = pki.PrivateKeyPEM(caMaterial.PrivateKey)
	if _, err := decoded.validateCredentials(now); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("mismatched private key accepted: %v", err)
	}
}

func bytesReader(payload []byte) *bytes.Reader {
	return bytes.NewReader(append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...))
}

func TestConnectPreservesAnonymousCredentialsAcrossTLSConsumers(t *testing.T) {
	directory := t.TempDir()
	credentials := new(runtimeCredentialFiles)
	defer credentials.close()
	path, err := credentials.add(directory, "fixture", []byte("private runtime fixture"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "private runtime fixture" {
			t.Fatalf("credential read %d failed: %q, %v", index, data, err)
		}
		if err := credentials.rewind(); err != nil {
			t.Fatal(err)
		}
	}
	if items, err := os.ReadDir(directory); err != nil || len(items) != 0 {
		t.Fatalf("anonymous files left a directory entry: %v", err)
	}
}
