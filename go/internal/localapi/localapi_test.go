package localapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServerClientLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanewayd.sock")
	var selected ExitSelection
	server := Server{SocketPath: path, Snapshot: func() (Status, []Peer, []Route) {
		return Status{Running: true, Actor: "exit-node", NodeID: "node", OverlayAddresses: []string{"100.96.0.1/32"}, SelectedRoutes: []string{"0.0.0.0/0"}, MTU: 1200, ProductVersion: "1.0.0", ControlVersion: "1.0", PacketVersion: 1, Capabilities: "relay-v1", SelectedPath: "relay-quic", Controller: ControllerStatus{CandidateExchangeEnabled: true, CertificateRenewalNeeded: true, CertificateNotAfterUnixSeconds: 12345, IdentityLeaseExpiresAtUnixSeconds: 23456, ConfigurationLeaseValidUntilUnixSeconds: 34567, ConfigurationLeaseExpired: true}, Exit: ExitStatus{Serving: true, ForwardingReady: true, NATReady: true, ForwardedPackets: 12, NamespaceCleanupFailures: 1}},
			[]Peer{{NodeID: "peer", Name: "homelab-gateway", Prefixes: []string{"100.96.0.2/32"}, Path: "direct"}},
			[]Route{{Prefix: "100.96.0.2/32", ViaNode: "peer", Kind: "peer"}}
	}, SetExit: func(_ context.Context, selection ExitSelection) error {
		selected = selection
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(path)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		status, err = client.Status(context.Background())
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil || !status.Running || status.Actor != "exit-node" || len(status.OverlayAddresses) != 1 || len(status.SelectedRoutes) != 1 || status.MTU != 1200 || status.ProductVersion != "1.0.0" || status.ControlVersion != "1.0" || status.PacketVersion != 1 || status.Capabilities != "relay-v1" || status.SelectedPath != "relay-quic" || !status.Controller.CandidateExchangeEnabled || !status.Controller.CertificateRenewalNeeded || status.Controller.CertificateNotAfterUnixSeconds != 12345 || status.Controller.IdentityLeaseExpiresAtUnixSeconds != 23456 || status.Controller.ConfigurationLeaseValidUntilUnixSeconds != 34567 || !status.Controller.ConfigurationLeaseExpired || !status.Exit.Serving || !status.Exit.NATReady || status.Exit.ForwardedPackets != 12 || status.Exit.NamespaceCleanupFailures != 1 {
		t.Fatalf("status = %#v, %v", status, err)
	}
	peers, err := client.Peers(context.Background())
	if err != nil || len(peers) != 1 || peers[0].NodeID != "peer" || peers[0].Name != "homelab-gateway" || peers[0].Path != "direct" {
		t.Fatalf("peers = %#v, %v", peers, err)
	}
	routes, err := client.Routes(context.Background())
	if err != nil || len(routes) != 1 || routes[0].Kind != "peer" {
		t.Fatalf("routes = %#v, %v", routes, err)
	}
	if err := client.SetExit(context.Background(), ExitSelection{Enabled: true, SelectedNodeID: "peer"}); err != nil {
		t.Fatal(err)
	}
	if !selected.Enabled || selected.SelectedNodeID != "peer" {
		t.Fatalf("exit selection = %#v", selected)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket was not removed: %v", err)
	}
}

func TestRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanewayd.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (Server{SocketPath: path, Snapshot: func() (Status, []Peer, []Route) { return Status{}, nil, nil }}).Serve(context.Background())
	if err == nil {
		t.Fatal("non-socket path was accepted")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != "do not replace" {
		t.Fatalf("foreign file changed: %q, %v", contents, readErr)
	}
}
