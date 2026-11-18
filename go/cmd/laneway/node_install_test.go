//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/pelletier/go-toml/v2"
)

func TestManagedNodeConfigurationUsesAuthenticatedDiscoveryAndDirectDefault(t *testing.T) {
	serviceID, err := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	if err != nil {
		t.Fatal(err)
	}
	metadata := bootstrap.Metadata{
		NetworkID: "000102030405060708090a0b0c0d0e0f",
		Controller: bootstrap.Controller{
			EnrollmentEndpoint: "https://controller.example:8443",
			QUICEndpoint:       "controller.example:8443",
			ServerName:         "controller.example",
			ServiceID:          "101112131415161718191a1b1c1d1e1f",
		},
	}
	contents, err := renderManagedNodeConfig(metadata, "managed-node", managedNodeRelay{serviceID: serviceID, endpoint: "relay.example:4433"}, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Decode(bytes.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Node.Name != "managed-node" || cfg.Node.RelayAddress != "relay.example:4433" || cfg.Node.RelayServiceID != serviceID.String() ||
		cfg.Controller.NetworkID != metadata.NetworkID || cfg.Controller.ServiceID != metadata.Controller.ServiceID ||
		cfg.Controller.QUICEndpoint != metadata.Controller.QUICEndpoint || !cfg.Direct.Enabled || cfg.Direct.Listen != "0.0.0.0:0" ||
		cfg.WireGuard.Enabled || cfg.WireGuard.PrivateKeyFile != "/etc/laneway/wireguard.key" {
		t.Fatalf("generated managed config = %#v", cfg)
	}
	contents, err = renderManagedNodeConfig(metadata, "managed-node", managedNodeRelay{serviceID: serviceID, endpoint: "relay.example:4433"}, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Decode(bytes.NewReader(contents))
	if err != nil || cfg.Direct.Enabled {
		t.Fatalf("explicit direct opt-out = %#v, %v", cfg.Direct, err)
	}
}

func TestManagedNodeRelaySelectionIsDeterministicAndBounded(t *testing.T) {
	first, _ := identity.ParseID("101112131415161718191a1b1c1d1e1f")
	second, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	configuration := &lanewayv1.NodeConfiguration{Relays: []*lanewayv1.RelayEndpoint{
		{ServiceId: second[:], Endpoint: "relay-b.example:4433"},
		{ServiceId: first[:], Endpoint: "relay-a.example:4433"},
	}}
	selected, err := managedNodeRelayFromConfiguration(configuration)
	if err != nil || selected.serviceID != first || selected.endpoint != "relay-a.example:4433" {
		t.Fatalf("selected relay = %#v, %v", selected, err)
	}
	if _, err := managedNodeRelayFromConfiguration(&lanewayv1.NodeConfiguration{}); err == nil {
		t.Fatal("accepted a managed configuration without a relay")
	}
}

func TestNodeInstallRejectsAmbiguousArgumentsBeforePrivilege(t *testing.T) {
	for _, args := range [][]string{{}, {"one.example", "two.example"}, {"one.example", "--name", " bad"}} {
		if err := runNodeInstall(args); err == nil {
			t.Fatalf("accepted unsafe arguments %v", args)
		}
	}
}

func TestManagedNodeStartRequiresStableActiveState(t *testing.T) {
	originalActive, originalInterval := nodeSystemctlActive, managedNodeActiveProbeInterval
	t.Cleanup(func() { nodeSystemctlActive, managedNodeActiveProbeInterval = originalActive, originalInterval })
	managedNodeActiveProbeInterval = time.Nanosecond
	probes := 0
	nodeSystemctlActive = func(_ context.Context, unit string) error {
		if unit != managedGoUnit {
			t.Fatalf("probing wrong unit: %s", unit)
		}
		probes++
		if probes == 4 {
			return errors.New("service crashed")
		}
		return nil
	}
	if err := waitManagedNodeActive(context.Background(), managedGoUnit); err == nil || probes != 4 {
		t.Fatalf("unstable service error=%v probes=%d", err, probes)
	}
	probes = 0
	nodeSystemctlActive = func(context.Context, string) error { probes++; return nil }
	if err := waitManagedNodeActive(context.Background(), managedGoUnit); err != nil || probes != 10 {
		t.Fatalf("stable service error=%v probes=%d", err, probes)
	}
}

func TestManagedNodeCleanupAttemptsStopDisableAndReset(t *testing.T) {
	original := nodeSystemctl
	t.Cleanup(func() { nodeSystemctl = original })
	var calls []string
	nodeSystemctl = func(_ context.Context, args ...string) error {
		if args[len(args)-1] != managedRustUnit {
			t.Fatalf("cleaning wrong unit: %v", args)
		}
		calls = append(calls, args[0])
		if args[0] == "stop" {
			return errors.New("already failed")
		}
		return nil
	}
	if err := cleanupManagedNodeService(context.Background(), managedRustUnit); err == nil {
		t.Fatal("cleanup hid the stop failure")
	}
	if got := strings.Join(calls, ","); got != "stop,disable" {
		t.Fatalf("cleanup calls = %s", got)
	}
}

func TestManagedRustConfigurationPinsAuthorityAndProtectsRenewableLeaf(t *testing.T) {
	netID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	nodeID, _ := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	relayID, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	metadata := bootstrap.Metadata{Controller: bootstrap.Controller{
		EnrollmentEndpoint: "https://node.example:8443", QUICEndpoint: "node.example:8443",
		ServerName: "node.example", ServiceID: "303132333435363738393a3b3c3d3e3f",
	}}
	node := identity.NodeIdentity{NetworkID: netID, NodeID: nodeID}
	relay := managedNodeRelay{serviceID: relayID, endpoint: "node.example:4433"}
	render := func(authority string, direct bool) map[string]any {
		t.Helper()
		raw, err := renderManagedRustNodeConfig(authority, metadata, node, relay, direct)
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		if err := toml.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		return config
	}
	cfg := render("node.example:7443", true)
	if cfg["tls"].(map[string]any)["certificate"] != managedRustCertificate ||
		cfg["controller"].(map[string]any)["auto_renew_certificate"] != true ||
		cfg["relay"].(map[string]any)["service_id"] != relayID.String() ||
		cfg["identity"].(map[string]any)["node_id"] != nodeID.String() ||
		cfg["tcp_fallback"].(map[string]any)["address"] != "node.example:7443" ||
		cfg["direct"] == nil || cfg["wireguard"] != nil {
		t.Fatalf("unexpected Rust config: %#v", cfg)
	}
	if cfg := render("different.example", false); cfg["tcp_fallback"] != nil || cfg["direct"] != nil {
		t.Fatalf("unapproved fallback or direct path: %#v", cfg)
	}
	if mode, uid, gid := managedNodeFilePermissions(managedRustCertificate, managedNodeOwner{uid: 700, gid: 701}); mode != 0o400 || uid != 700 || gid != 701 {
		t.Fatalf("bad renewable certificate ownership: %o %d:%d", mode, uid, gid)
	}
	if mode, uid, gid := managedNodeFilePermissions("/etc/laneway/node.key", managedNodeOwner{uid: 700, gid: 701}); mode != 0o640 || uid != 0 || gid != 701 {
		t.Fatalf("bad read-only key ownership: %o %d:%d", mode, uid, gid)
	}
}
