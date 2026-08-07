package config

import (
	"strings"
	"testing"
	"time"
)

const validNode = `
mode = "node"
state_dir = "/tmp/laneway"
socket_path = "/tmp/laneway.sock"

[tls]
certificate = "/tmp/node.crt"
private_key = "/tmp/node.key"
ca = "/tmp/ca.crt"
server_name = "relay.example.test"

[node]
name = "test-node"
relay_address = "relay.example.test:4433"
relay_network_id = "000102030405060708090a0b0c0d0e0f"
relay_service_id = "202122232425262728292a2b2c2d2e2f"
overlay_addresses = ["100.96.0.1/32"]
reconnect_min = "250ms"
reconnect_max = "5s"

[[peers]]
network_id = "000102030405060708090a0b0c0d0e0f"
node_id = "101112131415161718191a1b1c1d1e1f"
prefixes = ["100.96.0.2/32"]
`

func TestDecodeNode(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validNode))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeNode || cfg.Node.ReconnectMin.Duration() != 250*time.Millisecond || cfg.Relay.QueueDepth != 256 {
		t.Fatalf("unexpected configuration: %#v", cfg)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Prefixes[0] != "100.96.0.2/32" {
		t.Fatalf("unexpected peers: %#v", cfg.Peers)
	}
}

func TestDecodeRejectsSpecialUsePeerPrefixes(t *testing.T) {
	for _, prefix := range []string{"127.0.0.1/32", "169.254.0.0/16", "224.0.0.0/4", "fe80::/64", "ff00::/8"} {
		source := strings.Replace(validNode, "100.96.0.2/32", prefix, 1)
		if _, err := Decode(strings.NewReader(source)); err == nil {
			t.Fatalf("special-use peer prefix %s accepted", prefix)
		}
	}
}

func TestDecodeTCPFallback(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validNode + `
[tcp_fallback]
address = "relay.example.test:443"
handshake_timeout = "3s"
write_timeout = "4s"
idle_timeout = "30s"
keepalive_period = "10s"
queue_depth = 64
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TCPFallback.Address != "relay.example.test:443" || cfg.TCPFallback.WriteTimeout.Duration() != 4*time.Second || cfg.TCPFallback.QueueDepth != 64 {
		t.Fatalf("unexpected TCP fallback config: %#v", cfg.TCPFallback)
	}
	cfg.TCPFallback.KeepAlivePeriod = cfg.TCPFallback.IdleTimeout
	if err := cfg.Validate(); err == nil {
		t.Fatal("keepalive equal to idle timeout accepted")
	}
}

func TestDecodeDirectConnectivity(t *testing.T) {
	cfg, err := Decode(strings.NewReader(validNode + `
[direct]
enabled = true
listen = "0.0.0.0:4242"
candidate_ttl = "90s"
probe_interval = "100ms"
probe_timeout = "2s"
max_candidates = 4
allow_loopback = false
allow_link_local = false
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Direct.Enabled || cfg.Direct.Listen != "0.0.0.0:4242" || cfg.Direct.MaxCandidates != 4 || cfg.Direct.ProbeInterval.Duration() != 100*time.Millisecond {
		t.Fatalf("direct config = %#v", cfg.Direct)
	}
	cfg.Direct.MaxCandidates = 33
	if err := cfg.Validate(); err == nil {
		t.Fatal("unbounded direct candidates accepted")
	}
}

func TestDecodeRejectsUnknownAndOversize(t *testing.T) {
	if _, err := Decode(strings.NewReader(validNode + "\nunknown = true\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Decode(strings.NewReader(strings.Repeat("x", MaxFileSize+1))); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}

func TestDecodeController(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
mode = "controller"
state_dir = "/var/lib/laneway-controller"
socket_path = "/run/laneway/controller.sock"
[tls]
certificate = "/etc/laneway/controller.crt"
private_key = "/etc/laneway/controller.key"
ca = "/etc/laneway/ca.crt"
[controller]
listen = ":8443"
quic_listen = ":8443"
database = "/var/lib/laneway-controller/controller.db"
ca_private_key = "/etc/laneway/ca.key"
issuer_certificate = "/etc/laneway/intermediate.crt"
admin_token_file = "/etc/laneway/admin.token"
leaf_validity = "720h"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeController || cfg.Controller.LeafValidity.Duration() != 30*24*time.Hour || cfg.Controller.IssuerCertificateFile != "/etc/laneway/intermediate.crt" {
		t.Fatalf("unexpected controller config: %#v", cfg)
	}
}

func TestDecodeControllerBackedRelay(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`
mode = "relay"
state_dir = "/var/lib/laneway-relay"
socket_path = "/run/laneway/relay.sock"
[tls]
certificate = "/etc/laneway/relay.crt"
private_key = "/etc/laneway/relay.key"
ca = "/etc/laneway/ca.crt"
[relay]
listen = ":4433"
[controller]
endpoint = "https://controller.example.test:8443"
quic_endpoint = "controller.example.test:8443"
server_name = "controller.example.test"
network_id = "000102030405060708090a0b0c0d0e0f"
service_id = "303132333435363738393a3b3c3d3e3f"
poll_interval = "5s"
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Controller.Endpoint == "" || len(cfg.Peers) != 0 {
		t.Fatalf("unexpected relay controller configuration: %#v", cfg)
	}
	withoutQUIC := cfg
	withoutQUIC.Controller.QUICEndpoint = ""
	if err := withoutQUIC.Validate(); err == nil {
		t.Fatal("controller-backed relay accepted a missing QUIC endpoint")
	}
	cfg.Peers = []AuthorizedPeer{{
		NetworkID: "000102030405060708090a0b0c0d0e0f",
		NodeID:    "101112131415161718191a1b1c1d1e1f", Prefixes: []string{"100.96.0.2/32"},
	}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("mixed static and controller relay authorization accepted")
	}
	cfg.Controller.Endpoint = ""
	cfg.Peers = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("relay without any authorization source accepted")
	}
}

func TestDecodeExplicitExitSelection(t *testing.T) {
	controllerNode := validNode[:strings.Index(validNode, "[[peers]]")]
	controllerNode = strings.Replace(controllerNode, `overlay_addresses = ["100.96.0.1/32"]`, "", 1)
	cfg, err := Decode(strings.NewReader(controllerNode + `
[controller]
endpoint = "https://controller.example.test:8443"
quic_endpoint = "controller.example.test:8443"
server_name = "controller.example.test"
network_id = "000102030405060708090a0b0c0d0e0f"
service_id = "303132333435363738393a3b3c3d3e3f"
poll_interval = "10s"
[exit]
enabled = true
selected_node_id = "101112131415161718191a1b1c1d1e1f"
failure_mode = "closed"
dns_servers = ["1.1.1.1"]
local_lan_bypasses = ["192.168.0.0/16"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Exit.Enabled || cfg.Exit.FailureMode != "closed" {
		t.Fatalf("unexpected exit config: %#v", cfg.Exit)
	}
	cfg.Exit.FailureMode = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("implicit exit failure mode accepted")
	}
}

func TestControllerNodeMayOmitStaticOverlayAndPeers(t *testing.T) {
	configuration := `
mode = "node"
state_dir = "/tmp/laneway"
socket_path = "/tmp/laneway.sock"
[tls]
certificate = "/tmp/node.crt"
private_key = "/tmp/node.key"
ca = "/tmp/ca.crt"
[node]
name = "controller-node"
relay_address = "relay.example.test:4433"
relay_network_id = "000102030405060708090a0b0c0d0e0f"
relay_service_id = "202122232425262728292a2b2c2d2e2f"
[controller]
endpoint = "https://controller.example.test:8443"
quic_endpoint = "controller.example.test:8443"
network_id = "000102030405060708090a0b0c0d0e0f"
service_id = "303132333435363738393a3b3c3d3e3f"
poll_interval = "10s"
`
	cfg, err := Decode(strings.NewReader(configuration))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Node.OverlayAddresses) != 0 || len(cfg.Peers) != 0 {
		t.Fatalf("controller node retained static authority: %#v", cfg)
	}
}

func TestValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"mode", func(c *Config) { c.Mode = "invalid" }},
		{"tls", func(c *Config) { c.TLS.CAFile = "" }},
		{"relay", func(c *Config) { c.Node.RelayAddress = "" }},
		{"overlay", func(c *Config) { c.Node.OverlayAddresses = []string{"100.96.0.1/24"} }},
		{"queue", func(c *Config) { c.Relay.QueueDepth = 0 }},
		{"identity", func(c *Config) { c.Peers[0].NodeID = "BAD" }},
		{"tcp endpoint role", func(c *Config) { c.TCPFallback.Listen = ":443" }},
		{"tcp queue", func(c *Config) { c.TCPFallback.QueueDepth = 5000 }},
		{"direct timeout", func(c *Config) { c.Direct.ProbeTimeout = Duration(31 * time.Second) }},
	}
	base, err := Decode(strings.NewReader(validNode))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			cfg.Peers = append([]AuthorizedPeer(nil), base.Peers...)
			test.edit(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
