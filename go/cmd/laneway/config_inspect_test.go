package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const controllerInitialNetworkID = "000102030405060708090a0b0c0d0e0f"
const foreignControllerInitialNetworkID = "f0e0d0c0b0a090807060504030201000"

func TestConfigInspectControllerInitialNetwork(t *testing.T) {
	tests := []struct {
		name          string
		initialTOML   string
		bootstrapTOML string
		want          string
	}{
		{
			name: "absent",
			want: "{\n  \"configured\": false\n}\n",
		},
		{
			name: "canonical table",
			initialTOML: `[controller.initial_network]
network_id = "` + controllerInitialNetworkID + `"
name = "production"
ipv4_pool = "100.96.0.0/16"
ipv6_pool = "fd00:96::/64"
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "canonical table without optional IPv6 pool",
			initialTOML: `[controller.initial_network]
network_id = "` + controllerInitialNetworkID + `"
name = "production"
ipv4_pool = "100.96.0.0/16"
`,
			want: `{
  "configured": true,
  "network_id": "000102030405060708090a0b0c0d0e0f",
  "name": "production",
  "ipv4_pool": "100.96.0.0/16"
}
`,
		},
		{
			name: "quoted table key",
			initialTOML: `[controller."initial_network"]
network_id = "` + controllerInitialNetworkID + `"
name = "production"
ipv4_pool = "100.96.0.0/16"
ipv6_pool = "fd00:96::/64"
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "literal table key and values",
			initialTOML: `[controller.'initial_network']
network_id = '` + controllerInitialNetworkID + `'
name = 'production'
ipv4_pool = '100.96.0.0/16'
ipv6_pool = 'fd00:96::/64'
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "escaped table key and value",
			initialTOML: `[controller."initial\u005fnetwork"]
network_id = "` + controllerInitialNetworkID + `"
name = "produc\u0074ion"
ipv4_pool = "100.96.0.0/16"
ipv6_pool = "fd00:96::/64"
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "dotted keys",
			initialTOML: `initial_network.network_id = "` + controllerInitialNetworkID + `"
initial_network.name = "production"
initial_network.ipv4_pool = "100.96.0.0/16"
initial_network.ipv6_pool = "fd00:96::/64"
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "inline table",
			initialTOML: `initial_network = { network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = "100.96.0.0/16", ipv6_pool = "fd00:96::/64" }
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "quoted inline table",
			initialTOML: `"initial_network" = { network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = "100.96.0.0/16", ipv6_pool = "fd00:96::/64" }
`,
			want: configuredInitialNetworkJSON,
		},
		{
			name: "quoted bootstrap table and keys",
			initialTOML: `initial_network = { network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = "100.96.0.0/16" }
`,
			bootstrapTOML: `["bootstrap"]
"network_id" = "` + controllerInitialNetworkID + `"
"controller_endpoint" = "https://lane.example.test:8443"
"controller_quic_endpoint" = "lane.example.test:8443"
"controller_server_name" = "lane.example.test"
`,
			want: configuredInitialNetworkWithBootstrapJSON,
		},
		{
			name: "dotted bootstrap mismatch remains visible",
			bootstrapTOML: `bootstrap.network_id = "` + foreignControllerInitialNetworkID + `"
bootstrap.controller_endpoint = "https://lane.example.test:8443"
bootstrap.controller_quic_endpoint = "lane.example.test:8443"
bootstrap.controller_server_name = "lane.example.test"
`,
			want: `{
  "configured": false,
  "bootstrap_network_id": "f0e0d0c0b0a090807060504030201000"
}
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeControllerInspectionConfigWithBootstrap(t, test.initialTOML, test.bootstrapTOML)
			output, err := captureConfigStdout(t, func() error {
				return runConfig([]string{"inspect-controller-initial-network", "-config", path})
			})
			if err != nil {
				t.Fatal(err)
			}
			if output != test.want {
				t.Fatalf("inspection output = %q, want %q", output, test.want)
			}
			for _, secretOrUnrelated := range []string{"controller.key", "ca.key", "admin.token", "state_dir", "socket_path"} {
				if strings.Contains(output, secretOrUnrelated) {
					t.Fatalf("inspection output exposes unrelated configuration %q: %s", secretOrUnrelated, output)
				}
			}
		})
	}
}

func TestConfigInspectControllerInitialNetworkRejectsAmbiguousOrInvalidTOML(t *testing.T) {
	tests := []struct {
		name        string
		initialTOML string
	}{
		{
			name: "semantic duplicate",
			initialTOML: `initial_network = { network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = "100.96.0.0/16" }
"initial\u005fnetwork" = { network_id = "` + controllerInitialNetworkID + `", name = "foreign", ipv4_pool = "100.97.0.0/16" }
`,
		},
		{
			name: "array",
			initialTOML: `initial_network = [{ network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = "100.96.0.0/16" }]
`,
		},
		{
			name:        "malformed",
			initialTOML: `initial_network = { network_id = "` + controllerInitialNetworkID + `", name = "production", ipv4_pool = `,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeControllerInspectionConfig(t, test.initialTOML)
			output, err := captureConfigStdout(t, func() error {
				return runConfig([]string{"inspect-controller-initial-network", "-config", path})
			})
			if err == nil {
				t.Fatal("invalid or ambiguous initial-network TOML was accepted")
			}
			if output != "" {
				t.Fatalf("failed inspection wrote output %q", output)
			}
		})
	}
}

func TestConfigInspectControllerInitialNetworkRejectsNonControllerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.toml")
	configuration := `
mode = "relay"
state_dir = "/state"
socket_path = "/socket"
[tls]
certificate = "/secret/relay.crt"
private_key = "/secret/relay.key"
ca = "/secret/ca.crt"
[controller]
endpoint = "https://controller.example.test:8443"
quic_endpoint = "controller.example.test:8443"
network_id = "000102030405060708090a0b0c0d0e0f"
service_id = "101112131415161718191a1b1c1d1e1f"
[relay]
listen = ":4433"
`
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := captureConfigStdout(t, func() error {
		return runConfig([]string{"inspect-controller-initial-network", "-config", path})
	})
	if err == nil || !strings.Contains(err.Error(), `want "controller"`) {
		t.Fatalf("non-controller inspection error = %v", err)
	}
	if output != "" {
		t.Fatalf("failed inspection wrote output %q", output)
	}
}

const configuredInitialNetworkJSON = `{
  "configured": true,
  "network_id": "000102030405060708090a0b0c0d0e0f",
  "name": "production",
  "ipv4_pool": "100.96.0.0/16",
  "ipv6_pool": "fd00:96::/64"
}
`

const configuredInitialNetworkWithBootstrapJSON = `{
  "configured": true,
  "network_id": "000102030405060708090a0b0c0d0e0f",
  "name": "production",
  "ipv4_pool": "100.96.0.0/16",
  "bootstrap_network_id": "000102030405060708090a0b0c0d0e0f"
}
`

func writeControllerInspectionConfig(t *testing.T, initialTOML string) string {
	t.Helper()
	return writeControllerInspectionConfigWithBootstrap(t, initialTOML, "")
}

func writeControllerInspectionConfigWithBootstrap(t *testing.T, initialTOML, bootstrapTOML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.toml")
	configuration := `
mode = "controller"
state_dir = "/state"
socket_path = "/socket"
` + bootstrapTOML + `
[tls]
certificate = "/secret/controller.crt"
private_key = "/secret/controller.key"
ca = "/secret/ca.crt"
[controller]
listen = ":8443"
quic_listen = ":8443"
database = "/state/controller.db"
ca_private_key = "/secret/ca.key"
admin_token_file = "/secret/admin.token"
leaf_validity = "720h"
` + initialTOML
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func captureConfigStdout(t *testing.T, invoke func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	invokeErr := invoke()
	os.Stdout = original
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output), invokeErr
}
