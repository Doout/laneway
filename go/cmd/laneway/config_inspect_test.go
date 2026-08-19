package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigInspectControllerInitialNetwork(t *testing.T) {
	for _, test := range []struct {
		name        string
		initialTOML string
		want        string
	}{
		{name: "absent", want: "{\n  \"configured\": false\n}\n"},
		{
			name: "configured",
			initialTOML: `[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "production"
ipv4_pool = "100.96.0.0/16"
ipv6_pool = "fd00:96::/64"
`,
			want: `{
  "configured": true,
  "network_id": "000102030405060708090a0b0c0d0e0f",
  "name": "production",
  "ipv4_pool": "100.96.0.0/16",
  "ipv6_pool": "fd00:96::/64"
}
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeControllerInspectionConfig(t, test.initialTOML)
			output, err := captureConfigStdout(t, func() error {
				return runConfig([]string{"inspect-controller-initial-network", "-config", path})
			})
			if err != nil {
				t.Fatal(err)
			}
			if output != test.want {
				t.Fatalf("inspection output=%q want=%q", output, test.want)
			}
			for _, excluded := range []string{"controller.key", "ca.key", "admin.token", "state_dir", "socket_path"} {
				if strings.Contains(output, excluded) {
					t.Fatalf("inspection output exposes unrelated configuration %q", excluded)
				}
			}
		})
	}
}

func TestConfigInspectControllerInitialNetworkRejectsInvalidInput(t *testing.T) {
	path := writeControllerInspectionConfig(t, `[controller.initial_network]
network_id = "000102030405060708090a0b0c0d0e0f"
name = "production"
ipv4_pool = "100.96.1.0/16"
`)
	output, err := captureConfigStdout(t, func() error {
		return runConfig([]string{"inspect-controller-initial-network", "-config", path})
	})
	if err == nil || output != "" {
		t.Fatalf("invalid inspection output=%q error=%v", output, err)
	}
}

func writeControllerInspectionConfig(t *testing.T, initialTOML string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.toml")
	configuration := `
mode = "controller"
state_dir = "/state"
socket_path = "/socket"
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
