//go:build linux

package nodeapp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Doout/laneway/go/internal/config"
)

func TestResolveEphemeralExitCredentialsIncludesWireGuardKey(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "node.crt", "node.key", "wireguard.key"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	value := config.Config{TLS: config.TLS{CAFile: "@credential/ca.crt", CertificateFile: "@credential/node.crt",
		PrivateKeyFile: "@credential/node.key"}, WireGuard: config.WireGuard{PrivateKeyFile: "@credential/wireguard.key"}}
	if err := resolveEphemeralExitCredentials(&value); err != nil {
		t.Fatal(err)
	}
	for label, path := range map[string]string{"ca": value.TLS.CAFile, "certificate": value.TLS.CertificateFile,
		"private key": value.TLS.PrivateKeyFile, "WireGuard key": value.WireGuard.PrivateKeyFile} {
		if filepath.Dir(path) != directory {
			t.Fatalf("%s escaped credential directory: %q", label, path)
		}
	}
}
