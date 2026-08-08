//go:build linux

package wireguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateKeyFileRejectsLinksPermissionsAndWrongSize(t *testing.T) {
	privateKey, publicKey := deviceKey(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "wireguard.key")
	if err := os.WriteFile(path, privateKey.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedPrivate, loadedPublic, err := LoadPrivateKeyFile(path)
	if err != nil || loadedPrivate != privateKey || loadedPublic != publicKey {
		t.Fatalf("loaded=(%x,%x) error=%v", loadedPrivate, loadedPublic, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPrivateKeyFile(path); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("permissive mode error=%v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.key")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPrivateKeyFile(link); err == nil {
		t.Fatal("symlink accepted")
	}
	short := filepath.Join(directory, "short.key")
	if err := os.WriteFile(short, privateKey.Bytes()[:KeySize-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPrivateKeyFile(short); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("short key error=%v", err)
	}
}
