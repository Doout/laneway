package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/wireguard"
)

func TestUserProfileRoundTripUsesPrivateGeneration(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LANEWAY_PROFILE_DIR", root)
	authority := "lane.example.com"
	profile := userProfile{
		Version: userProfileVersion, Authority: authority,
		NetworkID: "101112131415161718191a1b1c1d1e1f", ControllerServiceID: "202122232425262728292a2b2c2d2e2f",
		NodeID: "303132333435363738393a3b3c3d3e3f", Name: "laptop", CreatedAt: time.Now().UTC(),
	}
	wg := make([]byte, wireguard.KeySize)
	if err := saveUserProfile(profile, []byte("ca"), []byte("certificate"), []byte("private"), wg); err != nil {
		t.Fatal(err)
	}
	loaded, files, err := loadUserProfile(authority)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NodeID != profile.NodeID || loaded.Generation == "" {
		t.Fatalf("loaded profile=%+v", loaded)
	}
	for _, path := range []string{filepath.Join(files.directory, "profile.json"), files.ca, files.certificate, files.privateKey, files.wireGuardKey} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe profile file %s mode=%v err=%v", path, info.Mode(), err)
		}
	}
	if _, _, err := loadUserProfile("other.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("other authority resolved this login: %v", err)
	}
}

func TestUserProfileRejectsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LANEWAY_PROFILE_DIR", root)
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, profilePath("lane.example.com")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadUserProfile("lane.example.com"); err == nil {
		t.Fatal("accepted symlinked saved-login directory")
	}
}

func TestDefaultUserProfileAuthority(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LANEWAY_PROFILE_DIR", root)
	if _, err := defaultUserProfileAuthority(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty profile root error = %v", err)
	}
	profile := userProfile{
		Version: userProfileVersion, Authority: "lane.example.com",
		NetworkID: "101112131415161718191a1b1c1d1e1f", ControllerServiceID: "202122232425262728292a2b2c2d2e2f",
		NodeID: "303132333435363738393a3b3c3d3e3f", Name: "laptop", CreatedAt: time.Now().UTC(),
	}
	if err := saveUserProfile(profile, []byte("ca"), []byte("certificate"), []byte("private"), make([]byte, wireguard.KeySize)); err != nil {
		t.Fatal(err)
	}
	if got, err := defaultUserProfileAuthority(); err != nil || got != profile.Authority {
		t.Fatalf("default authority = %q, %v", got, err)
	}
	profile.Authority = "other.example.com"
	if err := saveUserProfile(profile, []byte("ca"), []byte("certificate"), []byte("private"), make([]byte, wireguard.KeySize)); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultUserProfileAuthority(); err == nil || !strings.Contains(err.Error(), "multiple saved logins") {
		t.Fatalf("multiple profile error = %v", err)
	}
}
