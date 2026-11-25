//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeUpdateDestinations(t *testing.T) {
	bin := t.TempDir()
	resolvedBin, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"darwin", "linux"} {
		client, node, err := nativeUpdateDestinations(filepath.Join(resolvedBin, "laneway"), bin, goos, 501)
		if err != nil || client != filepath.Join(resolvedBin, "laneway") || node != filepath.Join(resolvedBin, "lanewayd") {
			t.Fatalf("%s user installation destinations = %s, %s, %v", goos, client, node, err)
		}
	}
	if _, node, err := nativeUpdateDestinations("/usr/local/bin/laneway", bin, "darwin", 501); err != nil || node != "" {
		t.Fatalf("legacy macOS installation node destination = %s, %v", node, err)
	}
	if _, node, err := nativeUpdateDestinations("/usr/local/bin/laneway", bin, "linux", 0); err != nil || node != "/usr/local/sbin/lanewayd" {
		t.Fatalf("Linux system daemon destination = %s, %v", node, err)
	}
	if _, _, err := nativeUpdateDestinations(filepath.Join(resolvedBin, "laneway"), bin, "linux", 0); err == nil {
		t.Fatal("root may not update a user's installation")
	}
	if _, _, err := nativeUpdateDestinations("/usr/local/bin/laneway", bin, "linux", 501); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("unprivileged Linux system update = %v", err)
	}
}

func TestInstallNativeUpdate(t *testing.T) {
	work := t.TempDir()
	target := t.TempDir()
	cli := nativeUpdateFile{source: filepath.Join(work, "laneway"), destination: filepath.Join(target, "laneway")}
	node := nativeUpdateFile{source: filepath.Join(work, "lanewayd"), destination: filepath.Join(target, "lanewayd")}
	compat := nativeUpdateFile{source: filepath.Join(work, "laneway-compat"), destination: filepath.Join(target, "laneway-compat")}
	files := []nativeUpdateFile{compat, node, cli}
	for path, contents := range map[string]string{
		cli.source: "new Rust CLI", node.source: "new Rust daemon", compat.source: "new Go helper",
		cli.destination: "previous CLI", compat.destination: "previous helper",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(cli.destination, node.destination); err != nil {
		t.Fatal(err)
	}
	if err := installNativeUpdate(files); err == nil {
		t.Fatal("unexpected per-user symlink was accepted")
	}
	for file, expected := range map[nativeUpdateFile]string{cli: "previous CLI", compat: "previous helper"} {
		if got, err := os.ReadFile(file.destination); err != nil || string(got) != expected {
			t.Fatalf("%s changed before all assets were ready: %q, %v", file.destination, got, err)
		}
	}
	if err := os.Remove(node.destination); err != nil {
		t.Fatal(err)
	}
	if err := installNativeUpdate(files); err != nil {
		t.Fatal(err)
	}
	for file, expected := range map[nativeUpdateFile]string{cli: "new Rust CLI", node: "new Rust daemon", compat: "new Go helper"} {
		got, err := os.ReadFile(file.destination)
		if err != nil || string(got) != expected {
			t.Fatalf("installed %s = %q, %v", file.destination, got, err)
		}
	}
}
