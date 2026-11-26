//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestRootlessCommandHelpDoesNotNeedAnInstalledRuntime(t *testing.T) {
	for command, want := range map[string]string{
		"configure":  "--state-dir",
		"start":      "--listen",
		"credential": "add|list|remove",
	} {
		root := newRootCommand()
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetArgs([]string{"help", command})
		if err := root.Execute(); err != nil || !strings.Contains(output.String(), want) {
			t.Fatalf("help %s = %q, %v", command, output.String(), err)
		}
	}
}

func TestExplicitSystemArgumentDoesNotConsumePublicFlagValues(t *testing.T) {
	for _, example := range []struct {
		args      []string
		system    bool
		remaining []string
	}{
		{[]string{"--system", "--config", "/etc/laneway/node-rust.toml"}, true, []string{"--config", "/etc/laneway/node-rust.toml"}},
		{[]string{"--state-dir", "--system"}, false, []string{"--state-dir", "--system"}},
		{[]string{"--", "--system"}, false, []string{"--", "--system"}},
	} {
		got, remaining := splitExplicitSystem(example.args)
		if got != example.system || !reflect.DeepEqual(remaining, example.remaining) {
			t.Errorf("%q: got (%v, %q), want (%v, %q)", example.args, got, remaining, example.system, example.remaining)
		}
	}
}

func TestRootlessRuntimeUsesMatchingArchiveLayout(t *testing.T) {
	pkg := t.TempDir()
	bin := filepath.Join(pkg, "bin")
	sbin := filepath.Join(pkg, "sbin")
	for _, dir := range []string{bin, sbin} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(bin, "laneway")
	sibling := filepath.Join(bin, "lanewayd-rs")
	archive := filepath.Join(sbin, "lanewayd-rs")
	expected := sibling
	if runtime.GOOS == "linux" {
		expected = archive
	}
	got, err := rootlessRuntimeCandidate(source)
	if err != nil || got != expected {
		t.Fatalf("archive candidate = %q, %v, want %q", got, err, expected)
	}
	if err := os.WriteFile(sibling, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err = rootlessRuntimeCandidate(source)
	if err != nil || got != sibling {
		t.Fatalf("sibling candidate = %q, %v", got, err)
	}
	if err := os.Remove(sibling); err != nil {
		t.Fatal(err)
	}
	moved := sbin + "-moved"
	if err := os.Rename(sbin, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, sbin); err != nil {
		t.Fatal(err)
	}
	got, err = rootlessRuntimeCandidate(source)
	if err != nil || got != sibling {
		t.Fatalf("symlinked archive candidate = %q, %v; want missing sibling", got, err)
	}
}
