//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootlessUpdateReplacesPairAndRejectsDowngrade(t *testing.T) {
	bin := t.TempDir()
	stage := t.TempDir()
	write := func(path, version string) {
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho '"+version+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	client := filepath.Join(bin, "laneway")
	daemon := filepath.Join(bin, "lanewayd-rs")
	nextClient := filepath.Join(stage, "laneway")
	nextDaemon := filepath.Join(stage, "lanewayd-rs")
	write(client, "1.2.3")
	write(daemon, "1.2.3")
	write(nextClient, "1.3.0")
	write(nextDaemon, "1.3.0")

	if err := installUserClientUpdate(bin, nextClient, nextDaemon, "1.3.0"); err != nil {
		t.Fatal(err)
	}
	write(nextClient, "1.2.3")
	write(nextDaemon, "1.2.3")
	if err := installUserClientUpdate(bin, nextClient, nextDaemon, "1.2.3"); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("older candidate should be rejected: %v", err)
	}
	for _, path := range []string{client, daemon} {
		got, err := updateExecutableVersion(path, "version")
		if err != nil || got != "1.3.0" {
			t.Fatalf("installed %s version = %q (%v)", path, got, err)
		}
	}
	lock := filepath.Join(bin, ".laneway-install.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installUserClientUpdate(bin, nextClient, nextDaemon, "1.4.0"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("busy installer should be rejected: %v", err)
	}
}
