//go:build darwin

package main

import (
	"sort"
	"strings"
	"testing"
)

func TestMacOSCLIContainsOnlyUserClientCommands(t *testing.T) {
	root := newRootCommand()
	names := make([]string, 0, len(root.Commands()))
	for _, item := range root.Commands() {
		names = append(names, item.Name())
	}
	sort.Strings(names)
	want := []string{"_network-helper", "bootstrap", "configure", "connect", "login", "logout", "update", "version"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("macOS commands = %v, want %v", names, want)
	}
}

func TestMacOSConnectRejectsExitModeLocally(t *testing.T) {
	err := runConnect([]string{"lane.example.com", "--exit", "gateway"})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -exit") {
		t.Fatalf("runConnect(--exit) error = %v, want unknown flag", err)
	}
}

func TestMacOSUpdateDomainIsOptional(t *testing.T) {
	root := newRootCommand()
	update, _, err := root.Find([]string{"update"})
	if err != nil {
		t.Fatal(err)
	}
	if update.Use != "update [DOMAIN]" {
		t.Fatalf("update usage = %q", update.Use)
	}
}
