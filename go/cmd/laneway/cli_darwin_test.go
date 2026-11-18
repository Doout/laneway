package main

import "testing"

func TestMacOSCommandTreeOnlyExposesClientWorkflows(t *testing.T) {
	root := newRootCommand()
	for _, name := range []string{"configure", "connect", "login", "logout", "update", "version"} {
		command, remaining, err := root.Find([]string{name})
		if err != nil || command.Name() != name || command.Hidden || len(remaining) != 0 {
			t.Fatalf("expected macOS command %q, got %v (%v), remaining %q", name, command, err, remaining)
		}
	}
	for _, command := range root.Commands() {
		if command.GroupID == "host" || command.GroupID == "control" {
			t.Fatalf("macOS client unexpectedly registers host command %q", command.Name())
		}
	}
	for _, name := range []string{"bootstrap", "_network-helper"} {
		command, remaining, err := root.Find([]string{name})
		if err != nil || command.Name() != name || !command.Hidden || len(remaining) != 0 {
			t.Fatalf("expected hidden compatibility command %q, got %v (%v)", name, command, err)
		}
	}
}
