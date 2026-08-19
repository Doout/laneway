//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestLinuxRootRegistersAdministratorLifecycleCommands(t *testing.T) {
	root := newRootCommand()
	for _, path := range [][]string{
		{"control", "administrator", "bootstrap"},
		{"control", "administrator", "recover"},
		{"control", "administrator", "root-token", "rotate"},
	} {
		command, remaining, err := root.Find(path)
		wantPath := "laneway " + strings.Join(path, " ")
		if err != nil || command.Hidden || command.CommandPath() != wantPath || len(remaining) != 0 {
			t.Fatalf("root command %q: resolved=%q remaining=%q hidden=%t error=%v", strings.Join(path, " "),
				command.CommandPath(), remaining, command.Hidden, err)
		}
	}
}

func TestLinuxRootRegistersControllerInitialNetworkInspector(t *testing.T) {
	root := newRootCommand()
	command, remaining, err := root.Find([]string{"config", "inspect-controller-initial-network"})
	if err != nil || command.CommandPath() != "laneway config inspect-controller-initial-network" || len(remaining) != 0 {
		t.Fatalf("config inspector: resolved=%q remaining=%q error=%v", command.CommandPath(), remaining, err)
	}
}
