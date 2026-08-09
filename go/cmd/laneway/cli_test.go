package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestRootHelpDoesNotLoadNodeConfiguration(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workingDirectory := t.TempDir()
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	if err := run(nil); err != nil {
		t.Fatalf("root help from %s: %v", workingDirectory, err)
	}
	if err := run([]string{"control", "--help"}); err != nil {
		t.Fatalf("control help from %s: %v", workingDirectory, err)
	}
}

func TestMacOSCLIContainsOnlyUserClientCommands(t *testing.T) {
	root := newRootCommandForOS("darwin")
	names := make([]string, 0, len(root.Commands()))
	for _, item := range root.Commands() {
		names = append(names, item.Name())
	}
	sort.Strings(names)
	want := []string{"_network-helper", "bootstrap", "connect", "login", "logout", "version"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("macOS commands = %v, want %v", names, want)
	}
}

func TestControlCommandIsIndependentOfWorkingDirectory(t *testing.T) {
	directory := t.TempDir()
	operator := filepath.Join(directory, "laneway-control")
	output := filepath.Join(directory, "invocation")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$PWD\" \"$@\" > \"$LANEWAY_TEST_OUTPUT\"\n"
	if err := os.WriteFile(operator, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEWAY_CONTROL_COMMAND", operator)
	t.Setenv("LANEWAY_TEST_OUTPUT", output)

	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workingDirectory := t.TempDir()
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	if err := run([]string{"control", "status", "--json"}); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	want := []string{workingDirectory, "status", "--json"}
	if strings.Join(lines, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("operator invocation = %q, want %q", lines, want)
	}
}
