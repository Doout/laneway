package main

import (
	"io"
	"os"
	"path/filepath"
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

func TestPublicCommandTreeGroupsWorkflows(t *testing.T) {
	root := newRootCommand()
	for _, name := range []string{"connect", "login", "logout", "node", "control", "version"} {
		command, _, err := root.Find([]string{name})
		if err != nil || command.Hidden {
			t.Fatalf("public command %q: hidden=%t error=%v", name, command != nil && command.Hidden, err)
		}
	}
	for _, name := range []string{"bootstrap", "config", "connector", "controller", "exit", "id", "invite", "join", "pki", "renew", "route", "status", "peers", "routes", "up"} {
		command, _, err := root.Find([]string{name})
		if err != nil || !command.Hidden {
			t.Fatalf("compatibility command %q: hidden=%t error=%v", name, command != nil && command.Hidden, err)
		}
	}
	for _, name := range []string{"status", "peers", "routes", "up", "exit", "route"} {
		command, _, err := root.Find([]string{"node", name})
		if err != nil || command.Hidden {
			t.Fatalf("node command %q: hidden=%t error=%v", name, command != nil && command.Hidden, err)
		}
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

func TestControlAdministratorCommandsForwardExactArguments(t *testing.T) {
	directory := t.TempDir()
	operator := filepath.Join(directory, "laneway-control")
	output := filepath.Join(directory, "invocation")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$LANEWAY_TEST_OUTPUT\"\n"
	if err := os.WriteFile(operator, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEWAY_CONTROL_COMMAND", operator)
	t.Setenv("LANEWAY_TEST_OUTPUT", output)

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"bootstrap", []string{"administrator", "bootstrap", "--username", "owner"}, []string{"administrator", "bootstrap", "--username", "owner"}},
		{"recover", []string{"administrator", "recover", "--username", "owner"}, []string{"administrator", "recover", "--username", "owner"}},
		{"root token rotation", []string{"administrator", "root-token", "rotate"}, []string{"administrator", "root-token", "rotate"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			control := controlCommand()
			control.SetArgs(test.args)
			if err := control.Execute(); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
			if strings.Join(lines, "\x00") != strings.Join(test.want, "\x00") {
				t.Fatalf("operator invocation = %q, want %q", lines, test.want)
			}
		})
	}
}

func TestControlAdministratorCommandTree(t *testing.T) {
	control := controlCommand()
	for _, path := range [][]string{
		{"administrator"},
		{"administrator", "bootstrap"},
		{"administrator", "recover"},
		{"administrator", "root-token"},
		{"administrator", "root-token", "rotate"},
	} {
		command, remaining, err := control.Find(path)
		wantPath := "control " + strings.Join(path, " ")
		if err != nil || command.Hidden || command.CommandPath() != wantPath || len(remaining) != 0 {
			t.Fatalf("control command %q: resolved=%q remaining=%q hidden=%t error=%v", strings.Join(path, " "),
				command.CommandPath(), remaining, command.Hidden, err)
		}
	}
}

func TestControlAdministratorCommandsRejectInvalidArgumentsBeforeWrapper(t *testing.T) {
	directory := t.TempDir()
	operator := filepath.Join(directory, "laneway-control")
	invoked := filepath.Join(directory, "invoked")
	script := "#!/bin/sh\n" +
		": > \"$LANEWAY_TEST_INVOKED\"\n"
	if err := os.WriteFile(operator, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEWAY_CONTROL_COMMAND", operator)
	t.Setenv("LANEWAY_TEST_INVOKED", invoked)

	for _, args := range [][]string{
		{"administrator", "bootstrap"},
		{"administrator", "bootstrap", "--user", "owner"},
		{"administrator", "bootstrap", "--username", "owner", "--password", "must-not-forward"},
		{"administrator", "bootstrap", "--username", "Owner"},
		{"administrator", "bootstrap", "--username", "owner name"},
		{"administrator", "bootstrap", "--username", "owner", "extra"},
		{"administrator", "recover"},
		{"administrator", "recover", "--user", "owner"},
		{"administrator", "recover", "--username", "owner", "--password", "must-not-forward"},
		{"administrator", "recover", "--username", "Owner"},
		{"administrator", "recover", "--username", "owner name"},
		{"administrator", "recover", "extra"},
		{"administrator", "root-token", "rotate", "extra"},
	} {
		control := controlCommand()
		control.SetOut(io.Discard)
		control.SetErr(io.Discard)
		control.SetArgs(args)
		if err := control.Execute(); err == nil {
			t.Fatalf("control %q unexpectedly succeeded", strings.Join(args, " "))
		}
		if _, err := os.Stat(invoked); !os.IsNotExist(err) {
			t.Fatalf("control %q invoked wrapper before validation: %v", strings.Join(args, " "), err)
		}
	}
}
