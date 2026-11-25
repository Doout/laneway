package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS != "linux" {
		return
	}
	if err := run([]string{"control", "--help"}); err != nil {
		t.Fatalf("control help from %s: %v", workingDirectory, err)
	}
}

func TestPublicCommandTreeGroupsWorkflows(t *testing.T) {
	root := newRootCommand()
	public := []string{"connect", "login", "logout", "configure", "start", "credential", "update", "version"}
	hidden := []string{"bootstrap", "_network-helper"}
	linuxPublic := []string{"node", "control"}
	linuxHidden := []string{"config", "connector", "controller", "exit", "id", "invite", "join", "pki", "renew", "route", "status", "peers", "routes", "up"}
	if runtime.GOOS == "linux" {
		public = append(public, linuxPublic...)
		hidden = append(hidden, linuxHidden...)
	}
	for _, names := range []struct {
		names  []string
		hidden bool
	}{{public, false}, {hidden, true}} {
		for _, name := range names.names {
			command, remaining, err := root.Find([]string{name})
			if err != nil || command == nil || command.CommandPath() != "laneway "+name ||
				len(remaining) != 0 || command.Hidden != names.hidden {
				t.Fatalf("command %q: resolved=%v remaining=%q error=%v, expected hidden=%t", name, command, remaining, err, names.hidden)
			}
		}
	}
	if runtime.GOOS != "linux" {
		for _, name := range append(linuxPublic, linuxHidden...) {
			for _, command := range root.Commands() {
				if command.Name() == name {
					t.Fatalf("Linux-only command %q is registered on %s", name, runtime.GOOS)
				}
			}
		}
		return
	}
	for _, name := range []string{"status", "peers", "routes", "up", "exit", "route"} {
		command, _, err := root.Find([]string{"node", name})
		if err != nil || command.Hidden {
			t.Fatalf("node command %q: hidden=%t error=%v", name, command != nil && command.Hidden, err)
		}
	}
}

func TestProductEntryPointsOfferOfflineHelp(t *testing.T) {
	for _, path := range []string{"configure", "configure server", "start", "credential", "update", "update client", "update server", "update connector"} {
		t.Run(path, func(t *testing.T) {
			args := strings.Fields(path)
			root := newRootCommand()
			target, rest, err := root.Find(args)
			if err != nil || len(rest) != 0 || target.CommandPath() != "laneway "+path || target.Hidden {
				t.Fatalf("cannot resolve public command %q", path)
			}
			root.SetOut(io.Discard)
			root.SetArgs(append(args, "--help"))
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := runProductUpdate("", []string{"unknown"}); err == nil {
		t.Fatal("accepted unknown update target")
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

	var commandError error
	if runtime.GOOS == "linux" {
		commandError = run([]string{"control", "status", "--json"})
	} else {
		control := controlCommand()
		control.SetArgs([]string{"status", "--json"})
		commandError = control.Execute()
	}
	if commandError != nil {
		t.Fatal(commandError)
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	physicalDirectory, err := filepath.EvalSymlinks(workingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{physicalDirectory, "status", "--json"}
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
