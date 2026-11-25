//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestMacOSPackageInstallsPrivateCompatibilityHelper(t *testing.T) {
	directory := t.TempDir()
	client := filepath.Join(directory, "laneway")
	compat := filepath.Join(directory, "laneway-compat")
	node := filepath.Join(directory, "lanewayd")
	for _, path := range []string{client, compat, node} {
		if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{client, compat} {
		files, err := macInstallFiles(source)
		if err != nil {
			t.Fatal(err)
		}
		expected := map[string]string{
			macClientPath: client,
			macCompatPath: compat,
			macHelperPath: compat,
			macNodePath:   node,
		}
		for _, file := range files {
			if expected[file.destination] != file.source {
				t.Fatalf("unexpected install file %+v", file)
			}
			delete(expected, file.destination)
		}
		if len(expected) != 0 {
			t.Fatalf("missing install files %v", expected)
		}
	}
}

func TestMacOSCLIContainsOnlyUserClientCommands(t *testing.T) {
	root := newRootCommand()
	names := make([]string, 0, len(root.Commands()))
	for _, item := range root.Commands() {
		names = append(names, item.Name())
	}
	sort.Strings(names)
	want := []string{"_network-helper", "bootstrap", "configure", "connect", "credential", "login", "logout", "start", "update", "version"}
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

func TestMacOSUpdateDoesNotRequireControllerDomain(t *testing.T) {
	root := newRootCommand()
	update, _, err := root.Find([]string{"update"})
	if err != nil {
		t.Fatal(err)
	}
	if update.Use != "update" {
		t.Fatalf("update usage = %q", update.Use)
	}
}

func TestMacOSCompareStableVersions(t *testing.T) {
	for _, test := range []struct {
		left       string
		right      string
		want       int
		comparable bool
	}{
		{left: "0.2.41", right: "0.2.42", want: -1, comparable: true},
		{left: "0.2.42", right: "0.2.42", comparable: true},
		{left: "1.0.0", right: "0.99.99", want: 1, comparable: true},
		{left: "dev", right: "0.2.42"},
		{left: "0.02.42", right: "0.2.42"},
	} {
		got, comparable := compareStableVersions(test.left, test.right)
		if got != test.want || comparable != test.comparable {
			t.Errorf("compareStableVersions(%q, %q) = (%d, %t), want (%d, %t)", test.left, test.right, got, comparable, test.want, test.comparable)
		}
	}
}
