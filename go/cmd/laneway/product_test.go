//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute the real command router in a child because the Unix frontend
// replaces itself with the daemon.
func TestProductCLIProcess(t *testing.T) {
	if os.Getenv("LANEWAY_TEST_PRODUCT_PROCESS") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg != "--" {
			continue
		}
		if err := executeCLI(os.Args[index+1:]); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("missing test arguments")
}

func TestProductUserCommandsReachInstalledDaemon(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("userspace commands require a normal user")
	}
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	daemon := filepath.Join(bin, "lanewayd")
	if err := os.WriteFile(daemon, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\nif [ \"$1\" = configure ]; then /bin/cat; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANEWAY_TEST_PRODUCT_PROCESS", "1")
	t.Setenv("HOME", home)
	t.Setenv("PATH", "/usr/bin:/bin")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args []string
		in   string
		want string
	}{
		{args: []string{"configure"}, in: "fixture-invitation\n", want: "configure\nfixture-invitation\n"},
		{args: []string{"start", "--state-dir", "/tmp/custom state", "--listen", "127.0.0.1:8080", "--proxy-only"}, want: "--state-dir\n/tmp/custom state\nrun\n--listen\n127.0.0.1:8080\n--proxy-only\n"},
		{args: []string{"start", "--no-proxy"}, want: "run\n--no-proxy\n"},
		{args: []string{"credential", "add", "local-client"}, want: "credential\nadd\nlocal-client\n"},
	} {
		t.Run(test.args[0], func(t *testing.T) {
			args := append([]string{"-test.run=^TestProductCLIProcess$", "--"}, test.args...)
			command := exec.Command(executable, args...)
			command.Stdin = strings.NewReader(test.in)
			output, err := command.CombinedOutput()
			if err != nil || string(output) != test.want {
				t.Fatalf("command %q output=%q error=%v", test.args, output, err)
			}
		})
	}
}

func TestProductOptionsRequireExplicitSystemMode(t *testing.T) {
	if err := runProductStart([]string{"--config", "node.toml"}); err == nil || !strings.Contains(err.Error(), "--config requires --system") {
		t.Fatalf("missing explicit system mode = %v", err)
	}
	if err := runConfigure([]string{"--system", "--state-dir", "/tmp/user"}); err == nil || !strings.Contains(err.Error(), "--state-dir is only used in userspace mode") {
		t.Fatalf("mixed setup modes = %v", err)
	}
	for _, arg := range [][]string{{"--listen", "127.0.0.1:8080"}, {"--no-proxy"}, {"--proxy-only"}} {
		if err := runProductStart(append([]string{"--system"}, arg...)); err == nil || !strings.Contains(err.Error(), "only used in userspace mode") {
			t.Fatalf("mixed start modes %q = %v", arg, err)
		}
	}
	if err := runProductStart([]string{"--no-proxy", "--proxy-only"}); err == nil || !strings.Contains(err.Error(), "--no-proxy cannot be used") {
		t.Fatalf("conflicting proxy modes = %v", err)
	}
}
