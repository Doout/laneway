//go:build linux || darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/spf13/cobra"
)

func addRootlessCommands(root *cobra.Command) {
	configureUsage := "configure [--state-dir PATH] [--discard-pending]"
	startUsage := "start [--state-dir PATH] [--listen ADDRESS | --no-proxy] [--proxy-only]"
	configureHelp := "Configure a per-user node using an enrollment token. Run 'laneway configure --system --check' to verify the installed macOS networking runtime, or use --system --yes to install from the release archive."
	startHelp := "Run an enrolled per-user node and the local SOCKS5 proxy in the foreground."
	if runtime.GOOS == "linux" {
		configureHelp = "Configure a per-user node using an enrollment token. Run 'sudo laneway configure --system' to configure a Linux system node using an st1 token read from standard input. Existing managed installations can still use 'laneway node install DOMAIN'."
		startHelp += " Run 'sudo laneway start --system [--config PATH]' to start the managed Linux daemon in the foreground."
	}
	for _, workflow := range []struct {
		use, summary, long string
		handler            commandHandler
	}{
		{configureUsage, "Configure a per-user node", configureHelp, runProductConfigure},
		{startUsage, "Start a per-user node", startHelp, runProductStart},
		{"credential <add|list|remove>", "Manage local proxy credentials", "Manage the local SOCKS5 proxy login for the per-user node.", func(args []string) error {
			return runRootless("credential", args)
		}},
	} {
		cmd := command(workflow.use, workflow.summary, workflow.handler)
		cmd.GroupID = "client"
		cmd.Long = workflow.long
		run := cmd.RunE
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				return cmd.Help()
			}
			return run(cmd, args)
		}
		if runtime.GOOS == "linux" && cmd.Name() == "configure" {
			cmd.AddCommand(&cobra.Command{
				Use:   "server [DOMAIN]",
				Short: "Show how to run the signed control-plane installer",
				Args:  cobra.MaximumNArgs(1),
				RunE: func(_ *cobra.Command, _ []string) error {
					return fmt.Errorf("download the official release install.sh and run it on the Linux server with sudo env LANEWAY_DOMAIN=YOUR_DOMAIN sh install.sh")
				},
			})
		}

		root.AddCommand(cmd)
	}
}

func splitExplicitSystem(args []string) (bool, []string) {
	system := false
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--system", "-system", "--system=true", "-system=true":
			system = true
		case "--":
			return system, append(remaining, args[i:]...)
		case "--state-dir", "-state-dir", "--listen", "-listen", "--config", "-config", "--token-file", "-token-file", "--name", "-name":
			remaining = append(remaining, arg)
			if i+1 < len(args) {
				i++
				remaining = append(remaining, args[i])
			}
		default:
			remaining = append(remaining, arg)
		}
	}
	return system, remaining
}

func runProductStart(args []string) error {
	if system, remaining := splitExplicitSystem(args); system {
		return runSystemStart(remaining)
	}
	return runRootless("start", args)
}

func runRootless(command string, args []string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	runtime, err := rootlessRuntime(source)
	if err != nil {
		return err
	}
	return syscall.Exec(runtime, append([]string{runtime, "_rootless", command}, args...), os.Environ())
}

func rootlessRuntime(source string) (string, error) {
	candidate, err := rootlessRuntimeCandidate(source)
	if err != nil {
		return "", err
	}
	if candidate == "" {
		return platformConnectRustRuntime()
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("install a matching Laneway client with an executable lanewayd-rs beside %s", source)
	}
	if os.Geteuid() == 0 {
		if err := protectedRootlessRuntime(candidate); err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, candidate, "--version")
	if os.Geteuid() == 0 {
		probe.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	output, err := probe.Output()
	if err != nil || strings.TrimSpace(string(output)) != buildinfo.Version {
		return "", fmt.Errorf("the Rust runtime must match Laneway %s; install the matching signed client", buildinfo.Version)
	}
	return candidate, nil
}

func rootlessRuntimeCandidate(source string) (string, error) {
	bin := filepath.Dir(source)
	candidate := filepath.Join(bin, "lanewayd-rs")
	if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
		return candidate, err
	}
	if source == "/usr/local/bin/laneway" {
		return "", nil
	}
	if runtime.GOOS == "linux" && filepath.Base(bin) == "bin" {
		sbin := filepath.Join(filepath.Dir(bin), "sbin")
		if directory, err := os.Lstat(sbin); err == nil && directory.IsDir() {
			return filepath.Join(sbin, "lanewayd-rs"), nil
		}
	}
	return candidate, nil
}

func runPlatformNetworkHelper(descriptor int) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("the installed network helper requires root")
	}
	runtime, err := platformConnectRustRuntime()
	if err != nil {
		return err
	}
	return syscall.Exec(runtime,
		[]string{runtime, "_network-helper", "--control-fd=" + strconv.Itoa(descriptor)},
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}

func protectedRootlessRuntime(runtime string) error {
	for path := runtime; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
			(path == runtime && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0)) ||
			(path != runtime && !info.IsDir()) {
			return fmt.Errorf("untrusted Rust runtime path %s: must be root-owned and non-writable by other users", path)
		}
		if path == "/" {
			return nil
		}
	}
}
