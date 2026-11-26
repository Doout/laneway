//go:build darwin

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/nethelper"
)

const credentialDescriptorDirectory = "/dev/fd"
const macRustRuntimePath = "/Library/Application Support/Laneway/lanewayd-rs"

func runProductConfigure(args []string) error {
	system, remaining := splitExplicitSystem(args)
	if !system {
		for _, arg := range args {
			if arg == "--" || strings.HasPrefix(arg, "--state-dir") || strings.HasPrefix(arg, "-state-dir") {
				break
			}
			flag, _, _ := strings.Cut(arg, "=")
			switch flag {
			case "--check", "-check", "--yes", "-yes":
				system = true
			}
		}
	}
	if system {
		return runMacConfigure(remaining)
	}
	return runRootless("configure", args)
}

func runSystemStart(args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("On macOS, use 'laneway configure --system' to install host networking and 'laneway connect DOMAIN' to start an authenticated host connection.")
		return nil
	}
	return errors.New("use 'laneway connect DOMAIN' for macOS host networking")
}

func foregroundTunName(string) string { return "utun" }

func prepareRustForegroundProcess(*exec.Cmd) func() { return func() {} }

func connectPlatformPreflight() error {
	source, err := currentExecutable()
	if err != nil {
		return err
	}
	return macConfigurationStatus(source)
}

func addPlatformConnectFlags(fs *flag.FlagSet, options *connectPlatformOptions) {
	options.rust = true
	fs.BoolFunc("rust", "use the Rust runtime (already the default)", func(value string) error {
		if value == "true" {
			return nil
		}
		return errors.New("macOS requires the Rust runtime")
	})
}

func platformConnectRustRuntime() (string, error) {
	if err := trustedMacRuntimePath(macRustRuntimePath, false); err != nil {
		return "", fmt.Errorf("Rust runtime is unavailable: %w", err)
	}
	if err := checkMacRustVersion(macRustRuntimePath); err != nil {
		return "", err
	}
	return macRustRuntimePath, nil
}

func checkMacRustVersion(executable string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, executable, "--version")
	probe.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := probe.Output()
	if err != nil || strings.TrimSpace(string(output)) != buildinfo.Version {
		return fmt.Errorf("the Rust runtime must match Laneway %s; reinstall the signed macOS package", buildinfo.Version)
	}
	return nil
}

func trustedMacRuntimePath(first string, directory bool) error {
	for path := first; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		expectsDirectory := directory || path != first
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
			(!expectsDirectory && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0)) ||
			(expectsDirectory && !info.IsDir()) {
			return fmt.Errorf("Rust runtime path %s must be root-owned and not writable by group or others", path)
		}
		if path == "/" {
			return nil
		}
	}
}

func validatePlatformArtifact(bootstrap.Metadata) error { return nil }

func connectUsage() error {
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions { return nethelper.StartOptions{} }
