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
	fs.BoolVar(&options.rust, "rust", false, "use the Rust split-tunnel runtime preview")
}

func platformConnectRustRuntime() (string, error) {
	if err := trustedMacRuntimePath(macRustRuntimePath, false); err != nil {
		return "", fmt.Errorf("Rust runtime preview is unavailable: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, macRustRuntimePath, "--version").Output()
	if err != nil || strings.TrimSpace(string(output)) != buildinfo.Version {
		return "", fmt.Errorf("the Rust runtime must match Laneway %s; reinstall the matching macOS preview archive", buildinfo.Version)
	}
	return macRustRuntimePath, nil
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
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--ephemeral [--token-file PATH]] [--rust]")
}

func platformNetworkHelperOptions() nethelper.StartOptions {
	return nethelper.StartOptions{Executable: "/Library/PrivilegedHelperTools/laneway-network-helper"}
}
