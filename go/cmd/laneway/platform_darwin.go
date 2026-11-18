//go:build darwin

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/nethelper"
)

const credentialDescriptorDirectory = "/dev/fd"
const macRustRuntimePath = "/Library/Application Support/Laneway/lanewayd-rs"

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
	for path := macRustRuntimePath; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("Rust runtime preview is not installed at %s: %w", macRustRuntimePath, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
			(path == macRustRuntimePath && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0)) ||
			(path != macRustRuntimePath && !info.IsDir()) {
			return "", fmt.Errorf("Rust runtime path %s must be root-owned and not writable by group or others", path)
		}
		if path == "/" {
			return macRustRuntimePath, nil
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
