//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/nethelper"
)

// Keep the existing sudo rule valid for compiled Go session clients. Replace
// the process rather than launching a child so its inherited socket survives.
func execNativeNetworkHelper(descriptor int) error {
	current, err := os.Executable()
	if err != nil {
		return err
	}
	frontend, err := verifiedNativeNetworkHelper(current)
	if err != nil {
		return err
	}
	argv := []string{frontend, "_network-helper-native", "--control-fd=" + strconv.Itoa(descriptor)}
	return unix.Exec(frontend, argv, nativeNetworkHelperEnvironment())
}

func nativeNetworkHelperEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
}

func verifiedNativeNetworkHelper(current string) (string, error) {
	frontend, err := nativeNetworkHelperFrontend(current)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, frontend, "_network-helper-native", "--version")
	probe.Env = nativeNetworkHelperEnvironment()
	version, err := probe.Output()
	if err != nil || strings.TrimSpace(string(version)) != buildinfo.Version {
		return "", fmt.Errorf("Laneway executable files do not provide matching native networking; reinstall the signed Laneway package")
	}
	return frontend, nil
}

func nativeNetworkHelperFrontend(current string) (string, error) {
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil || resolved != current || filepath.Base(current) != "laneway-compat" {
		return "", fmt.Errorf("expected the protected Laneway compatibility executable")
	}
	if err := nethelper.ValidateRootOwnedExecutable(current); err != nil {
		return "", err
	}
	frontend := filepath.Join(filepath.Dir(current), "laneway")
	currentInfo, err := os.Lstat(current)
	if err != nil {
		return "", err
	}
	frontendInfo, err := os.Lstat(frontend)
	if err != nil || !frontendInfo.Mode().IsRegular() || frontendInfo.Mode().Perm()&0o100 == 0 ||
		os.SameFile(currentInfo, frontendInfo) {
		return "", fmt.Errorf("missing or unsafe native Laneway helper at %s; reinstall the signed Laneway package", frontend)
	}
	if err := nethelper.ValidateRootOwnedExecutable(frontend); err != nil {
		return "", err
	}
	return frontend, nil
}
