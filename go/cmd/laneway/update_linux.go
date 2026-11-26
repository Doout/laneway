//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const deploymentUpdateRuntime = "/usr/local/sbin/lanewayd-rs"

var hostUpdateEnvironment = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"HOME=/root",
	"LANG=C",
}

func detectUpdateTarget() (string, error) {
	if installedUserCLI() {
		return "client", nil
	}
	if err := protectedRootlessRuntime(deploymentUpdateRuntime); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, deploymentUpdateRuntime, "_deployment-update", "detect")
	command.Env = hostUpdateEnvironment
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("detect the installed update target: %w", err)
	}
	target := strings.TrimSpace(string(output))
	switch target {
	case "client", "server", "connector":
		return target, nil
	default:
		return "", fmt.Errorf("unsupported installed update target %q", target)
	}
}

func updateDeployment(target string, args []string) error {
	switch target {
	case "server", "connector":
	default:
		return fmt.Errorf("unknown update target %q; choose client, server or connector", target)
	}
	if err := protectedRootlessRuntime(deploymentUpdateRuntime); err != nil {
		return err
	}
	command := exec.Command(deploymentUpdateRuntime, append([]string{"_deployment-update", target}, args...)...)
	return runHostUpdate(command)
}

func checkSystemUpdateScope(rootless bool) error {
	if rootless {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("run 'sudo /usr/local/bin/laneway update client' to update the system client")
	}
	if err := protectedRootlessRuntime("/usr/local/bin/laneway"); err != nil {
		return err
	}
	target, err := detectUpdateTarget()
	if err != nil {
		return err
	}
	if target != "client" {
		return fmt.Errorf("this managed host requires 'laneway update %s'", target)
	}
	return nil
}

func unixOwner(info fs.FileInfo) uint32 {
	return info.Sys().(*syscall.Stat_t).Uid
}

func installSystemClientUpdate(work, archive, _, _, version string, _ bool) error {
	lock := "/usr/local/bin/.laneway-install.lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("acquire Laneway install lock %s: %w", lock, err)
	}
	defer os.Remove(lock)
	installed, err := updateExecutableVersion("/usr/local/bin/laneway", "version")
	if err != nil {
		return err
	}
	if err := preventClientDowngrade(installed, version); err != nil {
		return err
	}
	// This archive was authenticated before extraction. Only its local installer
	// is allowed to modify system paths.
	extract := exec.Command("/usr/bin/tar", "--no-same-owner", "--no-same-permissions", "-xzf", archive, "-C", work)
	extract.Env = hostUpdateEnvironment
	if output, err := extract.CombinedOutput(); err != nil {
		return fmt.Errorf("extract verified system package: %w: %s", err, output)
	}
	script := filepath.Join(work, "laneway", "install.sh")
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("verified Linux package is missing its regular installer")
	}
	return runHostUpdate(exec.Command("/bin/sh", script, "--rust-preview"))
}

func runHostUpdate(command *exec.Cmd) error {
	command.Env = hostUpdateEnvironment
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
