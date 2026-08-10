//go:build darwin

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/releaseupdate"
)

const (
	macClientPath  = "/usr/local/bin/laneway"
	macHelperPath  = "/Library/PrivilegedHelperTools/laneway-network-helper"
	macBinaryLimit = 128 << 20
)

func runMacConfigure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	checkOnly := fs.Bool("check", false, "verify the installed client and helper without changing them")
	yes := fs.Bool("yes", false, "install without the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*checkOnly && *yes) {
		return errors.New("usage: laneway configure [--check | --yes]")
	}
	source, err := currentExecutable()
	if err != nil {
		return err
	}
	if err := preflightMacInstall(source); err != nil {
		return err
	}
	if err := macConfigurationStatus(source); err == nil {
		fmt.Printf("macOS client configured cli=%s helper=%s\n", macClientPath, macHelperPath)
		return nil
	} else if *checkOnly {
		return err
	}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			return errors.New("macOS configuration requires sudo, but sudo is not available")
		}
		if !*yes {
			approved, err := confirmMacConfiguration()
			if err != nil {
				return err
			}
			if !approved {
				return errors.New("macOS configuration cancelled; no changes were made")
			}
		}
		process := exec.Command("sudo", source, "configure", "--yes")
		process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
		return process.Run()
	}
	if err := installMacBinary(source); err != nil {
		return err
	}
	if err := macConfigurationStatus(macClientPath); err != nil {
		return fmt.Errorf("verify macOS configuration: %w", err)
	}
	fmt.Printf("macOS client configured cli=%s helper=%s\n", macClientPath, macHelperPath)
	return nil
}

func runMacUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "install the verified update without the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: laneway update [--yes]")
	}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			return errors.New("macOS update requires sudo for the final install, but sudo is not available")
		}
	}
	work, err := os.MkdirTemp("", "laneway-macos-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	candidate := filepath.Join(work, "laneway")
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	release, err := client.DownloadLatest(downloadCtx, "laneway_darwin_"+runtime.GOARCH, candidate, macBinaryLimit)
	downloadCancel()
	if err != nil {
		return err
	}
	if comparison, comparable := compareStableVersions(buildinfo.Version, strings.TrimPrefix(release.Tag, "v")); comparable && comparison > 0 {
		return fmt.Errorf("latest stable release %s would downgrade installed v%s", release.Tag, buildinfo.Version)
	}
	versionOutput, err := exec.Command(candidate, "version").Output()
	if err != nil {
		return fmt.Errorf("verify downloaded macOS client version: %w", err)
	}
	expectedVersion := strings.TrimPrefix(release.Tag, "v")
	if actualVersion := strings.TrimSpace(string(versionOutput)); actualVersion != expectedVersion {
		return fmt.Errorf("downloaded macOS client reports version %q, expected %q", actualVersion, expectedVersion)
	}
	configureArgs := []string{"configure"}
	if *yes {
		configureArgs = append(configureArgs, "--yes")
	}
	process := exec.Command(candidate, configureArgs...)
	process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := process.Run(); err != nil {
		return fmt.Errorf("install verified macOS update: %w", err)
	}
	if err := macConfigurationStatus(candidate); err != nil {
		return fmt.Errorf("verify updated macOS client and helper: %w", err)
	}
	fmt.Printf("updated client and network helper to %s sha256=%s\n", release.Tag, release.SHA256)
	return nil
}

func compareStableVersions(left, right string) (int, bool) {
	parse := func(value string) ([3]uint64, bool) {
		var result [3]uint64
		parts := strings.Split(value, ".")
		if len(parts) != len(result) {
			return result, false
		}
		for index, part := range parts {
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return result, false
			}
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return result, false
			}
			result[index] = number
		}
		return result, true
	}
	leftParts, leftOK := parse(left)
	rightParts, rightOK := parse(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1, true
		}
		if leftParts[index] > rightParts[index] {
			return 1, true
		}
	}
	return 0, true
}

func currentExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > macBinaryLimit {
		return "", errors.New("current executable is not a bounded regular file")
	}
	return executable, nil
}

func confirmMacConfiguration() (bool, error) {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, errors.New("confirmation requires a terminal; rerun with --yes for unattended installation")
	}
	defer terminal.Close()
	fmt.Fprintf(terminal, "Install the verified Laneway client and root-owned network helper? [y/N]: ")
	line, err := bufio.NewReader(terminal).ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func installMacBinary(source string) error {
	if err := ensureMacDirectory(filepath.Dir(macClientPath), false); err != nil {
		return err
	}
	if err := ensureMacDirectory(filepath.Dir(macHelperPath), true); err != nil {
		return err
	}
	clientStage, err := stageMacBinary(source, macClientPath)
	if err != nil {
		return err
	}
	defer os.Remove(clientStage)
	helperStage, err := stageMacBinary(source, macHelperPath)
	if err != nil {
		return err
	}
	defer os.Remove(helperStage)
	if err := os.Rename(helperStage, macHelperPath); err != nil {
		return fmt.Errorf("install network helper: %w", err)
	}
	if err := os.Rename(clientStage, macClientPath); err != nil {
		return fmt.Errorf("install client: %w", err)
	}
	return nil
}

func preflightMacInstall(source string) error {
	if _, err := fileSHA256(source); err != nil {
		return fmt.Errorf("read candidate binary: %w", err)
	}
	for _, item := range []struct {
		directory  string
		privileged bool
	}{
		{directory: filepath.Dir(macClientPath)},
		{directory: filepath.Dir(macHelperPath), privileged: true},
	} {
		info, err := os.Lstat(item.directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("installation directory %s is not a real directory", item.directory)
		}
		if item.privileged {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("privileged helper directory %s must be root:wheel and not group/world writable", item.directory)
			}
		}
	}
	for _, destination := range []string{macClientPath, macHelperPath} {
		info, err := os.Lstat(destination)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace non-regular installation path %s", destination)
		}
	}
	return nil
}

func ensureMacDirectory(directory string, privileged bool) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", directory, err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("installation directory %s is not a real directory", directory)
	}
	if privileged {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("privileged helper directory %s must be root:wheel and not group/world writable", directory)
		}
	}
	return nil
}

func stageMacBinary(source, destination string) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".laneway-install-*")
	if err != nil {
		return "", err
	}
	name := output.Name()
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := output.Chmod(0o755); err != nil {
		return "", err
	}
	if err := output.Chown(0, 0); err != nil {
		return "", err
	}
	written, err := io.Copy(output, io.LimitReader(input, macBinaryLimit+1))
	if err != nil || written <= 0 || written > macBinaryLimit {
		return "", errors.New("copy macOS binary exceeded the allowed size")
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func macConfigurationStatus(source string) error {
	want, err := fileSHA256(source)
	if err != nil {
		return err
	}
	for _, installed := range []string{macClientPath, macHelperPath} {
		info, err := os.Lstat(installed)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is not an installed regular file; run 'laneway configure'", installed)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s must be root:wheel, executable, and not writable by group/others; run 'laneway configure'", installed)
		}
		got, err := fileSHA256(installed)
		if err != nil || got != want {
			return fmt.Errorf("%s does not match this Laneway binary; run 'laneway configure'", installed)
		}
	}
	return nil
}

func fileSHA256(filename string) ([sha256.Size]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, macBinaryLimit+1))
	if err != nil || read <= 0 || read > macBinaryLimit {
		return [sha256.Size]byte{}, errors.New("hash input is empty or exceeds the allowed size")
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}
