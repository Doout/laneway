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
	"strings"
	"syscall"
	"time"

	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/releaseupdate"
)

const (
	macClientPath  = "/usr/local/bin/laneway"
	macCompatPath  = "/usr/local/bin/laneway-compat"
	macNodePath    = "/usr/local/bin/lanewayd"
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
		const sudo = "/usr/bin/sudo"
		if _, err := exec.LookPath(sudo); err != nil {
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
		compat, err := os.Executable()
		if err != nil {
			return err
		}
		process := exec.Command(sudo, compat, "configure", "--system", "--yes")
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
		if _, err := exec.LookPath("/usr/bin/sudo"); err != nil {
			return errors.New("macOS update requires sudo for the final install, but sudo is not available")
		}
	}
	tempBase := ""
	if os.Geteuid() == 0 {
		if err := releaseupdate.CheckSystemDirectory(filepath.Dir(macHelperPath)); err != nil {
			return err
		}
		tempBase = "/tmp"
	}
	work, err := os.MkdirTemp(tempBase, "laneway-macos-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	candidate := filepath.Join(work, "laneway")
	compat := filepath.Join(work, "laneway-compat")
	node := filepath.Join(work, "lanewayd")
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	tag, err := client.DownloadLatestSigned(downloadCtx, releaseupdate.Asset{
		Name: "laneway-native_darwin_" + runtime.GOARCH, Destination: candidate, MaxBytes: macBinaryLimit,
	}, releaseupdate.Asset{
		Name: "laneway-compat_darwin_" + runtime.GOARCH, Destination: compat, MaxBytes: macBinaryLimit,
	}, releaseupdate.Asset{
		Name: "lanewayd_darwin_" + runtime.GOARCH, Destination: node, MaxBytes: macBinaryLimit,
	})
	downloadCancel()
	if err != nil {
		return err
	}
	return installVerifiedMacUpdate(candidate, tag, *yes)
}

func installVerifiedMacUpdate(candidate, tag string, yes bool) error {
	if comparison, comparable := compareStableVersions(buildinfo.Version, strings.TrimPrefix(tag, "v")); comparable && comparison > 0 {
		return fmt.Errorf("latest stable release %s would downgrade installed v%s", tag, buildinfo.Version)
	}
	versionOutput, err := exec.Command(candidate, "version").Output()
	if err != nil {
		return fmt.Errorf("verify downloaded macOS client version: %w", err)
	}
	expectedVersion := strings.TrimPrefix(tag, "v")
	if actualVersion := strings.TrimSpace(string(versionOutput)); actualVersion != expectedVersion {
		return fmt.Errorf("downloaded macOS client reports version %q, expected %q", actualVersion, expectedVersion)
	}
	daemonVersion, err := exec.Command(macNodeCandidate(candidate), "--version").Output()
	if err != nil {
		return fmt.Errorf("verify downloaded macOS node version: %w", err)
	}
	if actual := strings.TrimSpace(string(daemonVersion)); actual != "lanewayd "+expectedVersion {
		return fmt.Errorf("downloaded macOS node reports version %q, expected %q", actual, "lanewayd "+expectedVersion)
	}
	compat := filepath.Join(filepath.Dir(candidate), "laneway-compat")
	helperVersion, err := exec.Command(compat, "version").Output()
	if err != nil {
		return fmt.Errorf("verify downloaded macOS compatibility helper version: %w", err)
	}
	if actual := strings.TrimSpace(string(helperVersion)); actual != expectedVersion {
		return fmt.Errorf("downloaded macOS compatibility helper reports version %q, expected %q", actual, expectedVersion)
	}
	if os.Geteuid() != 0 && !yes && macConfigurationStatus(candidate) != nil {
		approved, err := confirmMacConfiguration()
		if err != nil {
			return err
		}
		if !approved {
			return errors.New("macOS update cancelled")
		}
	}
	// The signed frontend owns the transaction and selects its helper implementation.
	process := exec.Command(candidate, "configure", "--system", "--yes")
	process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := process.Run(); err != nil {
		return fmt.Errorf("install verified macOS update: %w", err)
	}
	if err := macConfigurationStatus(candidate); err != nil {
		return fmt.Errorf("verify updated macOS client and helper: %w", err)
	}
	fmt.Printf("updated client, node, and network helper to %s\n", tag)
	fmt.Println("Restart any running lanewayd process to use the new version.")
	return nil
}

func currentExecutable() (string, error) {
	executable, err := publicCLIExecutable()
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
	files, err := macInstallFiles(source)
	if err != nil {
		return err
	}
	return installNativeUpdate(files)
}

func macInstallFiles(source string) ([]nativeUpdateFile, error) {
	if filepath.Base(source) == "laneway-compat" {
		public := filepath.Join(filepath.Dir(source), "laneway")
		info, err := os.Lstat(public)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("the matching macOS Laneway frontend is missing or unsafe")
		}
		source = public
	}
	files := []nativeUpdateFile{{source: source, destination: macClientPath}}
	helper := source
	compat := filepath.Join(filepath.Dir(source), "laneway-compat")
	if info, err := os.Lstat(compat); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid macOS compatibility executable at %s", compat)
		}
		helper = compat
		files = append(files, nativeUpdateFile{source: compat, destination: macCompatPath})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	files = append(files, nativeUpdateFile{source: helper, destination: macHelperPath})
	if node := macNodeCandidate(source); node != "" {
		files = append(files, nativeUpdateFile{source: node, destination: macNodePath})
	}
	return files, nil
}

func macNodeCandidate(client string) string {
	node := filepath.Join(filepath.Dir(client), "lanewayd")
	if info, err := os.Lstat(node); err == nil && info.Mode().IsRegular() {
		return node
	}
	return ""
}

func preflightMacInstall(source string) error {
	files, err := macInstallFiles(source)
	if err != nil {
		return err
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
	if len(files) > 2 {
		directory := filepath.Dir(macClientPath)
		for {
			if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
				break
			}
			directory = filepath.Dir(directory)
		}
		if err := releaseupdate.CheckSystemDirectory(directory); err != nil {
			return err
		}
	}
	for _, candidate := range files {
		if _, err := fileSHA256(candidate.source); err != nil {
			return fmt.Errorf("read candidate %s: %w", candidate.source, err)
		}
		destination := candidate.destination
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

func macConfigurationStatus(source string) error {
	candidates, err := macInstallFiles(source)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		installed := candidate.destination
		info, err := os.Lstat(installed)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not an installed regular file; run 'laneway configure --system'", installed)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("%s must be root:wheel, executable, and not writable by group/others; run 'laneway configure --system'", installed)
		}
		want, err := fileSHA256(candidate.source)
		if err != nil {
			return err
		}
		got, err := fileSHA256(installed)
		if err == nil && got == want {
			continue
		}
		// The helper path is stable across the migration. Installations may
		// contain either the verified Go companion or the verified frontend.
		if err == nil && installed == macHelperPath {
			frontend, err := fileSHA256(candidates[0].source)
			if err == nil && got == frontend {
				continue
			}
		}
		return fmt.Errorf("%s does not match this Laneway release; run 'laneway configure --system'", installed)
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
