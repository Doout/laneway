//go:build darwin

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
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

	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/releaseupdate"
)

const (
	macClientPath  = "/usr/local/bin/laneway"
	macBinaryLimit = 128 << 20
)

func runMacConfigure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	checkOnly := fs.Bool("check", false, "verify the installed CLI and Rust runtime without changing them")
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
	var rustSource string
	if source != macClientPath {
		rustSource = filepath.Join(filepath.Dir(source), "lanewayd-rs")
		if err := inspectMacRustCandidate(rustSource, runtime.GOARCH); err != nil {
			return err
		}
		if os.Geteuid() != 0 {
			if err := checkMacRustVersion(rustSource); err != nil {
				return err
			}
		}
	}
	status := func() error {
		if err := macConfigurationStatus(source); err != nil {
			return err
		}
		if rustSource != "" {
			return macRustConfigurationStatus(rustSource)
		}
		if os.Geteuid() != 0 {
			_, err := platformConnectRustRuntime()
			return err
		}
		return nil
	}
	if err := status(); err == nil {
		fmt.Printf("macOS client configured cli=%s runtime=%s\n", macClientPath, macRustRuntimePath)
		return nil
	} else if *checkOnly || rustSource == "" {
		return err
	}
	if err := preflightMacInstall(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		if !*yes {
			approved, err := confirmMacConfiguration()
			if err != nil {
				return err
			}
			if !approved {
				return errors.New("macOS configuration cancelled; no changes were made")
			}
		}
		process := exec.Command("/usr/bin/sudo", "--", source, "configure", "--yes")
		process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
		return process.Run()
	}
	if err := installMacBinaries(source, rustSource); err != nil {
		return err
	}
	if err := status(); err != nil {
		return fmt.Errorf("verify macOS configuration: %w", err)
	}
	fmt.Printf("macOS client configured cli=%s runtime=%s\n", macClientPath, macRustRuntimePath)
	return nil
}

func inspectMacRustCandidate(source, arch string) error {
	file, err := openMacBinary(source)
	if err != nil {
		return fmt.Errorf("macOS installation requires the complete release archive with bin/lanewayd-rs: %w", err)
	}
	defer file.Close()
	// Check only the fixed native Mach-O header. Do not parse unbounded load
	// commands in the privileged installer or execute a candidate as root.
	var header [16]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return fmt.Errorf("read native Rust runtime header: %w", err)
	}
	var cpu macho.Cpu
	switch arch {
	case "arm64":
		cpu = macho.CpuArm64
	case "amd64":
		cpu = macho.CpuAmd64
	default:
		return fmt.Errorf("unsupported macOS Rust runtime architecture %s", arch)
	}
	if binary.LittleEndian.Uint32(header[0:4]) != macho.Magic64 ||
		macho.Cpu(binary.LittleEndian.Uint32(header[4:8])) != cpu ||
		macho.Type(binary.LittleEndian.Uint32(header[12:16])) != macho.TypeExec {
		return errors.New("Rust runtime must be a native macOS executable matching the client architecture")
	}
	return nil
}

func stageMacRustRuntime(source string) (string, error) {
	directory := filepath.Dir(macRustRuntimePath)
	if err := trustedMacRuntimePath(filepath.Dir(directory), true); err != nil {
		return "", err
	}
	if err := ensureMacDirectory(directory, true); err != nil {
		return "", err
	}
	if err := trustedMacRuntimePath(macRustRuntimePath, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	staged, err := stageMacBinary(source, macRustRuntimePath)
	if err != nil {
		return "", err
	}
	// Never execute the staged program as root, even to query its version.
	if err := inspectMacRustCandidate(staged, runtime.GOARCH); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

func macRustConfigurationStatus(source string) error {
	if err := trustedMacRuntimePath(macRustRuntimePath, false); err != nil {
		return err
	}
	want, err := fileSHA256(source)
	if err != nil {
		return err
	}
	installed, err := fileSHA256(macRustRuntimePath)
	if err != nil || installed != want {
		return errors.New("installed Rust runtime differs from this macOS release archive")
	}
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
	if os.Geteuid() == 0 {
		return errors.New("run 'laneway update' as your normal macOS user; the verified package will request sudo to install")
	}
	work, err := os.MkdirTemp("", "laneway-macos-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	archive := filepath.Join(work, "client.tar.gz")
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer downloadCancel()
	verify, err := client.MacManifestVerifier(downloadCtx, work, runtime.GOARCH)
	if err != nil {
		return err
	}
	release, err := client.DownloadLatest(downloadCtx, "laneway_darwin_"+runtime.GOARCH+".tar.gz", archive, 2*macBinaryLimit, verify)
	if err != nil {
		return err
	}
	if comparison, comparable := compareStableVersions(buildinfo.Version, strings.TrimPrefix(release.Tag, "v")); comparable && comparison > 0 {
		return fmt.Errorf("latest stable release %s would downgrade installed v%s", release.Tag, buildinfo.Version)
	}
	expectedVersion := strings.TrimPrefix(release.Tag, "v")
	candidate, rustCandidate, err := releaseupdate.ExtractMacClient(archive, work, expectedVersion, macBinaryLimit)
	if err != nil {
		return fmt.Errorf("extract the verified macOS Rust package: %w", err)
	}
	if err := inspectMacRustCandidate(rustCandidate, runtime.GOARCH); err != nil {
		return err
	}
	for _, executable := range []struct{ path, flag string }{{candidate, "version"}, {rustCandidate, "--version"}} {
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(checkCtx, executable.path, executable.flag).Output()
		cancel()
		if err != nil || strings.TrimSpace(string(output)) != expectedVersion {
			return fmt.Errorf("downloaded %s must match release %s", filepath.Base(executable.path), release.Tag)
		}
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
		return fmt.Errorf("verify updated macOS CLI: %w", err)
	}
	if err := macRustConfigurationStatus(rustCandidate); err != nil {
		return fmt.Errorf("verify updated Rust runtime: %w", err)
	}
	fmt.Printf("updated CLI and Rust runtime to %s sha256=%s\n", release.Tag, release.SHA256)
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
	fmt.Fprintf(terminal, "Install the Laneway CLI and root-owned Rust network runtime? [y/N]: ")
	line, err := bufio.NewReader(terminal).ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func installMacBinaries(source, rustSource string) error {
	if err := ensureMacDirectory(filepath.Dir(macClientPath), false); err != nil {
		return err
	}
	clientStage, err := stageMacBinary(source, macClientPath)
	if err != nil {
		return err
	}
	defer os.Remove(clientStage)
	rustStage, err := stageMacRustRuntime(rustSource)
	if err != nil {
		return err
	}
	defer os.Remove(rustStage)
	if err := os.Rename(rustStage, macRustRuntimePath); err != nil {
		return fmt.Errorf("install the Rust runtime: %w", err)
	}
	if err := os.Rename(clientStage, macClientPath); err != nil {
		return fmt.Errorf("install client: %w", err)
	}
	return nil
}

func preflightMacInstall() error {
	for _, directory := range []string{filepath.Dir(macClientPath), filepath.Dir(macRustRuntimePath)} {
		info, err := os.Lstat(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("installation directory %s is not a real directory", directory)
		}
	}
	for _, destination := range []string{macClientPath, macRustRuntimePath} {
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
	if privileged {
		// macOS can inherit the parent's group (Application Support is
		// commonly root:admin). Enforce root:wheel when creating our directory.
		if err := os.Mkdir(directory, 0o755); err == nil {
			if err := os.Chown(directory, 0, 0); err != nil {
				return fmt.Errorf("set ownership of %s: %w", directory, err)
			}
		} else if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create %s: %w", directory, err)
		}
	} else if err := os.MkdirAll(directory, 0o755); err != nil {
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
	input, err := openMacBinary(source)
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
	if err := output.Chown(0, 0); err != nil {
		return "", err
	}
	written, err := io.Copy(output, io.LimitReader(input, macBinaryLimit+1))
	if err != nil || written <= 0 || written > macBinaryLimit {
		return "", errors.New("copy macOS binary exceeded the allowed size")
	}
	if err := output.Chmod(0o755); err != nil {
		return "", err
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

func openMacBinary(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Size() <= 0 || info.Size() > macBinaryLimit {
		_ = file.Close()
		return nil, errors.New("candidate is not a bounded regular executable")
	}
	return file, nil
}

func macConfigurationStatus(source string) error {
	want, err := fileSHA256(source)
	if err != nil {
		return err
	}
	installed, err := openMacBinary(macClientPath)
	if err != nil {
		return fmt.Errorf("installed CLI is missing or untrusted; reinstall the signed macOS package: %w", err)
	}
	defer installed.Close()
	info, err := installed.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("installed CLI must be root:wheel and not writable by other users")
	}
	got, err := macBinarySHA256(installed)
	if err != nil || got != want {
		return errors.New("installed CLI does not match this Laneway version; reinstall the signed macOS package")
	}
	if err := trustedMacRuntimePath(macRustRuntimePath, false); err != nil {
		return fmt.Errorf("installed Rust runtime is missing or untrusted; reinstall the signed macOS package: %w", err)
	}
	return inspectMacRustCandidate(macRustRuntimePath, runtime.GOARCH)
}

func fileSHA256(filename string) ([sha256.Size]byte, error) {
	file, err := openMacBinary(filename)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	return macBinarySHA256(file)
}

func macBinarySHA256(file *os.File) ([sha256.Size]byte, error) {
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, macBinaryLimit+1))
	if err != nil || read <= 0 || read > macBinaryLimit {
		return [sha256.Size]byte{}, errors.New("hash input is empty or exceeds the allowed size")
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result, nil
}
