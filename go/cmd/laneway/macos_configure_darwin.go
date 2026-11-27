//go:build darwin

package main

import (
	"bufio"
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
	"strings"
	"syscall"
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
	if nativeClientCommands == "1" && os.Geteuid() != 0 {
		runtime, err := nativeClientRuntime()
		if err != nil {
			return err
		}
		if runtime != "" {
			command := []string{runtime, "_mac-setup", source}
			if *checkOnly {
				command = append(command, "--check")
			}
			if *yes {
				command = append(command, "--yes")
			}
			return syscall.Exec(runtime, command, os.Environ())
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

func installSystemClientUpdate(_, _, candidate, rustCandidate, version string, yes bool) error {
	if os.Geteuid() == 0 {
		return errors.New("run 'laneway update client' as your normal macOS user; the verified package will request sudo to install")
	}
	if err := inspectMacRustCandidate(rustCandidate, runtime.GOARCH); err != nil {
		return err
	}
	if !yes {
		approved, err := confirmMacConfiguration()
		if err != nil {
			return err
		}
		if !approved {
			return errors.New("update cancelled")
		}
	}
	if installed, err := updateExecutableVersion(macClientPath, "version"); err == nil {
		if err := preventClientDowngrade(installed, version); err != nil {
			return err
		}
	} else if _, statErr := os.Lstat(macClientPath); !os.IsNotExist(statErr) {
		return fmt.Errorf("read installed system client version: %w", err)
	}
	// --yes selects the system path on both legacy and current candidates.
	process := exec.Command(candidate, "configure", "--yes")
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
	return nil
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
