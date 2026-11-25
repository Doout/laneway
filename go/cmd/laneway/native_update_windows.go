package main

import (
	"context"
	"debug/pe"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/releaseupdate"
)

func updateNativeClient(args []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	yes := flags.Bool("yes", false, "install a verified update without confirmation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: laneway update [--yes]")
	}
	binDir, err := windowsUpdateDirectory()
	if err != nil {
		return err
	}
	arch, err := windowsUpdateArchitecture()
	if err != nil {
		return err
	}
	powershell, err := exec.LookPath("pwsh.exe")
	if err != nil {
		return errors.New("laneway update requires PowerShell 7 (pwsh.exe)")
	}

	stage, err := os.MkdirTemp(binDir, ".laneway-stage-")
	if err != nil {
		return err
	}
	workerOwnsStage := false
	defer func() {
		if !workerOwnsStage {
			_ = os.RemoveAll(stage)
		}
	}()

	installer := filepath.Join(stage, "install-node.ps1")
	cliAsset := "laneway-native_windows_" + arch + ".exe"
	compatAsset := "laneway-compat_windows_" + arch + ".exe"
	daemonAsset := "lanewayd_windows_" + arch + ".exe"
	cliCandidate := filepath.Join(stage, cliAsset)
	compatCandidate := filepath.Join(stage, compatAsset)
	daemonCandidate := filepath.Join(stage, daemonAsset)
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tag, err := client.StageLatestSigned(ctx, stage,
		releaseupdate.Asset{Name: "install-node.ps1", Destination: installer, MaxBytes: 1 << 20},
		releaseupdate.Asset{Name: cliAsset, Destination: cliCandidate, MaxBytes: 128 << 20},
		releaseupdate.Asset{Name: compatAsset, Destination: compatCandidate, MaxBytes: 128 << 20},
		releaseupdate.Asset{Name: daemonAsset, Destination: daemonCandidate, MaxBytes: 128 << 20},
	)
	if err != nil {
		return err
	}
	version := strings.TrimPrefix(tag, "v")
	if comparison, comparable := compareStableVersions(buildinfo.Version, version); comparable && comparison > 0 {
		return fmt.Errorf("latest stable release %s would downgrade installed v%s", tag, buildinfo.Version)
	}
	checks := []struct{ executable, flag, expected string }{
		{cliCandidate, "version", version},
		{compatCandidate, "version", version},
		{daemonCandidate, "--version", "lanewayd " + version},
	}
	for _, check := range checks {
		output, err := exec.CommandContext(ctx, check.executable, check.flag).Output()
		if err != nil {
			return fmt.Errorf("check downloaded %s version: %w", filepath.Base(check.executable), err)
		}
		if actual := strings.TrimSpace(string(output)); actual != check.expected {
			return fmt.Errorf("downloaded %s reports version %q, expected %q",
				filepath.Base(check.executable), actual, check.expected)
		}
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "Install Laneway %s at %s? [y/N] ", tag, binDir)
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil || !strings.EqualFold(answer, "y") {
			return errors.New("update cancelled")
		}
	}

	arguments := []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installer,
		"-Version", tag, "-VerifiedStage", stage}
	apply := exec.Command(powershell, arguments...)
	apply.Stdout, apply.Stderr = os.Stdout, os.Stderr
	if err := apply.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 75 {
			return fmt.Errorf("install verified Windows update: %w", err)
		}
	} else {
		return nil
	}

	// Some Windows filesystems refuse to rename a mapped executable. The
	// installer restored the original executables before asking for a retry.
	log, err := os.CreateTemp(binDir, "laneway-update-*.log")
	if err != nil {
		return err
	}
	defer log.Close()
	arguments = append(arguments, "-WaitForProcessId", strconv.Itoa(os.Getpid()))
	if pid := windowsUpdateFrontendPID(filepath.Join(binDir, "laneway.exe")); pid != 0 {
		arguments = append(arguments, "-WaitForFrontendProcessId", strconv.Itoa(pid))
	}
	worker := exec.Command(powershell, arguments...)
	worker.Stdout, worker.Stderr = log, log
	worker.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW}
	if err := worker.Start(); err != nil {
		return fmt.Errorf("start deferred update (log %s): %w", log.Name(), err)
	}
	workerOwnsStage = true
	_ = worker.Process.Release()
	fmt.Printf("Verified Laneway %s is staged. Installation will finish after this command exits. Status: %s\n", tag, log.Name())
	return nil
}

func windowsUpdateArchitecture() (string, error) {
	var processMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine); err != nil {
		return "", fmt.Errorf("identify Windows architecture: %w", err)
	}
	switch nativeMachine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64", nil
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported Windows architecture (machine %#x)", nativeMachine)
	}
}

func windowsUpdateDirectory() (string, error) {
	local := os.Getenv("LOCALAPPDATA")
	if !filepath.IsAbs(local) {
		return "", errors.New("LOCALAPPDATA must be an absolute path")
	}
	binDir := filepath.Join(local, "Laneway", "bin")
	expected := filepath.Join(binDir, "laneway.exe")
	executable, err := publicCLIExecutable()
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(filepath.Clean(executable), expected) {
		return "", fmt.Errorf("run the per-user installed client at %s to update", expected)
	}
	realDir, err := filepath.EvalSymlinks(binDir)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(realDir, binDir) {
		return "", errors.New("the Laneway bin directory must not use a junction or symlink")
	}
	return binDir, nil
}

// The Rust frontend waits for this compatibility process on Windows. Identify
// it by installed path so a detached worker never waits on the user's shell.
func windowsUpdateFrontendPID(frontend string) int {
	pid := os.Getppid()
	if pid <= 0 {
		return 0
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(process)
	path := make([]uint16, 32768)
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(process, 0, &path[0], &size); err != nil {
		return 0
	}
	if !strings.EqualFold(filepath.Clean(windows.UTF16ToString(path[:size])), frontend) {
		return 0
	}
	return pid
}
