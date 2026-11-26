//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/nethelper"
)

const credentialDescriptorDirectory = "/proc/self/fd"

func foregroundTunName(runtimeDir string) string {
	// Session interfaces must not open the managed node's lane0. Linux
	// limits interface names to 15 printable bytes.
	digest := sha256.Sum256([]byte(runtimeDir))
	return fmt.Sprintf("lwc%x", digest[:6])
}

func connectPlatformPreflight() error {
	if os.Geteuid() != 0 {
		return errors.New("Linux foreground networking requires root; run 'sudo laneway connect ...' (saved logins: 'sudo laneway login DOMAIN')")
	}
	return nil
}

func runProductConfigure(args []string) error {
	if system, remaining := splitExplicitSystem(args); system {
		return runInstalledSystem("configure", remaining)
	}
	return runRootless("configure", args)
}

func runSystemStart(args []string) error {
	return runInstalledSystem("start", args)
}

func runInstalledSystem(workflow string, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		switch workflow {
		case "configure":
			fmt.Println("Usage: sudo laneway configure --system [--discard-pending]\nRead an st1 enrollment token from standard input, or discard a pending enrollment.")
		case "start":
			fmt.Println("Usage: sudo laneway start --system [--config PATH] [--check-config]")
		}
		return nil
	}
	runtime, err := platformConnectRustRuntime()
	if err != nil {
		return err
	}
	return syscall.Exec(runtime,
		append([]string{runtime, "_rootless", workflow, "--system"}, args...),
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}

func platformConnectRustRuntime() (string, error) {
	if err := protectedRootlessRuntime(managedRustBinary); err != nil {
		return "", fmt.Errorf("install the matching Laneway Linux package: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, managedRustBinary, "--version")
	probe.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := probe.Output()
	if err != nil || strings.TrimSpace(string(output)) != buildinfo.Version {
		return "", fmt.Errorf("the Rust runtime must match Laneway %s; install the matching Linux package", buildinfo.Version)
	}
	return managedRustBinary, nil
}

func prepareRustForegroundProcess(command *exec.Cmd) func() {
	// Linux delivers Pdeathsig when the creating thread terminates. Keep the
	// thread alive through Wait, so only losing the launcher ends the session.
	runtime.LockOSThread()
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return runtime.UnlockOSThread
}

func addPlatformConnectFlags(fs *flag.FlagSet, options *connectPlatformOptions) {
	options.rust = true
	fs.StringVar(&options.exitSelector, "exit", "", "controller-authorized exit node name or NodeID")
	fs.StringVar(&options.failureMode, "failure-mode", "closed", "exit path failure behavior: closed or open")
	fs.Func("dns", "temporary exit DNS server (repeatable; omitted preserves native DNS)", func(value string) error {
		options.dns = append(options.dns, value)
		return nil
	})
	fs.Func("local-lan", "native local-LAN bypass prefix for exit mode (repeatable)", func(value string) error {
		options.localLAN = append(options.localLAN, value)
		return nil
	})
}

func validatePlatformArtifact(metadata bootstrap.Metadata) error {
	_, err := metadata.ArtifactForCurrentPlatform()
	return err
}

func connectUsage() error {
	return errors.New("usage: laneway connect [DOMAIN] [--route PREFIX] [--exit NAME_OR_NODE_ID] [--dns ADDRESS] [--ephemeral [--token-file PATH]]")
}

func platformNetworkHelperOptions() nethelper.StartOptions { return nethelper.StartOptions{} }
