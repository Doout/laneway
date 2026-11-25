package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func runConfigure(args []string) error {
	flags := flag.NewFlagSet("configure", flag.ContinueOnError)
	system := flags.Bool("system", false, "configure native system networking")
	state := flags.String("state-dir", "", "override the per-user state directory")
	check := flags.Bool("check", false, "verify the installed macOS helper")
	yes := flags.Bool("yes", false, "install the macOS helper without confirmation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: laneway configure [--state-dir PATH | --system]")
	}
	if *system || *check || *yes {
		if *state != "" {
			return errors.New("--state-dir is only used in userspace mode")
		}
		return configureProductSystem(*check, *yes)
	}
	return runProductUser(*state, []string{"configure"})
}

func runProductStart(args []string) error {
	flags := flag.NewFlagSet("start", flag.ContinueOnError)
	system := flags.Bool("system", false, "start native system networking")
	state := flags.String("state-dir", "", "override the per-user state directory")
	config := flags.String("config", "", "use a Linux system configuration file")
	listen := flags.String("listen", "", "listen for SOCKS5 clients on a loopback address")
	noProxy := flags.Bool("no-proxy", false, "disable the local SOCKS5 listener")
	proxyOnly := flags.Bool("proxy-only", false, "open proxy connections without serving assigned routes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: laneway start [--state-dir PATH | --system [--config PATH]]")
	}
	if *system {
		if *state != "" {
			return errors.New("--state-dir is only used in userspace mode")
		}
		if *listen != "" || *noProxy || *proxyOnly {
			return errors.New("--listen, --no-proxy and --proxy-only are only used in userspace mode")
		}
		return startProductSystem(*config)
	}
	if *config != "" {
		return errors.New("--config requires --system")
	}
	if *noProxy && (*listen != "" || *proxyOnly) {
		return errors.New("--no-proxy cannot be used with --listen or --proxy-only")
	}
	daemonArgs := []string{"run"}
	if *listen != "" {
		daemonArgs = append(daemonArgs, "--listen", *listen)
	}
	if *noProxy {
		daemonArgs = append(daemonArgs, "--no-proxy")
	}
	if *proxyOnly {
		daemonArgs = append(daemonArgs, "--proxy-only")
	}
	return runProductUser(*state, daemonArgs)
}

func runProductCredential(args []string) error {
	return runProductUser("", append([]string{"credential"}, args...))
}

func runProductUser(state string, args []string) error {
	if err := guardManagedProductNode(); err != nil {
		return err
	}
	daemon, err := productDaemon()
	if err != nil {
		return err
	}
	if state != "" {
		args = append([]string{"--state-dir", state}, args...)
	}
	env := os.Environ()
	if os.Geteuid() == 0 {
		env = productSystemEnv(env)
	}
	return execProductDaemon(daemon, args, env)
}

func productDaemon() (string, error) {
	if os.Geteuid() == 0 {
		return productTrustedDaemon()
	}
	name := "lanewayd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	var candidates []string
	if current, err := os.Executable(); err == nil {
		directory := filepath.Dir(current)
		candidates = append(candidates, filepath.Join(directory, name))
		if runtime.GOOS == "linux" && directory == "/usr/local/bin" {
			candidates = append(candidates, "/usr/local/sbin/lanewayd")
		}
	}
	if runtime.GOOS == "windows" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			candidates = append(candidates, filepath.Join(local, "Laneway", "bin", name))
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "bin", name))
	}
	if path, err := exec.LookPath(name); err == nil {
		candidates = append(candidates, path)
	}
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "/usr/local/bin/lanewayd", "/usr/local/sbin/lanewayd")
	}
	for _, path := range candidates {
		if !filepath.IsAbs(path) {
			continue
		}
		realPath, err := filepath.EvalSymlinks(path)
		if err != nil || strings.EqualFold(filepath.Base(realPath), "laneway") || strings.EqualFold(filepath.Base(realPath), "laneway.exe") {
			continue
		}
		if _, err := exec.LookPath(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s executable was not found; install the Laneway node", name)
}

func productTrustedDaemon() (string, error) {
	var candidates []string
	if current, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(current), "lanewayd"))
	}
	candidates = append(candidates, "/usr/local/sbin/lanewayd", "/usr/local/bin/lanewayd", "/usr/bin/lanewayd")
	for _, path := range candidates {
		if trustedSystemDaemon(path) {
			return path, nil
		}
	}
	return "", errors.New("no system-owned lanewayd executable found; install the Laneway system package")
}

func productSystemEnv(env []string) []string {
	// The system daemon invokes networking tools. Use the system search
	// path even when launched from a root shell with a customized PATH.
	filtered := env[:0]
	for _, value := range env {
		if !strings.HasPrefix(value, "PATH=") {
			filtered = append(filtered, value)
		}
	}
	return append(filtered, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
}
