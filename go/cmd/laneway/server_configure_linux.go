//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	serverSystemOperator   = "/usr/local/sbin/laneway-control"
	serverDefaultOperator  = "/opt/laneway/laneway-control"
	serverPackageInstaller = "/usr/local/share/laneway/deploy/compose/install-control-plane.sh"
	serverReleaseInstaller = "/usr/local/share/laneway/install-control-plane-release.sh"
	serverPinnedVerifier   = "/usr/local/libexec/laneway/cosign-v3.1.3"
)

var serverDomainName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func configureServer(args []string) error {
	return configureServerOnHost(args, os.Geteuid(), runningInContainer(), findServerOperator, checkInstalledServerDomain, runServerHostCommand)
}

func configureServerOnHost(args []string, uid int, container bool, findOperator func() (string, error), checkDomain func(string, string) error, run func(string, string, ...string) error) error {
	domain := ""
	if len(args) > 1 || len(args) == 1 && (len(args[0]) > 253 || !serverDomainName.MatchString(args[0])) {
		return errors.New("usage: laneway configure server [DOMAIN] (use a fully qualified DNS name)")
	}
	handoff := "sudo laneway configure server"
	if len(args) == 1 {
		domain = args[0]
		handoff += " " + domain
	}
	if container {
		return fmt.Errorf("server configuration runs on the Linux host; exit the container and run %s", handoff)
	}
	if uid != 0 {
		return fmt.Errorf("server configuration requires root; run %s", handoff)
	}

	operator, err := findOperator()
	if err != nil {
		return err
	}
	if operator == "" {
		return run(serverPackageInstaller, domain)
	}
	if domain != "" {
		if err := checkDomain(filepath.Join(filepath.Dir(operator), ".env"), domain); err != nil {
			return err
		}
	}
	if err := run(operator, "", "init"); err != nil {
		return err
	}
	return run(operator, "", "production-check")
}

func findServerOperator() (string, error) {
	for _, path := range []string{serverSystemOperator, serverDefaultOperator} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspect installed control-plane operator: %w", err)
		}
		if err := checkProtectedServerParents(path); err != nil {
			return "", err
		}
		if path == serverSystemOperator && info.Mode()&os.ModeSymlink != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || stat.Gid != 0 {
				return "", fmt.Errorf("control-plane operator link must be owned by root: %s", path)
			}
			target, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) || target != filepath.Clean(target) ||
				(filepath.Base(target) != "laneway-control" && filepath.Base(target) != "lane") {
				return "", fmt.Errorf("invalid installed control-plane operator link: %s", path)
			}
			path = target
		}
		if err := checkProtectedServerFile(path, true); err != nil {
			return "", fmt.Errorf("unsafe installed control-plane operator: %w", err)
		}
		return path, nil
	}
	return "", nil
}

func checkInstalledServerDomain(path, domain string) error {
	if err := checkProtectedServerFile(path, false); err != nil {
		return fmt.Errorf("read installed server domain: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	const setting = "LANEWAY_CONTROLLER_SERVER_NAME="
	var configured string
	found := false
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		if value, ok := strings.CutPrefix(lines.Text(), setting); ok {
			if found {
				return errors.New("installed control-plane configuration contains multiple server names")
			}
			configured, found = value, true
		}
	}
	if err := lines.Err(); err != nil {
		return err
	}
	if !found || !strings.EqualFold(domain, configured) {
		return fmt.Errorf("domain %q differs from the installed control-plane domain in %s", domain, path)
	}
	return nil
}

func checkProtectedServerFile(path string, executable bool) error {
	if err := checkProtectedServerParents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || executable && info.Mode().Perm()&0o100 == 0 || !protectedServerEntry(info) {
		return fmt.Errorf("expected a protected root-owned file at %s", path)
	}
	return nil
}

func checkProtectedServerParents(path string) error {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return fmt.Errorf("expected a canonical absolute path: %s", path)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if !info.IsDir() || !protectedServerEntry(info) {
			return fmt.Errorf("expected a protected root-owned directory at %s", parent)
		}
		if parent == "/" {
			return nil
		}
	}
}

func protectedServerEntry(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm()&0o022 == 0
}

func serverInstallerCommand(domain string, checkFile func(string, bool) error) (string, []string, error) {
	var missing string
	for _, path := range []string{serverPackageInstaller, serverPinnedVerifier} {
		err := checkFile(path, true)
		if errors.Is(err, os.ErrNotExist) {
			missing = path
			break
		}
		if err != nil {
			return "", nil, err
		}
	}
	if missing == "" {
		return serverPackageInstaller, nil, nil
	}
	if err := checkFile(serverReleaseInstaller, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, serverInstallInstructions("control-plane setup component is missing at "+missing, domain)
		}
		return "", nil, err
	}
	return serverReleaseInstaller, []string{"--control-plane", "--production"}, nil
}

func runServerHostCommand(path, domain string, args ...string) error {
	if path == serverPackageInstaller {
		var err error
		path, args, err = serverInstallerCommand(domain, checkProtectedServerFile)
		if err != nil {
			return err
		}
	} else if err := checkProtectedServerFile(path, true); err != nil {
		return err
	}
	process := exec.Command(path, args...)
	process.Dir = "/"
	process.Env = []string{"HOME=/root", "LC_ALL=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if path == serverPackageInstaller {
		process.Env = append(process.Env, "LANEWAY_PRODUCTION_MODE=true")
	}
	if domain != "" {
		process.Env = append(process.Env, "LANEWAY_DOMAIN="+domain)
	}
	process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := process.Run(); err != nil {
		return fmt.Errorf("run %s: %w", strings.Join(process.Args, " "), err)
	}
	return nil
}

func serverInstallInstructions(reason, domain string) error {
	command := "sudo sh ./install.sh --control-plane --production"
	if domain != "" {
		command = "sudo env LANEWAY_DOMAIN=" + domain + " sh ./install.sh --control-plane --production"
	}
	return fmt.Errorf("%s; download https://github.com/Doout/laneway/releases/latest/download/install.sh and run %s", reason, command)
}
