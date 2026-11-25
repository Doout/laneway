//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const (
	installedControl = "/usr/local/sbin/laneway-control"
	connectorUpdater = "/usr/local/sbin/laneway-update-connector"
	connectorPrefix  = "laneway-connector-"
)

var connectorName = regexp.MustCompile(`^laneway-connector-[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// runningInContainer identifies container boundaries independently of deployment
// role. Other commands can use it to avoid managing host services in a container.
func runningInContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := os.Lstat(marker); err == nil {
			return true
		}
	}
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	return containerCgroup(string(cgroup))
}

func containerCgroup(cgroup string) bool {
	for _, field := range strings.FieldsFunc(cgroup, func(r rune) bool {
		return r == '/' || r == ':' || r == '\n'
	}) {
		switch {
		case field == "docker", field == "kubepods", field == "lxc",
			strings.HasPrefix(field, "docker-") && strings.HasSuffix(field, ".scope"),
			strings.HasPrefix(field, "libpod-") && strings.HasSuffix(field, ".scope"),
			strings.HasPrefix(field, "kubepods-") && strings.HasSuffix(field, ".slice"):
			return true
		}
	}
	return false
}

func deploymentContainerRole() (role, name string) {
	cmdline, _ := os.ReadFile("/proc/1/cmdline")
	hostname, _ := os.Hostname()
	state, stateErr := os.Stat("/var/lib/laneway/connector")
	return containerDeployment(string(cmdline), hostname, stateErr == nil && state.IsDir())
}

func containerDeployment(cmdline, hostname string, connectorState bool) (role, name string) {
	argv := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
	switch filepath.Base(argv[0]) {
	case "laneway-controller", "laneway-relay":
		return "server", ""
	case "laneway", "laneway-compat", "lanewayd":
		if len(argv) >= 3 {
			switch {
			case (argv[1] == "-config" || argv[1] == "--config") &&
				(argv[2] == "/etc/laneway/controller.toml" || argv[2] == "/etc/laneway/relay.toml"):
				return "server", ""
			case argv[1] == "connector" && argv[2] == "run":
				connectorState = true
			}
		}
	}
	if connectorState {
		if connectorName.MatchString(hostname) {
			return "connector", hostname
		}
		return "connector", ""
	}
	return "", ""
}

// updateContainerHandoff prevents in-container updates even if the host socket
// happens to be mounted. The deployment, rather than the container, owns updates.
func updateContainerHandoff(target string) error {
	if !runningInContainer() {
		return nil
	}
	role, name := deploymentContainerRole()
	return containerUpdateError(target, role, name)
}

func containerUpdateError(target, role, name string) error {
	if role != "" {
		target = role
	}
	switch target {
	case "server":
		return errors.New("this container is managed by its deployment; on the host run: sudo laneway update server")
	case "connector":
		if name != "" {
			return fmt.Errorf("this container is managed by its deployment; on the host run: sudo laneway update connector %s", name)
		}
		return errors.New("this container is managed by its deployment; on the host run sudo docker container ls to find its name, then run: sudo laneway update connector laneway-connector-NAME")
	case "client":
		return errors.New("update the client on its host with: laneway update client")
	default:
		return errors.New("this container is managed by its deployment; on the host run: sudo laneway update")
	}
}

type linuxUpdater struct {
	uid        int
	userClient bool
	server     func() (bool, error)
	managed    func(name string) ([]string, error)
	execute    func(path string, args []string) error
}

func linuxDeploymentUpdater() linuxUpdater {
	return linuxUpdater{
		uid: os.Geteuid(), userClient: installedUserCLI(),
		server: installedServer, managed: localManagedConnectors, execute: runUpdateHelper,
	}
}

func detectUpdateTarget() (string, error) {
	if err := updateContainerHandoff(""); err != nil {
		return "", err
	}
	return linuxDeploymentUpdater().detect()
}

func (u linuxUpdater) detect() (string, error) {
	server, err := u.server()
	if err != nil {
		return "", err
	}
	// The per-user CLI can update independently on a Docker workstation.
	// A separately installed control plane is still reported to its operator.
	if u.userClient && u.uid != 0 && !server {
		return "client", nil
	}
	connectors, err := u.managed("")
	if err != nil {
		if server && errors.Is(err, errLocalDockerUnavailable) {
			return "server", nil
		}
		return "", fmt.Errorf("cannot determine the update target: %w; choose laneway update client, sudo laneway update server, or sudo laneway update connector laneway-connector-NAME", err)
	}
	switch {
	case server && len(connectors) != 0:
		return "", errors.New("both a control plane and managed Connectors are installed; run sudo laneway update server or sudo laneway update connector laneway-connector-NAME")
	case server:
		return "server", nil
	case len(connectors) == 1:
		return "connector", nil
	case len(connectors) > 1:
		return "", multipleConnectors(connectors)
	default:
		return "client", nil
	}
}

func updateDeployment(target string, args []string) error {
	if err := updateContainerHandoff(target); err != nil {
		return err
	}
	if _, set := os.LookupEnv("LANEWAY_CONTROL_COMMAND"); target == "server" && set {
		return errors.New("LANEWAY_CONTROL_COMMAND is not allowed for control-plane updates")
	}
	return linuxDeploymentUpdater().update(target, args)
}

func (u linuxUpdater) update(target string, args []string) error {
	switch target {
	case "server":
		if len(args) != 0 {
			return errors.New("usage: laneway update server")
		}
		if u.uid != 0 {
			return errors.New("on the control-plane host run: sudo laneway update server")
		}
		installed, err := u.server()
		if err != nil {
			return err
		}
		if !installed {
			return fmt.Errorf("no managed control plane found via %s", installedControl)
		}
		return u.execute(installedControl, []string{"update"})
	case "connector":
		name, err := connectorUpdateName(args)
		if err != nil {
			return err
		}
		if u.uid != 0 {
			if name != "" {
				return fmt.Errorf("on the Connector host run: sudo laneway update connector %s", name)
			}
			return errors.New("on the Connector host run: sudo laneway update connector")
		}
		connectors, err := u.managed(name)
		if err != nil {
			return err
		}
		switch len(connectors) {
		case 0:
			if name != "" {
				return fmt.Errorf("%s is not a running standard managed Connector on the local Docker Engine", name)
			}
			return errors.New("no running standard managed Connector on the local Docker Engine")
		case 1:
			return u.execute(connectorUpdater, []string{connectors[0]})
		default:
			return multipleConnectors(connectors)
		}
	default:
		return fmt.Errorf("unknown Linux deployment update target %q", target)
	}
}

func connectorUpdateName(args []string) (string, error) {
	var name string
	switch {
	case len(args) == 0:
		return "", nil
	case len(args) == 1:
		name = strings.TrimPrefix(args[0], "--name=")
	case len(args) == 2 && args[0] == "--name":
		name = args[1]
	default:
		return "", errors.New("usage: laneway update connector [NAME]")
	}
	if !strings.HasPrefix(name, connectorPrefix) {
		name = connectorPrefix + name
	}
	if !connectorName.MatchString(name) {
		return "", errors.New("Connector name must be NAME or laneway-connector-NAME using letters, digits, dots, underscores or hyphens")
	}
	return name, nil
}

func multipleConnectors(names []string) error {
	return fmt.Errorf("multiple managed Connectors found (%s); choose one with sudo laneway update connector laneway-connector-NAME", strings.Join(names, ", "))
}

func installedUserCLI() bool {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return false
	}
	executable, err := publicCLIExecutable()
	if err != nil || executable != filepath.Join(home, ".local", "bin", "laneway") {
		return false
	}
	info, err := os.Lstat(executable)
	return err == nil && info.Mode().IsRegular() && unixOwner(info) == uint32(os.Geteuid()) &&
		info.Mode().Perm()&0o022 == 0
}

func installedServer() (bool, error) {
	return managedServerLink(installedControl)
}

func managedServerLink(link string) (bool, error) {
	info, err := os.Lstat(link)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect control-plane installation %s: %w", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 || unixOwner(info) != 0 {
		return false, fmt.Errorf("control-plane command %s must be an installed root-owned symlink", link)
	}
	target, err := os.Readlink(link)
	if err != nil {
		return false, fmt.Errorf("read control-plane command link: %w", err)
	}
	if !filepath.IsAbs(target) || filepath.Clean(target) != target ||
		(filepath.Base(target) != "laneway-control" && filepath.Base(target) != "lane") {
		return false, fmt.Errorf("control-plane command %s has an unsupported installation target", link)
	}
	if err := protectedUpdateDirectories(filepath.Dir(link)); err != nil {
		return false, err
	}
	base := filepath.Dir(target)
	if err := protectedUpdateDirectories(base); err != nil {
		return false, err
	}
	helper := target
	if filepath.Base(helper) == "lane" {
		legacy, err := os.Lstat(helper)
		if errors.Is(err, fs.ErrPermission) && os.Geteuid() != 0 {
			return true, nil
		}
		if err == nil && legacy.Mode()&os.ModeSymlink != 0 {
			to, err := os.Readlink(helper)
			if err != nil || unixOwner(legacy) != 0 ||
				(to != "laneway-control" && to != filepath.Join(base, "laneway-control")) {
				return false, fmt.Errorf("legacy control-plane command link is unsafe: %s", helper)
			}
			helper = filepath.Join(base, "laneway-control")
		}
	}
	for _, path := range []string{helper, filepath.Join(base, "compose.yaml"), filepath.Join(base, ".env")} {
		file, err := os.Lstat(path)
		// The installer makes the deployment root-only. The trusted symlink
		// still gives non-root CLI users a reliable route to the server command.
		if errors.Is(err, fs.ErrPermission) && os.Geteuid() != 0 {
			return true, nil
		}
		if err != nil || !file.Mode().IsRegular() || unixOwner(file) != 0 || file.Mode().Perm()&0o022 != 0 {
			return false, fmt.Errorf("managed control-plane file is missing or unsafe: %s", path)
		}
		if path == helper && file.Mode().Perm()&0o100 == 0 {
			return false, fmt.Errorf("control-plane command is not executable: %s", path)
		}
	}
	return true, nil
}

func unixOwner(info fs.FileInfo) uint32 {
	return info.Sys().(*syscall.Stat_t).Uid
}

func protectedUpdateDirectories(dir string) error {
	for {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || unixOwner(info) != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("update path has an unsafe or inaccessible directory: %s", dir)
		}
		if dir == "/" {
			return nil
		}
		dir = filepath.Dir(dir)
	}
}

func runUpdateHelper(path string, args []string) error {
	if path == connectorUpdater {
		if err := protectedUpdateDirectories(filepath.Dir(path)); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || unixOwner(info) != 0 ||
			info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0 {
			return fmt.Errorf("managed Connector updater is missing or unsafe at %s; install the signed Laneway Linux host package first", path)
		}
	}
	command := exec.Command(path, args...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
