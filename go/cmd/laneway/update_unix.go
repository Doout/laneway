//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/releaseupdate"
	"github.com/spf13/cobra"
)

const updateBinaryLimit = 128 << 20

var stableUpdateTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func addUpdateCommand(root *cobra.Command) {
	update := command("update [client | server | connector [NAME]]", "Install the latest signed Laneway release", runUpdate)
	if runtime.GOOS == "darwin" {
		update.Use = "update"
	}
	update.GroupID = "client"
	root.AddCommand(update)
}

func runUpdate(args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		if runtime.GOOS == "darwin" {
			fmt.Fprintln(os.Stdout, "usage: laneway update [client] [--yes]")
		} else {
			fmt.Fprintln(os.Stdout, "usage: laneway update [client [--yes] | server [vMAJOR.MINOR.PATCH] | connector [NAME]]")
		}
		return nil
	}
	if handled, err := tryNativeUpdate(args); handled || err != nil {
		return err
	}
	target := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, args = args[0], args[1:]
	}
	if target == "" {
		var err error
		target, err = detectUpdateTarget()
		if err != nil {
			return err
		}
	}
	if target != "client" {
		return updateDeployment(target, args)
	}
	return updateClient(args)
}

func updateClient(args []string) error {
	fs := flag.NewFlagSet("update client", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "install the verified update without the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: laneway update client [--yes]")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	rootless := installedUserCLI()
	if runtime.GOOS == "linux" && !rootless && executable != "/usr/local/bin/laneway" {
		return errors.New("update from the installed laneway in ~/.local/bin or /usr/local/bin")
	}
	if err := checkSystemUpdateScope(rootless); err != nil {
		return err
	}
	current, err := updateExecutableVersion(executable, "version")
	if err != nil || !stableUpdateTag.MatchString("v"+current) {
		return fmt.Errorf("cannot determine the installed stable Laneway version at %s", executable)
	}
	temporaryParent := ""
	if runtime.GOOS == "linux" && !rootless {
		// The privileged updater may run a verified script from this stage.
		// Use the already checked system directory instead of caller TMPDIR.
		temporaryParent = filepath.Dir(executable)
	}
	work, err := os.MkdirTemp(temporaryParent, ".laneway-client-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	archive := filepath.Join(work, "client.tar.gz")
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	verify, err := client.ReleaseManifestVerifier(ctx, work, runtime.GOOS, runtime.GOARCH, installedUpdateVerifier())
	if err != nil {
		return err
	}
	release, err := client.DownloadLatest(ctx, "laneway_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz", archive, 3*updateBinaryLimit, verify)
	if err != nil {
		return err
	}
	version := strings.TrimPrefix(release.Tag, "v")
	if err := preventClientDowngrade(current, version); err != nil {
		return err
	}
	extract := releaseupdate.ExtractLinuxClient
	if runtime.GOOS == "darwin" {
		extract = releaseupdate.ExtractMacClient
	}
	candidate, daemon, err := extract(archive, work, version, updateBinaryLimit)
	if err != nil {
		return fmt.Errorf("extract verified client package: %w", err)
	}
	for _, entry := range []struct{ path, flag string }{{candidate, "version"}, {daemon, "--version"}} {
		got, err := updateExecutableVersion(entry.path, entry.flag)
		if err != nil || got != version {
			return fmt.Errorf("downloaded %s must match release %s", filepath.Base(entry.path), release.Tag)
		}
	}
	if rootless {
		err = installUserClientUpdate(filepath.Dir(executable), candidate, daemon, version)
	} else {
		err = installSystemClientUpdate(work, archive, candidate, daemon, version, *yes)
	}
	if err != nil {
		return err
	}
	fmt.Printf("updated CLI and Rust runtime to %s sha256=%s\n", release.Tag, release.SHA256)
	return nil
}

func installedUpdateVerifier() string {
	for _, path := range []string{
		"/usr/local/libexec/laneway/cosign-v3.1.3",
		"/usr/local/bin/cosign",
		"/usr/bin/cosign",
	} {
		if protectedRootlessRuntime(path) == nil {
			return path
		}
	}
	return ""
}

func updateExecutableVersion(path, argument string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, argument)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, err := command.Output()
	return strings.TrimSpace(string(out)), err
}

func installedUserCLI() bool {
	if os.Geteuid() == 0 {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	executable, err = filepath.EvalSymlinks(executable)
	bin, binErr := filepath.EvalSymlinks(filepath.Join(home, ".local", "bin"))
	return err == nil && binErr == nil && executable == filepath.Join(bin, "laneway") &&
		safeUserUpdateFile(executable) == nil
}

func safeUserUpdateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || unixOwner(info) != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing to replace unsafe file %s", path)
	}
	return nil
}

// Share the shell installer's lock and publish the CLI last, so normal errors
// can restore the previous daemon before another installer proceeds.
func installUserClientUpdate(bin, candidate, daemon, version string) (result error) {
	lock := filepath.Join(bin, ".laneway-install.lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("acquire Laneway install lock %s: %w", lock, err)
	}
	restoreFailed := false
	defer func() {
		if !restoreFailed {
			result = errors.Join(result, os.RemoveAll(lock))
		}
	}()
	cliTarget := filepath.Join(bin, "laneway")
	daemonTarget := filepath.Join(bin, "lanewayd-rs")
	for _, path := range []string{cliTarget, daemonTarget} {
		if err := safeUserUpdateFile(path); err != nil {
			return err
		}
	}
	installed, err := updateExecutableVersion(cliTarget, "version")
	if err != nil {
		return err
	}
	if err := preventClientDowngrade(installed, version); err != nil {
		return err
	}
	cliStage := filepath.Join(lock, "laneway")
	daemonStage := filepath.Join(lock, "lanewayd-rs")
	backup := filepath.Join(lock, "previous-daemon")
	for _, entry := range []struct{ source, dest string }{
		{candidate, cliStage}, {daemon, daemonStage}, {daemonTarget, backup},
	} {
		if err := copyUpdateBinary(entry.source, entry.dest); err != nil {
			return err
		}
	}
	// Keep the same recovery marker as the shared shell installer.
	if err := os.WriteFile(filepath.Join(lock, "publishing"), nil, 0o600); err != nil {
		return err
	}
	if err := os.Rename(daemonStage, daemonTarget); err != nil {
		return err
	}
	if err := os.Rename(cliStage, cliTarget); err != nil {
		if restoreErr := os.Rename(backup, daemonTarget); restoreErr != nil {
			restoreFailed = true
			return errors.Join(err, fmt.Errorf("restore previous daemon from %s: %w", backup, restoreErr))
		}
		return err
	}
	return nil
}

func copyUpdateBinary(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	return errors.Join(err, output.Close())
}

func preventClientDowngrade(installed, candidate string) error {
	comparison, comparable := compareStableVersions(installed, candidate)
	if !comparable {
		return errors.New("client update requires two stable release versions")
	}
	if comparison > 0 {
		return fmt.Errorf("latest stable release v%s would downgrade installed v%s", candidate, installed)
	}
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
