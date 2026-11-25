//go:build linux || darwin

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
	"runtime"
	"strings"
	"time"

	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/releaseupdate"
)

const nativeUpdateBinaryLimit = 128 << 20

func updateNativeClient(args []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	yes := flags.Bool("yes", false, "install a verified update without confirmation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: laneway update [--yes]")
	}
	executable, err := publicCLIExecutable()
	if err != nil {
		return err
	}
	uid := os.Geteuid()
	userBin := ""
	if uid == 0 {
		if executable != "/usr/local/bin/laneway" {
			return errors.New("root may update only the system installation in /usr/local/bin")
		}
		if err := releaseupdate.CheckSystemDirectory(filepath.Dir(executable)); err != nil {
			return err
		}
	} else {
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			return err
		}
		if home, err := os.UserHomeDir(); err == nil {
			userBin = filepath.Join(home, ".local", "bin")
		}
	}
	clientPath, nodePath, err := nativeUpdateDestinations(executable, userBin, runtime.GOOS, uid)
	if err != nil {
		return err
	}
	if nodePath == "" {
		return updateLegacyNativeClient(args)
	}
	tempBase := ""
	if uid == 0 {
		if err := releaseupdate.CheckSystemDirectory(filepath.Dir(nodePath)); err != nil {
			return err
		}
		tempBase = "/tmp"
	}
	work, err := os.MkdirTemp(tempBase, "laneway-client-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	client := releaseupdate.NewGitHubClient("Doout/laneway")
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	suffix := "_" + runtime.GOOS + "_" + runtime.GOARCH
	versions := []nativeUpdateFile{
		{source: filepath.Join(work, "laneway-compat"), destination: filepath.Join(filepath.Dir(clientPath), "laneway-compat")},
		{source: filepath.Join(work, "lanewayd"), destination: nodePath},
		{source: filepath.Join(work, "laneway"), destination: clientPath},
	}
	tag, err := client.DownloadLatestSigned(ctx,
		releaseupdate.Asset{Name: "laneway-compat" + suffix, Destination: versions[0].source, MaxBytes: nativeUpdateBinaryLimit},
		releaseupdate.Asset{Name: "lanewayd" + suffix, Destination: versions[1].source, MaxBytes: nativeUpdateBinaryLimit},
		releaseupdate.Asset{Name: "laneway-native" + suffix, Destination: versions[2].source, MaxBytes: nativeUpdateBinaryLimit},
	)
	if err != nil {
		return err
	}
	version := strings.TrimPrefix(tag, "v")
	if comparison, comparable := compareStableVersions(buildinfo.Version, version); comparable && comparison > 0 {
		return fmt.Errorf("latest stable release %s would downgrade installed v%s", tag, buildinfo.Version)
	}
	for index, check := range []struct{ flag, expected string }{
		{"version", version},
		{"--version", "lanewayd " + version},
		{"version", version},
	} {
		output, err := exec.CommandContext(ctx, versions[index].source, check.flag).Output()
		if err != nil {
			return fmt.Errorf("check downloaded %s version: %w", filepath.Base(versions[index].destination), err)
		}
		if actual := strings.TrimSpace(string(output)); actual != check.expected {
			return fmt.Errorf("downloaded %s reports version %q, expected %q", filepath.Base(versions[index].destination), actual, check.expected)
		}
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "Install Laneway %s at %s and %s? [y/N] ", tag, clientPath, nodePath)
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil || (answer != "y" && answer != "Y") {
			return errors.New("update cancelled")
		}
	}
	if err := installNativeUpdate(versions); err != nil {
		return err
	}
	fmt.Printf("Updated laneway, lanewayd, and laneway-compat to %s\n", tag)
	fmt.Println("Restart any running lanewayd process to use the new version.")
	return nil
}

func nativeUpdateDestinations(executable, userBin, goos string, uid int) (string, string, error) {
	if uid != 0 && userBin != "" {
		resolvedBin, err := filepath.EvalSymlinks(userBin)
		if err == nil && executable == filepath.Join(resolvedBin, "laneway") {
			return executable, filepath.Join(resolvedBin, "lanewayd"), nil
		}
	}
	if executable != "/usr/local/bin/laneway" {
		return "", "", fmt.Errorf("Laneway update supports installations in %s and /usr/local/bin", userBin)
	}
	if goos == "darwin" {
		return executable, "", nil
	}
	if uid != 0 {
		return "", "", errors.New("system installation requires sudo laneway update")
	}
	return executable, "/usr/local/sbin/lanewayd", nil
}

type nativeUpdateFile struct {
	source, destination string
}

func installNativeUpdate(files []nativeUpdateFile) error {
	// Share the installer lock for the same set of executables.
	lock := filepath.Join(filepath.Dir(files[0].destination), ".laneway-update-lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("lock Laneway installation: %w", err)
	}
	defer os.Remove(lock)

	type staged struct {
		work, next, previous, destination string
	}
	items := make([]staged, 0, len(files))
	preserve := make(map[string]bool)
	for _, file := range files {
		work, err := os.MkdirTemp(filepath.Dir(file.destination), ".laneway-update-*")
		if err != nil {
			return err
		}
		defer func() {
			if !preserve[work] {
				_ = os.RemoveAll(work)
			}
		}()
		item := staged{work: work, next: filepath.Join(work, "next"), destination: file.destination}
		if err := copyNativeUpdate(file.source, item.next); err != nil {
			return err
		}
		info, err := os.Lstat(file.destination)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			item.previous = filepath.Join(work, "previous")
			switch {
			case info.Mode().IsRegular():
				err = os.Link(file.destination, item.previous)
			case file.destination == "/usr/local/sbin/lanewayd" && info.Mode()&os.ModeSymlink != 0:
				var link string
				link, err = os.Readlink(file.destination)
				if err == nil && link != "../bin/laneway" {
					err = fmt.Errorf("refusing to replace unexpected symlink %s", file.destination)
				}
				if err == nil {
					err = os.Symlink(link, item.previous)
				}
			default:
				err = fmt.Errorf("refusing to replace non-regular file %s", file.destination)
			}
			if err != nil {
				return err
			}
		}
		items = append(items, item)
	}

	for index, item := range items {
		if err := os.Rename(item.next, item.destination); err != nil {
			for _, replaced := range items[:index] {
				if replaced.previous == "" {
					err = errors.Join(err, os.Remove(replaced.destination))
				} else if restoreErr := os.Rename(replaced.previous, replaced.destination); restoreErr != nil {
					preserve[replaced.work] = true
					err = errors.Join(err, fmt.Errorf("restore %s from %s: %w", replaced.destination, replaced.previous, restoreErr))
				}
			}
			return fmt.Errorf("install Laneway update: %w", err)
		}
	}
	return nil
}

func copyNativeUpdate(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, nativeUpdateBinaryLimit+1))
	if copyErr == nil && (written == 0 || written > nativeUpdateBinaryLimit) {
		copyErr = errors.New("staged executable is empty or exceeds the size limit")
	}
	if copyErr == nil && os.Geteuid() == 0 {
		copyErr = output.Chown(0, 0)
	}
	if copyErr == nil {
		copyErr = output.Chmod(0o755)
	}
	if copyErr == nil {
		copyErr = output.Sync()
	}
	return errors.Join(copyErr, output.Close())
}
