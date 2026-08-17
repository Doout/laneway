//go:build linux

package nodeapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Doout/laneway/go/internal/config"
	"golang.org/x/sys/unix"
)

func resolveEphemeralExitCredentials(cfg *config.Config) error {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fmt.Errorf("CREDENTIALS_DIRECTORY is not a clean absolute path")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credential directory is missing or unsafe")
	}
	resolve := func(value string) (string, error) {
		const prefix = "@credential/"
		if !strings.HasPrefix(value, prefix) {
			return "", fmt.Errorf("credential path %q does not use the protected credential directory", value)
		}
		name := strings.TrimPrefix(value, prefix)
		if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "\x00/\\") {
			return "", fmt.Errorf("credential name is invalid")
		}
		path := filepath.Join(directory, name)
		fileInfo, statErr := os.Lstat(path)
		if statErr != nil || fileInfo == nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("credential %s is missing or unsafe", name)
		}
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 {
			return "", fmt.Errorf("credential %s is not single-linked", name)
		}
		return path, nil
	}
	if cfg.TLS.CAFile, err = resolve(cfg.TLS.CAFile); err != nil {
		return err
	}
	if cfg.TLS.CertificateFile, err = resolve(cfg.TLS.CertificateFile); err != nil {
		return err
	}
	if cfg.TLS.PrivateKeyFile, err = resolve(cfg.TLS.PrivateKeyFile); err != nil {
		return err
	}
	if cfg.WireGuard.PrivateKeyFile, err = resolve(cfg.WireGuard.PrivateKeyFile); err != nil {
		return err
	}
	return nil
}

func hardenEphemeralExitProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable process dumps: %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("lock runtime memory: %w", err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("enumerate inherited descriptors: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == "0" || entry.Name() == "1" || entry.Name() == "2" {
			continue
		}
		target, readErr := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if readErr == nil && (strings.HasPrefix(target, "/") || strings.HasPrefix(target, "pipe:")) {
			return fmt.Errorf("unexpected inherited file descriptor")
		}
	}
	os.Clearenv()
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		return fmt.Errorf("set trusted executable path: %w", err)
	}
	return nil
}
