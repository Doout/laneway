//go:build linux || darwin

package releaseupdate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func cosignPath() (string, error) {
	if os.Geteuid() != 0 {
		return exec.LookPath("cosign")
	}
	for _, path := range []string{
		"/usr/local/libexec/laneway/cosign-v3.1.3",
		"/usr/local/bin/cosign",
		"/usr/bin/cosign",
	} {
		if CheckSystemDirectory(filepath.Dir(path)) != nil {
			continue
		}
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && rootControlled(info) && info.Mode().Perm()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("root requires a protected cosign in /usr/local/libexec/laneway, /usr/local/bin, or /usr/bin")
}

// CheckSystemDirectory verifies that no user-controlled entry can redirect
// a privileged update through the directory.
func CheckSystemDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return fmt.Errorf("system directory %s must be absolute", directory)
	}
	directory = filepath.Clean(directory)
	if parent := filepath.Dir(directory); parent != directory {
		if err := CheckSystemDirectory(parent); err != nil {
			return err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect system directory %s: %w", directory, err)
	}
	if !info.IsDir() || !rootControlled(info) {
		return fmt.Errorf("system directory %s must be root-owned and protected", directory)
	}
	return nil
}

func rootControlled(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}
