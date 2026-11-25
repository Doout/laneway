//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

func execProductDaemon(path string, args, env []string) error {
	return syscall.Exec(path, append([]string{path}, args...), env)
}

func trustedSystemDaemon(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0o100 == 0 {
				return false
			}
		} else if !info.IsDir() {
			return false
		}
		if current == "/" {
			return true
		}
	}
}
