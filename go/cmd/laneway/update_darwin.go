//go:build darwin

package main

import (
	"fmt"
	"io/fs"
	"syscall"
)

func detectUpdateTarget() (string, error) { return "client", nil }

func updateDeployment(target string, _ []string) error {
	return fmt.Errorf("update %s is only available on Linux deployment hosts", target)
}

func checkSystemUpdateScope(bool) error { return nil }

func unixOwner(info fs.FileInfo) uint32 {
	return info.Sys().(*syscall.Stat_t).Uid
}
