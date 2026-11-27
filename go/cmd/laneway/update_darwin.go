//go:build darwin

package main

import (
	"fmt"
	"io/fs"
	"os"
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

func tryNativeUpdate(args []string) (bool, error) {
	runtime, err := nativeClientRuntime()
	if runtime == "" || err != nil {
		return false, err
	}
	source, err := os.Executable()
	if err != nil {
		return true, err
	}
	return true, syscall.Exec(runtime, append([]string{runtime, "_host-update", source}, args...), os.Environ())
}
