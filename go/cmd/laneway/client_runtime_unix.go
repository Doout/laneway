//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// Release packaging enables native commands when the matching runtime is present.
// The standalone client and control-tools-only installations continue to work
// without a sibling runtime.
var nativeClientCommands string

func nativeClientRuntime() (string, error) {
	if nativeClientCommands != "1" {
		return "", nil
	}
	source, err := os.Executable()
	if err != nil {
		return "", err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return "", err
	}
	runtime, err := rootlessRuntime(source)
	if err != nil {
		return "", nil
	}
	return runtime, nil
}

func tryNativeClient(args ...string) (bool, error) {
	runtime, err := nativeClientRuntime()
	if runtime == "" || err != nil {
		return false, err
	}
	return true, syscall.Exec(runtime, append([]string{runtime, "_client"}, args...), os.Environ())
}
