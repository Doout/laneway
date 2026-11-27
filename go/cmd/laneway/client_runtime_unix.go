//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/Doout/laneway/go/internal/bootstrap"
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

func fetchBootstrap(ctx context.Context, authority string) (bootstrap.Metadata, error) {
	runtime, err := nativeClientRuntime()
	if err != nil {
		return bootstrap.Metadata{}, err
	}
	if runtime == "" {
		return bootstrap.Fetch(ctx, authority)
	}
	cmd := exec.CommandContext(ctx, runtime, "_client", "discover", "--", authority)
	data, err := cmd.Output()
	if err != nil {
		if failed, ok := err.(*exec.ExitError); ok && len(failed.Stderr) != 0 {
			return bootstrap.Metadata{}, fmt.Errorf("bootstrap: %s", failed.Stderr)
		}
		return bootstrap.Metadata{}, fmt.Errorf("run native bootstrap discovery: %w", err)
	}
	var metadata bootstrap.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return bootstrap.Metadata{}, fmt.Errorf("decode native bootstrap discovery: %w", err)
	}
	return metadata, nil
}
