//go:build !linux && !darwin && !windows

package main

import "errors"

func updateNativeClient([]string) error {
	return errors.New("native client updates are available on Linux, macOS, and Windows")
}
