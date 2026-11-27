//go:build !linux && !darwin

package main

import "errors"

func nativeClientRuntime() (string, error) {
	return "", nil
}

func tryNativeClient(...string) (bool, error) {
	return false, nil
}

func execNativeConnect(string, []string) error {
	return errors.New("native connect requires Linux or macOS")
}
