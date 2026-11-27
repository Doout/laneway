//go:build !linux && !darwin

package main

func nativeClientRuntime() (string, error) {
	return "", nil
}

func tryNativeClient(...string) (bool, error) {
	return false, nil
}
