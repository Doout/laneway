//go:build !linux && !darwin

package main

import "errors"

func configureProductSystem(bool, bool) error {
	return errors.New("native system configuration is available on Linux and macOS")
}

func startProductSystem(string) error {
	return errors.New("native system networking is available on Linux and macOS")
}
