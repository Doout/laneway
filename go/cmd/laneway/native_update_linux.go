package main

import "errors"

func updateLegacyNativeClient([]string) error {
	return errors.New("legacy macOS client update is only available on macOS")
}
