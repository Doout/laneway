package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// publicCLIExecutable reports the frontend path for commands that manage the
// installed client. Commands re-executing legacy Go code still use os.Executable.
func publicCLIExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	base := strings.ToLower(filepath.Base(executable))
	if base != "laneway-compat" && base != "laneway-compat.exe" {
		return executable, nil
	}
	public := filepath.Join(filepath.Dir(executable), "laneway"+filepath.Ext(base))
	info, err := os.Lstat(public)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("missing matching Laneway frontend at %s", public)
	}
	return public, nil
}
