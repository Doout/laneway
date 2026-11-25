//go:build laneway_compat && darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"laneway.dev/laneway/internal/nethelper"
)

const nativeNetworkHelperBridge = false

func compatibilityNetworkHelper(args []string) error {
	return runNetworkHelperCommand(args, execInstalledMacNetworkHelper)
}

func execInstalledMacNetworkHelper(descriptor int) error {
	for _, path := range []string{macClientPath, macHelperPath} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return fmt.Errorf("missing or unsafe Laneway executable at %s; run 'laneway configure --system'", path)
		}
		if err := nethelper.ValidateRootOwnedExecutable(path); err != nil {
			return err
		}
	}
	current, err := os.Executable()
	if err != nil {
		return err
	}
	compat, err := fileSHA256(current)
	if err != nil {
		return err
	}
	frontend, err := fileSHA256(macClientPath)
	if err != nil {
		return err
	}
	helper, err := fileSHA256(macHelperPath)
	if err != nil || helper != frontend || helper == compat {
		return fmt.Errorf("macOS networking helper does not match the frontend; run 'laneway configure --system'")
	}
	return unix.Exec(macHelperPath,
		[]string{macHelperPath, "_network-helper", "--control-fd=" + strconv.Itoa(descriptor)},
		[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}
