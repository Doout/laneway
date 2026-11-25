package main

import (
	"fmt"
	"os"
	"path/filepath"

	"laneway.dev/laneway/internal/nethelper"
)

func preflightConnectSessionHelper() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if nativeNetworkHelperBridge {
		_, err := verifiedNativeNetworkHelper(executable)
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("resolve installed connect dataplane: %w", err)
	}
	if err := nethelper.ValidateRootOwnedExecutable(executable); err != nil {
		return fmt.Errorf("install the system package to use host networking: %w", err)
	}
	return nil
}
