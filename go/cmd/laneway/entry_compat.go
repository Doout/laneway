//go:build laneway_compat

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"

	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/nodeapp"
)

// This is the private backend shipped next to the Rust CLI. Keep an explicit
// list so the release linker can discard migrated public CLI implementations.
func processCommand(args []string) error {
	err := runtimeCommand(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func runtimeCommand(args []string) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(os.Stdout, buildinfo.Version)
		return nil
	}
	if len(args) > 0 {
		if args[0] == "_network-helper" {
			return compatibilityNetworkHelper(args[1:])
		}
		if args[0] == "_network-helper-bridge-version" && len(args) == 1 && nativeNetworkHelperBridge {
			fmt.Fprintln(os.Stdout, buildinfo.Version)
			return nil
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			switch args[0] {
			case "_connect-preflight":
				return runConnectSessionPreflight(args[1:])
			case "_connect-session":
				return runConnectSession(args[1:])
			}
		}
	}
	if runtime.GOOS == "linux" && len(args) >= 2 {
		if args[0] == "node" && args[1] == "run" {
			return nodeapp.Run(args[2:])
		}
		if args[0] == "pki" {
			switch args[1] {
			case "intermediate":
				return pkiIntermediate(args[2:])
			case "verify-authority":
				return pkiVerifyAuthority(args[2:])
			case "node":
				return pkiNode(args[2:])
			case "relay":
				return pkiRelay(args[2:])
			case "controller":
				return pkiController(args[2:])
			}
		}
	}
	return errors.New("use the laneway command for client and server operations")
}
