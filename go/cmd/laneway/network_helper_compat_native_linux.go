//go:build laneway_compat && linux

package main

const nativeNetworkHelperBridge = true

func compatibilityNetworkHelper(args []string) error {
	return runNetworkHelperCommand(args, execNativeNetworkHelper)
}
