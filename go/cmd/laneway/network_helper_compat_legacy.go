//go:build laneway_compat && !darwin && !linux

package main

const nativeNetworkHelperBridge = false

func compatibilityNetworkHelper(args []string) error {
	return runNetworkHelper(args)
}
