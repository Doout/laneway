//go:build !laneway_compat

package main

const nativeNetworkHelperBridge = false

// Legacy update clients fetch this executable by its historical asset name.
// Keep their original public command surface until they install the Rust CLI.
func processCommand(args []string) error {
	return run(args)
}
