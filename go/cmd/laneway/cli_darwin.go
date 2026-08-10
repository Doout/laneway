//go:build darwin

package main

import "github.com/spf13/cobra"

func addPlatformCommands(root *cobra.Command) {
	root.AddCommand(
		command("configure", "Install and verify the macOS client and network helper", runMacConfigure),
		command("update", "Install the latest stable macOS client release", runMacUpdate),
	)
}
