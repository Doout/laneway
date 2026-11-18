//go:build darwin

package main

import "github.com/spf13/cobra"

func addPlatformCommands(root *cobra.Command) {
	for _, client := range []*cobra.Command{
		command("configure", "Install and verify the macOS CLI and Rust runtime", runMacConfigure),
		command("update", "Install the latest signed macOS release", runMacUpdate),
	} {
		client.GroupID = "client"
		root.AddCommand(client)
	}
}
