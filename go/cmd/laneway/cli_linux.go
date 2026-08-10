//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"laneway.dev/laneway/internal/identity"
)

func addPlatformCommands(root *cobra.Command) {
	root.AddCommand(command("id", "Generate a random Laneway ID", func([]string) error {
		id, err := identity.NewID()
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, id.String())
		return nil
	}))

	for _, local := range []struct{ name, summary string }{
		{"up", "Verify that the local node is running"},
		{"status", "Show local node and transport status"},
		{"peers", "List peers known to the local node"},
		{"routes", "List routes installed by the local node"},
	} {
		name := local.name
		root.AddCommand(command(name, local.summary, func(args []string) error { return runLocal(name, args) }))
	}

	root.AddCommand(
		command("join TOKEN", "Enroll a node with a controller", runJoin),
		command("invite", "Issue an invite using a controller configuration", runInvite),
		command("renew", "Renew this node's controller-issued certificate", runRenew),
		group("connector", "Activate and run an unprivileged Connector", runConnector,
			forwarded("activate", "Activate from a single-use setup token", "activate", runConnector)),
	)

	root.AddCommand(group("node", "Install and operate a persistent host node", runNode,
		forwarded("install DOMAIN", "Enroll and install a managed node", "install", runNodeDispatch),
		forwarded("renew", "Rotate a managed node credential", "renew", runNodeDispatch),
		forwarded("run", "Run the persistent node service", "run", runNodeDispatch),
		forwarded("uninstall", "Remove command-owned node state", "uninstall", runNodeDispatch),
	))
	root.AddCommand(group("exit", "Configure exit-node routing", runExit,
		forwarded("enable", "Advertise this gateway as an exit node", "enable", runExit),
		forwarded("use NAME_OR_NODE_ID", "Select an authorized exit node", "use", runExit),
		forwarded("disable", "Return to split-tunnel routing", "disable", runExit),
	))
	root.AddCommand(routeCommand("route", "Advertise and manage routes"))
	root.AddCommand(controllerCommand())
	root.AddCommand(pkiCommand())
	root.AddCommand(group("config", "Inspect and validate configuration", runConfig,
		forwarded("validate", "Validate a laneway.toml file", "validate", runConfig),
	))
	root.AddCommand(controlCommand())
}
