//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/spf13/cobra"
)

func addPlatformCommands(root *cobra.Command) {
	id := command("id", "Generate a random Laneway ID", func([]string) error {
		id, err := identity.NewID()
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, id.String())
		return nil
	})
	id.Hidden = true
	root.AddCommand(id)

	localAliases := make([]*cobra.Command, 0, 4)
	for _, local := range []struct{ name, summary string }{
		{"up", "Verify that the local node is running"},
		{"status", "Show local node and transport status"},
		{"peers", "List peers known to the local node"},
		{"routes", "List routes installed by the local node"},
	} {
		name := local.name
		alias := command(name, local.summary, func(args []string) error { return runLocal(name, args) })
		alias.Hidden = true
		root.AddCommand(alias)
		localAliases = append(localAliases, forwarded(name, local.summary, name, runNodeLocal))
	}

	for _, hidden := range []*cobra.Command{
		command("join TOKEN", "Enroll a node with a controller", runJoin),
		command("invite", "Issue an invite using a controller configuration", runInvite),
		command("renew", "Renew this node's controller-issued certificate", runRenew),
		group("connector", "Activate and run an unprivileged Connector", runConnector,
			forwarded("activate", "Activate from a single-use setup token", "activate", runConnector),
			forwarded("bootstrap-seal", "Seal a short-lived Connector bootstrap payload", "bootstrap-seal", runConnector),
			forwarded("bootstrap-activate", "Activate from an encrypted bootstrap payload", "bootstrap-activate", runConnector),
			forwarded("configure", "Validate or migrate persistent Connector configuration", "configure", runConnector),
			forwarded("run", "Activate if needed and run the Connector", "run", runConnector),
			forwarded("validate", "Validate persistent Connector identity", "validate", runConnector)),
	} {
		hidden.Hidden = true
		root.AddCommand(hidden)
	}

	node := group("node", "Install, operate, and inspect this host", runNode,
		forwarded("install DOMAIN", "Enroll and install a managed node", "install", runNodeDispatch),
		forwarded("renew", "Rotate a managed node credential", "renew", runNodeDispatch),
		forwarded("run", "Run the persistent node service", "run", runNodeDispatch),
		forwarded("uninstall", "Remove command-owned node state", "uninstall", runNodeDispatch),
	)
	node.AddCommand(localAliases...)
	ephemeralExitPrepare := forwarded("ephemeral-exit-prepare", "Prepare a RAM-only ephemeral Exit runtime", "ephemeral-exit-prepare", runNodeDispatch)
	ephemeralExitPrepare.Hidden = true
	node.AddCommand(ephemeralExitPrepare)
	node.AddCommand(group("exit", "Configure exit-node routing", runExit,
		forwarded("enable", "Advertise this gateway as an exit node", "enable", runExit),
		forwarded("use NAME_OR_NODE_ID", "Select an authorized exit node", "use", runExit),
		forwarded("disable", "Return to split-tunnel routing", "disable", runExit),
	))
	node.AddCommand(routeCommand("route", "Advertise and manage routes"))
	node.GroupID = "host"
	root.AddCommand(node)

	for _, hidden := range []*cobra.Command{
		group("exit", "Configure exit-node routing", runExit,
			forwarded("enable", "Advertise this gateway as an exit node", "enable", runExit),
			forwarded("use NAME_OR_NODE_ID", "Select an authorized exit node", "use", runExit),
			forwarded("disable", "Return to split-tunnel routing", "disable", runExit)),
		routeCommand("route", "Advertise and manage routes"),
		controllerCommand(),
		pkiCommand(),
		group("config", "Inspect and validate configuration", runConfig,
			forwarded("validate", "Validate a laneway.toml file", "validate", runConfig),
		),
	} {
		hidden.Hidden = true
		root.AddCommand(hidden)
	}
	control := controlCommand()
	control.GroupID = "control"
	root.AddCommand(control)
}

func runNodeLocal(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing local node command")
	}
	return runLocal(args[0], args[1:])
}
