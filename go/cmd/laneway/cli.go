package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"laneway.dev/laneway/internal/buildinfo"
)

type commandHandler func([]string) error

func executeCLI(args []string) error {
	// Keep the historical single-dash spelling accepted by the old dispatcher.
	if len(args) == 1 && args[0] == "-version" {
		args[0] = "version"
	}
	root := newRootCommand()
	root.SetArgs(args)
	return root.Execute()
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "laneway",
		Short:         "Private networking without the network-shaped command line",
		SilenceErrors: true,
		SilenceUsage:  true,
		Version:       buildinfo.Version,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.CompletionOptions.HiddenDefaultCmd = true

	root.AddCommand(command("version", "Print the Laneway build version", func([]string) error {
		fmt.Fprintln(os.Stdout, buildinfo.Version)
		return nil
	}))
	root.AddCommand(
		command("login DOMAIN", "Save a renewable user login", runLogin),
		command("connect DOMAIN", "Connect using a saved login", runConnect),
		command("logout DOMAIN", "Remove a saved user login", runLogout),
	)
	root.AddCommand(group("bootstrap", "Inspect bootstrap metadata or download a verified release", runBootstrap,
		forwarded("inspect DOMAIN", "Inspect public bootstrap metadata", "inspect", runBootstrap),
		forwarded("download DOMAIN", "Download a verified release artifact", "download", runBootstrap),
	))
	helper := command("_network-helper", "Internal privileged network helper", runNetworkHelper)
	helper.Hidden = true
	root.AddCommand(helper)
	addPlatformCommands(root)
	return root
}

func command(use, summary string, handler commandHandler) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              summary,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			err := handler(args)
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		},
	}
}

func forwarded(use, summary, prefix string, handler commandHandler) *cobra.Command {
	return command(use, summary, func(args []string) error {
		return handler(append([]string{prefix}, args...))
	})
}

func group(use, summary string, fallback commandHandler, children ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: summary,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return fallback(args)
		},
	}
	cmd.AddCommand(children...)
	return cmd
}

func runNodeDispatch(args []string) error { return runNode(args) }

func routeCommand(use, summary string) *cobra.Command {
	return group(use, summary, runControllerRoute,
		forwarded("advertise PREFIX", "Advertise a subnet or exit route", "advertise", runControllerRoute),
		forwarded("withdraw", "Withdraw a route advertisement", "withdraw", runControllerRoute),
		forwarded("approve", "Approve a route advertisement", "approve", runControllerRoute),
		forwarded("list", "List route advertisements", "list", runControllerRoute),
	)
}

func controllerCommand() *cobra.Command {
	controller := group("controller", "Administer controller resources", runController)
	controller.AddCommand(
		resourceCommand("network", "Manage networks", runControllerNetwork, "create", "get", "list"),
		resourceCommand("enrollment-token", "Issue enrollment tokens", runControllerEnrollmentToken, "issue"),
		routeCommand("route", "Manage controller routes"),
		resourceCommand("acl", "Manage access-control rules", runControllerACL, "add", "delete", "list"),
		resourceCommand("node", "Manage enrolled nodes", runControllerNode, "revoke", "capabilities", "list"),
		resourceCommand("certificate", "Manage certificates", runControllerCertificate, "revoke", "list"),
		resourceCommand("relay", "Manage relays", runControllerRelay, "register", "update", "disable", "list"),
		command("audit", "List controller audit events", runControllerAudit),
	)
	return controller
}

func resourceCommand(use, summary string, handler commandHandler, actions ...string) *cobra.Command {
	children := make([]*cobra.Command, 0, len(actions))
	for _, action := range actions {
		children = append(children, forwarded(action, action+" "+use, action, handler))
	}
	return group(use, summary, handler, children...)
}

func pkiCommand() *cobra.Command {
	return group("pki", "Create and verify Laneway identities", runPKI,
		forwarded("init", "Create a development certificate authority", "init", runPKI),
		forwarded("intermediate", "Create an online intermediate issuer", "intermediate", runPKI),
		forwarded("verify-authority", "Verify an issuer against its offline root", "verify-authority", runPKI),
		forwarded("node", "Issue a node certificate", "node", runPKI),
		forwarded("relay", "Issue a relay certificate", "relay", runPKI),
		forwarded("controller", "Issue a controller certificate", "controller", runPKI),
	)
}

func controlCommand() *cobra.Command {
	control := &cobra.Command{
		Use:   "control",
		Short: "Operate the installed Docker Compose control plane",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	for _, item := range []struct{ name, summary string }{
		{"init", "Initialize or validate the control plane"},
		{"user-token", "Create a one-time local-user login token"},
		{"invite", "Create a single-use enrollment command"},
		{"status", "Show control-plane service health"},
		{"update", "Update to the latest stable release"},
		{"production-check", "Run fail-closed production checks"},
		{"backup", "Create an encrypted recovery bundle"},
		{"restore", "Restore an encrypted recovery bundle"},
		{"upgrade", "Upgrade using a prepared release environment"},
		{"rollback", "Roll back to the previous release selection"},
	} {
		name := item.name
		control.AddCommand(command(name, item.summary, func(args []string) error {
			return runControl(append([]string{name}, args...))
		}))
	}
	return control
}

func runControl(args []string) error {
	path, err := controlCommandPath()
	if err != nil {
		return err
	}
	process := exec.Command(path, args...)
	process.Stdin = os.Stdin
	process.Stdout = os.Stdout
	process.Stderr = os.Stderr
	return process.Run()
}

func controlCommandPath() (string, error) {
	if override := os.Getenv("LANEWAY_CONTROL_COMMAND"); override != "" {
		path, err := exec.LookPath(override)
		if err != nil {
			return "", fmt.Errorf("find control-plane command %q: %w", override, err)
		}
		return path, nil
	}
	for _, candidate := range []string{"/usr/local/sbin/laneway-control", "/opt/laneway/laneway-control"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath("laneway-control"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("control plane is not installed; expected %s", "/usr/local/sbin/laneway-control")
}
