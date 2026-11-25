package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/buildinfo"
)

type commandHandler func([]string) error

func executeCLI(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "_connect-preflight":
			return runConnectSessionPreflight(args[1:])
		case "_connect-session":
			return runConnectSession(args[1:])
		}
	}
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
	root.SetHelpCommandGroupID("utility")
	root.AddGroup(
		&cobra.Group{ID: "client", Title: "Client Commands:"},
		&cobra.Group{ID: "host", Title: "Host Commands:"},
		&cobra.Group{ID: "control", Title: "Control Plane Commands:"},
		&cobra.Group{ID: "utility", Title: "Other Commands:"},
	)

	version := command("version", "Print the Laneway build version", func([]string) error {
		fmt.Fprintln(os.Stdout, buildinfo.Version)
		return nil
	})
	version.GroupID = "utility"
	root.AddCommand(version)
	configure := productCommand("configure [--system]", "Set up this node (userspace by default)", "  laneway configure\n  sudo laneway configure --system\n  sudo laneway configure server lane.example.com", runConfigure)
	configure.Long = "Enter your native invitation at the prompt. First-time userspace setup creates a local proxy login. Use --state-dir PATH for a separate userspace identity or --system for host networking."
	configure.AddCommand(productCommand("server [DOMAIN]", "Configure the Docker Compose control plane on this host", "  sudo laneway configure server lane.example.com", configureServer))
	update := productCommand("update", "Update the detected local installation", "  laneway update\n  laneway update client\n  sudo laneway update server\n  sudo laneway update connector", func(args []string) error {
		return runProductUpdate("", args)
	})
	update.Long = "Update the local installation. Select a target on a host with several roles. Run server and Docker connector updates on the Linux deployment host."
	for _, target := range []struct{ name, summary string }{
		{"client", "Update the installed client and node"},
		{"server", "Update the managed Docker Compose control plane"},
		{"connector [NAME]", "Update a managed Docker connector from its host"},
	} {
		name := strings.Fields(target.name)[0]
		update.AddCommand(productCommand(target.name, target.summary, "", func(args []string) error {
			return runProductUpdate(name, args)
		}))
	}
	update.GroupID = "utility"
	root.AddCommand(update)
	start := productCommand("start [--system]", "Start this node (userspace by default)", "  laneway start\n  laneway start --no-proxy\n  sudo laneway start --system", runProductStart)
	start.Long = "Start the foreground node. The local SOCKS5 proxy listens on 127.0.0.1:1080. Use --listen ADDRESS to change the loopback listener, --no-proxy to serve routes only, or --proxy-only to originate connections only. Use --state-dir PATH for a separate userspace identity."
	for _, client := range []*cobra.Command{
		configure, start,
		productCommand("credential <add|list|remove>", "Manage local SOCKS5 credentials", "  laneway credential add laptop\n  laneway credential list\n  laneway credential remove laptop", runProductCredential),
		command("login DOMAIN", "Save a renewable user login", runLogin),
		command("connect [DOMAIN]", "Connect using a saved login", runConnect),
		command("logout DOMAIN", "Remove a saved user login", runLogout),
	} {
		client.GroupID = "client"
		root.AddCommand(client)
	}

	// These commands are implementation and recovery surfaces used by the
	// installers, control-plane wrapper, and advanced deployments. Keep their
	// stable spellings without presenting them as everyday product workflows.
	bootstrap := group("bootstrap", "Inspect bootstrap metadata or download a verified release", runBootstrap,
		forwarded("inspect DOMAIN", "Inspect public bootstrap metadata", "inspect", runBootstrap),
		forwarded("download DOMAIN", "Download a verified release artifact", "download", runBootstrap),
	)
	bootstrap.Hidden = true
	root.AddCommand(bootstrap)
	helper := command("_network-helper", "Internal privileged network helper", runNetworkHelper)
	helper.Hidden = true
	root.AddCommand(helper)
	addPlatformCommands(root)
	return root
}

// These entry points forward options to their owning implementation while
// keeping help available before installation or host detection.
func productCommand(use, summary, example string, handler commandHandler) *cobra.Command {
	cmd := command(use, summary, handler)
	cmd.Example = example
	run := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
			return cmd.Help()
		}
		return run(cmd, args)
	}
	return cmd
}

func runProductUpdate(target string, args []string) error {
	if target == "" && len(args) != 0 && (len(args) != 1 || args[0] != "--yes") {
		return errors.New("usage: laneway update [client | server | connector [NAME]]")
	}
	if err := updateContainerHandoff(target); err != nil {
		return err
	}
	if target == "" {
		var err error
		target, err = detectUpdateTarget()
		if err != nil {
			return err
		}
	}
	if target == "client" {
		return updateNativeClient(args)
	}
	return updateDeployment(target, args)
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
		forwarded("assign", "Assign and authorize a destination through a Connector", "assign", runControllerRoute),
		forwarded("withdraw", "Withdraw a route advertisement", "withdraw", runControllerRoute),
		forwarded("approve", "Approve a route advertisement", "approve", runControllerRoute),
		forwarded("list", "List route advertisements", "list", runControllerRoute),
	)
}

func controllerCommand() *cobra.Command {
	controller := group("controller", "Administer controller resources", runController)
	controller.AddCommand(
		command("overview", "Show active nodes and their approved forwarding", runControllerOverview),
		controllerAdministratorCommand(),
		resourceCommand("network", "Manage networks", runControllerNetwork, "create", "get", "list"),
		resourceCommand("enrollment-token", "Issue enrollment tokens", runControllerEnrollmentToken, "issue"),
		resourceCommand("bootstrap-bundle", "Manage short-lived Connector bootstrap bundles", runControllerBootstrapBundle, "create"),
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
		{"route", "Assign an approved destination to a Connector"},
		{"status", "Show service health, active enrollments, and forwarding"},
		{"update", "Update to the latest stable release"},
		{"production-check", "Run fail-closed production checks"},
		{"backup", "Create an encrypted recovery bundle"},
		{"restore", "Restore an encrypted recovery bundle"},
		{"upgrade", "Upgrade using a prepared release environment"},
		{"rollback", "Roll back to the previous release selection"},
	} {
		name := item.name
		use := name
		if name == "route" {
			use = "route add --connector NAME --to IP_OR_PREFIX"
		}
		control.AddCommand(command(use, item.summary, func(args []string) error {
			return runControl(append([]string{name}, args...))
		}))
	}
	administrator := &cobra.Command{
		Use:   "administrator",
		Short: "Bootstrap and recover administrator access",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	var bootstrapUsername string
	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap the first administrator",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !adminauth.ValidateUsername(bootstrapUsername) {
				return errors.New("administrator bootstrap requires a valid --username")
			}
			return runControl([]string{"administrator", "bootstrap", "--username", bootstrapUsername})
		},
	}
	bootstrap.Flags().StringVar(&bootstrapUsername, "username", "", "username for the first administrator")
	var recoveryUsername string
	recoverAdministrator := &cobra.Command{
		Use:   "recover",
		Short: "Recover administrator access",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !adminauth.ValidateUsername(recoveryUsername) {
				return errors.New("administrator recovery requires a valid --username")
			}
			return runControl([]string{"administrator", "recover", "--username", recoveryUsername})
		},
	}
	recoverAdministrator.Flags().StringVar(&recoveryUsername, "username", "", "username of the owner to recover")
	administrator.AddCommand(bootstrap, recoverAdministrator)
	rootToken := &cobra.Command{
		Use:   "root-token",
		Short: "Manage the control-plane root administrator token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	rootToken.AddCommand(controlNoArgs("rotate", "Rotate the root administrator token", "administrator", "root-token", "rotate"))
	administrator.AddCommand(rootToken)
	control.AddCommand(administrator)
	return control
}

func controlNoArgs(use, summary string, forwarded ...string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: summary,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runControl(append([]string(nil), forwarded...))
		},
	}
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
