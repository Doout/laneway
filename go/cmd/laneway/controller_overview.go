package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

type controllerOverview struct {
	NetworkID string                   `json:"network_id"`
	Nodes     []controllerOverviewNode `json:"nodes"`
}

type controllerOverviewNode struct {
	Name       string                      `json:"name"`
	NodeID     string                      `json:"node_id"`
	Role       string                      `json:"role"`
	Enrollment string                      `json:"enrollment"`
	Overlay    []string                    `json:"overlay_addresses"`
	Forwarding []controllerOverviewForward `json:"forwarding"`
}

type controllerOverviewForward struct {
	Prefix string `json:"prefix"`
	Mode   string `json:"mode"`
	Kind   string `json:"kind"`
}

func runControllerOverview(args []string) error {
	fs := flag.NewFlagSet("controller overview", flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	networkText := fs.String("network-id", "", "network ID")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("overview --network-id: %w", err)
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	nodes, err := client.Nodes(ctx, networkID, 1000)
	if err != nil {
		return err
	}
	routes, err := client.Routes(ctx, networkID, 1000)
	if err != nil {
		return err
	}
	overview := buildControllerOverview(networkID.String(), nodes, routes, time.Now())
	if *jsonOutput {
		return printJSON(overview)
	}
	return printControllerOverview(overview)
}

func buildControllerOverview(networkID string, nodes []controllerclient.Node, routes []controllerclient.Route, now time.Time) controllerOverview {
	forwarding := make(map[string][]controllerOverviewForward)
	for _, route := range routes {
		if route.State != "approved" || (route.Kind != "subnet" && route.Kind != "exit") ||
			(route.ValidUntilUnixSeconds != nil && *route.ValidUntilUnixSeconds <= now.Unix()) {
			continue
		}
		forwarding[route.NodeID] = append(forwarding[route.NodeID], controllerOverviewForward{
			Prefix: route.Prefix, Mode: route.Mode, Kind: route.Kind,
		})
	}
	overview := controllerOverview{NetworkID: networkID}
	for _, node := range nodes {
		if node.RevokedAtUnixSeconds != nil ||
			(node.LeaseExpiresAtUnixSeconds != nil && *node.LeaseExpiresAtUnixSeconds <= now.Unix()) {
			continue
		}
		addresses := make([]string, 0, 2)
		if node.IPv4Address != "" {
			addresses = append(addresses, node.IPv4Address)
		}
		if node.IPv6Address != "" {
			addresses = append(addresses, node.IPv6Address)
		}
		routes := forwarding[node.NodeID]
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Prefix == routes[j].Prefix {
				return routes[i].Kind < routes[j].Kind
			}
			return routes[i].Prefix < routes[j].Prefix
		})
		overview.Nodes = append(overview.Nodes, controllerOverviewNode{
			Name: node.Name, NodeID: node.NodeID, Role: controllerNodeRole(node),
			Enrollment: node.EnrollmentClass, Overlay: addresses, Forwarding: routes,
		})
	}
	sort.Slice(overview.Nodes, func(i, j int) bool {
		if overview.Nodes[i].Role == overview.Nodes[j].Role {
			return overview.Nodes[i].Name < overview.Nodes[j].Name
		}
		return overview.Nodes[i].Role < overview.Nodes[j].Role
	})
	return overview
}

func controllerNodeRole(node controllerclient.Node) string {
	if node.EnrollmentClass == "ephemeral" || node.EnrollmentClass == "remembered" {
		return "user"
	}
	capabilities := protocol.Capability(node.EnabledCapabilities)
	if capabilities.Has(protocol.CapabilitySubnetRouterV1) {
		return "connector"
	}
	if capabilities.Has(protocol.CapabilityExitNodeV1) {
		return "exit-node"
	}
	return "node"
}

func printControllerOverview(overview controllerOverview) error {
	fmt.Printf("\nActive enrollment inventory (%s)\n", overview.NetworkID)
	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "NAME\tROLE\tOVERLAY\tFORWARDING"); err != nil {
		return err
	}
	for _, node := range overview.Nodes {
		name := node.Name
		if name == "" {
			name = node.NodeID
		}
		forwards := make([]string, 0, len(node.Forwarding))
		for _, route := range node.Forwarding {
			forwards = append(forwards, fmt.Sprintf("%s (%s)", route.Prefix, route.Mode))
		}
		if len(forwards) == 0 {
			forwards = append(forwards, "-")
		}
		overlay := strings.Join(node.Overlay, ",")
		if overlay == "" {
			overlay = "-"
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", name, node.Role, overlay, strings.Join(forwards, ", ")); err != nil {
			return err
		}
	}
	if len(overview.Nodes) == 0 {
		if _, err := fmt.Fprintln(writer, "-\t-\t-\t-"); err != nil {
			return err
		}
	}
	return writer.Flush()
}
