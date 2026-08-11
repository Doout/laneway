package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

const controllerCommandTimeout = 30 * time.Second

type remoteFlags struct {
	endpoint, ca, serverName, controllerNetwork, controllerService, cert, key, adminTokenFile *string
}

func addRemoteFlags(fs *flag.FlagSet, node, admin bool) remoteFlags {
	flags := remoteFlags{
		endpoint:          fs.String("controller", "", "controller HTTPS origin"),
		ca:                fs.String("ca", "/etc/laneway/ca.crt", "controller CA certificate"),
		serverName:        fs.String("server-name", "", "optional controller DNS name"),
		controllerNetwork: fs.String("controller-network-id", "", "expected controller certificate network ID"),
		controllerService: fs.String("controller-service-id", "", "expected controller certificate service ID"),
	}
	if node {
		flags.cert = fs.String("cert", "/etc/laneway/node.crt", "node certificate chain")
		flags.key = fs.String("key", "/etc/laneway/node.key", "node private key")
	}
	if admin {
		flags.adminTokenFile = fs.String("admin-token-file", "/etc/laneway/admin.token", "admin bearer token file")
	}
	return flags
}

func (f remoteFlags) client() (*controllerclient.Client, error) {
	if f.endpoint == nil || *f.endpoint == "" {
		return nil, errors.New("--controller is required")
	}
	options := controllerclient.Options{Endpoint: *f.endpoint, CAFile: *f.ca, ServerName: *f.serverName}
	networkID, err := identity.ParseNetworkID(*f.controllerNetwork)
	if err != nil {
		return nil, fmt.Errorf("--controller-network-id: %w", err)
	}
	serviceID, err := identity.ParseID(*f.controllerService)
	if err != nil {
		return nil, fmt.Errorf("--controller-service-id: %w", err)
	}
	options.ExpectedNetworkID, options.ExpectedServiceID = networkID, serviceID
	if f.cert != nil {
		options.CertificateFile, options.PrivateKeyFile = *f.cert, *f.key
	}
	if f.adminTokenFile != nil {
		options.AdminTokenFile = *f.adminTokenFile
	}
	return controllerclient.New(options)
}

func runController(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway controller <overview|network|enrollment-token|bootstrap-bundle|route|acl|node|certificate|relay|audit> ...")
	}
	switch args[0] {
	case "overview":
		return runControllerOverview(args[1:])
	case "network":
		return runControllerNetwork(args[1:])
	case "enrollment-token":
		return runControllerEnrollmentToken(args[1:])
	case "bootstrap-bundle":
		return runControllerBootstrapBundle(args[1:])
	case "route":
		return runControllerRoute(args[1:])
	case "acl":
		return runControllerACL(args[1:])
	case "node":
		return runControllerNode(args[1:])
	case "certificate":
		return runControllerCertificate(args[1:])
	case "relay":
		return runControllerRelay(args[1:])
	case "audit":
		return runControllerAudit(args[1:])
	default:
		return fmt.Errorf("unknown controller command %q", args[0])
	}
}

func runControllerBootstrapBundle(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: laneway controller bootstrap-bundle create --payload-file PATH --expires-at UNIX [controller options]")
	}
	fs := flag.NewFlagSet("controller bootstrap-bundle create", flag.ContinueOnError)
	payloadFile := fs.String("payload-file", "", "protected file containing the encrypted bootstrap wrapper")
	expiresAtUnix := fs.Int64("expires-at", 0, "absolute bootstrap expiry as Unix seconds")
	remote := addRemoteFlags(fs, false, true)
	if err := parseNoArgs(fs, args[1:]); err != nil {
		return err
	}
	if *payloadFile == "" || !filepath.IsAbs(*payloadFile) || *expiresAtUnix <= 0 {
		return errors.New("bootstrap-bundle create requires an absolute --payload-file and --expires-at")
	}
	info, err := os.Lstat(*payloadFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > bootstrap.MaxBundleBytes {
		return errors.New("--payload-file must be a nonempty regular file within the bootstrap size limit")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("--payload-file must not be accessible by group or other users")
	}
	payload, err := os.ReadFile(*payloadFile)
	if err != nil {
		return fmt.Errorf("read bootstrap payload: %w", err)
	}
	defer clear(payload)
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	bundle, err := client.CreateBootstrapBundle(ctx, payload, time.Unix(*expiresAtUnix, 0).UTC())
	if err != nil {
		return err
	}
	return printJSON(bundle)
}

func runControllerCertificate(args []string) error {
	if len(args) == 0 || (args[0] != "revoke" && args[0] != "list") {
		return errors.New("usage: laneway controller certificate <revoke|list> [options]")
	}
	fs := flag.NewFlagSet("controller certificate "+args[0], flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	networkText := fs.String("network-id", "", "network ID")
	if args[0] == "list" {
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil || *limit < 1 || *limit > 1000 {
			return errors.New("certificate list requires --network-id and --limit from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		values, err := client.Certificates(ctx, networkID, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Certificates []controllerclient.Certificate `json:"certificates"`
		}{values})
	}
	serialText := fs.String("serial", "", "canonical lowercase certificate serial in hexadecimal")
	reason := fs.String("reason", "", "revocation reason")
	if err := parseNoArgs(fs, args[1:]); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("certificate revoke --network-id: %w", err)
	}
	if *serialText == "" || len(*serialText) > 64 || len(*serialText)%2 != 0 || strings.ToLower(*serialText) != *serialText || (len(*serialText) > 2 && strings.HasPrefix(*serialText, "00")) {
		return errors.New("certificate revoke --serial must be canonical lowercase even-length hexadecimal")
	}
	serial, err := hex.DecodeString(*serialText)
	if err != nil || len(serial) == 0 || serial[0] == 0 {
		return errors.New("certificate revoke --serial must be canonical lowercase positive hexadecimal")
	}
	if strings.TrimSpace(*reason) == "" {
		return errors.New("certificate revoke requires --reason")
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	result, err := client.RevokeCertificate(ctx, networkID, serial, *reason)
	if err != nil {
		return err
	}
	return printJSON(result)
}

func runControllerRelay(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway controller relay <register|update|disable|list> [options]")
	}
	fs := flag.NewFlagSet("controller relay "+args[0], flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	switch args[0] {
	case "register":
		networkText := fs.String("network-id", "", "network ID")
		serviceText := fs.String("service-id", "", "relay certificate service ID")
		nodeText := fs.String("node-id", "", "optional node ID hosted with the relay")
		name := fs.String("name", "", "relay name")
		endpoint := fs.String("endpoint", "", "relay endpoint")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil {
			return fmt.Errorf("relay register --network-id: %w", err)
		}
		serviceID, err := identity.ParseID(*serviceText)
		if err != nil {
			return fmt.Errorf("relay register --service-id: %w", err)
		}
		var nodeID *identity.NodeID
		if *nodeText != "" {
			parsed, err := identity.ParseNodeID(*nodeText)
			if err != nil {
				return fmt.Errorf("relay register --node-id: %w", err)
			}
			nodeID = &parsed
		}
		if strings.TrimSpace(*name) == "" || strings.TrimSpace(*endpoint) == "" {
			return errors.New("relay register requires --name and --endpoint")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.RegisterRelay(ctx, networkID, serviceID, nodeID, *name, *endpoint)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "disable":
		relayText := fs.String("relay-id", "", "relay record ID")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		relayID, err := identity.ParseID(*relayText)
		if err != nil {
			return fmt.Errorf("relay disable --relay-id: %w", err)
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.DisableRelay(ctx, relayID)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "update":
		relayText := fs.String("relay-id", "", "relay record ID")
		name := fs.String("name", "", "relay name")
		endpoint := fs.String("endpoint", "", "relay endpoint")
		enabled := fs.Bool("enabled", true, "enable or disable the relay")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		relayID, err := identity.ParseID(*relayText)
		if err != nil || strings.TrimSpace(*name) == "" || strings.TrimSpace(*endpoint) == "" {
			return errors.New("relay update requires --relay-id, --name, and --endpoint")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.UpdateRelay(ctx, relayID, *name, *endpoint, *enabled)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		networkText := fs.String("network-id", "", "network ID")
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil || *limit < 1 || *limit > 1000 {
			return errors.New("relay list requires --network-id and --limit from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		values, err := client.Relays(ctx, networkID, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Relays []controllerclient.Relay `json:"relays"`
		}{values})
	default:
		return fmt.Errorf("unknown controller relay command %q", args[0])
	}
}

func runControllerNetwork(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway controller network <create|get|list> [options]")
	}
	fs := flag.NewFlagSet("controller network "+args[0], flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	switch args[0] {
	case "create":
		networkText := fs.String("network-id", "", "optional pre-generated immutable network ID")
		name := fs.String("name", "", "network name")
		poolText := fs.String("ipv4-pool", "", "canonical IPv4 pool CIDR")
		pool6Text := fs.String("ipv6-pool", "", "optional canonical IPv6 pool CIDR (/64 through /120)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		pool, err := netip.ParsePrefix(*poolText)
		if *name == "" || err != nil || !pool.Addr().Is4() || pool != pool.Masked() {
			return errors.New("network create requires --name and a canonical IPv4 --ipv4-pool")
		}
		var pool6 netip.Prefix
		if *pool6Text != "" {
			pool6, err = netip.ParsePrefix(*pool6Text)
			if err != nil || !pool6.Addr().Is6() || pool6.Addr().Is4In6() || pool6 != pool6.Masked() || pool6.Bits() < 64 || pool6.Bits() > 120 {
				return errors.New("--ipv6-pool must be a canonical IPv6 /64 through /120")
			}
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		var result *controllerclient.Network
		if *networkText == "" {
			result, err = client.CreateNetworkDualStack(ctx, *name, pool, pool6)
		} else {
			var networkID identity.NetworkID
			networkID, err = identity.ParseNetworkID(*networkText)
			if err != nil {
				return fmt.Errorf("network create --network-id: %w", err)
			}
			result, err = client.CreateNetworkDualStackWithID(ctx, networkID, *name, pool, pool6)
		}
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		if *limit < 1 || *limit > 1000 {
			return errors.New("--limit must be from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.Networks(ctx, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Networks []controllerclient.Network `json:"networks"`
		}{result})
	case "get":
		networkText := fs.String("network-id", "", "network ID")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil {
			return fmt.Errorf("network get --network-id: %w", err)
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.Network(ctx, networkID)
		if err != nil {
			return err
		}
		return printJSON(result)
	default:
		return fmt.Errorf("unknown controller network command %q", args[0])
	}
}

func runControllerEnrollmentToken(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New("usage: laneway controller enrollment-token issue --network-id ID --label LABEL [--class durable|ephemeral|remembered] [--session-lifetime 8h] [--expires-in 1h] [connection options]")
	}
	fs := flag.NewFlagSet("controller enrollment-token issue", flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	networkText := fs.String("network-id", "", "network ID")
	label := fs.String("label", "", "single-use token label")
	expiresIn := fs.Duration("expires-in", time.Hour, "token lifetime")
	class := fs.String("class", "durable", "enrollment class: durable, ephemeral, or remembered")
	sessionLifetime := fs.Duration("session-lifetime", 0, "ephemeral identity lifetime (default 8h for --class ephemeral)")
	requestedName := fs.String("requested-name", "", "bind enrollment to this exact node name")
	connector := fs.Bool("connector", false, "bind Connector subnet-forwarding capability to this invite")
	exitNode := fs.Bool("exit-node", false, "bind Exit Node capability and an approved IPv4 default route to this invite")
	if err := parseNoArgs(fs, args[1:]); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("enrollment-token --network-id: %w", err)
	}
	if *label == "" || *expiresIn <= 0 {
		return errors.New("enrollment-token issue requires --label and a positive --expires-in")
	}
	if *class != "durable" && *class != "ephemeral" && *class != "remembered" {
		return errors.New("--class must be durable, ephemeral, or remembered")
	}
	if *class == "ephemeral" && *sessionLifetime == 0 {
		*sessionLifetime = 8 * time.Hour
	}
	if (*class == "ephemeral" && *sessionLifetime <= 0) || (*class != "ephemeral" && *sessionLifetime != 0) {
		return errors.New("--session-lifetime is required only for ephemeral enrollment")
	}
	if *connector && *exitNode {
		return errors.New("choose either --connector or --exit-node")
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	var enabledCapabilities uint64
	if *connector {
		enabledCapabilities = uint64(protocol.CapabilitySubnetRouterV1)
	} else if *exitNode {
		enabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
	}
	result, err := client.IssueEnrollmentTokenWithOptions(ctx, networkID, *label, time.Now().UTC().Add(*expiresIn), controllerclient.EnrollmentTokenOptions{
		Class: *class, SessionLifetime: *sessionLifetime, RequestedName: *requestedName, EnabledCapabilities: enabledCapabilities,
	})
	if err != nil {
		return err
	}
	// This is the sole management command that intentionally emits a secret.
	return printJSON(result)
}

func runControllerRoute(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway controller route <advertise|assign|withdraw|approve|list> [options]")
	}
	fs := flag.NewFlagSet("controller route "+args[0], flag.ContinueOnError)
	nodeAuth := args[0] == "advertise" || args[0] == "withdraw"
	remote := addRemoteFlags(fs, nodeAuth, !nodeAuth)
	switch args[0] {
	case "assign":
		networkText := fs.String("network-id", "", "network ID")
		nodeSelector := fs.String("connector", "", "exact Connector name or node ID")
		destination := fs.String("to", "", "destination IP address or prefix")
		allowedUser := fs.String("allow", "", "optional exact user node name or node ID")
		mode := fs.String("mode", "nat", "nat or routed")
		metric := fs.Uint("metric", 0, "route metric")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil || *nodeSelector == "" || *destination == "" {
			return errors.New("route assign requires --network-id, --connector, and --to")
		}
		if *mode != "nat" && *mode != "routed" {
			return errors.New("--mode must be nat or routed")
		}
		if *metric > uint(^uint32(0)) {
			return errors.New("--metric exceeds uint32")
		}
		prefix, err := assignedRoutePrefix(*destination)
		if err != nil {
			return err
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		nodeID, err := resolveControllerNode(ctx, client, networkID, *nodeSelector)
		if err != nil {
			return err
		}
		var allowedUserID identity.NodeID
		if *allowedUser != "" {
			allowedUserID, err = resolveControllerNode(ctx, client, networkID, *allowedUser)
			if err != nil {
				return fmt.Errorf("resolve --allow: %w", err)
			}
		}
		route, err := client.AssignRoute(ctx, networkID, nodeID, prefix, *mode, uint32(*metric))
		if err != nil {
			return err
		}
		trafficSelector := &lanewayv1.TrafficSelector{
			DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: prefix.Addr().AsSlice(), PrefixLength: uint32(prefix.Bits())}},
			IpProtocol:          lanewayv1.IpProtocol_IP_PROTOCOL_ANY,
		}
		if *allowedUser != "" {
			trafficSelector.SourceNodeIds = [][]byte{append([]byte(nil), allowedUserID[:]...)}
		}
		selector, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(trafficSelector)
		if err != nil {
			return err
		}
		description := "managed route " + prefix.String() + " via " + *nodeSelector
		if *allowedUser != "" {
			description += " for " + *allowedUser
		}
		rules, err := client.ACLRules(ctx, networkID, 1000)
		if err != nil {
			return err
		}
		var acl *controllerclient.ACLRule
		for i := range rules {
			if rules[i].Action == "accept" && string(rules[i].Selector) == string(selector) {
				acl = &rules[i]
				break
			}
		}
		if acl == nil {
			acl, err = client.AddACLRule(ctx, networkID, 100, "accept", selector, description)
			if err != nil {
				return err
			}
		}
		return printJSON(struct {
			Route *controllerclient.Route   `json:"route"`
			ACL   *controllerclient.ACLRule `json:"acl_rule"`
		}{route, acl})
	case "advertise":
		prefixText := fs.String("prefix", "", "canonical route prefix")
		kind := fs.String("kind", "subnet", "subnet or exit")
		mode := fs.String("mode", "nat", "nat or routed")
		metric := fs.Uint("metric", 0, "route metric")
		validFor := fs.Duration("valid-for", 0, "optional route lifetime")
		advertiseArgs := args[1:]
		positionalPrefix := ""
		// The product CLI spells the common case as `route advertise PREFIX`.
		// Pull that leading positional selector before flag parsing so optional
		// flags may still follow it; flag-first invocations remain compatible.
		if len(advertiseArgs) != 0 && !strings.HasPrefix(advertiseArgs[0], "-") {
			positionalPrefix, advertiseArgs = advertiseArgs[0], advertiseArgs[1:]
		}
		if err := fs.Parse(advertiseArgs); err != nil {
			return err
		}
		if fs.NArg() > 1 || (fs.NArg() == 1 && positionalPrefix != "") {
			return errors.New("usage: laneway route advertise PREFIX [options]")
		}
		if fs.NArg() == 1 {
			positionalPrefix = fs.Arg(0)
		}
		if positionalPrefix != "" {
			if *prefixText != "" {
				return errors.New("route advertise accepts either positional PREFIX or --prefix, not both")
			}
			*prefixText = positionalPrefix
		}
		prefix, err := netip.ParsePrefix(*prefixText)
		if err != nil || prefix != prefix.Masked() {
			return errors.New("route advertise requires a canonical PREFIX")
		}
		if *kind != "subnet" && *kind != "exit" {
			return errors.New("--kind must be subnet or exit")
		}
		if *mode != "nat" && *mode != "routed" {
			return errors.New("--mode must be nat or routed")
		}
		if *metric > uint(^uint32(0)) || *validFor < 0 {
			return errors.New("invalid --metric or --valid-for")
		}
		var validUntil *time.Time
		if *validFor > 0 {
			value := time.Now().UTC().Add(*validFor)
			validUntil = &value
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.AdvertiseRoute(ctx, prefix, *kind, *mode, uint32(*metric), validUntil)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "withdraw", "approve":
		routeText := fs.String("route-id", "", "route ID")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		routeID, err := identity.ParseID(*routeText)
		if err != nil {
			return fmt.Errorf("route --route-id: %w", err)
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		var result *controllerclient.Epoch
		if args[0] == "withdraw" {
			result, err = client.WithdrawRoute(ctx, routeID)
		} else {
			result, err = client.ApproveRoute(ctx, routeID)
		}
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		networkText := fs.String("network-id", "", "network ID")
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil {
			return fmt.Errorf("route list --network-id: %w", err)
		}
		if *limit < 1 || *limit > 1000 {
			return errors.New("--limit must be from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		routes, err := client.Routes(ctx, networkID, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Routes []controllerclient.Route `json:"routes"`
		}{routes})
	default:
		return fmt.Errorf("unknown controller route command %q", args[0])
	}
}

func assignedRoutePrefix(value string) (netip.Prefix, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address, bits), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
		return netip.Prefix{}, errors.New("--to must be an IP address or canonical non-default prefix")
	}
	return prefix, nil
}

func resolveControllerNode(ctx context.Context, client *controllerclient.Client, networkID identity.NetworkID, selector string) (identity.NodeID, error) {
	if nodeID, err := identity.ParseNodeID(selector); err == nil {
		return nodeID, nil
	}
	nodes, err := client.Nodes(ctx, networkID, 1000)
	if err != nil {
		return identity.NodeID{}, err
	}
	names := map[string]struct{}{selector: {}}
	if strings.HasPrefix(selector, "laneway-connector-") {
		names[strings.TrimPrefix(selector, "laneway-connector-")] = struct{}{}
	}
	var match identity.NodeID
	count := 0
	for _, node := range nodes {
		if node.RevokedAtUnixSeconds != nil {
			continue
		}
		if _, ok := names[node.Name]; !ok {
			continue
		}
		parsed, err := identity.ParseNodeID(node.NodeID)
		if err != nil {
			return identity.NodeID{}, errors.New("controller returned an invalid node identity")
		}
		match, count = parsed, count+1
	}
	if count == 0 {
		return identity.NodeID{}, fmt.Errorf("no active Connector has the exact name %q", selector)
	}
	if count != 1 {
		return identity.NodeID{}, fmt.Errorf("Connector name %q is ambiguous", selector)
	}
	return match, nil
}

func runControllerACL(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway controller acl <add|delete|list> [options]")
	}
	fs := flag.NewFlagSet("controller acl "+args[0], flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	switch args[0] {
	case "add":
		networkText := fs.String("network-id", "", "network ID")
		priority := fs.Uint("priority", 0, "rule priority")
		action := fs.String("action", "", "accept or deny")
		selectorText := fs.String("selector", "", "TrafficSelector protojson")
		selectorFile := fs.String("selector-file", "", "file containing TrafficSelector protojson")
		description := fs.String("description", "", "rule description")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil {
			return fmt.Errorf("acl add --network-id: %w", err)
		}
		if (*selectorText == "") == (*selectorFile == "") {
			return errors.New("acl add requires exactly one of --selector or --selector-file")
		}
		if *action != "accept" && *action != "deny" {
			return errors.New("--action must be accept or deny")
		}
		if *priority > uint(^uint32(0)) {
			return errors.New("--priority exceeds uint32")
		}
		selector := []byte(*selectorText)
		if *selectorFile != "" {
			selector, err = readBounded(*selectorFile, controllerclient.MaxJSONRequestBytes)
			if err != nil {
				return err
			}
		}
		if !json.Valid(selector) {
			return errors.New("selector is not valid JSON")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.AddACLRule(ctx, networkID, uint32(*priority), *action, json.RawMessage(selector), *description)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "delete":
		ruleText := fs.String("rule-id", "", "ACL rule ID")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		ruleID, err := identity.ParseID(*ruleText)
		if err != nil {
			return fmt.Errorf("acl delete --rule-id: %w", err)
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		result, err := client.DeleteACLRule(ctx, ruleID)
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		networkText := fs.String("network-id", "", "network ID")
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil || *limit < 1 || *limit > 1000 {
			return errors.New("acl list requires --network-id and --limit from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		values, err := client.ACLRules(ctx, networkID, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Rules []controllerclient.ACLRule `json:"acl_rules"`
		}{values})
	default:
		return fmt.Errorf("unknown controller acl command %q", args[0])
	}
}

func runControllerNode(args []string) error {
	if len(args) == 0 || (args[0] != "revoke" && args[0] != "capabilities" && args[0] != "list") {
		return errors.New("usage: laneway controller node <revoke|capabilities|list> [options]")
	}
	fs := flag.NewFlagSet("controller node "+args[0], flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	if args[0] == "list" {
		networkText := fs.String("network-id", "", "network ID")
		limit := fs.Int("limit", 100, "maximum records (1..1000)")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		networkID, err := identity.ParseNetworkID(*networkText)
		if err != nil || *limit < 1 || *limit > 1000 {
			return errors.New("node list requires --network-id and --limit from 1 through 1000")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		values, err := client.Nodes(ctx, networkID, *limit)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Nodes []controllerclient.Node `json:"nodes"`
		}{values})
	}
	nodeText := fs.String("node-id", "", "node ID")
	var reason *string
	var subnet, exit *bool
	if args[0] == "revoke" {
		reason = fs.String("reason", "", "revocation reason")
	} else {
		subnet = fs.Bool("subnet-router", false, "authorize subnet advertisements and gateway activation")
		exit = fs.Bool("exit-node", false, "authorize exit advertisements and gateway activation")
	}
	if err := parseNoArgs(fs, args[1:]); err != nil {
		return err
	}
	nodeID, err := identity.ParseNodeID(*nodeText)
	if err != nil {
		return fmt.Errorf("node revoke --node-id: %w", err)
	}
	if reason != nil && strings.TrimSpace(*reason) == "" {
		return errors.New("node revoke requires --reason")
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	var result *controllerclient.Epoch
	if reason != nil {
		result, err = client.RevokeNode(ctx, nodeID, *reason)
	} else {
		var capabilities protocol.Capability
		if *subnet {
			capabilities |= protocol.CapabilitySubnetRouterV1
		}
		if *exit {
			capabilities |= protocol.CapabilityExitNodeV1
		}
		result, err = client.SetNodeCapabilities(ctx, nodeID, uint64(capabilities))
	}
	if err != nil {
		return err
	}
	return printJSON(result)
}

func runControllerAudit(args []string) error {
	fs := flag.NewFlagSet("controller audit", flag.ContinueOnError)
	remote := addRemoteFlags(fs, false, true)
	networkText := fs.String("network-id", "", "network ID")
	limit := fs.Int("limit", 100, "maximum records (1..1000)")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("audit --network-id: %w", err)
	}
	if *limit < 1 || *limit > 1000 {
		return errors.New("--limit must be from 1 through 1000")
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	ctx, cancel := commandContext()
	defer cancel()
	events, err := client.Audit(ctx, networkID, *limit)
	if err != nil {
		return err
	}
	return printJSON(struct {
		Events []controllerclient.AuditEvent `json:"events"`
	}{events})
}

func parseNoArgs(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected positional arguments", fs.Name())
	}
	return nil
}

func commandContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), controllerCommandTimeout)
}

func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(contents) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", path, limit)
	}
	return contents, nil
}
