package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/localapi"
	"laneway.dev/laneway/internal/nethelper"
	"laneway.dev/laneway/internal/nodeapp"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/wireguard"
)

func main() {
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == "lanewayd" {
		args = append([]string{"node", "run"}, args...)
	}
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, "laneway:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return executeCLI(args)
}

func runNetworkHelper(args []string) error {
	fs := flag.NewFlagSet("_network-helper", flag.ContinueOnError)
	fd := fs.Int("control-fd", -1, "inherited control socket descriptor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *fd < 0 {
		return errors.New("invalid privileged helper invocation")
	}
	return nethelper.ServeInheritedFD(context.Background(), *fd, nethelper.ProductionConfig())
}

func runNode(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway node <install|renew|run|uninstall> [options]; laneway node run [-config path] [-diagnostics 127.0.0.1:PORT]")
	}
	switch args[0] {
	case "install":
		return runNodeInstall(args[1:])
	case "run":
		return nodeapp.Run(args[1:])
	case "renew":
		return runManagedNodeRenew(args[1:])
	case "uninstall":
		return runNodeUninstall(args[1:])
	default:
		return fmt.Errorf("unknown node command %q; usage: laneway node run [-config path]", args[0])
	}
}

func runExit(args []string) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "use" && args[0] != "disable") {
		return errors.New("usage: laneway exit <enable|use NAME_OR_NODE_ID|disable> [options]")
	}
	command := args[0]
	if command == "enable" {
		return runExitEnable(args[1:])
	}
	fs := flag.NewFlagSet("exit "+command, flag.ContinueOnError)
	path := fs.String("config", "/etc/laneway/laneway.toml", "configuration file")
	socket := fs.String("socket", "", "local daemon Unix socket (bypasses configuration loading)")
	commandArgs := args[1:]
	selector := ""
	if command == "use" && len(commandArgs) != 0 && !strings.HasPrefix(commandArgs[0], "-") {
		selector, commandArgs = commandArgs[0], commandArgs[1:]
	}
	if err := fs.Parse(commandArgs); err != nil {
		return err
	}
	selection := localapi.ExitSelection{}
	if command == "use" {
		if fs.NArg() > 1 || (fs.NArg() == 1 && selector != "") {
			return errors.New("usage: laneway exit use NAME_OR_NODE_ID [-config path | -socket path]")
		}
		if fs.NArg() == 1 {
			selector = fs.Arg(0)
		}
		if selector == "" {
			return errors.New("usage: laneway exit use NAME_OR_NODE_ID [-config path | -socket path]")
		}
		selection.Enabled = true
	} else if fs.NArg() != 0 {
		return errors.New("usage: laneway exit disable [-config path | -socket path]")
	}
	socketPath, err := localSocketPath(*path, *socket)
	if err != nil {
		return err
	}
	client, err := localapi.NewClient(socketPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if command == "use" {
		nodeID, err := identity.ParseNodeID(selector)
		if err != nil {
			peers, peerErr := client.Peers(ctx)
			if peerErr != nil {
				return fmt.Errorf("resolve exit name: %w", peerErr)
			}
			nodeID, err = resolveExitSelector(selector, peers)
			if err != nil {
				return err
			}
		}
		selection.SelectedNodeID = nodeID.String()
	}
	if err := client.SetExit(ctx, selection); err != nil {
		return err
	}
	if selection.Enabled {
		fmt.Printf("selected exit node %s\n", selection.SelectedNodeID)
	} else {
		fmt.Println("exit routing disabled")
	}
	return nil
}

func resolveExitSelector(selector string, peers []localapi.Peer) (identity.NodeID, error) {
	if selector == "" {
		return identity.NodeID{}, errors.New("exit node name is empty")
	}
	matches := make(map[identity.NodeID]struct{})
	for _, peer := range peers {
		if peer.Name != selector {
			continue
		}
		nodeID, err := identity.ParseNodeID(peer.NodeID)
		if err != nil || nodeID.IsZero() {
			return identity.NodeID{}, fmt.Errorf("exit name %q maps to an invalid node identity", selector)
		}
		matches[nodeID] = struct{}{}
	}
	if len(matches) == 0 {
		return identity.NodeID{}, fmt.Errorf("no peer has the exact name %q", selector)
	}
	if len(matches) != 1 {
		return identity.NodeID{}, fmt.Errorf("exit name %q is ambiguous across %d node identities", selector, len(matches))
	}
	for nodeID := range matches {
		return nodeID, nil
	}
	panic("unreachable")
}

// runExitEnable is the operator-friendly exit-gateway counterpart of route
// advertise. It requests controller approval for the default routes; the
// daemon still requires exit.serve=true and only activates forwarding after
// those advertisements are approved in a controller snapshot.
func runExitEnable(args []string) error {
	fs := flag.NewFlagSet("exit enable", flag.ContinueOnError)
	remote := addRemoteFlags(fs, true, false)
	configPath := fs.String("config", "/etc/laneway/laneway.toml", "gateway configuration file")
	family := fs.String("family", "dual", "exit family: dual, ipv4, or ipv6")
	mode := fs.String("mode", "nat", "nat or routed")
	metric := fs.Uint("metric", 0, "route metric")
	validFor := fs.Duration("valid-for", 0, "optional advertisement lifetime")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if *family != "dual" && *family != "ipv4" && *family != "ipv6" {
		return errors.New("--family must be dual, ipv4, or ipv6")
	}
	if *mode != "nat" && *mode != "routed" {
		return errors.New("--mode must be nat or routed")
	}
	if *metric > uint(^uint32(0)) || *validFor < 0 {
		return errors.New("invalid --metric or --valid-for")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Mode != config.ModeNode || !cfg.Exit.Serve {
		return errors.New("exit enable requires node mode with exit.serve=true")
	}
	// The normal command uses the same authenticated controller settings as
	// lanewayd. Explicit connection flags remain useful for controlled
	// migrations and override their config-file counterparts.
	if !flagProvided(args, "controller") {
		*remote.endpoint = cfg.Controller.Endpoint
	}
	if !flagProvided(args, "ca") {
		*remote.ca = cfg.TLS.CAFile
	}
	if !flagProvided(args, "server-name") {
		*remote.serverName = cfg.Controller.ServerName
	}
	if !flagProvided(args, "controller-network-id") {
		*remote.controllerNetwork = cfg.Controller.NetworkID
	}
	if !flagProvided(args, "controller-service-id") {
		*remote.controllerService = cfg.Controller.ServiceID
	}
	if !flagProvided(args, "cert") {
		*remote.cert = cfg.TLS.CertificateFile
	}
	if !flagProvided(args, "key") {
		*remote.key = cfg.TLS.PrivateKeyFile
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
	prefixes := []netip.Prefix(nil)
	if *family == "dual" || *family == "ipv4" {
		prefixes = append(prefixes, netip.MustParsePrefix("0.0.0.0/0"))
	}
	if *family == "dual" || *family == "ipv6" {
		prefixes = append(prefixes, netip.MustParsePrefix("::/0"))
	}
	ctx, cancel := commandContext()
	defer cancel()
	advertisements := make([]*controllerclient.Route, 0, len(prefixes))
	for _, prefix := range prefixes {
		advertisement, advertiseErr := client.AdvertiseRoute(ctx, prefix, "exit", *mode, uint32(*metric), validUntil)
		if advertiseErr != nil {
			return fmt.Errorf("advertise exit prefix %s after %d successful request(s): %w", prefix, len(advertisements), advertiseErr)
		}
		advertisements = append(advertisements, advertisement)
	}
	return printJSON(struct {
		Advertisements []*controllerclient.Route `json:"advertisements"`
		ApprovalNeeded bool                      `json:"approval_needed"`
	}{Advertisements: advertisements, ApprovalNeeded: true})
}

func flagProvided(args []string, name string) bool {
	long, short := "--"+name, "-"+name
	for _, arg := range args {
		if arg == long || arg == short || strings.HasPrefix(arg, long+"=") || strings.HasPrefix(arg, short+"=") {
			return true
		}
	}
	return false
}

func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "protected file containing the one-time enrollment token")
	bootstrapAuthority := fs.String("bootstrap", "", "public Web PKI discovery authority (for example lane.example.com)")
	endpoint := fs.String("controller", "", "controller HTTPS origin")
	caPath := fs.String("ca", "/etc/laneway/ca.crt", "controller CA certificate")
	serverName := fs.String("server-name", "", "optional controller DNS name")
	controllerNetwork := fs.String("controller-network-id", "", "expected controller certificate network ID")
	controllerService := fs.String("controller-service-id", "", "expected controller certificate service ID")
	name := fs.String("name", "", "requested node name")
	outCert := fs.String("out-cert", "/etc/laneway/node.crt", "output node certificate")
	outKey := fs.String("out-key", "/etc/laneway/node.key", "output node private key")
	outWireGuardKey := fs.String("out-wireguard-key", "/etc/laneway/wireguard.key", "output raw WireGuard private key")
	joinArgs := args
	token := ""
	tokenFromArg := false
	// The documented product spelling puts TOKEN before connection flags. The
	// standard flag package stops at the first positional argument, so extract
	// that leading selector while retaining flag-first compatibility.
	if len(joinArgs) != 0 && !strings.HasPrefix(joinArgs[0], "-") {
		token, joinArgs = joinArgs[0], joinArgs[1:]
		tokenFromArg = true
	}
	if err := fs.Parse(joinArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && token != "") {
		return errors.New("usage: laneway join TOKEN|--token-file PATH --controller https://host:port --name NAME [options]")
	}
	if fs.NArg() == 1 {
		token = fs.Arg(0)
		tokenFromArg = true
	}
	// A hostname in the documented leading position selects the safe discovery
	// flow. Enrollment tokens are base64url and therefore cannot contain a dot.
	if *bootstrapAuthority == "" && *endpoint == "" && strings.Contains(token, ".") {
		*bootstrapAuthority, token = token, ""
		tokenFromArg = false
	}
	if *tokenFile != "" {
		if token != "" {
			return errors.New("join accepts either TOKEN or --token-file, not both")
		}
		info, err := os.Stat(*tokenFile)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
			return errors.New("--token-file must be a nonempty regular file no larger than 4096 bytes")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("--token-file must not be accessible by group or other users")
		}
		contents, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read --token-file: %w", err)
		}
		token = strings.TrimSpace(string(contents))
		if token == "" || strings.ContainsAny(token, " \t\r\n") {
			return errors.New("--token-file contains an invalid enrollment token")
		}
	}
	var authenticatedCAPEM []byte
	if *bootstrapAuthority != "" {
		for _, advanced := range []string{"controller", "ca", "server-name", "controller-network-id", "controller-service-id"} {
			if flagProvided(args, advanced) {
				return fmt.Errorf("--%s cannot override authenticated bootstrap metadata", advanced)
			}
		}
		if tokenFromArg {
			return errors.New("bootstrap enrollment refuses a code in argv; use the prompt or --token-file")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		metadata, err := bootstrap.Fetch(ctx, *bootstrapAuthority)
		cancel()
		if err != nil {
			return err
		}
		if _, err := metadata.ArtifactForCurrentPlatform(); err != nil {
			return err
		}
		*endpoint = metadata.Controller.EnrollmentEndpoint
		*serverName = metadata.Controller.ServerName
		*controllerNetwork = metadata.NetworkID
		*controllerService = metadata.Controller.ServiceID
		authenticatedCAPEM = []byte(metadata.Trust.CAPEM)
		if *tokenFile == "" {
			token, err = promptEnrollmentCode("Enrollment code: ")
			if err != nil {
				return err
			}
		}
	}
	if token == "" || *endpoint == "" || (*name == "" && *bootstrapAuthority == "") {
		return errors.New("usage: laneway join lane.example.com [--token-file PATH], or laneway join TOKEN --controller https://host:port --name NAME [advanced options]")
	}
	if err := requireAbsentCredentialOutputs(*outCert, *outKey, *outWireGuardKey); err != nil {
		return err
	}
	expectedNetwork, err := identity.ParseNetworkID(*controllerNetwork)
	if err != nil {
		return fmt.Errorf("--controller-network-id: %w", err)
	}
	expectedService, err := identity.ParseID(*controllerService)
	if err != nil {
		return fmt.Errorf("--controller-service-id: %w", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate node key: %w", err)
	}
	wireGuardPrivateKey, wireGuardPublicKey, err := wireguard.GenerateKey()
	if err != nil {
		return err
	}
	csrName := *name
	if csrName == "" {
		csrName = "laneway-bootstrap-enrollment"
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: csrName}}, private)
	if err != nil {
		return fmt.Errorf("create enrollment CSR: %w", err)
	}
	trustedCAFile := *caPath
	if len(authenticatedCAPEM) != 0 {
		trustedCAFile = ""
	}
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: *endpoint, CAFile: trustedCAFile, CAPEM: authenticatedCAPEM, ServerName: *serverName,
		ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedService,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.EnrollForNetwork(ctx, token, *name, csrDER, wireGuardPublicKey.Bytes(), expectedNetwork)
	if err != nil {
		return err
	}
	if len(response.GetNetworkId()) != identity.IDSize || len(response.GetNodeId()) != identity.IDSize ||
		response.GetCertificateChain() == nil || len(response.GetCertificateChain().GetCertificatesDer()) == 0 || len(response.GetOverlayAddresses()) == 0 {
		return errors.New("controller returned an incomplete enrollment response")
	}
	overlays := make([]string, 0, len(response.GetOverlayAddresses()))
	for i, raw := range response.GetOverlayAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("controller returned invalid overlay address %d", i)
		}
		overlays = append(overlays, netip.PrefixFrom(address, address.BitLen()).String())
	}
	leaf, err := x509.ParseCertificate(response.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		return fmt.Errorf("parse issued node certificate: %w", err)
	}
	authenticated, err := identity.IdentityFromCertificate(leaf)
	if err != nil {
		return err
	}
	if !bytes.Equal(authenticated.NetworkID[:], response.GetNetworkId()) || !bytes.Equal(authenticated.NodeID[:], response.GetNodeId()) {
		return errors.New("issued certificate identity does not match enrollment response")
	}
	if authenticated.NetworkID != expectedNetwork {
		return errors.New("enrollment code belongs to a different network than authenticated bootstrap metadata")
	}
	if !wireGuardPublicKey.Equal(response.GetWireguardPublicKey()) {
		return errors.New("controller returned a different WireGuard public key than the locally generated key")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(public)
	gotPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(wantPublic, gotPublic) {
		return errors.New("issued certificate does not contain the locally generated public key")
	}
	var certificatePEM []byte
	for _, der := range response.GetCertificateChain().GetCertificatesDer() {
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("parse issued certificate chain: %w", err)
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := pki.PrivateKeyPEM(private)
	if err != nil {
		return err
	}
	if err := writeCredentialTriple(*outCert, certificatePEM, *outKey, privatePEM, *outWireGuardKey, wireGuardPrivateKey.Bytes()); err != nil {
		return err
	}
	fmt.Printf("enrolled network=%s node=%s overlay=%s certificate=%s\n", authenticated.NetworkID, authenticated.NodeID, strings.Join(overlays, ","), *outCert)
	return nil
}

func promptEnrollmentCode(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("open controlling terminal for enrollment code; use --token-file on non-interactive input")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	secret, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", fmt.Errorf("read enrollment code: %w", err)
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	value := strings.TrimSpace(string(secret))
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, " \t\r\n") {
		return "", errors.New("enrollment code is invalid")
	}
	return value, nil
}

func runRenew(args []string) error {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	endpoint := fs.String("controller", "", "controller HTTPS origin")
	quicEndpoint := fs.String("controller-quic", "", "controller mTLS QUIC host:port")
	allowLegacyHTTPS := fs.Bool("allow-legacy-controller-https", false, "explicitly allow legacy authenticated HTTPS renewal")
	caPath := fs.String("ca", "/etc/laneway/ca.crt", "controller CA certificate")
	serverName := fs.String("server-name", "", "optional controller DNS name")
	controllerNetwork := fs.String("controller-network-id", "", "expected controller certificate network ID")
	controllerService := fs.String("controller-service-id", "", "expected controller certificate service ID")
	currentCert := fs.String("cert", "/etc/laneway/node.crt", "current node certificate chain")
	currentKey := fs.String("key", "/etc/laneway/node.key", "current node private key")
	outCert := fs.String("out-cert", "/etc/laneway/node.next.crt", "new certificate output (must not be current path)")
	outKey := fs.String("out-key", "/etc/laneway/node.next.key", "new private key output (must not be current path)")
	outWireGuardKey := fs.String("out-wireguard-key", "/etc/laneway/wireguard.next.key", "new raw WireGuard private key output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *endpoint == "" || (*quicEndpoint == "" && !*allowLegacyHTTPS) {
		return errors.New("usage: laneway renew --controller https://host:port --controller-quic host:port [options]")
	}
	expectedNetwork, err := identity.ParseNetworkID(*controllerNetwork)
	if err != nil {
		return fmt.Errorf("--controller-network-id: %w", err)
	}
	expectedService, err := identity.ParseID(*controllerService)
	if err != nil {
		return fmt.Errorf("--controller-service-id: %w", err)
	}
	if filepath.Clean(*outCert) == filepath.Clean(*currentCert) || filepath.Clean(*outKey) == filepath.Clean(*currentKey) {
		return errors.New("renewal output paths must differ from the active certificate and key paths")
	}
	if err := requireAbsentCredentialOutputs(*outCert, *outKey, *outWireGuardKey); err != nil {
		return err
	}
	currentPEM, err := os.ReadFile(*currentCert)
	if err != nil {
		return fmt.Errorf("read current node certificate: %w", err)
	}
	currentLeaf, err := firstCertificatePEM(currentPEM)
	if err != nil {
		return fmt.Errorf("parse current node certificate: %w", err)
	}
	currentIdentity, err := identity.IdentityFromCertificate(currentLeaf)
	if err != nil {
		return fmt.Errorf("current node certificate identity: %w", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate renewal key: %w", err)
	}
	wireGuardPrivateKey, wireGuardPublicKey, err := wireguard.GenerateKey()
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: currentLeaf.Subject}, private)
	if err != nil {
		return fmt.Errorf("create renewal CSR: %w", err)
	}
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: *endpoint, QUICEndpoint: *quicEndpoint, CAFile: *caPath, ServerName: *serverName,
		CertificateFile: *currentCert, PrivateKeyFile: *currentKey,
		ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedService,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	response, err := client.Renew(ctx, csrDER, wireGuardPublicKey.Bytes())
	if err != nil {
		return err
	}
	if response.GetCertificateChain() == nil || len(response.GetCertificateChain().GetCertificatesDer()) == 0 {
		return errors.New("controller returned an incomplete renewal response")
	}
	issuedLeaf, err := x509.ParseCertificate(response.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		return fmt.Errorf("parse renewed node certificate: %w", err)
	}
	issuedIdentity, err := identity.IdentityFromCertificate(issuedLeaf)
	if err != nil {
		return fmt.Errorf("renewed node certificate identity: %w", err)
	}
	if issuedIdentity != currentIdentity {
		return errors.New("renewed certificate changed the node identity")
	}
	if !wireGuardPublicKey.Equal(response.GetWireguardPublicKey()) {
		return errors.New("controller returned a different WireGuard public key than the locally generated renewal key")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(public)
	gotPublic, err := x509.MarshalPKIXPublicKey(issuedLeaf.PublicKey)
	if err != nil || !bytes.Equal(wantPublic, gotPublic) {
		return errors.New("renewed certificate does not contain the locally generated public key")
	}
	var certificatePEM []byte
	for _, der := range response.GetCertificateChain().GetCertificatesDer() {
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("parse renewed certificate chain: %w", err)
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := pki.PrivateKeyPEM(private)
	if err != nil {
		return err
	}
	if err := writeCredentialTriple(*outCert, certificatePEM, *outKey, privatePEM, *outWireGuardKey, wireGuardPrivateKey.Bytes()); err != nil {
		return err
	}
	fmt.Printf("renewed network=%s node=%s certificate=%s\n", issuedIdentity.NetworkID, issuedIdentity.NodeID, *outCert)
	return nil
}

func firstCertificatePEM(contents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("expected a PEM CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func runLocal(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", "/etc/laneway/laneway.toml", "configuration file")
	socket := fs.String("socket", "", "local daemon Unix socket (bypasses configuration loading)")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: laneway %s [-config path | -socket path] [-json]", command)
	}
	socketPath, err := localSocketPath(*path, *socket)
	if err != nil {
		return err
	}
	client, err := localapi.NewClient(socketPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch command {
	case "up", "status":
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(status)
		}
		actor := status.Actor
		if actor == "" {
			actor = "node"
		}
		fmt.Printf("actor=%s node=%s name=%s network=%s overlay=%s interface=%s mtu=%d relay=%s running=%t\n",
			actor, status.NodeID, status.Name, status.NetworkID, strings.Join(status.OverlayAddresses, ","), status.Interface, status.MTU, status.Relay, status.Running)
		fmt.Printf("version=%s control=%s packet=%d capabilities=%s path=%s\n",
			status.ProductVersion, status.ControlVersion, status.PacketVersion, status.Capabilities, status.SelectedPath)
		fmt.Printf("selected_routes=%s\n", strings.Join(status.SelectedRoutes, ","))
		fmt.Printf("connections=%d reconnects=%d sent=%d received=%d dropped=%d\n",
			status.Metrics.Connections, status.Metrics.Reconnects, status.Metrics.PacketsSent,
			status.Metrics.PacketsReceived, status.Metrics.PacketsDropped)
		fmt.Printf("tcp_connections=%d quic_failures=%d tcp_failures=%d\n",
			status.Metrics.TCPConnections, status.Metrics.QUICFailures, status.Metrics.TCPFailures)
		if status.Controller.CertificateNotAfterUnixSeconds != 0 || status.Controller.IdentityLeaseExpiresAtUnixSeconds != 0 || status.Controller.ConfigurationLeaseValidUntilUnixSeconds != 0 {
			fmt.Printf("controller_candidate_exchange=%t configuration_lease_valid_until=%d configuration_lease_expired=%t certificate_renewal_needed=%t certificate_renew_after=%d certificate_not_after=%d identity_lease_expires_at=%d\n",
				status.Controller.CandidateExchangeEnabled, status.Controller.ConfigurationLeaseValidUntilUnixSeconds,
				status.Controller.ConfigurationLeaseExpired, status.Controller.CertificateRenewalNeeded,
				status.Controller.CertificateRenewAfterUnixSeconds,
				status.Controller.CertificateNotAfterUnixSeconds,
				status.Controller.IdentityLeaseExpiresAtUnixSeconds)
		}
		if status.Exit.Enabled || status.Exit.Serving {
			fmt.Printf("exit=%s authorized=%t serving=%t forwarding_ready=%t nat_ready=%t forwarded_packets=%d namespace_cleanup_failures=%d\n",
				status.Exit.SelectedNodeID, status.Exit.Authorized, status.Exit.Serving,
				status.Exit.ForwardingReady, status.Exit.NATReady, status.Exit.ForwardedPackets,
				status.Exit.NamespaceCleanupFailures)
		}
	case "peers":
		peers, err := client.Peers(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(peers)
		}
		for _, peer := range peers {
			if peer.Name != "" {
				fmt.Printf("%s\t%s\t%s\t%s\n", peer.Name, peer.NodeID, peer.Path, strings.Join(peer.Prefixes, ","))
			} else {
				fmt.Printf("%s\t%s\t%s\n", peer.NodeID, peer.Path, strings.Join(peer.Prefixes, ","))
			}
		}
	case "routes":
		routes, err := client.Routes(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(routes)
		}
		for _, route := range routes {
			fmt.Printf("%s\tvia %s\t%s\n", route.Prefix, route.ViaNode, route.Kind)
		}
	}
	return nil
}

func localSocketPath(configPath, override string) (string, error) {
	if override != "" {
		return override, nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", err
	}
	return cfg.SocketPath, nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func runConfig(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: laneway config validate [-config path]")
	}
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	path := fs.String("config", "/etc/laneway/laneway.toml", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if _, err := config.Load(*path); err != nil {
		return err
	}
	fmt.Println("configuration is valid")
	return nil
}

func runPKI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: laneway pki <init|intermediate|verify-authority|node|relay|controller>")
	}
	switch args[0] {
	case "init":
		return pkiInit(args[1:])
	case "intermediate":
		return pkiIntermediate(args[1:])
	case "verify-authority":
		return pkiVerifyAuthority(args[1:])
	case "node":
		return pkiNode(args[1:])
	case "relay":
		return pkiRelay(args[1:])
	case "controller":
		return pkiController(args[1:])
	default:
		return fmt.Errorf("unknown pki command %q", args[0])
	}
}

func pkiVerifyAuthority(args []string) error {
	fs := flag.NewFlagSet("pki verify-authority", flag.ContinueOnError)
	rootPath := fs.String("root", "ca.crt", "offline root public certificate")
	issuerPath := fs.String("issuer", "intermediate-chain.crt", "issuer-first intermediate chain")
	keyPath := fs.String("key", "intermediate.key", "online intermediate private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: laneway pki verify-authority --root ca.crt --issuer intermediate-chain.crt --key intermediate.key")
	}
	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return fmt.Errorf("read offline root certificate: %w", err)
	}
	roots, err := pki.ParseCertificatesPEM(rootPEM)
	if err != nil || len(roots) != 1 {
		return errors.New("offline root file must contain exactly one certificate")
	}
	root := roots[0]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return errors.New("offline root certificate is not a self-signed CA")
	}
	issuerPEM, err := os.ReadFile(*issuerPath)
	if err != nil {
		return fmt.Errorf("read online issuer chain: %w", err)
	}
	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read online issuer key: %w", err)
	}
	issuer, _, chain, err := pki.ParseAuthorityBundle(issuerPEM, keyPEM)
	if err != nil {
		return err
	}
	if len(chain) < 2 || !chain[len(chain)-1].Equal(root) {
		return errors.New("online issuer chain is not anchored by the supplied offline root")
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	intermediatePool := x509.NewCertPool()
	for _, certificate := range chain[1 : len(chain)-1] {
		intermediatePool.AddCert(certificate)
	}
	if _, err := issuer.Verify(x509.VerifyOptions{
		Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verify online issuer: %w", err)
	}
	fmt.Println("online issuer key and chain are valid for the offline root")
	return nil
}

func pkiIntermediate(args []string) error {
	fs := flag.NewFlagSet("pki intermediate", flag.ContinueOnError)
	caCertPath, caKeyPath := caFlags(fs)
	name := fs.String("name", "Laneway Intermediate CA", "intermediate CA common name")
	outCert := fs.String("out-cert", "intermediate.crt", "output issuer certificate bundle")
	outKey := fs.String("out-key", "intermediate.key", "output issuer private key")
	validity := fs.Duration("validity", 5*365*24*time.Hour, "intermediate CA validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	parent, signer, parentChain, err := loadAuthorityBundle(*caCertPath, *caKeyPath)
	if err != nil {
		return err
	}
	material, _, err := pki.IssueIntermediate(parent, signer, *name, time.Now(), *validity)
	if err != nil {
		return err
	}
	certificate := pki.CertificatePEM(material.CertificateDER)
	for _, parentCertificate := range parentChain {
		certificate = append(certificate, pki.CertificatePEM(parentCertificate.Raw)...)
	}
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		return err
	}
	if err := writePair(*outCert, certificate, *outKey, key); err != nil {
		return err
	}
	fmt.Printf("created intermediate certificate bundle %s and private key %s\n", *outCert, *outKey)
	return nil
}

func pkiInit(args []string) error {
	fs := flag.NewFlagSet("pki init", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "output directory")
	name := fs.String("name", "Laneway Development CA", "CA common name")
	validity := fs.Duration("validity", 10*365*24*time.Hour, "CA validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	material, _, err := pki.NewAuthority(*name, time.Now(), *validity)
	if err != nil {
		return err
	}
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		return err
	}
	certPath := filepath.Join(*outDir, "ca.crt")
	keyPath := filepath.Join(*outDir, "ca.key")
	if err := writePair(certPath, pki.CertificatePEM(material.CertificateDER), keyPath, key); err != nil {
		return err
	}
	fmt.Printf("created CA certificate %s and private key %s\n", certPath, keyPath)
	return nil
}

func pkiNode(args []string) error {
	fs := flag.NewFlagSet("pki node", flag.ContinueOnError)
	caCertPath, caKeyPath := caFlags(fs)
	networkText := fs.String("network-id", "", "32-character NetworkID")
	nodeText := fs.String("node-id", "", "32-character NodeID")
	outCert := fs.String("out-cert", "node.crt", "output certificate")
	outKey := fs.String("out-key", "node.key", "output private key")
	validity := fs.Duration("validity", pki.DefaultLeafValidity, "certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("network ID: %w", err)
	}
	nodeID, err := identity.ParseNodeID(*nodeText)
	if err != nil {
		return fmt.Errorf("node ID: %w", err)
	}
	ca, signer, issuerChain, err := loadAuthorityBundle(*caCertPath, *caKeyPath)
	if err != nil {
		return err
	}
	material, _, err := pki.IssueNode(ca, signer, identity.NodeIdentity{NetworkID: networkID, NodeID: nodeID}, time.Now(), *validity)
	if err != nil {
		return err
	}
	return saveIssued(*outCert, *outKey, material, issuerChain)
}

func pkiRelay(args []string) error {
	return pkiService(args, pki.RoleRelay, "relay")
}

func pkiController(args []string) error {
	return pkiService(args, pki.RoleController, "controller")
}

func pkiService(args []string, role pki.ServiceRole, name string) error {
	fs := flag.NewFlagSet("pki "+name, flag.ContinueOnError)
	caCertPath, caKeyPath := caFlags(fs)
	networkText := fs.String("network-id", "", "32-character NetworkID")
	serviceText := fs.String("service-id", "", "32-character service ID")
	dnsText := fs.String("dns", "", "comma-separated service DNS names")
	ipText := fs.String("ip", "", "comma-separated service IP addresses")
	outCert := fs.String("out-cert", name+".crt", "output certificate")
	outKey := fs.String("out-key", name+".key", "output private key")
	validity := fs.Duration("validity", pki.DefaultLeafValidity, "certificate validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	networkID, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return fmt.Errorf("network ID: %w", err)
	}
	serviceID, err := identity.ParseID(*serviceText)
	if err != nil {
		return fmt.Errorf("service ID: %w", err)
	}
	dnsNames := splitNonempty(*dnsText)
	var ips []net.IP
	for _, value := range splitNonempty(*ipText) {
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("invalid IP address %q", value)
		}
		ips = append(ips, ip)
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		return errors.New("at least one --dns or --ip identity is required")
	}
	ca, signer, issuerChain, err := loadAuthorityBundle(*caCertPath, *caKeyPath)
	if err != nil {
		return err
	}
	material, _, err := pki.IssueService(ca, signer, pki.ServiceIdentity{
		NetworkID: networkID,
		ServiceID: serviceID,
		Role:      role,
	}, dnsNames, ips, time.Now(), *validity)
	if err != nil {
		return err
	}
	return saveIssued(*outCert, *outKey, material, issuerChain)
}

func caFlags(fs *flag.FlagSet) (*string, *string) {
	return fs.String("ca-cert", "ca.crt", "CA certificate"), fs.String("ca-key", "ca.key", "CA private key")
}

func loadAuthorityBundle(certPath, keyPath string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read CA private key: %w", err)
	}
	return pki.ParseAuthorityBundle(certificate, key)
}

func saveIssued(certPath, keyPath string, material pki.Material, issuerChain []*x509.Certificate) error {
	key, err := pki.PrivateKeyPEM(material.PrivateKey)
	if err != nil {
		return err
	}
	certificate := pki.CertificatePEM(material.CertificateDER)
	for _, der := range pki.IssuerChainDER(issuerChain) {
		certificate = append(certificate, pki.CertificatePEM(der)...)
	}
	if err := writePair(certPath, certificate, keyPath, key); err != nil {
		return err
	}
	fmt.Printf("created certificate %s and private key %s\n", certPath, keyPath)
	return nil
}

func writePair(certPath string, certificate []byte, keyPath string, key []byte) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return errors.New("certificate and key paths must differ")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	writtenKey, err := linkExclusive(keyPath, key, 0o600)
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	writtenCert, err := linkExclusive(certPath, certificate, 0o644)
	if err != nil {
		_ = os.Remove(writtenKey)
		return fmt.Errorf("write certificate: %w", err)
	}
	_ = writtenCert
	return nil
}

func writeCredentialTriple(certPath string, certificate []byte, keyPath string, key []byte, wireGuardKeyPath string, wireGuardKey []byte) error {
	cleanCert, cleanKey, cleanWireGuard := filepath.Clean(certPath), filepath.Clean(keyPath), filepath.Clean(wireGuardKeyPath)
	if cleanWireGuard == cleanCert || cleanWireGuard == cleanKey || len(wireGuardKey) != wireguard.KeySize {
		return errors.New("certificate, TLS key, and valid WireGuard key paths must be distinct")
	}
	if err := os.MkdirAll(filepath.Dir(wireGuardKeyPath), 0o700); err != nil {
		return err
	}
	writtenWireGuardKey, err := linkExclusive(wireGuardKeyPath, wireGuardKey, 0o600)
	if err != nil {
		return fmt.Errorf("write WireGuard private key: %w", err)
	}
	if err := writePair(certPath, certificate, keyPath, key); err != nil {
		_ = os.Remove(writtenWireGuardKey)
		return err
	}
	return nil
}

func requireAbsentCredentialOutputs(paths ...string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("credential output paths must be distinct")
		}
		seen[clean] = struct{}{}
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to replace existing credential output %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect credential output %s: %w", path, err)
		}
	}
	return nil
}

func linkExclusive(path string, data []byte, mode os.FileMode) (string, error) {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".laneway-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func splitNonempty(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
