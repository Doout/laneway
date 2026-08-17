package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nethelper"
	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/nodeapp"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/wireguard"
)

type connectEnrollment struct {
	identity                     identity.NodeIdentity
	certificatePEM               []byte
	privateKeyPEM                []byte
	overlays                     []netip.Prefix
	class                        lanewayv1.EnrollmentClass
	leaseExpiresAt               time.Time
	wireGuardPrivateKey          wireguard.PrivateKey
	ephemeralExitLeaseGeneration uint64
}

type runtimeCredentialFiles struct {
	files []*os.File
}

type connectPlatformOptions struct {
	exitSelector, failureMode string
	dns, localLAN             []string
}

func (f *runtimeCredentialFiles) add(directory, label string, contents []byte) (string, error) {
	file, err := os.CreateTemp(directory, "."+label+"-*")
	if err != nil {
		return "", err
	}
	f.files = append(f.files, file)
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(contents); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "", err
	}
	// Keep credential bytes reachable only through this process's open file
	// descriptors. A crash closes the descriptors and leaves no pathname.
	if err := os.Remove(file.Name()); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%d", credentialDescriptorDirectory, file.Fd()), nil
}

func (f *runtimeCredentialFiles) close() error {
	var result error
	for _, file := range f.files {
		result = errors.Join(result, file.Close())
	}
	f.files = nil
	return result
}

func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "protected file containing the one-time enrollment code")
	remembered := fs.Bool("remembered", false, "enroll and save a remembered-user login when none exists")
	ephemeral := fs.Bool("ephemeral", false, "use a one-time temporary session instead of the saved login")
	options := connectPlatformOptions{failureMode: "closed"}
	var routeValues []string
	fs.Func("route", "controller-authorized subnet prefix (repeatable)", func(value string) error {
		routeValues = append(routeValues, value)
		return nil
	})
	addPlatformConnectFlags(fs, &options)
	connectArgs := args
	authority := ""
	if len(connectArgs) != 0 && !strings.HasPrefix(connectArgs[0], "-") {
		authority, connectArgs = connectArgs[0], connectArgs[1:]
	}
	if err := fs.Parse(connectArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && authority != "") {
		return connectUsage()
	}
	if fs.NArg() == 1 {
		authority = fs.Arg(0)
	}
	if *remembered && *ephemeral {
		return connectUsage()
	}
	if authority == "" {
		var err error
		authority, err = defaultUserProfileAuthority()
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("no saved login; run 'laneway login DOMAIN' or specify DOMAIN for an ephemeral connection")
		}
		if err != nil {
			return err
		}
	}
	if options.failureMode != "closed" && options.failureMode != "open" {
		return errors.New("--failure-mode must be closed or open")
	}
	if options.exitSelector == "" && (len(options.dns) != 0 || len(options.localLAN) != 0 || flagProvided(args, "failure-mode")) {
		return errors.New("--dns, --local-lan, and --failure-mode require --exit")
	}
	if err := connectPlatformPreflight(); err != nil {
		return err
	}
	routes, err := parseConnectPrefixes(routeValues, false)
	if err != nil {
		return fmt.Errorf("--route: %w", err)
	}
	localLAN, err := parseConnectPrefixes(options.localLAN, false)
	if err != nil {
		return fmt.Errorf("--local-lan: %w", err)
	}
	dns, err := parseConnectAddresses(options.dns)
	if err != nil {
		return fmt.Errorf("--dns: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, 20*time.Second)
	metadata, err := bootstrap.Fetch(discoveryCtx, authority)
	cancelDiscovery()
	if err != nil {
		return err
	}
	if err := validatePlatformArtifact(metadata); err != nil {
		return err
	}
	runtimeDir, err := os.MkdirTemp("", "laneway-connect-*")
	if err != nil {
		return fmt.Errorf("create temporary runtime directory: %w", err)
	}
	defer os.RemoveAll(runtimeDir)
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		return err
	}
	credentials := new(runtimeCredentialFiles)
	defer credentials.close()
	var enrollment connectEnrollment
	var caPath, certPath, keyPath, wireGuardKeyPath string
	var savedProfile userProfile
	var savedProfileFiles userProfileFiles
	usingSavedLogin := !*ephemeral
	if *ephemeral {
		code, codeErr := connectEnrollmentCode(*tokenFile)
		if codeErr != nil {
			return codeErr
		}
		enrollmentCtx, cancelEnrollment := context.WithTimeout(ctx, 30*time.Second)
		enrollment, err = enrollForConnect(enrollmentCtx, metadata, code, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER)
		cancelEnrollment()
		code = ""
		if err != nil {
			return err
		}
		caPath, err = credentials.add(runtimeDir, "ca", []byte(metadata.Trust.CAPEM))
		if err == nil {
			certPath, err = credentials.add(runtimeDir, "certificate", enrollment.certificatePEM)
		}
		if err == nil {
			keyPath, err = credentials.add(runtimeDir, "private-key", enrollment.privateKeyPEM)
		}
		if err == nil {
			wireGuardKeyPath, err = credentials.add(runtimeDir, "wireguard-key", enrollment.wireGuardPrivateKey.Bytes())
		}
		if err != nil {
			return err
		}
	} else {
		profile, profileFiles, profileErr := loadUserProfile(authority)
		if errors.Is(profileErr, os.ErrNotExist) && *remembered {
			code, codeErr := connectEnrollmentCode(*tokenFile)
			if codeErr != nil {
				return codeErr
			}
			enrollmentCtx, cancelEnrollment := context.WithTimeout(ctx, 30*time.Second)
			rememberedEnrollment, enrollErr := enrollForConnect(enrollmentCtx, metadata, code, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER)
			cancelEnrollment()
			code = ""
			if enrollErr != nil {
				return enrollErr
			}
			profile = userProfile{Version: userProfileVersion, Authority: authority, NetworkID: metadata.NetworkID, ControllerServiceID: metadata.Controller.ServiceID, NodeID: rememberedEnrollment.identity.NodeID.String(), Name: "remembered-user", CreatedAt: time.Now().UTC()}
			if err := saveUserProfile(profile, []byte(metadata.Trust.CAPEM), rememberedEnrollment.certificatePEM, rememberedEnrollment.privateKeyPEM, rememberedEnrollment.wireGuardPrivateKey.Bytes()); err != nil {
				return err
			}
			profile, profileFiles, profileErr = loadUserProfile(authority)
		}
		if profileErr != nil {
			if errors.Is(profileErr, os.ErrNotExist) {
				return fmt.Errorf("no saved login for %s; run 'laneway login %s' or use --ephemeral", authority, authority)
			}
			return profileErr
		}
		if *tokenFile != "" {
			return errors.New("--token-file is only used by login, --remembered enrollment, or --ephemeral sessions")
		}
		if err := validateProfileMetadata(profile, profileFiles, metadata); err != nil {
			return err
		}
		due, _, err := profileRenewalDue(profileFiles.certificate, time.Now())
		if err != nil {
			return err
		}
		if due {
			renewCtx, cancelRenew := context.WithTimeout(ctx, 30*time.Second)
			profile, profileFiles, err = renewUserProfile(renewCtx, profile, profileFiles, metadata)
			cancelRenew()
			if err != nil {
				return err
			}
			fmt.Printf("laneway refreshed saved login network=%s node=%s\n", profile.NetworkID, profile.NodeID)
		}
		networkID, _ := identity.ParseNetworkID(profile.NetworkID)
		nodeID, _ := identity.ParseNodeID(profile.NodeID)
		enrollment.identity = identity.NodeIdentity{NetworkID: networkID, NodeID: nodeID}
		enrollment.class = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER
		caPath, certPath, keyPath, wireGuardKeyPath = profileFiles.ca, profileFiles.certificate, profileFiles.privateKey, profileFiles.wireGuardKey
		savedProfile, savedProfileFiles = profile, profileFiles
	}
	expectedNetwork, _ := identity.ParseNetworkID(metadata.NetworkID)
	expectedController, _ := identity.ParseID(metadata.Controller.ServiceID)
	configurationClient, err := controllerclient.New(controllerclient.Options{
		Endpoint: metadata.Controller.EnrollmentEndpoint, QUICEndpoint: metadata.Controller.QUICEndpoint,
		CAFile: caPath, CertificateFile: certPath, PrivateKeyFile: keyPath, ServerName: metadata.Controller.ServerName,
		ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedController,
	})
	if err != nil {
		return err
	}
	configurationCtx, cancelConfiguration := context.WithTimeout(ctx, 20*time.Second)
	initial, _, err := configurationClient.Configuration(configurationCtx, 0)
	cancelConfiguration()
	if err != nil {
		return fmt.Errorf("fetch temporary session configuration: %w", err)
	}
	name := connectLocalName(initial, enrollment.identity.NodeID)
	selectedExit, err := resolveConnectExit(initial, options.exitSelector, enrollment.identity.NodeID)
	if err != nil {
		return err
	}
	filter := connectConfigurationFilter(routes, selectedExit, enrollment.identity.NodeID)
	if usingSavedLogin && len(routes) == 0 {
		filter = connectAuthorizedConfigurationFilter(selectedExit, enrollment.identity.NodeID)
	}
	filteredInitial, err := filter(initial)
	if err != nil {
		return err
	}
	cfg, err := connectConfig(runtimeDir, metadata, name, caPath, certPath, keyPath, wireGuardKeyPath, selectedExit, options.failureMode, dns, localLAN)
	if err != nil {
		return err
	}
	selection := "overlay-only"
	if usingSavedLogin && len(routes) == 0 {
		selection = "authorized-private-routes"
	}
	if len(routes) != 0 {
		values := make([]string, 0, len(routes))
		for _, prefix := range routes {
			values = append(values, prefix.String())
		}
		selection = "routes=" + strings.Join(values, ",")
	}
	if !selectedExit.IsZero() {
		selection = "exit=" + options.exitSelector + " failure-mode=" + options.failureMode
	}
	lastPath := ""
	ownedRoutes := connectPrefixList(routes)
	if usingSavedLogin && len(routes) == 0 {
		ownedRoutes = connectPrefixList(connectSubnetPrefixes(filteredInitial))
	}
	bypasses := connectPrefixList(localLAN)
	dnsOwnership := "native"
	if len(dns) != 0 {
		dnsOwnership = "temporary-session"
	}
	status := func(value nodeapp.RuntimeStatus) {
		if value.Path == lastPath {
			return
		}
		lastPath = value.Path
		overlays := make([]string, 0, len(value.OverlayAddresses))
		for _, prefix := range value.OverlayAddresses {
			overlays = append(overlays, prefix.String())
		}
		lease := "durable"
		if !enrollment.leaseExpiresAt.IsZero() {
			lease = fmt.Sprint(enrollment.leaseExpiresAt.Unix())
		}
		fmt.Printf("laneway connected actor=user network=%s node=%s name=%s overlay=%s identity_lease_expires_at=%s interface=%s selection=%s owned_routes=%s bypasses=%s dns_owner=%s cleanup_journal=helper-active path=%s\n",
			value.NetworkID, value.NodeID, name, strings.Join(overlays, ","), lease, value.Interface,
			selection, ownedRoutes, bypasses, dnsOwnership, value.Path)
	}
	for {
		sessionCtx := ctx
		cancelSession := func() {}
		if usingSavedLogin {
			_, renewAt, renewalErr := profileRenewalDue(savedProfileFiles.certificate, time.Now())
			if renewalErr != nil {
				return renewalErr
			}
			sessionCtx, cancelSession = context.WithDeadline(ctx, renewAt)
		}
		err = nodeapp.RunForeground(sessionCtx, cfg, nodeapp.ForegroundOptions{
			NetworkOpener: helperNetworkOpener, Status: status, FilterConfiguration: filter,
		})
		cancelSession()
		if err != nil {
			return err
		}
		if ctx.Err() != nil || !usingSavedLogin {
			fmt.Println("laneway disconnected; temporary networking restored")
			return nil
		}
		// The foreground runtime has restored its temporary routes before key
		// rotation. Refresh discovery, rotate the saved credential atomically,
		// and reconnect without asking for another token.
		discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, 20*time.Second)
		metadata, err = bootstrap.Fetch(discoveryCtx, authority)
		cancelDiscovery()
		if err != nil {
			return fmt.Errorf("refresh discovery before login renewal: %w", err)
		}
		if err := validateProfileMetadata(savedProfile, savedProfileFiles, metadata); err != nil {
			return err
		}
		renewCtx, cancelRenew := context.WithTimeout(ctx, 30*time.Second)
		savedProfile, savedProfileFiles, err = renewUserProfile(renewCtx, savedProfile, savedProfileFiles, metadata)
		cancelRenew()
		if err != nil {
			return err
		}
		caPath, certPath, keyPath, wireGuardKeyPath = savedProfileFiles.ca, savedProfileFiles.certificate, savedProfileFiles.privateKey, savedProfileFiles.wireGuardKey
		cfg, err = connectConfig(runtimeDir, metadata, name, caPath, certPath, keyPath, wireGuardKeyPath, selectedExit, options.failureMode, dns, localLAN)
		if err != nil {
			return err
		}
		lastPath = ""
		fmt.Printf("laneway refreshed saved login network=%s node=%s; reconnecting authorized routes\n", savedProfile.NetworkID, savedProfile.NodeID)
	}
}

func connectPrefixList(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "none"
	}
	values := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		values = append(values, prefix.String())
	}
	return strings.Join(values, ",")
}

func connectEnrollmentCode(path string) (string, error) {
	if path == "" {
		return promptEnrollmentCode("Enrollment code: ")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("--token-file must be a nonempty mode-0600 regular file no larger than 4096 bytes")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read --token-file: %w", err)
	}
	value := strings.TrimSpace(string(contents))
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", errors.New("--token-file contains an invalid enrollment code")
	}
	return value, nil
}

func enrollForConnect(ctx context.Context, metadata bootstrap.Metadata, code string, expectedClass lanewayv1.EnrollmentClass) (connectEnrollment, error) {
	expectedNetwork, err := identity.ParseNetworkID(metadata.NetworkID)
	if err != nil {
		return connectEnrollment{}, err
	}
	expectedService, err := identity.ParseID(metadata.Controller.ServiceID)
	if err != nil {
		return connectEnrollment{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return connectEnrollment{}, err
	}
	wireGuardPrivateKey, wireGuardPublicKey, err := wireguard.GenerateKey()
	if err != nil {
		return connectEnrollment{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "laneway-temporary-user"}}, private)
	if err != nil {
		return connectEnrollment{}, err
	}
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: metadata.Controller.EnrollmentEndpoint, CAPEM: []byte(metadata.Trust.CAPEM), ServerName: metadata.Controller.ServerName,
		ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedService,
	})
	if err != nil {
		return connectEnrollment{}, err
	}
	response, err := client.EnrollForNetworkAndClass(ctx, code, "", csrDER, wireGuardPublicKey.Bytes(), expectedNetwork, expectedClass)
	if err != nil {
		return connectEnrollment{}, err
	}
	if len(response.GetNetworkId()) != identity.IDSize || len(response.GetNodeId()) != identity.IDSize || response.GetCertificateChain() == nil ||
		len(response.GetCertificateChain().GetCertificatesDer()) == 0 || len(response.GetOverlayAddresses()) == 0 || response.GetEnrollmentClass() != expectedClass {
		return connectEnrollment{}, errors.New("controller returned an incomplete or class-mismatched enrollment response")
	}
	leaf, err := x509.ParseCertificate(response.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		return connectEnrollment{}, err
	}
	authenticated, err := identity.IdentityFromCertificate(leaf)
	if err != nil {
		return connectEnrollment{}, err
	}
	if authenticated.NetworkID != expectedNetwork || !bytes.Equal(authenticated.NetworkID[:], response.GetNetworkId()) || !bytes.Equal(authenticated.NodeID[:], response.GetNodeId()) {
		return connectEnrollment{}, errors.New("issued certificate identity does not match authenticated bootstrap and enrollment response")
	}
	if !wireGuardPublicKey.Equal(response.GetWireguardPublicKey()) {
		return connectEnrollment{}, errors.New("controller returned a different WireGuard public key than the locally generated key")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(public)
	gotPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(wantPublic, gotPublic) {
		return connectEnrollment{}, errors.New("issued certificate does not contain the locally generated public key")
	}
	overlays := make([]netip.Prefix, 0, len(response.GetOverlayAddresses()))
	for i, raw := range response.GetOverlayAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return connectEnrollment{}, fmt.Errorf("controller returned invalid overlay address %d", i)
		}
		overlays = append(overlays, netip.PrefixFrom(address, address.BitLen()))
	}
	var certificatePEM []byte
	for _, der := range response.GetCertificateChain().GetCertificatesDer() {
		if _, err := x509.ParseCertificate(der); err != nil {
			return connectEnrollment{}, err
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := pki.PrivateKeyPEM(private)
	if err != nil {
		return connectEnrollment{}, err
	}
	var lease time.Time
	if expectedClass == lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER {
		seconds := response.GetLeaseExpiresAtUnixSeconds()
		if seconds == 0 || seconds > uint64(1<<63-1) {
			return connectEnrollment{}, errors.New("ephemeral enrollment response has no bounded lease")
		}
		lease = time.Unix(int64(seconds), 0).UTC()
		if !lease.After(time.Now()) || leaf.NotAfter.After(lease) {
			return connectEnrollment{}, errors.New("ephemeral certificate exceeds or outlives its session lease")
		}
	} else if response.GetLeaseExpiresAtUnixSeconds() != 0 {
		return connectEnrollment{}, errors.New("remembered enrollment response unexpectedly contains an ephemeral lease")
	}
	return connectEnrollment{identity: authenticated, certificatePEM: certificatePEM, privateKeyPEM: privatePEM, overlays: overlays, class: expectedClass, leaseExpiresAt: lease, wireGuardPrivateKey: wireGuardPrivateKey}, nil
}

func connectConfig(runtimeDir string, metadata bootstrap.Metadata, name, caPath, certPath, keyPath, wireGuardKeyPath string, selectedExit identity.NodeID,
	failureMode string, dns []netip.Addr, localLAN []netip.Prefix,
) (config.Config, error) {
	if len(metadata.Relays) == 0 {
		return config.Config{}, errors.New("bootstrap metadata contains no relay")
	}
	cfg := config.Defaults()
	cfg.Mode = config.ModeNode
	cfg.StateDir = filepath.Join(runtimeDir, "state")
	cfg.SocketPath = filepath.Join(runtimeDir, "laneway.sock")
	cfg.TLS = config.TLS{CertificateFile: certPath, PrivateKeyFile: keyPath, CAFile: caPath}
	cfg.WireGuard = config.WireGuard{PrivateKeyFile: wireGuardKeyPath, InterfaceName: "lane0", MTU: 1280}
	cfg.Node.Name = name
	cfg.Node.RelayAddress = metadata.Relays[0].Endpoint
	cfg.Node.RelayNetworkID = metadata.NetworkID
	cfg.Node.RelayServiceID = metadata.Relays[0].ServiceID
	cfg.Controller.Endpoint = metadata.Controller.EnrollmentEndpoint
	cfg.Controller.QUICEndpoint = metadata.Controller.QUICEndpoint
	cfg.Controller.ServerName = metadata.Controller.ServerName
	cfg.Controller.NetworkID = metadata.NetworkID
	cfg.Controller.ServiceID = metadata.Controller.ServiceID
	cfg.Controller.PollInterval = config.Duration(5 * time.Second)
	cfg.Direct.Enabled = true
	cfg.Direct.Listen = ":0"
	if !selectedExit.IsZero() {
		cfg.Exit.Enabled = true
		cfg.Exit.SelectedNodeID = selectedExit.String()
		cfg.Exit.FailureMode = failureMode
		for _, address := range dns {
			cfg.Exit.DNSServers = append(cfg.Exit.DNSServers, address.String())
		}
		for _, prefix := range localLAN {
			cfg.Exit.LocalLANBypasses = append(cfg.Exit.LocalLANBypasses, prefix.String())
		}
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func helperNetworkOpener(ctx context.Context, tunConfig platform.TUNConfig, routes platform.RoutePlan) (nodeapp.HostNetwork, error) {
	setup := nethelper.Setup{Name: tunConfig.Name, MTU: tunConfig.MTU}
	for _, address := range tunConfig.Addresses {
		setup.Addresses = append(setup.Addresses, address.String())
	}
	for _, route := range routes.Routes {
		setup.Routes.Routes = append(setup.Routes.Routes, nethelper.Route{Prefix: route.Prefix.String(), Metric: route.Metric})
	}
	for _, bypass := range routes.TransportBypass {
		setup.Routes.Bypasses = append(setup.Routes.Bypasses, bypass.String())
	}
	options := platformNetworkHelperOptions()
	session, err := nethelper.Start(ctx, setup, options)
	if err != nil {
		return nodeapp.HostNetwork{}, err
	}
	return nodeapp.HostNetwork{
		TUN: session.TUN, Routes: session.RouteManager(), ExitRoutes: session.ExitRouteManager(), DNS: session.DNSManager(), Close: session.Close,
	}, nil
}

func parseConnectPrefixes(values []string, allowDefault bool) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || netvalidate.RoutablePrefix(prefix, allowDefault) != nil {
			return nil, fmt.Errorf("%q is not a canonical routable prefix", value)
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
}

func parseConnectAddresses(values []string) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{}, len(values))
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("%q is not a unicast IP address", value)
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result, nil
}

func connectLocalName(configuration *lanewayv1.NodeConfiguration, local identity.NodeID) string {
	for _, peer := range configuration.GetPeers() {
		if bytes.Equal(peer.GetNodeId(), local[:]) {
			return peer.GetName()
		}
	}
	return "temporary-user"
}

func resolveConnectExit(configuration *lanewayv1.NodeConfiguration, selector string, local identity.NodeID) (identity.NodeID, error) {
	if selector == "" {
		return identity.NodeID{}, nil
	}
	selected, parseErr := identity.ParseNodeID(selector)
	if parseErr != nil {
		for _, peer := range configuration.GetPeers() {
			if peer.GetName() != selector || len(peer.GetNodeId()) != identity.IDSize {
				continue
			}
			if !selected.IsZero() {
				return identity.NodeID{}, fmt.Errorf("exit name %q is ambiguous", selector)
			}
			copy(selected[:], peer.GetNodeId())
		}
	}
	if selected.IsZero() || selected == local {
		return identity.NodeID{}, fmt.Errorf("exit %q does not identify a different controller peer", selector)
	}
	authorized := false
	for _, raw := range configuration.GetExitPolicy().GetAuthorizedNodeIds() {
		authorized = authorized || bytes.Equal(raw, selected[:])
	}
	if !authorized {
		return identity.NodeID{}, fmt.Errorf("exit %q is not controller-authorized", selector)
	}
	for _, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_EXIT && bytes.Equal(route.GetViaNodeId(), selected[:]) {
			return selected, nil
		}
	}
	return identity.NodeID{}, fmt.Errorf("exit %q has no approved exit route", selector)
}

func connectConfigurationFilter(requested []netip.Prefix, selectedExit, local identity.NodeID) func(*lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error) {
	wanted := make(map[netip.Prefix]struct{}, len(requested))
	for _, prefix := range requested {
		wanted[prefix] = struct{}{}
	}
	return func(configuration *lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error) {
		if configuration == nil || configuration.GetRoutes() == nil {
			return nil, errors.New("controller configuration is incomplete")
		}
		filtered := proto.Clone(configuration).(*lanewayv1.NodeConfiguration)
		kept := filtered.Routes.Routes[:0]
		seen := make(map[netip.Prefix]struct{}, len(wanted))
		exitRoute := false
		for _, route := range filtered.Routes.Routes {
			switch route.GetKind() {
			case lanewayv1.RouteKind_ROUTE_KIND_OVERLAY:
				kept = append(kept, route)
			case lanewayv1.RouteKind_ROUTE_KIND_SUBNET:
				prefix, err := connectProtoPrefix(route.GetDestination())
				if err != nil {
					return nil, err
				}
				if _, ok := wanted[prefix]; ok && !bytes.Equal(route.GetViaNodeId(), local[:]) {
					kept = append(kept, route)
					seen[prefix] = struct{}{}
				}
			case lanewayv1.RouteKind_ROUTE_KIND_EXIT:
				if !selectedExit.IsZero() && bytes.Equal(route.GetViaNodeId(), selectedExit[:]) {
					kept = append(kept, route)
					exitRoute = true
				}
			}
		}
		filtered.Routes.Routes = kept
		for prefix := range wanted {
			if _, ok := seen[prefix]; !ok {
				return nil, fmt.Errorf("requested route %s is no longer controller-authorized", prefix)
			}
		}
		if !selectedExit.IsZero() {
			if !exitRoute {
				return nil, errors.New("selected exit is no longer controller-authorized")
			}
			authorized := false
			for _, raw := range configuration.GetExitPolicy().GetAuthorizedNodeIds() {
				authorized = authorized || bytes.Equal(raw, selectedExit[:])
			}
			if !authorized {
				return nil, errors.New("selected exit was withdrawn from controller exit policy")
			}
			if filtered.ExitPolicy == nil {
				filtered.ExitPolicy = new(lanewayv1.ExitNodePolicy)
			}
			filtered.ExitPolicy.AuthorizedNodeIds = [][]byte{append([]byte(nil), selectedExit[:]...)}
		} else if filtered.ExitPolicy != nil {
			filtered.ExitPolicy.AuthorizedNodeIds = nil
		}
		return filtered, nil
	}
}

// connectAuthorizedConfigurationFilter derives split routes from ACCEPT rules
// that can apply to this remembered user. The complete policy remains in the
// snapshot and is still enforced packet-by-packet; this only limits which
// private prefixes the host sends to Laneway. Default routes remain exclusive
// to an explicit, controller-authorized --exit selection.
func connectAuthorizedConfigurationFilter(selectedExit, local identity.NodeID) func(*lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error) {
	return func(configuration *lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error) {
		if configuration == nil || configuration.GetRoutes() == nil || configuration.GetPolicy() == nil {
			return nil, errors.New("controller configuration is incomplete")
		}
		filtered := proto.Clone(configuration).(*lanewayv1.NodeConfiguration)
		kept := filtered.Routes.Routes[:0]
		seen := make(map[string]struct{})
		exitRoute := false
		for _, route := range filtered.Routes.Routes {
			switch route.GetKind() {
			case lanewayv1.RouteKind_ROUTE_KIND_OVERLAY:
				kept = append(kept, route)
			case lanewayv1.RouteKind_ROUTE_KIND_SUBNET:
				routePrefix, err := connectProtoPrefix(route.GetDestination())
				if err != nil {
					return nil, err
				}
				if routePrefix.Bits() == 0 || bytes.Equal(route.GetViaNodeId(), local[:]) {
					continue
				}
				for _, prefix := range connectAuthorizedRoutePrefixes(configuration, route, routePrefix, local) {
					key := prefix.String() + "\x00" + string(route.GetViaNodeId())
					if _, duplicate := seen[key]; duplicate {
						continue
					}
					seen[key] = struct{}{}
					copyRoute := proto.Clone(route).(*lanewayv1.Route)
					copyRoute.Destination = &lanewayv1.IpPrefix{Address: append([]byte(nil), prefix.Addr().AsSlice()...), PrefixLength: uint32(prefix.Bits())}
					kept = append(kept, copyRoute)
				}
			case lanewayv1.RouteKind_ROUTE_KIND_EXIT:
				if !selectedExit.IsZero() && bytes.Equal(route.GetViaNodeId(), selectedExit[:]) {
					kept = append(kept, route)
					exitRoute = true
				}
			}
		}
		filtered.Routes.Routes = kept
		if !selectedExit.IsZero() {
			if !exitRoute {
				return nil, errors.New("selected exit is no longer controller-authorized")
			}
			authorized := false
			for _, raw := range configuration.GetExitPolicy().GetAuthorizedNodeIds() {
				authorized = authorized || bytes.Equal(raw, selectedExit[:])
			}
			if !authorized {
				return nil, errors.New("selected exit was withdrawn from controller exit policy")
			}
			if filtered.ExitPolicy == nil {
				filtered.ExitPolicy = new(lanewayv1.ExitNodePolicy)
			}
			filtered.ExitPolicy.AuthorizedNodeIds = [][]byte{append([]byte(nil), selectedExit[:]...)}
		} else if filtered.ExitPolicy != nil {
			filtered.ExitPolicy.AuthorizedNodeIds = nil
		}
		return filtered, nil
	}
}

func connectAuthorizedRoutePrefixes(configuration *lanewayv1.NodeConfiguration, route *lanewayv1.Route, routePrefix netip.Prefix, local identity.NodeID) []netip.Prefix {
	var result []netip.Prefix
	for _, rule := range configuration.GetPolicy().GetRules() {
		if rule.GetAction() != lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT || !connectSourceMatches(rule.GetSelector(), configuration.GetOverlayAddresses(), local) {
			continue
		}
		selector := rule.GetSelector()
		if len(selector.GetDestinationNodeIds()) != 0 && !connectIDListContains(selector.GetDestinationNodeIds(), route.GetViaNodeId()) {
			continue
		}
		if len(selector.GetDestinationPrefixes()) == 0 {
			result = append(result, routePrefix)
			continue
		}
		for _, raw := range selector.GetDestinationPrefixes() {
			prefix, err := connectProtoPrefix(raw)
			if err != nil || prefix.Bits() == 0 || prefix.Addr().BitLen() != routePrefix.Addr().BitLen() {
				continue
			}
			switch {
			case routePrefix.Contains(prefix.Addr()) && prefix.Bits() >= routePrefix.Bits():
				result = append(result, prefix)
			case prefix.Contains(routePrefix.Addr()) && routePrefix.Bits() >= prefix.Bits():
				result = append(result, routePrefix)
			}
		}
	}
	return result
}

func connectSourceMatches(selector *lanewayv1.TrafficSelector, overlays [][]byte, local identity.NodeID) bool {
	if selector == nil {
		return false
	}
	if len(selector.GetSourceNodeIds()) != 0 && !connectIDListContains(selector.GetSourceNodeIds(), local[:]) {
		return false
	}
	if len(selector.GetSourcePrefixes()) == 0 {
		return true
	}
	for _, rawPrefix := range selector.GetSourcePrefixes() {
		prefix, err := connectProtoPrefix(rawPrefix)
		if err != nil {
			continue
		}
		for _, rawAddress := range overlays {
			if address, ok := netip.AddrFromSlice(rawAddress); ok && !address.Is4In6() && prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func connectIDListContains(values [][]byte, wanted []byte) bool {
	for _, value := range values {
		if bytes.Equal(value, wanted) {
			return true
		}
	}
	return false
}

func connectSubnetPrefixes(configuration *lanewayv1.NodeConfiguration) []netip.Prefix {
	var result []netip.Prefix
	for _, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_SUBNET {
			continue
		}
		if prefix, err := connectProtoPrefix(route.GetDestination()); err == nil {
			result = append(result, prefix)
		}
	}
	return result
}

func connectProtoPrefix(value *lanewayv1.IpPrefix) (netip.Prefix, error) {
	if value == nil {
		return netip.Prefix{}, errors.New("controller route has no destination")
	}
	address, ok := netip.AddrFromSlice(value.GetAddress())
	if !ok || address.Is4In6() || value.GetPrefixLength() > uint32(address.BitLen()) {
		return netip.Prefix{}, errors.New("controller route has an invalid destination")
	}
	prefix := netip.PrefixFrom(address, int(value.GetPrefixLength()))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("controller route has a noncanonical destination")
	}
	return prefix, nil
}
