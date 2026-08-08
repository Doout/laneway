package nodeapp

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/dataplane"
	"laneway.dev/laneway/internal/directpath"
	"laneway.dev/laneway/internal/endpointpin"
	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/localapi"
	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/nodeservice"
	"laneway.dev/laneway/internal/observability"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/policy"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/revocation"
	"laneway.dev/laneway/internal/routing"
	"laneway.dev/laneway/internal/subnet"
	"laneway.dev/laneway/internal/tcpfallback"
	"laneway.dev/laneway/internal/transport"
	"laneway.dev/laneway/internal/wireguard"
)

const (
	defaultLaneMTU = 1200
)

var productVersion = buildinfo.Version

// Run executes the persistent host-node service. It is shared by the unified
// `laneway node run` command and the legacy `lanewayd` compatibility wrapper.
// It never calls os.Exit, so callers retain control of exit-code policy.
func Run(args []string) error {
	fs := flag.NewFlagSet("laneway node run", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/laneway/laneway.toml", "configuration file")
	diagnostics := fs.String("diagnostics", "", "loopback metrics/pprof address (for example 127.0.0.1:6060)")
	version := fs.Bool("version", false, "print the Laneway build version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected node run argument %q", fs.Arg(0))
	}
	if *version {
		fmt.Println(buildinfo.Version)
		return nil
	}
	return nonCancellationError(run(*configPath, *diagnostics))
}

func nonCancellationError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var result error
		for _, child := range joined.Unwrap() {
			result = errors.Join(result, nonCancellationError(child))
		}
		return result
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func run(path, diagnostics string) (retErr error) {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runConfig(ctx, cfg, diagnostics, runtimeOptions{})
}

func runConfig(ctx context.Context, cfg config.Config, diagnostics string, options runtimeOptions) (retErr error) {
	if ctx == nil {
		return errors.New("node runtime requires a context")
	}
	if cfg.Mode != config.ModeNode {
		return fmt.Errorf("configuration mode is %q, want %q", cfg.Mode, config.ModeNode)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	exitIntentStore := newExitIntentStore(cfg.StateDir)
	var exitIntentPersisted bool
	var err error
	cfg.Exit, exitIntentPersisted, err = exitIntentStore.Load(cfg.Exit)
	if err != nil {
		return fmt.Errorf("load persisted exit intent: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration with persisted exit intent: %w", err)
	}
	if cfg.WireGuard.Enabled && cfg.Controller.Endpoint == "" {
		return errors.New("WireGuard runtime requires controller authority")
	}
	if cfg.WireGuard.Enabled && cfg.Direct.Enabled {
		return errors.New("WireGuard runtime requires encrypted direct transport or direct.enabled=false")
	}
	revokedCertificates := new(revocation.Set)
	tlsConfig, err := transport.LoadClientTLSConfigWithRevocations(cfg.TLS.CAFile, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, revokedCertificates)
	if err != nil {
		return err
	}
	if cfg.TLS.ServerName != "" {
		tlsConfig.ServerName = cfg.TLS.ServerName
	}
	local, err := identity.IdentityFromCertificate(tlsConfig.Certificates[0].Leaf)
	if err != nil {
		return err
	}
	relayNetworkID, _ := identity.ParseNetworkID(cfg.Node.RelayNetworkID)
	relayServiceID, _ := identity.ParseID(cfg.Node.RelayServiceID)
	if relayNetworkID != local.NetworkID {
		return errors.New("configured relay network ID does not match the node certificate network")
	}
	if cfg.Controller.Endpoint == "" {
		if err := transport.RequirePeerService(tlsConfig, identity.AuthenticatedIdentity{
			NetworkID: relayNetworkID, Role: identity.IdentityRoleRelay, SubjectID: relayServiceID,
		}); err != nil {
			return err
		}
	}
	// Resolve each native transport exactly once. The numeric dial targets and
	// installed host-route bypasses below are therefore the same endpoints for
	// every reconnect, even if DNS rotates after lane0 becomes active.
	relayEndpoint, err := endpointpin.HostPort(ctx, cfg.Node.RelayAddress, endpointpin.Options{})
	if err != nil {
		return fmt.Errorf("pin relay endpoint: %w", err)
	}
	var tcpEndpoint endpointpin.Endpoint
	if cfg.TCPFallback.Address != "" {
		tcpEndpoint, err = endpointpin.HostPort(ctx, cfg.TCPFallback.Address, endpointpin.Options{})
		if err != nil {
			return fmt.Errorf("pin TCP fallback endpoint: %w", err)
		}
	}
	var controllerEndpoint endpointpin.Endpoint
	var controllerQUICEndpoint endpointpin.Endpoint
	if cfg.Controller.Endpoint != "" {
		controllerEndpoint, err = endpointpin.HTTPS(ctx, cfg.Controller.Endpoint, endpointpin.Options{})
		if err != nil {
			return fmt.Errorf("pin controller endpoint: %w", err)
		}
		if cfg.Controller.QUICEndpoint != "" {
			controllerQUICEndpoint, err = endpointpin.HostPort(ctx, cfg.Controller.QUICEndpoint, endpointpin.Options{})
			if err != nil {
				return fmt.Errorf("pin controller QUIC endpoint: %w", err)
			}
		}
	}
	var configurationClient configurationSource
	var initialConfiguration *lanewayv1.NodeConfiguration
	var addresses []netip.Prefix
	if cfg.Controller.Endpoint != "" {
		controllerNetworkID, _ := identity.ParseNetworkID(cfg.Controller.NetworkID)
		controllerServiceID, _ := identity.ParseID(cfg.Controller.ServiceID)
		if controllerNetworkID != local.NetworkID {
			return errors.New("configured controller network ID does not match the node certificate network")
		}
		client, err := controllerclient.New(controllerclient.Options{
			Endpoint: cfg.Controller.Endpoint, QUICEndpoint: cfg.Controller.QUICEndpoint, QUICDialAddress: controllerQUICEndpoint.DialAddress, CAFile: cfg.TLS.CAFile,
			CertificateFile: cfg.TLS.CertificateFile, PrivateKeyFile: cfg.TLS.PrivateKeyFile,
			ServerName: cfg.Controller.ServerName, DialAddress: controllerEndpoint.DialAddress,
			ExpectedNetworkID: controllerNetworkID, ExpectedServiceID: controllerServiceID,
		})
		if err != nil {
			return err
		}
		initialConfiguration, _, err = client.Configuration(ctx, 0)
		if err != nil {
			return fmt.Errorf("fetch initial controller configuration: %w", err)
		}
		configurationClient = client
		if options.filterConfiguration != nil {
			initialConfiguration, err = options.filterConfiguration(initialConfiguration)
			if err != nil {
				return fmt.Errorf("filter initial controller configuration: %w", err)
			}
			configurationClient = filteredConfigurationSource{source: client, filter: options.filterConfiguration}
		}
		addresses, err = controllerOverlayAddresses(initialConfiguration, local, time.Now())
		if err != nil {
			return fmt.Errorf("initial controller configuration: %w", err)
		}
	} else {
		addresses, err = overlayAddresses(cfg.Node.OverlayAddresses)
		if err != nil {
			return err
		}
	}
	controllerState := &controllerApplyState{revoked: revokedCertificates}
	var controllerRelayBypass []netip.Addr
	controllerState.candidateEnabled.Store(cfg.Direct.Enabled)
	controllerState.candidateMax.Store(uint32(cfg.Direct.MaxCandidates))
	controllerState.candidateTTLSeconds.Store(uint32(cfg.Direct.CandidateTTL.Duration() / time.Second))
	if initialConfiguration != nil {
		controllerState.authority, err = newNodeRuntimeAuthority(
			relayServiceID, cfg.Node.RelayAddress, cfg.Direct.Enabled, cfg.Direct.MaxCandidates,
			cfg.Direct.CandidateTTL.Duration(), tlsConfig.Certificates[0].Leaf,
		)
		if err != nil {
			return err
		}
		status, validateErr := validateNodeRuntimeAuthority(initialConfiguration, controllerState.authority, time.Now())
		if validateErr != nil {
			return fmt.Errorf("initial controller runtime authority: %w", validateErr)
		}
		status.relayTargets, controllerRelayBypass, err = resolveNodeRelayTargets(ctx, status.relayTargets)
		if err != nil {
			return err
		}
		controllerState.publishRelayTargets(status.relayTargets)
		status.relayBypass = append([]netip.Addr(nil), controllerRelayBypass...)
		controllerState.candidateEnabled.Store(status.candidateEnabled)
		controllerState.candidateMax.Store(status.candidateMax)
		controllerState.candidateTTLSeconds.Store(status.candidateTTLSeconds)
		controllerState.certificateRenewalNeeded.Store(status.renewalNeeded)
		controllerState.certificateRenewAfter.Store(status.certificateRenewAfter)
		controllerState.certificateNotAfter.Store(status.certificateNotAfter)
	}
	laneMTU := defaultLaneMTU
	for _, address := range addresses {
		if address.Addr().Is6() {
			laneMTU = platform.MinIPv6MTU
			break
		}
	}
	if cfg.WireGuard.Enabled {
		laneMTU = cfg.WireGuard.MTU
	}
	routeTable, osRoutes, err := buildRoutes(local, cfg.Peers)
	if err != nil {
		return err
	}
	advertisedPrefixes, err := parseForwardPrefixes(cfg.Routing.Advertise)
	if err != nil {
		return err
	}
	var forwardPrefixes []netip.Prefix
	// Static-only nodes retain their configured forwarding authorization. With
	// a controller, subnet authorization comes exclusively from approved
	// self-owned routes in each configuration snapshot.
	if cfg.Controller.Endpoint == "" {
		forwardPrefixes = append(forwardPrefixes, advertisedPrefixes...)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o755); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	bypass := []netip.Addr{relayEndpoint.Address}
	if tcpEndpoint.Address.IsValid() {
		bypass = append(bypass, tcpEndpoint.Address)
	}
	if controllerEndpoint.Address.IsValid() {
		bypass = append(bypass, controllerEndpoint.Address)
	}
	if controllerQUICEndpoint.Address.IsValid() && controllerQUICEndpoint.Address != controllerEndpoint.Address {
		bypass = append(bypass, controllerQUICEndpoint.Address)
	}
	staticBypass := append([]netip.Addr(nil), bypass...)
	bypass = append(bypass, controllerRelayBypass...)

	initialRoutePlan := platform.RoutePlan{Routes: osRoutes, TransportBypass: bypass}
	var secureWireGuard secureWireGuardRuntime
	var hostNetwork HostNetwork
	if cfg.WireGuard.Enabled {
		if options.networkOpener != nil {
			return errors.New("foreground network helpers do not yet support the WireGuard device")
		}
		privateKey, _, keyErr := wireguard.LoadPrivateKeyFile(cfg.WireGuard.PrivateKeyFile)
		if keyErr != nil {
			return keyErr
		}
		wireGuardOpener := options.wireGuardOpener
		if wireGuardOpener == nil {
			wireGuardOpener = func(ctx context.Context, config wireguard.SecureManagerConfig) (secureWireGuardRuntime, error) {
				return wireguard.OpenSecureManager(ctx, config)
			}
		}
		secureWireGuard, err = wireGuardOpener(ctx, wireguard.SecureManagerConfig{
			Manager: wireguard.ManagerConfig{Device: wireguard.DeviceConfig{
				Name: cfg.WireGuard.InterfaceName, MTU: cfg.WireGuard.MTU, Addresses: addresses,
				PrivateKey: privateKey, ListenPort: cfg.WireGuard.ListenPort,
			}},
			Firewall: wireguard.FirewallConfig{Interface: cfg.WireGuard.InterfaceName},
		})
		if err != nil {
			return err
		}
		routes, routeErr := platform.NewRouteManager(platform.RouteManagerConfig{InterfaceName: secureWireGuard.Name()})
		if routeErr != nil {
			return errors.Join(routeErr, secureWireGuard.Close())
		}
		if routeErr = routes.Apply(ctx, initialRoutePlan); routeErr != nil {
			return errors.Join(routeErr, routes.Close(), secureWireGuard.Close())
		}
		hostNetwork = HostNetwork{Routes: routes, Close: routes.Close}
	} else {
		tunConfig := platform.TUNConfig{Name: platform.DefaultTUNName, MTU: laneMTU, Addresses: addresses}
		networkOpener := options.networkOpener
		if networkOpener == nil {
			networkOpener = openDirectHostNetwork
		}
		hostNetwork, err = networkOpener(ctx, tunConfig, initialRoutePlan)
		if err != nil {
			return err
		}
	}
	if (hostNetwork.TUN == nil && secureWireGuard == nil) || hostNetwork.Routes == nil || hostNetwork.Close == nil {
		if hostNetwork.Close != nil {
			_ = hostNetwork.Close()
		}
		if secureWireGuard != nil {
			_ = secureWireGuard.Close()
		}
		return errors.New("network opener returned an incomplete host network")
	}
	tun, routeManager := hostNetwork.TUN, hostNetwork.Routes
	var interfaceName string
	var interfaceMTU int
	if secureWireGuard != nil {
		interfaceName, interfaceMTU = secureWireGuard.Name(), secureWireGuard.MTU()
	} else {
		interfaceName, interfaceMTU = tun.Name(), tun.MTU()
	}
	if secureWireGuard != nil {
		defer func() {
			if closeErr := secureWireGuard.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("restore WireGuard device: %w", closeErr))
			}
		}()
		controllerState.wireGuard = secureWireGuard
	}
	defer func() {
		if closeErr := hostNetwork.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore host networking: %w", closeErr))
		}
	}()
	var ipForwardManager *daemonIPForwardManager
	if cfg.Controller.Endpoint != "" && (cfg.Routing.OutputInterface != "" || cfg.Exit.Serve) {
		ipForwardManager = newDaemonIPForwardManager()
		defer func() {
			if closeErr := ipForwardManager.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("restore shared IP forwarding: %w", closeErr))
			}
		}()
	}
	var subnetForwarding subnet.ForwardingManager
	if (cfg.Controller.Endpoint != "" && cfg.Routing.OutputInterface != "") ||
		(cfg.Controller.Endpoint == "" && len(advertisedPrefixes) != 0) {
		subnetForwarding, err = subnet.NewForwardingManager(subnet.ForwardingManagerConfig{
			InputInterface: interfaceName, OutputInterface: cfg.Routing.OutputInterface,
		})
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := subnetForwarding.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("restore subnet forwarding: %w", closeErr))
			}
		}()
		if cfg.Controller.Endpoint == "" {
			mode := subnet.ModeRouted
			if cfg.Routing.NAT {
				mode = subnet.ModeNAT
			}
			if err := subnetForwarding.Apply(ctx, subnet.ForwardingPlan{AuthorizedPrefixes: advertisedPrefixes, Mode: mode}); err != nil {
				return err
			}
		}
	}

	var exitManagers *daemonExitManagers
	if cfg.Controller.Endpoint != "" || cfg.Exit.Serve {
		exitManagers, err = newDaemonExitManagers(cfg, local, interfaceName, staticBypass, routeTable, exitIntentStore, exitIntentPersisted,
			hostNetwork.ExitRoutes, hostNetwork.DNS)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := exitManagers.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("restore exit routing: %w", closeErr))
			}
		}()
	}
	bootID, err := identity.NewID()
	if err != nil {
		return err
	}
	var packetPolicy nodeservice.PacketPolicy
	var packetIO nodeservice.PacketIO
	if tun != nil {
		packetIO = tunPacketIO{tun}
	}
	var policyTable *policy.Table
	if cfg.Controller.Endpoint != "" {
		policyTable = new(policy.Table)
		packetPolicy = nodeservice.PacketPolicyFunc(func(source, destination identity.NodeID, packet []byte) bool {
			return policyTable.Evaluate(source, destination, packet).Action == policy.Accept
		})
	}
	var tcpFallbackConfig *tcpfallback.Config
	if cfg.TCPFallback.Address != "" {
		tcpFallbackConfig = &tcpfallback.Config{
			HandshakeTimeout: cfg.TCPFallback.HandshakeTimeout.Duration(),
			WriteTimeout:     cfg.TCPFallback.WriteTimeout.Duration(),
			IdleTimeout:      cfg.TCPFallback.IdleTimeout.Duration(),
			KeepAlivePeriod:  cfg.TCPFallback.KeepAlivePeriod.Duration(),
			QueueDepth:       cfg.TCPFallback.QueueDepth,
			MaxPacketPayload: laneMTU + protocol.PacketHeaderSize,
		}
	}
	var unifiedDataPlane *dataplane.Engine
	var pathManager *pathmanager.Manager
	var directController *dataplane.DirectController
	var directEndpoint *directpath.Endpoint
	var relayDialer nodeservice.RelayDialer
	var candidateSink dataplane.CandidateSink
	var localCandidate *lanewayv1.EndpointCandidate
	if cfg.Direct.Enabled {
		listenAddress, err := net.ResolveUDPAddr("udp", cfg.Direct.Listen)
		if err != nil {
			return fmt.Errorf("resolve direct listener: %w", err)
		}
		packetConn, err := net.ListenUDP("udp", listenAddress)
		if err != nil {
			return fmt.Errorf("listen for direct peers: %w", err)
		}
		directEndpoint, err = directpath.NewEndpoint(packetConn, local, directpath.Credentials{
			Roots: tlsConfig.RootCAs, Certificate: tlsConfig.Certificates[0], Revocations: revokedCertificates,
		}, directpath.Config{MaxPacketPayload: laneMTU, CandidatePolicy: directCandidatePolicy(cfg.Direct)})
		if err != nil {
			_ = packetConn.Close()
			return err
		}
		defer directEndpoint.Close()
		pathManager = pathmanager.MustNew(pathmanager.Config{})
		localAddresses := make([]netip.Addr, 0, len(addresses))
		for _, prefix := range addresses {
			localAddresses = append(localAddresses, prefix.Addr())
		}
		unifiedDataPlane, err = dataplane.New(dataplane.Config{
			Identity: local, Routes: routeTable, Packets: packetIO, Paths: pathManager,
			Policy: packetPolicy, LocalAddresses: localAddresses, ForwardPrefixes: forwardPrefixes, MaxPacketSize: laneMTU,
		})
		if err != nil {
			return err
		}
		directController, err = dataplane.NewDirectController(dataplane.DirectConfig{
			Local: local, Endpoint: directEndpoint, Paths: unifiedDataPlane, Authorizer: dataplane.RouteAuthorizer{Routes: routeTable},
			CandidateAuthority: controllerState,
			CandidatePolicy:    directCandidatePolicy(cfg.Direct), CandidateTTL: cfg.Direct.CandidateTTL.Duration(),
			ProbeInterval: cfg.Direct.ProbeInterval.Duration(), ProbeTimeout: cfg.Direct.ProbeTimeout.Duration(),
		})
		if err != nil {
			return err
		}
		relayDialer, candidateSink = directEndpoint, directController
		// The relay discards all claimed endpoint fields and replaces them with
		// the identity and UDP source it authenticated on this shared socket.
		localCandidate = &lanewayv1.EndpointCandidate{Transport: lanewayv1.EndpointTransport_ENDPOINT_TRANSPORT_QUIC_UDP}
	}
	var relayAuthority nodeservice.RelayAuthority
	if initialConfiguration != nil {
		relayAuthority = controllerState
	}
	service, err := nodeservice.New(nodeservice.Config{
		Identity:                 local,
		BootID:                   bootID,
		RelayAddress:             relayEndpoint.DialAddress,
		RelayServiceID:           relayServiceID,
		TLSConfig:                tlsConfig,
		Transport:                &transport.Config{MaxIdleTimeout: cfg.Relay.IdleTimeout.Duration()},
		TCPFallbackAddress:       tcpEndpoint.DialAddress,
		TCPFallback:              tcpFallbackConfig,
		QUICRecoveryInterval:     cfg.TCPFallback.QUICProbeInterval.Duration(),
		DirectRendezvousInterval: cfg.Direct.RendezvousInterval.Duration(),
		Routes:                   routeTable,
		Packets:                  packetIO,
		PacketPolicy:             packetPolicy,
		DataPlane:                unifiedDataPlane,
		CandidateSink:            candidateSink,
		CandidateAuthority:       controllerState,
		LocalCandidate:           localCandidate,
		RelayDialer:              relayDialer,
		RelayAuthority:           relayAuthority,
		WireGuardRelay:           secureWireGuard,
		ReconnectInitial:         cfg.Node.ReconnectMin.Duration(),
		ReconnectMaximum:         cfg.Node.ReconnectMax.Duration(),
		ForwardPrefixes:          forwardPrefixes,
	})
	if err != nil {
		return err
	}
	var subnetManager *daemonSubnetManager
	if cfg.Controller.Endpoint != "" {
		subnetManager = &daemonSubnetManager{
			forwarding: subnetForwarding, fixedForwardPrefixes: append([]netip.Prefix(nil), forwardPrefixes...),
			setRelayPrefixes: service.SetForwardPrefixes, serveExit: cfg.Exit.Serve,
		}
		if unifiedDataPlane != nil {
			subnetManager.setDirectPrefixes = unifiedDataPlane.SetForwardPrefixes
		}
	}
	if exitManagers != nil {
		if unifiedDataPlane != nil {
			exitManagers.SetPathAvailable(unifiedDataPlane.PathAvailable)
		} else {
			exitManagers.SetPathAvailable(service.PathAvailable)
		}
	}
	if directEndpoint != nil && exitManagers != nil && exitManagers.client != nil {
		if err := directEndpoint.SetPathEndpointHandler(func(endpoints []netip.Addr) error {
			updateCtx, cancel := context.WithTimeout(context.Background(), exitnode.DefaultShutdownTimeout)
			defer cancel()
			return exitManagers.SetDirectPathEndpoints(updateCtx, endpoints)
		}); err != nil {
			return fmt.Errorf("configure direct-path exit bypasses: %w", err)
		}
	}
	if initialConfiguration != nil {
		if err := applyControllerConfiguration(ctx, initialConfiguration, local, routeTable, routeManager, staticBypass,
			policyTable, subnetManager, ipForwardManager, exitManagers, controllerState); err != nil {
			return fmt.Errorf("apply initial controller configuration: %w", err)
		}
	}
	if !options.foreground {
		fmt.Printf("lanewayd node=%s interface=%s mtu=%d relay=%s\n", local.NodeID, interfaceName, interfaceMTU, cfg.Node.RelayAddress)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if options.status != nil {
		baseStatus := RuntimeStatus{
			NetworkID: local.NetworkID.String(), NodeID: local.NodeID.String(), Interface: interfaceName,
			OverlayAddresses: append([]netip.Prefix(nil), addresses...),
		}
		emitStatus := func(path string) {
			status := baseStatus
			status.OverlayAddresses = append([]netip.Prefix(nil), baseStatus.OverlayAddresses...)
			status.Path = path
			options.status(status)
		}
		emitStatus("connecting")
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			last := "connecting"
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					path := foregroundPath(local.NodeID, controllerState, pathManager, service)
					if path != last {
						last = path
						emitStatus(path)
					}
				}
			}
		}()
	}
	if exitManagers != nil {
		go exitManagers.MonitorPath(runCtx, time.Second)
	}
	diagnosticsDone, err := observability.Start(runCtx, observability.Config{Listen: diagnostics, Snapshot: func() map[string]uint64 {
		metrics := service.Metrics()
		values := map[string]uint64{
			"node_connections_total":      metrics.Connections,
			"node_reconnects_total":       metrics.Reconnects,
			"node_packets_sent_total":     metrics.PacketsSent,
			"node_packets_received_total": metrics.PacketsReceived,
			"node_packets_dropped_total":  metrics.PacketsDropped,
			"node_malformed_total":        metrics.MalformedPackets,
			"node_control_errors_total":   metrics.ControlErrors,
			"node_tcp_connections_total":  metrics.TCPConnections,
			"node_quic_failures_total":    metrics.QUICFailures,
			"node_tcp_failures_total":     metrics.TCPFailures,
		}
		if unifiedDataPlane != nil {
			dataMetrics := unifiedDataPlane.Metrics()
			values["dataplane_packets_sent_total"] = dataMetrics.PacketsSent
			values["dataplane_packets_received_total"] = dataMetrics.PacketsReceived
			values["dataplane_packets_dropped_total"] = dataMetrics.PacketsDropped
			values["dataplane_malformed_total"] = dataMetrics.MalformedPackets
			values["dataplane_path_failures_total"] = dataMetrics.PathFailures
			values["dataplane_path_switch_retries_total"] = dataMetrics.PathSwitchRetries
		}
		if secureWireGuard != nil {
			wireGuardMetrics := secureWireGuard.RelayMetrics()
			values["wireguard_packets_sent_total"] = wireGuardMetrics.PacketsSent
			values["wireguard_packets_received_total"] = wireGuardMetrics.PacketsReceived
			values["wireguard_packets_dropped_total"] = wireGuardMetrics.PacketsDropped
			values["wireguard_unknown_sources_total"] = wireGuardMetrics.UnknownSources
			values["wireguard_unauthorized_peers_total"] = wireGuardMetrics.UnauthorizedPeers
		}
		addPathManagerDiagnostics(values, pathManager)
		values["controller_certificate_renewal_needed"] = 0
		if controllerState.CertificateRenewalNeeded(time.Now()) {
			values["controller_certificate_renewal_needed"] = 1
		}
		values["controller_certificate_not_after_unix_seconds"] = controllerState.certificateNotAfter.Load()
		values["controller_certificate_renew_after_unix_seconds"] = controllerState.certificateRenewAfter.Load()
		values["controller_candidate_exchange_enabled"] = 0
		if controllerState.candidateEnabled.Load() {
			values["controller_candidate_exchange_enabled"] = 1
		}
		return values
	}})
	if err != nil {
		return err
	}
	api := localapi.Server{SocketPath: cfg.SocketPath, Snapshot: func() (localapi.Status, []localapi.Peer, []localapi.Route) {
		metrics := service.Metrics()
		packetSent, packetReceived, packetDropped := metrics.PacketsSent, metrics.PacketsReceived, metrics.PacketsDropped
		if unifiedDataPlane != nil {
			dataMetrics := unifiedDataPlane.Metrics()
			packetSent, packetReceived, packetDropped = dataMetrics.PacketsSent, dataMetrics.PacketsReceived, dataMetrics.PacketsDropped
		}
		if secureWireGuard != nil {
			wireGuardMetrics := secureWireGuard.RelayMetrics()
			packetSent, packetReceived, packetDropped = wireGuardMetrics.PacketsSent, wireGuardMetrics.PacketsReceived, wireGuardMetrics.PacketsDropped
		}
		status := localapi.Status{
			Running: true, NetworkID: local.NetworkID.String(), NodeID: local.NodeID.String(), Name: cfg.Node.Name,
			Interface: interfaceName, Relay: cfg.Node.RelayAddress, MTU: interfaceMTU,
			ProductVersion: productVersion, ControlVersion: "1.0", PacketVersion: uint8(protocol.PacketVersion1),
			Capabilities: service.AdvertisedCapabilities().String(), SelectedPath: service.SelectedCarrier(),
			Metrics: localapi.Metrics{
				Connections: metrics.Connections, Reconnects: metrics.Reconnects, PacketsSent: packetSent,
				PacketsReceived: packetReceived, PacketsDropped: packetDropped,
				TCPConnections: metrics.TCPConnections, QUICFailures: metrics.QUICFailures, TCPFailures: metrics.TCPFailures,
			},
			Controller: localapi.ControllerStatus{
				CandidateExchangeEnabled:         controllerState.candidateEnabled.Load(),
				CertificatePresentedSerial:       fmt.Sprintf("%x", tlsConfig.Certificates[0].Leaf.SerialNumber.Bytes()),
				CertificateRenewalNeeded:         controllerState.CertificateRenewalNeeded(time.Now()),
				CertificateRenewAfterUnixSeconds: controllerState.certificateRenewAfter.Load(),
				CertificateNotAfterUnixSeconds:   controllerState.certificateNotAfter.Load(),
			},
		}
		if exitManagers != nil {
			status.Exit = exitManagers.Status()
		}
		peers := make([]localapi.Peer, 0, len(cfg.Peers))
		for _, peer := range cfg.Peers {
			nodeID, _ := identity.ParseNodeID(peer.NodeID)
			peers = append(peers, localapi.Peer{NodeID: peer.NodeID, Name: peer.Name, Prefixes: append([]string(nil), peer.Prefixes...), Path: peerPathState(nodeID, pathManager, service)})
		}
		controllerState.mu.Lock()
		if controllerState.accepted != nil {
			for _, peer := range controllerState.accepted.configuration.GetPeers() {
				var nodeID identity.NodeID
				copy(nodeID[:], peer.GetNodeId())
				if nodeID == local.NodeID {
					continue
				}
				prefixes := make([]string, 0, len(peer.GetOverlayAddresses()))
				for _, raw := range peer.GetOverlayAddresses() {
					if address, ok := netip.AddrFromSlice(raw); ok && !address.Is4In6() {
						prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()).String())
					}
				}
				peers = append(peers, localapi.Peer{NodeID: nodeID.String(), Name: peer.GetName(), Prefixes: prefixes, Path: peerPathState(nodeID, pathManager, service)})
			}
		}
		controllerState.mu.Unlock()
		routes := make([]localapi.Route, 0, routeTable.Snapshot().Len())
		for _, route := range routeTable.Snapshot().Routes() {
			routes = append(routes, localapi.Route{Prefix: route.Prefix.String(), ViaNode: route.NextHop.String(), Kind: "peer"})
		}
		return status, peers, routes
	}}
	if exitManagers != nil && exitManagers.client != nil {
		api.SetExit = func(ctx context.Context, selection localapi.ExitSelection) error {
			if secureWireGuard != nil && selection.Enabled {
				return errors.New("WireGuard exit selection requires an isolated cryptokey-routing boundary")
			}
			var selected identity.NodeID
			if selection.Enabled {
				var err error
				selected, err = identity.ParseNodeID(selection.SelectedNodeID)
				if err != nil {
					return err
				}
			}
			return exitManagers.SetSelection(ctx, selection.Enabled, selected)
		}
	}
	type componentResult struct {
		name string
		err  error
	}
	componentDone := make(chan componentResult, 6)
	components := 2
	if diagnosticsDone != nil {
		components++
		go func() { componentDone <- componentResult{"diagnostics", <-diagnosticsDone} }()
	}
	if configurationClient != nil {
		components++
		go func() {
			componentDone <- componentResult{"configuration", runConfigurationUpdates(runCtx, cfg.Controller.PollInterval.Duration(), configurationClient,
				local, addresses, initialConfiguration, routeTable, routeManager, staticBypass, policyTable, subnetManager, ipForwardManager, exitManagers, controllerState)}
		}()
	}
	if unifiedDataPlane != nil {
		components += 2
		go func() { componentDone <- componentResult{"dataplane", unifiedDataPlane.Run(runCtx)} }()
		go func() { componentDone <- componentResult{"direct", directController.Run(runCtx)} }()
	}
	go func() { componentDone <- componentResult{"service", service.Run(runCtx)} }()
	go func() { componentDone <- componentResult{"local API", api.Serve(runCtx)} }()
	first := <-componentDone
	err = first.err
	cancelRun()
	for range components - 1 {
		<-componentDone
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		err = fmt.Errorf("%s: %w", first.name, err)
	}
	metrics := service.Metrics()
	sent, received, dropped := metrics.PacketsSent, metrics.PacketsReceived, metrics.PacketsDropped
	if unifiedDataPlane != nil {
		dataMetrics := unifiedDataPlane.Metrics()
		sent, received, dropped = dataMetrics.PacketsSent, dataMetrics.PacketsReceived, dataMetrics.PacketsDropped
	}
	if secureWireGuard != nil {
		wireGuardMetrics := secureWireGuard.RelayMetrics()
		sent, received, dropped = wireGuardMetrics.PacketsSent, wireGuardMetrics.PacketsReceived, wireGuardMetrics.PacketsDropped
	}
	if !options.foreground {
		fmt.Printf("lanewayd stopped connections=%d sent=%d received=%d dropped=%d\n",
			metrics.Connections, sent, received, dropped)
	}
	return err
}

func addPathManagerDiagnostics(values map[string]uint64, manager *pathmanager.Manager) {
	if manager == nil {
		return
	}
	metrics := manager.Snapshot().Metrics()
	values["path_observations_total"] = metrics.Observations
	values["path_failures_total"] = metrics.HardFailures
	values["path_direct_failures_total"] = metrics.DirectFailures
	values["path_switches_total"] = metrics.Switches
	values["path_peers"] = uint64(metrics.Peers)
}

func peerPathState(peer identity.NodeID, manager *pathmanager.Manager, service *nodeservice.Service) string {
	if manager != nil {
		if path := manager.BestPath(peer); path != nil {
			return path.Name()
		}
	}
	if service != nil && service.PathAvailable(peer) {
		return service.SelectedCarrier()
	}
	return "disconnected"
}

func foregroundPath(local identity.NodeID, state *controllerApplyState, manager *pathmanager.Manager, service *nodeservice.Service) string {
	if state != nil && manager != nil {
		state.mu.Lock()
		if state.accepted != nil {
			for _, peer := range state.accepted.configuration.GetPeers() {
				if len(peer.GetNodeId()) != identity.IDSize {
					continue
				}
				var peerID identity.NodeID
				copy(peerID[:], peer.GetNodeId())
				if peerID == local {
					continue
				}
				if path := manager.BestPath(peerID); path != nil && strings.HasPrefix(path.Name(), "direct-quic/") {
					state.mu.Unlock()
					return "direct"
				}
			}
		}
		state.mu.Unlock()
	}
	return service.SelectedCarrier()
}

func directCandidatePolicy(config config.Direct) directpath.CandidatePolicy {
	return directpath.CandidatePolicy{MaxCandidates: config.MaxCandidates, AllowLoopback: config.AllowLoopback, AllowLinkLocal: config.AllowLinkLocal}
}

type configurationSource interface {
	Configuration(context.Context, uint64) (*lanewayv1.NodeConfiguration, bool, error)
}

type filteredConfigurationSource struct {
	source configurationSource
	filter func(*lanewayv1.NodeConfiguration) (*lanewayv1.NodeConfiguration, error)
}

func (s filteredConfigurationSource) Configuration(ctx context.Context, epoch uint64) (*lanewayv1.NodeConfiguration, bool, error) {
	configuration, unchanged, err := s.source.Configuration(ctx, epoch)
	if err != nil || unchanged {
		return configuration, unchanged, err
	}
	filtered, err := s.filter(configuration)
	return filtered, false, err
}

func controllerOverlayAddresses(configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity, now time.Time) ([]netip.Prefix, error) {
	if configuration == nil || configuration.GetConfigurationEpoch() == 0 || configuration.GetRoutes() == nil || configuration.GetPolicy() == nil ||
		string(configuration.GetRoutes().GetNetworkId()) != string(local.NetworkID[:]) ||
		string(configuration.GetPolicy().GetNetworkId()) != string(local.NetworkID[:]) {
		return nil, errors.New("configuration is incomplete or belongs to another network")
	}
	if _, err := configurationDeadline(configuration.GetValidUntilUnixSeconds(), now); err != nil {
		return nil, err
	}
	if err := validateConfigurationIdentityLease(configuration, now); err != nil {
		return nil, err
	}
	if len(configuration.GetOverlayAddresses()) == 0 {
		return nil, errors.New("controller assigned no overlay address")
	}
	assigned := make(map[netip.Prefix]bool, len(configuration.GetOverlayAddresses()))
	addresses := make([]netip.Prefix, 0, len(configuration.GetOverlayAddresses()))
	for i, raw := range configuration.GetOverlayAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("overlay address %d is not a supported unicast IP address", i)
		}
		prefix := netip.PrefixFrom(address, address.BitLen())
		if _, duplicate := assigned[prefix]; duplicate {
			return nil, fmt.Errorf("overlay address %d is duplicated", i)
		}
		assigned[prefix] = false
		addresses = append(addresses, prefix)
	}
	for i, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_OVERLAY || len(route.GetViaNodeId()) != identity.IDSize {
			continue
		}
		var owner identity.NodeID
		copy(owner[:], route.GetViaNodeId())
		if owner != local.NodeID {
			continue
		}
		prefix, err := protoPrefix(route.GetDestination())
		if err != nil {
			return nil, fmt.Errorf("local overlay route %d is invalid", i)
		}
		if _, ok := assigned[prefix]; !ok {
			return nil, fmt.Errorf("controller routed unassigned local overlay prefix %s", prefix)
		}
		assigned[prefix] = true
	}
	for prefix, routed := range assigned {
		if !routed {
			return nil, fmt.Errorf("controller omitted local overlay route %s", prefix)
		}
	}
	return addresses, nil
}

func validateConfigurationIdentityLease(configuration *lanewayv1.NodeConfiguration, now time.Time) error {
	class := configuration.GetEnrollmentClass()
	lease := configuration.GetIdentityLeaseExpiresAtUnixSeconds()
	switch class {
	case lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_UNSPECIFIED, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE,
		lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER:
		if lease != 0 {
			return errors.New("non-ephemeral controller identity has an unexpected lease")
		}
	case lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER:
		if lease == 0 || lease > uint64(1<<63-1) || !time.Unix(int64(lease), 0).After(now) {
			return errors.New("ephemeral controller identity lease is missing or expired")
		}
		if configuration.GetValidUntilUnixSeconds() > lease {
			return errors.New("controller snapshot exceeds the ephemeral identity lease")
		}
	default:
		return errors.New("controller returned an unknown enrollment class")
	}
	return nil
}

func configurationDeadline(seconds uint64, now time.Time) (time.Time, error) {
	if seconds == 0 || seconds > uint64(1<<63-1) {
		return time.Time{}, errors.New("controller configuration has no valid snapshot deadline")
	}
	deadline := time.Unix(int64(seconds), 0).UTC()
	if !deadline.After(now) {
		return time.Time{}, errors.New("controller configuration snapshot is expired")
	}
	return deadline, nil
}

func samePrefixes(left, right []netip.Prefix) bool {
	if len(left) != len(right) {
		return false
	}
	set := make(map[netip.Prefix]int, len(left))
	for _, prefix := range left {
		set[prefix]++
	}
	for _, prefix := range right {
		if set[prefix] == 0 {
			return false
		}
		set[prefix]--
	}
	return true
}

func runConfigurationUpdates(ctx context.Context, interval time.Duration, source configurationSource, local identity.NodeIdentity,
	expectedAddresses []netip.Prefix, initial *lanewayv1.NodeConfiguration, routeTable *routing.Table, routeManager platform.RouteManager, bypass []netip.Addr, policyTable *policy.Table,
	subnetManager *daemonSubnetManager, ipForwardManager *daemonIPForwardManager, exitManagers *daemonExitManagers,
	stateArgs ...*controllerApplyState,
) error {
	if initial == nil || interval <= 0 {
		return errors.New("controller configuration updater requires an initial snapshot")
	}
	epoch := initial.GetConfigurationEpoch()
	last := initial
	deadline, err := configurationDeadline(initial.GetValidUntilUnixSeconds(), time.Now())
	if err != nil {
		return err
	}
	failClosed := false
	applyState := new(controllerApplyState)
	if len(stateArgs) != 0 && stateArgs[0] != nil {
		applyState = stateArgs[0]
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		if !failClosed && !deadline.After(time.Now()) {
			expired := failClosedNodeConfiguration(last, local)
			if closeErr := applyControllerConfiguration(ctx, expired, local, routeTable, routeManager, bypass, policyTable, subnetManager, ipForwardManager, exitManagers, applyState); closeErr != nil {
				if ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "lanewayd: expire controller snapshot:", closeErr)
				}
			}
			// The fail-close apply publishes empty userspace routes, forwarding
			// authorization, and deny policy before returning cleanup errors.
			failClosed = true
		}
		requestCtx := ctx
		cancelRequest := func() {}
		if !failClosed && deadline.After(time.Now()) {
			requestCtx, cancelRequest = context.WithDeadline(ctx, deadline)
		}
		configuration, unchanged, updateErr := source.Configuration(requestCtx, epoch)
		cancelRequest()
		if updateErr == nil {
			if unchanged {
				var renewedDeadline time.Time
				renewedDeadline, updateErr = configurationDeadline(configuration.GetValidUntilUnixSeconds(), time.Now())
				if updateErr == nil && renewedDeadline.Before(deadline) {
					updateErr = errors.New("controller lease deadline moved backwards")
				}
				if updateErr == nil {
					deadline = renewedDeadline
					last.ValidUntilUnixSeconds = configuration.GetValidUntilUnixSeconds()
					if failClosed {
						updateErr = applyControllerConfiguration(ctx, last, local, routeTable, routeManager, bypass, policyTable, subnetManager, ipForwardManager, exitManagers, applyState)
						failClosed = updateErr != nil
					}
				}
			} else {
				if configuration.GetConfigurationEpoch() <= epoch {
					updateErr = fmt.Errorf("controller configuration epoch %d did not advance from %d", configuration.GetConfigurationEpoch(), epoch)
				}
				var receivedAddresses []netip.Prefix
				if updateErr == nil {
					receivedAddresses, updateErr = controllerOverlayAddresses(configuration, local, time.Now())
				}
				if updateErr == nil && !samePrefixes(receivedAddresses, expectedAddresses) {
					updateErr = errors.New("controller attempted to change the active TUN overlay assignment")
				}
				if updateErr == nil {
					updateErr = applyControllerConfiguration(ctx, configuration, local, routeTable, routeManager, bypass, policyTable, subnetManager, ipForwardManager, exitManagers, applyState)
				}
				if updateErr == nil {
					epoch, last = configuration.GetConfigurationEpoch(), configuration
					deadline, _ = configurationDeadline(configuration.GetValidUntilUnixSeconds(), time.Now())
					failClosed = false
				}
			}
		}
		if updateErr != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "lanewayd: controller update:", updateErr)
		}
		if errors.Is(updateErr, errControllerRuntimeUnauthorized) && !failClosed {
			expired := failClosedNodeConfiguration(last, local)
			if closeErr := applyControllerConfiguration(ctx, expired, local, routeTable, routeManager, bypass, policyTable, subnetManager, ipForwardManager, exitManagers, applyState); closeErr != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "lanewayd: fail close withdrawn runtime authority:", closeErr)
			}
			failClosed = true
		}
		if !failClosed && !deadline.After(time.Now()) {
			expired := failClosedNodeConfiguration(last, local)
			if closeErr := applyControllerConfiguration(ctx, expired, local, routeTable, routeManager, bypass, policyTable, subnetManager, ipForwardManager, exitManagers, applyState); closeErr != nil {
				if ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "lanewayd: expire controller snapshot:", closeErr)
				}
			}
			failClosed = true
		}
		next := interval
		if until := time.Until(deadline); until > 0 && until < next {
			next = until
		}
		if next <= 0 {
			next = min(interval, time.Second)
		}
		timer.Reset(next)
	}
}

func failClosedNodeConfiguration(last *lanewayv1.NodeConfiguration, local identity.NodeIdentity) *lanewayv1.NodeConfiguration {
	epoch := last.GetConfigurationEpoch()
	return &lanewayv1.NodeConfiguration{
		ConfigurationEpoch: epoch, OverlayAddresses: last.GetOverlayAddresses(),
		Routes: &lanewayv1.RouteSnapshot{NetworkId: append([]byte(nil), local.NetworkID[:]...), ConfigurationEpoch: epoch},
		Policy: &lanewayv1.PolicySnapshot{NetworkId: append([]byte(nil), local.NetworkID[:]...), ConfigurationEpoch: epoch,
			DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY},
		EnabledCapabilities: last.GetEnabledCapabilities(), ValidUntilUnixSeconds: last.GetValidUntilUnixSeconds(),
	}
}

func applyControllerConfiguration(ctx context.Context, configuration *lanewayv1.NodeConfiguration, local identity.NodeIdentity,
	routeTable *routing.Table, routeManager platform.RouteManager, bypass []netip.Addr, policyTable *policy.Table,
	subnetManager *daemonSubnetManager, ipForwardManager *daemonIPForwardManager, exitManagers *daemonExitManagers,
	stateArgs ...*controllerApplyState,
) error {
	state := new(controllerApplyState)
	if len(stateArgs) != 0 && stateArgs[0] != nil {
		state = stateArgs[0]
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	next, err := prepareControllerConfiguration(configuration, local, bypass, subnetManager, exitManagers)
	if err != nil {
		return err
	}
	if !next.failClosing {
		next.authorityStatus, err = validateNodeRuntimeAuthority(configuration, state.authority, time.Now())
		if err != nil {
			return err
		}
		if state.authority != nil {
			var relayBypass []netip.Addr
			next.authorityStatus.relayTargets, relayBypass, err = resolveNodeRelayTargets(ctx, next.authorityStatus.relayTargets)
			if err != nil {
				return err
			}
			next.osPlan.TransportBypass = append(append([]netip.Addr(nil), bypass...), relayBypass...)
			next.authorityStatus.relayBypass = append([]netip.Addr(nil), relayBypass...)
		}
	}
	if state.wireGuard != nil {
		if next.failClosing {
			next.wireGuard = &wireguard.SecureSnapshot{Firewall: wireguard.FirewallPlan{
				Epoch: configuration.GetConfigurationEpoch(), LocalNode: local.NodeID,
				PeerPrefixes: map[identity.NodeID][]netip.Prefix{}, DefaultAction: wireguard.FirewallDeny,
			}}
		} else {
			var selectedExit identity.NodeID
			if exitManagers != nil {
				selectedExit = exitManagers.SelectedNode()
			}
			preparedWireGuard, prepareErr := prepareWireGuardSnapshot(configuration, local, state.wireGuard.PublicKey(), selectedExit)
			if prepareErr != nil {
				return prepareErr
			}
			next.wireGuard = &wireguard.SecureSnapshot{Peers: preparedWireGuard.peers, Firewall: preparedWireGuard.firewall}
		}
	}
	if state.accepted != nil && !state.accepted.failClosing && !next.failClosing &&
		next.configuration.GetConfigurationEpoch() <= state.accepted.configuration.GetConfigurationEpoch() {
		return fmt.Errorf("controller configuration epoch %d did not advance from %d",
			next.configuration.GetConfigurationEpoch(), state.accepted.configuration.GetConfigurationEpoch())
	}
	if state.revoked != nil {
		if err := state.revoked.Replace(next.revokedSerials); err != nil {
			return err
		}
	}
	if next.failClosing {
		var wireGuardErr error
		if state.wireGuard != nil {
			wireGuardErr = state.wireGuard.ApplySnapshot(ctx, *next.wireGuard)
		}
		state.publishRelayTargets(nil)
		state.candidateEnabled.Store(false)
		state.candidateMax.Store(0)
		state.candidateTTLSeconds.Store(0)
		state.certificateRenewalNeeded.Store(true)
		// Authorization is revoked in userspace before best-effort privileged
		// cleanup. A stuck route, nftables, DNS, or sysctl owner must never keep
		// the expired dataplane and policy authorized.
		routeTable.Replace(next.snapshot)
		result := errors.Join(wireGuardErr, policyTable.Replace(next.policy))
		result = errors.Join(result, subnetManager.DenyForwardPrefixes())
		result = errors.Join(result, routeManager.Apply(ctx, next.osPlan))
		result = errors.Join(result, subnetManager.ApplyPlan(ctx, next.subnetPlan))
		if exitManagers != nil {
			result = errors.Join(result, exitManagers.SetControllerRelayEndpoints(ctx, nil))
			result = errors.Join(result, exitManagers.Apply(ctx, configuration, next.routes))
		}
		if ipForwardManager != nil {
			result = errors.Join(result, ipForwardManager.Apply(ctx, ipForwardFamilies{}))
		}
		state.accepted = next
		return result
	}
	// Route and ACL state are published through separate read-mostly tables.
	// Install an epoch-scoped deny guard before any slow native mutation so a
	// packet can never observe newly authorized routing under an older, broader
	// ACL. The desired policy is published only after routes and forwarding are
	// complete; failures restore the prior complete authority last.
	var previousPolicy *policy.Engine
	if state.accepted != nil {
		previousPolicy = state.accepted.policy
	}
	if err := policyTable.Replace(next.denyPolicy); err != nil {
		return err
	}
	restorePreviousPolicy := func() error {
		if previousPolicy == nil {
			return nil // The fail-closed transition policy remains authoritative.
		}
		return policyTable.Replace(previousPolicy)
	}
	if state.wireGuard != nil {
		if err := state.wireGuard.ApplyGuard(ctx, next.wireGuard.Firewall); err != nil {
			return errors.Join(err, restorePreviousPolicy())
		}
	}
	rollback := func(cause error) error {
		var wireGuardErr error
		if state.wireGuard != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if state.accepted != nil && state.accepted.wireGuard != nil {
				wireGuardErr = state.wireGuard.ApplySnapshot(rollbackCtx, *state.accepted.wireGuard)
			} else {
				wireGuardErr = state.wireGuard.RestoreGuard(rollbackCtx)
			}
		}
		return errors.Join(cause,
			rollbackControllerConfiguration(ctx, state.accepted, bypass, routeManager, subnetManager, ipForwardManager, exitManagers),
			wireGuardErr,
			restorePreviousPolicy())
	}
	if ipForwardManager != nil {
		if err := ipForwardManager.Apply(ctx, next.forwarding); err != nil {
			return rollback(err)
		}
	}
	if err := routeManager.Apply(ctx, next.osPlan); err != nil {
		return rollback(err)
	}
	if err := subnetManager.ApplyPlan(ctx, next.subnetPlan); err != nil {
		return rollback(err)
	}
	if exitManagers != nil {
		if err := exitManagers.Apply(ctx, configuration, next.routes); err != nil {
			return rollback(err)
		}
	}
	if err := subnetManager.PublishPrefixes(next.forwardPrefix); err != nil {
		return rollback(err)
	}
	if state.wireGuard != nil {
		if err := state.wireGuard.ApplySnapshot(ctx, *next.wireGuard); err != nil {
			return rollback(err)
		}
	}
	if exitManagers == nil {
		routeTable.Replace(next.snapshot)
	}
	if err := policyTable.Replace(next.policy); err != nil {
		previousPrefixes := []netip.Prefix(nil)
		if state.accepted != nil {
			previousPrefixes = state.accepted.forwardPrefix
		}
		return errors.Join(subnetManager.PublishPrefixes(previousPrefixes), rollback(err))
	}
	if exitManagers != nil {
		if err := exitManagers.SetControllerRelayEndpoints(ctx, next.authorityStatus.relayBypass); err != nil {
			return rollback(err)
		}
	}
	state.accepted = next
	state.candidateEnabled.Store(next.authorityStatus.candidateEnabled)
	state.candidateMax.Store(next.authorityStatus.candidateMax)
	state.candidateTTLSeconds.Store(next.authorityStatus.candidateTTLSeconds)
	state.certificateRenewalNeeded.Store(next.authorityStatus.renewalNeeded)
	state.certificateRenewAfter.Store(next.authorityStatus.certificateRenewAfter)
	state.certificateNotAfter.Store(next.authorityStatus.certificateNotAfter)
	state.publishRelayTargets(next.authorityStatus.relayTargets)
	return nil
}

type daemonExitManagers struct {
	mu                    sync.Mutex
	client                *exitnode.ClientManager
	gateway               exitnode.GatewayManager
	selected              identity.NodeID
	local                 identity.NodeIdentity
	failureMode           exitnode.FailureMode
	failureModeConfigured bool
	staticBypass          []netip.Addr
	directBypass          []netip.Addr
	controllerRelayBypass []netip.Addr
	bypass                []netip.Addr
	localLAN              []netip.Prefix
	dns                   []netip.Addr
	enabled               bool
	authorized            bool
	latest                *lanewayv1.NodeConfiguration
	baseRoutes            []routing.Route
	routeTable            *routing.Table
	pathHealthy           func(identity.NodeID) bool
	intentStore           *exitIntentStore
	intentPersisted       bool
}

func (m *daemonExitManagers) SelectedNode() identity.NodeID {
	if m == nil {
		return identity.NodeID{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return identity.NodeID{}
	}
	return m.selected
}

func newDaemonExitManagers(cfg config.Config, local identity.NodeIdentity, interfaceName string, bypass []netip.Addr, routeTable *routing.Table,
	intentStore *exitIntentStore, intentPersisted bool, externalRoutes exitnode.RouteManager, externalDNS exitnode.DNSManager,
) (*daemonExitManagers, error) {
	managers := &daemonExitManagers{local: local, staticBypass: append([]netip.Addr(nil), bypass...), bypass: append([]netip.Addr(nil), bypass...), enabled: cfg.Exit.Enabled,
		routeTable: routeTable, failureModeConfigured: cfg.Exit.FailureMode == "open" || cfg.Exit.FailureMode == "closed",
		intentStore: intentStore, intentPersisted: intentPersisted}
	var err error
	if cfg.Exit.Enabled {
		managers.selected, err = identity.ParseNodeID(cfg.Exit.SelectedNodeID)
		if err != nil {
			return nil, err
		}
		if managers.selected.IsZero() || managers.selected == local.NodeID {
			return nil, errors.New("selected exit node must be nonzero and different from the local node")
		}
		if cfg.Exit.FailureMode == "open" {
			managers.failureMode = exitnode.FailureModeOpen
		} else {
			managers.failureMode = exitnode.FailureModeClosed
		}
	}
	if cfg.Exit.FailureMode == "open" {
		managers.failureMode = exitnode.FailureModeOpen
	} else {
		managers.failureMode = exitnode.FailureModeClosed
	}
	for _, value := range cfg.Exit.DNSServers {
		managers.dns = append(managers.dns, netip.MustParseAddr(value))
	}
	for _, value := range cfg.Exit.LocalLANBypasses {
		managers.localLAN = append(managers.localLAN, netip.MustParsePrefix(value))
	}
	if cfg.Controller.Endpoint != "" {
		if (externalRoutes == nil) != (externalDNS == nil) {
			return nil, errors.New("exit route and DNS managers must be supplied together")
		}
		routes, dns := externalRoutes, externalDNS
		if routes == nil {
			routes, err = exitnode.NewRouteManager(exitnode.RouteManagerConfig{InterfaceName: interfaceName})
			if err != nil {
				return nil, err
			}
			dns, err = exitnode.NewDNSManager(exitnode.DNSManagerConfig{InterfaceName: interfaceName})
			if err != nil {
				routes.Close()
				return nil, err
			}
		}
		managers.client, err = exitnode.NewClientManager(routes, dns, 0)
		if err != nil {
			routes.Close()
			dns.Close()
			return nil, err
		}
	}
	if cfg.Exit.Serve {
		managers.gateway, err = exitnode.NewGatewayManager(exitnode.GatewayManagerConfig{
			InputInterface: interfaceName, OutputInterface: cfg.Routing.OutputInterface,
			ForwardingExternallyManaged: true,
		})
		if err != nil {
			if managers.client != nil {
				managers.client.Close()
			}
			return nil, err
		}
	}
	return managers, nil
}

func (m *daemonExitManagers) Apply(ctx context.Context, configuration *lanewayv1.NodeConfiguration, baseRoutes []routing.Route) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(ctx, configuration, baseRoutes)
}

func (m *daemonExitManagers) Validate(configuration *lanewayv1.NodeConfiguration, baseRoutes []routing.Route) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.prepareLocked(configuration, baseRoutes)
	return err
}

func (m *daemonExitManagers) Restore(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var result error
	if m.gateway != nil {
		result = errors.Join(result, m.gateway.Restore(ctx))
	}
	if m.client != nil {
		result = errors.Join(result, m.client.Restore(ctx))
	}
	if result == nil {
		m.latest = nil
		m.baseRoutes = nil
		m.authorized = false
		if m.routeTable != nil {
			m.routeTable.Replace(nil)
		}
	}
	return result
}

type daemonExitPlan struct {
	client     exitnode.ClientPlan
	gateway    exitnode.GatewayPlan
	routes     *routing.Snapshot
	authorized bool
}

func (m *daemonExitManagers) prepareLocked(configuration *lanewayv1.NodeConfiguration, baseRoutes []routing.Route) (daemonExitPlan, error) {
	var clientAuthorized, gatewayAuthorized bool
	var clientExitPrefixes []netip.Prefix
	var overlaySources []netip.Prefix
	for _, route := range configuration.GetRoutes().GetRoutes() {
		prefix, err := protoPrefix(route.GetDestination())
		if err != nil || len(route.GetViaNodeId()) != identity.IDSize {
			return daemonExitPlan{}, errors.New("invalid exit configuration route")
		}
		var via identity.NodeID
		copy(via[:], route.GetViaNodeId())
		switch route.GetKind() {
		case lanewayv1.RouteKind_ROUTE_KIND_EXIT:
			if prefix.Bits() == 0 {
				if m.enabled && via == m.selected {
					clientAuthorized = true
					clientExitPrefixes = append(clientExitPrefixes, prefix)
				}
				gatewayAuthorized = gatewayAuthorized || via == m.local.NodeID
			}
		case lanewayv1.RouteKind_ROUTE_KIND_OVERLAY:
			if prefix.Bits() > 0 {
				overlaySources = append(overlaySources, prefix)
			}
		}
	}
	pathAvailable := false
	if clientAuthorized && m.pathHealthy != nil {
		pathAvailable = m.pathHealthy(m.selected)
	}
	clientPlan := exitnode.ClientPlan{
		Enabled: clientAuthorized, Authorized: clientAuthorized, FailureMode: m.failureMode,
		PathAvailable: pathAvailable, ExitPrefixes: clientExitPrefixes, TransportBypass: m.bypass,
		LocalLANBypass: m.localLAN, DNSServers: m.dns,
	}
	if m.client != nil {
		if err := exitnode.ValidateClientPlan(clientPlan); err != nil {
			return daemonExitPlan{}, err
		}
	}
	routes := append([]routing.Route(nil), baseRoutes...)
	if clientAuthorized {
		for _, prefix := range clientExitPrefixes {
			routes = append(routes, routing.Route{Prefix: prefix, NextHop: m.selected})
		}
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		return daemonExitPlan{}, err
	}
	gatewayPlan := exitnode.GatewayPlan{Enabled: gatewayAuthorized, Authorized: gatewayAuthorized, OverlaySources: overlaySources}
	if m.gateway != nil {
		if err := exitnode.ValidateGatewayPlan(gatewayPlan); err != nil {
			return daemonExitPlan{}, err
		}
	}
	return daemonExitPlan{client: clientPlan, gateway: gatewayPlan, routes: snapshot, authorized: clientAuthorized}, nil
}

func (m *daemonExitManagers) applyLocked(ctx context.Context, configuration *lanewayv1.NodeConfiguration, baseRoutes []routing.Route) error {
	next, err := m.prepareLocked(configuration, baseRoutes)
	if err != nil {
		return err
	}
	var previous daemonExitPlan
	if m.latest != nil {
		previous, err = m.prepareLocked(m.latest, m.baseRoutes)
		if err != nil {
			return fmt.Errorf("prepare previous exit snapshot: %w", err)
		}
	}
	if m.client != nil {
		if err := m.client.Apply(ctx, next.client); err != nil {
			return err
		}
	}
	if m.gateway != nil {
		if err := m.gateway.Apply(ctx, next.gateway); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), exitnode.DefaultShutdownTimeout)
			defer cancel()
			var rollbackErr error
			if m.latest != nil {
				rollbackErr = errors.Join(rollbackErr, m.gateway.Apply(rollbackCtx, previous.gateway))
			} else {
				rollbackErr = errors.Join(rollbackErr, m.gateway.Restore(rollbackCtx))
			}
			if m.client != nil {
				if m.latest != nil {
					rollbackErr = errors.Join(rollbackErr, m.client.Apply(rollbackCtx, previous.client))
				} else {
					rollbackErr = errors.Join(rollbackErr, m.client.Restore(rollbackCtx))
				}
			}
			return errors.Join(err, rollbackErr)
		}
	}
	if m.routeTable != nil {
		m.routeTable.Replace(next.routes)
	}
	m.latest = configuration
	m.baseRoutes = append(m.baseRoutes[:0], baseRoutes...)
	m.authorized = next.authorized
	return nil
}

func (m *daemonExitManagers) SetSelection(ctx context.Context, enabled bool, selected identity.NodeID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return errors.New("exit client is not configured")
	}
	if enabled && (selected.IsZero() || selected == m.local.NodeID) {
		return errors.New("selected exit node is invalid")
	}
	if enabled && !m.enabled && !m.failureModeConfigured {
		return errors.New("exit failure_mode is not configured")
	}
	if enabled && len(m.dns) == 0 {
		return errors.New("exit DNS servers are not configured")
	}
	failureMode := ""
	if enabled {
		switch m.failureMode {
		case exitnode.FailureModeOpen:
			failureMode = "open"
		case exitnode.FailureModeClosed:
			failureMode = "closed"
		default:
			return errors.New("exit failure_mode is not configured")
		}
	}
	previousEnabled, previousSelected := m.enabled, m.selected
	previousPersisted := m.intentPersisted
	if m.intentStore != nil {
		if err := m.intentStore.Save(enabled, selected, failureMode); err != nil {
			return fmt.Errorf("persist exit selection: %w", err)
		}
		m.intentPersisted = true
	}
	m.enabled, m.selected = enabled, selected
	if m.latest != nil {
		if err := m.applyLocked(ctx, m.latest, m.baseRoutes); err != nil {
			m.enabled, m.selected = previousEnabled, previousSelected
			rollbackCtx, cancel := context.WithTimeout(context.Background(), exitnode.DefaultShutdownTimeout)
			defer cancel()
			applyRollbackErr := m.applyLocked(rollbackCtx, m.latest, m.baseRoutes)
			var persistenceRollbackErr error
			if m.intentStore != nil {
				if previousPersisted {
					previousMode := ""
					if previousEnabled {
						switch m.failureMode {
						case exitnode.FailureModeOpen:
							previousMode = "open"
						case exitnode.FailureModeClosed:
							previousMode = "closed"
						}
					}
					persistenceRollbackErr = m.intentStore.Save(previousEnabled, previousSelected, previousMode)
				} else {
					persistenceRollbackErr = m.intentStore.Remove()
				}
				m.intentPersisted = previousPersisted
			}
			if persistenceRollbackErr != nil {
				persistenceRollbackErr = fmt.Errorf("restore persisted exit selection: %w", persistenceRollbackErr)
			}
			return errors.Join(err, applyRollbackErr, persistenceRollbackErr)
		}
	}
	return nil
}

func (m *daemonExitManagers) SetPathAvailable(check func(identity.NodeID) bool) {
	m.mu.Lock()
	m.pathHealthy = check
	m.mu.Unlock()
}

// SetDirectPathEndpoints transactionally folds active authenticated peer
// endpoints into the exit client's native transport bypasses. This prevents a
// selected direct QUIC path from being recursively captured by lane0's full
// tunnel routes. An update that cannot be installed leaves the prior bypass
// set and exit plan active.
func (m *daemonExitManagers) SetDirectPathEndpoints(ctx context.Context, endpoints []netip.Addr) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	previous := append([]netip.Addr(nil), m.directBypass...)
	m.directBypass = append([]netip.Addr(nil), endpoints...)
	m.mu.Unlock()
	if err := m.reconcileTransportBypasses(ctx); err != nil {
		m.mu.Lock()
		m.directBypass = previous
		m.mu.Unlock()
		return err
	}
	return nil
}

func (m *daemonExitManagers) SetControllerRelayEndpoints(ctx context.Context, endpoints []netip.Addr) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	previous := append([]netip.Addr(nil), m.controllerRelayBypass...)
	m.controllerRelayBypass = append([]netip.Addr(nil), endpoints...)
	m.mu.Unlock()
	if err := m.reconcileTransportBypasses(ctx); err != nil {
		m.mu.Lock()
		m.controllerRelayBypass = previous
		m.mu.Unlock()
		return err
	}
	return nil
}

func (m *daemonExitManagers) reconcileTransportBypasses(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := append(append(append([]netip.Addr(nil), m.staticBypass...), m.controllerRelayBypass...), m.directBypass...)
	unique := make(map[netip.Addr]struct{}, len(all))
	next := make([]netip.Addr, 0, len(all))
	for _, address := range all {
		address = address.Unmap()
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("invalid direct transport bypass endpoint %q", address)
		}
		if _, exists := unique[address]; exists {
			continue
		}
		unique[address] = struct{}{}
		next = append(next, address)
	}
	sort.Slice(next, func(i, j int) bool { return next[i].Compare(next[j]) < 0 })
	if slices.Equal(m.bypass, next) {
		return nil
	}
	previous := append([]netip.Addr(nil), m.bypass...)
	m.bypass = next
	if m.latest == nil {
		return nil
	}
	if err := m.applyLocked(ctx, m.latest, m.baseRoutes); err != nil {
		m.bypass = previous
		rollbackCtx, cancel := context.WithTimeout(context.Background(), exitnode.DefaultShutdownTimeout)
		defer cancel()
		return errors.Join(err, m.applyLocked(rollbackCtx, m.latest, m.baseRoutes))
	}
	return nil
}

func (m *daemonExitManagers) MonitorPath(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			if m.latest != nil {
				if err := m.applyLocked(ctx, m.latest, m.baseRoutes); err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "lanewayd: reconcile exit path:", err)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *daemonExitManagers) Status() localapi.ExitStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := localapi.ExitStatus{Enabled: m.enabled, Authorized: m.authorized}
	if !m.selected.IsZero() {
		status.SelectedNodeID = m.selected.String()
	}
	return status
}

func (m *daemonExitManagers) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result error
	if m.client != nil {
		result = errors.Join(result, m.client.Close())
	}
	if m.gateway != nil {
		result = errors.Join(result, m.gateway.Close())
	}
	return result
}

func protoPrefix(value *lanewayv1.IpPrefix) (netip.Prefix, error) {
	if value == nil {
		return netip.Prefix{}, errors.New("nil prefix")
	}
	address, ok := netip.AddrFromSlice(value.GetAddress())
	if !ok || address.Is4In6() || value.GetPrefixLength() > uint32(address.BitLen()) {
		return netip.Prefix{}, errors.New("invalid prefix address")
	}
	prefix := netip.PrefixFrom(address, int(value.GetPrefixLength()))
	if prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("noncanonical prefix")
	}
	return prefix, nil
}

type tunPacketIO struct{ platform.TUNDevice }

func (t tunPacketIO) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	return t.Read(ctx, buffer)
}

func (t tunPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	n, err := t.Write(ctx, packet)
	if err == nil && n != len(packet) {
		return fmt.Errorf("short TUN write: %d of %d", n, len(packet))
	}
	return err
}

func buildRoutes(local identity.NodeIdentity, peers []config.AuthorizedPeer) (*routing.Table, []platform.Route, error) {
	var routes []routing.Route
	var osRoutes []platform.Route
	for i, peer := range peers {
		networkID, err := identity.ParseNetworkID(peer.NetworkID)
		if err != nil {
			return nil, nil, err
		}
		if networkID != local.NetworkID {
			return nil, nil, fmt.Errorf("peers[%d] belongs to a different network", i)
		}
		nodeID, err := identity.ParseNodeID(peer.NodeID)
		if err != nil {
			return nil, nil, err
		}
		if nodeID == local.NodeID {
			continue
		}
		for _, value := range peer.Prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, nil, err
			}
			if netvalidate.RoutablePrefix(prefix, false) != nil {
				return nil, nil, fmt.Errorf("peer route must be a canonical non-default IP prefix, got %s", prefix)
			}
			routes = append(routes, routing.Route{Prefix: prefix, NextHop: nodeID})
			osRoutes = append(osRoutes, platform.Route{Prefix: prefix})
		}
	}
	snapshot, err := routing.NewSnapshot(routes)
	if err != nil {
		return nil, nil, err
	}
	return routing.NewTable(snapshot), osRoutes, nil
}

func parseForwardPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || netvalidate.RoutablePrefix(prefix, false) != nil {
			return nil, fmt.Errorf("advertised route %q must be a canonical non-default IP prefix", value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func overlayAddresses(values []string) ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		hostBits := 32
		if err == nil && prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
			hostBits = 128
		}
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() != hostBits || prefix != prefix.Masked() ||
			prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			return nil, fmt.Errorf("overlay address %q must be a canonical unicast IPv4 /32 or IPv6 /128", value)
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}
