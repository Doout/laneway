package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/endpointpin"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/observability"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/relay"
	"github.com/Doout/laneway/go/internal/relayservice"
	"github.com/Doout/laneway/go/internal/revocation"
	"github.com/Doout/laneway/go/internal/tcpfallback"
	"github.com/Doout/laneway/go/internal/transport"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const relayMaxPacketPayload = 2048

func main() {
	fs := flag.NewFlagSet("laneway-relay", flag.ExitOnError)
	configPath := fs.String("config", "/etc/laneway/laneway.toml", "configuration file")
	diagnostics := fs.String("diagnostics", "", "loopback metrics/pprof address (for example 127.0.0.1:6060)")
	version := fs.Bool("version", false, "print the Laneway build version")
	_ = fs.Parse(os.Args[1:])
	if *version {
		fmt.Println(buildinfo.Version)
		return
	}
	if err := run(*configPath, *diagnostics); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "laneway-relay:", err)
		os.Exit(1)
	}
}

func run(path, diagnostics string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Mode != config.ModeRelay {
		return fmt.Errorf("configuration mode is %q, want %q", cfg.Mode, config.ModeRelay)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	revokedCertificates := new(revocation.Set)
	tlsConfig, err := transport.LoadServerTLSConfigWithRevocations(cfg.TLS.CAFile, cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, revokedCertificates)
	if err != nil {
		return err
	}
	var authorizer relayservice.Authorizer
	var packetPolicy relayservice.PacketPolicy
	var controllerSource relayConfigurationSource
	var controllerClient *controllerclient.Client
	var controllerState *controllerRelayState
	if cfg.Controller.Endpoint == "" {
		static, err := staticAuthorizer(cfg.Peers)
		if err != nil {
			return err
		}
		authorizer = static
	} else {
		if len(tlsConfig.Certificates) == 0 || tlsConfig.Certificates[0].Leaf == nil {
			return errors.New("relay certificate identity is unavailable")
		}
		relayIdentity, err := identity.AuthenticatedIdentityFromCertificate(tlsConfig.Certificates[0].Leaf)
		if err != nil || relayIdentity.RequireRole(identity.IdentityRoleRelay) != nil {
			return errors.New("relay certificate does not contain a valid relay identity")
		}
		controllerState, err = newControllerRelayState(relayIdentity.NetworkID, revokedCertificates)
		if err != nil {
			return err
		}
		if err := controllerState.SetLocalCertificate(tlsConfig.Certificates[0].Leaf); err != nil {
			return err
		}
		controllerEndpoint, err := endpointpin.HTTPS(ctx, cfg.Controller.Endpoint, endpointpin.Options{})
		if err != nil {
			return fmt.Errorf("pin controller endpoint: %w", err)
		}
		var controllerQUICEndpoint endpointpin.Endpoint
		if cfg.Controller.QUICEndpoint != "" {
			controllerQUICEndpoint, err = endpointpin.HostPort(ctx, cfg.Controller.QUICEndpoint, endpointpin.Options{})
			if err != nil {
				return fmt.Errorf("pin controller QUIC endpoint: %w", err)
			}
		}
		controllerNetworkID, _ := identity.ParseNetworkID(cfg.Controller.NetworkID)
		controllerServiceID, _ := identity.ParseID(cfg.Controller.ServiceID)
		if controllerNetworkID != relayIdentity.NetworkID {
			return errors.New("configured controller network ID does not match the relay certificate network")
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
		controllerClient = client
		controllerSource = client
		authorizer, packetPolicy = controllerState, controllerState
	}
	tcpConfig := &tcpfallback.Config{
		HandshakeTimeout: cfg.TCPFallback.HandshakeTimeout.Duration(),
		WriteTimeout:     cfg.TCPFallback.WriteTimeout.Duration(),
		IdleTimeout:      cfg.TCPFallback.IdleTimeout.Duration(),
		KeepAlivePeriod:  cfg.TCPFallback.KeepAlivePeriod.Duration(),
		QueueDepth:       cfg.TCPFallback.QueueDepth,
		MaxPacketPayload: relayMaxPacketPayload + protocol.PacketHeaderSize,
	}
	serviceConfig := relayservice.Config{
		Authorizer: authorizer, PacketPolicy: packetPolicy, Revocations: revokedCertificates,
		Registry: relay.Config{
			MaxSessions:             4096,
			MaxHandlesPerSession:    4096,
			OutboundQueueCapacity:   cfg.Relay.QueueDepth,
			MaxPacketPayload:        relayMaxPacketPayload,
			DuplicatePolicy:         relay.ReplaceDuplicate,
			QueuePolicy:             relay.DropNewest,
			PacketRateBitsPerSecond: cfg.Relay.PacketRateBitsPerSecond,
			PacketBurstBytes:        cfg.Relay.PacketBurstBytes,
		},
		Transport: &transport.Config{
			HandshakeIdleTimeout: cfg.Relay.HandshakeTimeout.Duration(),
			MaxIdleTimeout:       cfg.Relay.IdleTimeout.Duration(),
		},
		TCPFallback:        tcpConfig,
		MaxPacketPayload:   relayMaxPacketPayload,
		ConfigurationEpoch: 1,
		ProtocolVersion:    protocol.Version{Major: protocol.ProtocolMajor1},
	}
	if controllerState != nil {
		serviceConfig.ConfigurationEpoch = 0
		serviceConfig.ConfigurationEpochSource = controllerState.Epoch
	}
	service, err := relayservice.New(serviceConfig)
	if err != nil {
		return err
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	var updatesDone chan error
	if controllerSource != nil {
		ready := make(chan error, 1)
		updatesDone = make(chan error, 1)
		go func() {
			updatesDone <- runRelayConfigurationUpdates(runCtx, cfg.Controller.PollInterval.Duration(), controllerSource,
				controllerState, func(updateCtx context.Context) error {
					_, updateErr := service.Reauthorize(updateCtx)
					return updateErr
				}, ready, func(updateErr error) {
					fmt.Fprintln(os.Stderr, "laneway-relay: controller update:", updateErr)
				})
		}()
		if err := <-ready; err != nil {
			cancelRun()
			<-updatesDone
			return err
		}
	}
	quicListener, err := transport.Listen(cfg.Relay.Listen, tlsConfig, &transport.Config{
		HandshakeIdleTimeout: cfg.Relay.HandshakeTimeout.Duration(),
		MaxIdleTimeout:       cfg.Relay.IdleTimeout.Duration(),
	})
	if err != nil {
		cancelRun()
		if updatesDone != nil {
			<-updatesDone
		}
		return err
	}
	defer quicListener.Close()
	diagnosticsDone, err := observability.Start(runCtx, observability.Config{Listen: diagnostics, Snapshot: func() map[string]uint64 {
		serviceMetrics := service.Metrics()
		metrics := serviceMetrics.Registry
		values := map[string]uint64{
			"relay_sessions":              uint64(metrics.Sessions),
			"relay_bindings":              uint64(metrics.Bindings),
			"relay_queued_packets":        uint64(metrics.QueuedPackets),
			"relay_queued_bytes":          uint64(metrics.QueuedBytes),
			"transport_connections_total": serviceMetrics.ConnectionsAccepted,
			"transport_failures_total":    serviceMetrics.AcceptFailures,
			"malformed_input_total":       serviceMetrics.MalformedInput + metrics.DroppedMalformed,
			"authorization_failures_total": serviceMetrics.AuthorizationFailures + metrics.DroppedUnknownHandle +
				metrics.DroppedNoReturnHandle + metrics.DroppedSource + metrics.DroppedDestination + metrics.DroppedCapability,
			"policy_drops_total":      serviceMetrics.PolicyDrops,
			"forwarded_packets_total": metrics.ForwardedPackets,
			"forwarded_bytes_total":   metrics.ForwardedBytes,
			"throttled_packets_total": metrics.ThrottledPackets,
			"throttled_bytes_total":   metrics.ThrottledBytes,
			"limiter_saturated":       metrics.LimiterSaturated,
			"queue_full_drops_total":  metrics.DroppedQueueFull,
			"dropped_packets_total":   metrics.DroppedPackets + serviceMetrics.DroppedPackets,
			"dropped_bytes_total":     metrics.DroppedBytes + serviceMetrics.DroppedBytes,
		}
		if controllerState != nil {
			renewal, renewAfter, notAfter := controllerState.CertificateHealth()
			values["controller_certificate_renew_after_unix_seconds"] = renewAfter
			values["controller_certificate_not_after_unix_seconds"] = notAfter
			if renewal {
				values["controller_certificate_renewal_needed"] = 1
			}
		}
		return values
	}})
	if err != nil {
		return err
	}
	serveDone := make(chan error, 1)
	if cfg.TCPFallback.Listen == "" {
		fmt.Printf("laneway-relay QUIC listening on %s\n", cfg.Relay.Listen)
		go func() { serveDone <- service.Serve(runCtx, quicListener) }()
	} else {
		var tcpListener *tcpfallback.Listener
		var listenErr error
		if cfg.PublicHTTPS.ServerName == "" {
			tcpListener, listenErr = tcpfallback.Listen(cfg.TCPFallback.Listen, tlsConfig, tcpConfig)
		} else {
			if err := os.MkdirAll(cfg.PublicHTTPS.CacheDir, 0o700); err != nil {
				return fmt.Errorf("create public certificate cache: %w", err)
			}
			manager := &autocert.Manager{
				Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(cfg.PublicHTTPS.CacheDir),
				HostPolicy: autocert.HostWhitelist(cfg.PublicHTTPS.ServerName),
			}
			publicTLS := manager.TLSConfig()
			publicTLS.MinVersion = tls.VersionTLS13
			publicTLS.MaxVersion = tls.VersionTLS13
			// The socket is handed to an already-TLS HTTP/1 server after ALPN
			// dispatch; keep TLS-ALPN ACME and HTTP/1.1 explicit here.
			publicTLS.NextProtos = []string{"http/1.1", acme.ALPNProto}
			limiter := newPublicRateLimiter()
			tcpListener, listenErr = tcpfallback.ListenWithHTTPS(cfg.TCPFallback.Listen, tlsConfig, tcpConfig, tcpfallback.HTTPSOptions{
				TLSConfig: publicTLS, Handler: publicBootstrapHandler(controllerClient, limiter),
				Authenticated: limiter.MarkAuthenticated,
			})
		}
		if listenErr != nil {
			cancelRun()
			if updatesDone != nil {
				<-updatesDone
			}
			return listenErr
		}
		defer tcpListener.Close()
		fmt.Printf("laneway-relay QUIC=%s TCP-fallback=%s\n", cfg.Relay.Listen, cfg.TCPFallback.Listen)
		go func() { serveDone <- service.ServeTransports(runCtx, quicListener, tcpListener) }()
	}
	select {
	case err = <-serveDone:
		cancelRun()
		if diagnosticsDone != nil {
			<-diagnosticsDone
		}
	case diagnosticsErr := <-diagnosticsDone:
		cancelRun()
		<-serveDone
		err = diagnosticsErr
	}
	if updatesDone != nil {
		<-updatesDone
	}
	serviceMetrics := service.Metrics()
	metrics := serviceMetrics.Registry
	dropped := metrics.DroppedMalformed + metrics.DroppedUnknownHandle + metrics.DroppedNoReturnHandle +
		metrics.DroppedSource + metrics.DroppedDestination + metrics.DroppedTooLarge +
		metrics.DroppedCapability + metrics.DroppedQueueFull + metrics.DroppedClosed + metrics.DroppedDisconnect + serviceMetrics.PolicyDrops
	fmt.Printf("laneway-relay stopped sessions=%d forwarded=%d dropped=%d\n",
		metrics.Sessions, metrics.ForwardedPackets, dropped)
	return err
}

type publicBootstrapSource interface {
	BootstrapMetadata(context.Context) ([]byte, error)
	BootstrapBundle(context.Context, string) ([]byte, error)
	PublicConsole(*http.Request) (*http.Response, error)
}

func publicBootstrapHandler(client *controllerclient.Client, limiter *publicRateLimiter) http.Handler {
	if client == nil {
		return publicBootstrapHandlerFromSource(nil, limiter)
	}
	return publicBootstrapHandlerFromSource(client, limiter)
}

func publicBootstrapHandlerFromSource(client publicBootstrapSource, limiter *publicRateLimiter) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		bundleID, bundlePath := bootstrap.BundleIDFromPath(request.URL.Path)
		bootstrapPath := request.URL.Path == bootstrap.WellKnownPath || bundlePath
		if !bootstrapPath {
			proxyPublicConsole(writer, request, client)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !limiter.Allow(request.RemoteAddr) {
			writer.Header().Set("Retry-After", "1")
			http.Error(writer, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			http.NotFound(writer, request)
			return
		}
		if client == nil {
			http.Error(writer, "bootstrap metadata temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		var contents []byte
		var err error
		if bundlePath {
			contents, err = client.BootstrapBundle(request.Context(), bundleID)
		} else {
			contents, err = client.BootstrapMetadata(request.Context())
		}
		if err != nil {
			if bundlePath {
				http.NotFound(writer, request)
				return
			}
			http.Error(writer, "bootstrap metadata temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if bundlePath {
			writer.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		} else {
			writer.Header().Set("Content-Type", "application/json")
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(contents)
		clear(contents)
	})
}

func proxyPublicConsole(writer http.ResponseWriter, request *http.Request, client publicBootstrapSource) {
	path := request.URL.Path
	administrator := path == "/v1/admin" || strings.HasPrefix(path, "/v1/admin/")
	reserved := path == "/v1" || strings.HasPrefix(path, "/v1/") ||
		path == "/.well-known" || strings.HasPrefix(path, "/.well-known/")
	if !administrator && reserved {
		http.NotFound(writer, request)
		return
	}
	if client == nil {
		http.Error(writer, "console temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	response, err := client.PublicConsole(request)
	if err != nil {
		http.Error(writer, "console temporarily unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

func staticAuthorizer(peers []config.AuthorizedPeer) (relayservice.StaticAuthorizer, error) {
	authorizer := make(relayservice.StaticAuthorizer, len(peers))
	for i, peer := range peers {
		networkID, err := identity.ParseNetworkID(peer.NetworkID)
		if err != nil {
			return nil, fmt.Errorf("peers[%d]: %w", i, err)
		}
		nodeID, err := identity.ParseNodeID(peer.NodeID)
		if err != nil {
			return nil, fmt.Errorf("peers[%d]: %w", i, err)
		}
		id := identity.NodeIdentity{NetworkID: networkID, NodeID: nodeID}
		if _, duplicate := authorizer[id]; duplicate {
			return nil, fmt.Errorf("peers[%d]: duplicate identity", i)
		}
		authorization := relayservice.Authorization{}
		for _, value := range peer.Prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("peers[%d] prefix: %w", i, err)
			}
			authorization.AuthorizedPrefixes = append(authorization.AuthorizedPrefixes, prefix)
			if prefix.Bits() == prefix.Addr().BitLen() {
				authorization.OverlayAddresses = append(authorization.OverlayAddresses, prefix.Addr())
			}
		}
		if len(authorization.OverlayAddresses) == 0 {
			return nil, fmt.Errorf("peers[%d] has no overlay host prefix", i)
		}
		authorizer[id] = authorization
	}
	return authorizer, nil
}
