package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/buildinfo"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerservice"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/observability"
	"laneway.dev/laneway/internal/pki"
)

const maxAdminTokenFile = 4096

func main() {
	fs := flag.NewFlagSet("laneway-controller", flag.ExitOnError)
	configPath := fs.String("config", "/etc/laneway/controller.toml", "configuration file")
	diagnostics := fs.String("diagnostics", "", "loopback metrics/pprof address (for example 127.0.0.1:6060)")
	backup := fs.String("backup", "", "write a consistent database backup and exit (never overwrites)")
	restore := fs.String("restore", "", "restore a backup into a missing database and exit")
	consoleDir := fs.String("console-dir", "", "optional absolute directory containing the Laneway administrator console")
	consoleCertificate := fs.String("console-certificate", "", "optional browser-compatible certificate for the HTTPS console and management API")
	consolePrivateKey := fs.String("console-private-key", "", "private key for -console-certificate")
	consoleServerName := fs.String("console-server-name", "", "DNS name or IP address covered by -console-certificate")
	version := fs.Bool("version", false, "print the Laneway build version")
	_ = fs.Parse(os.Args[1:])
	if *version {
		fmt.Println(buildinfo.Version)
		return
	}
	var err error
	switch {
	case fs.NArg() != 0:
		err = fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	case *backup != "" && *restore != "":
		err = errors.New("-backup and -restore are mutually exclusive")
	case (*consoleCertificate == "") != (*consolePrivateKey == "") || (*consoleCertificate == "") != (*consoleServerName == ""):
		err = errors.New("-console-certificate, -console-private-key, and -console-server-name must be specified together")
	case (*backup != "" || *restore != "") && *diagnostics != "":
		err = errors.New("-diagnostics is not valid with a maintenance operation")
	case *backup != "":
		err = runBackup(*configPath, *backup)
	case *restore != "":
		err = runRestore(*configPath, *restore)
	default:
		err = run(*configPath, *diagnostics, *consoleDir, *consoleCertificate, *consolePrivateKey, *consoleServerName)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "laneway-controller:", err)
		os.Exit(1)
	}
}

func loadControllerConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	if cfg.Mode != config.ModeController {
		return config.Config{}, fmt.Errorf("configuration mode is %q, want %q", cfg.Mode, config.ModeController)
	}
	return cfg, nil
}

func runBackup(configPath, destination string) error {
	cfg, err := loadControllerConfig(configPath)
	if err != nil {
		return err
	}
	info, err := os.Lstat(cfg.Controller.DatabaseFile)
	if err != nil {
		return fmt.Errorf("inspect controller database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("controller database is not a regular file: %s", cfg.Controller.DatabaseFile)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := controller.BackupDatabase(ctx, cfg.Controller.DatabaseFile, destination); err != nil {
		return err
	}
	fmt.Printf("controller database backup written to %s\n", destination)
	return nil
}

func runRestore(configPath, source string) error {
	cfg, err := loadControllerConfig(configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Controller.DatabaseFile), 0o700); err != nil {
		return fmt.Errorf("create controller database directory: %w", err)
	}
	lock, err := acquireControllerRestoreLock(cfg.Controller.DatabaseFile)
	if err != nil {
		return fmt.Errorf("restore requires a stopped controller: %w", err)
	}
	defer lock.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := controller.RestoreDatabase(ctx, source, cfg.Controller.DatabaseFile); err != nil {
		return err
	}
	fmt.Printf("controller database restored from %s; start the controller to apply compatible migrations\n", source)
	return nil
}

func run(path, diagnostics, consoleDir, consoleCertificate, consolePrivateKey, consoleServerName string) error {
	cfg, err := loadControllerConfig(path)
	if err != nil {
		return err
	}
	adminCredential, err := adminBearerCredentialFromFile(cfg.Controller.AdminTokenFile)
	if err != nil {
		return err
	}
	defer adminCredential.clear()
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create controller state directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Controller.DatabaseFile), 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	lock, err := acquireControllerDatabaseLock(cfg.Controller.DatabaseFile)
	if err != nil {
		return err
	}
	defer lock.Close()
	caPEM, err := os.ReadFile(cfg.TLS.CAFile)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	issuerPath := cfg.Controller.IssuerCertificateFile
	if issuerPath == "" {
		issuerPath = cfg.TLS.CAFile
	}
	issuerPEM, err := os.ReadFile(issuerPath)
	if err != nil {
		return fmt.Errorf("read issuer certificate bundle: %w", err)
	}
	caKeyPEM, err := os.ReadFile(cfg.Controller.CAPrivateKeyFile)
	if err != nil {
		return fmt.Errorf("read CA private key: %w", err)
	}
	ca, caKey, issuerChain, err := pki.ParseAuthorityBundle(issuerPEM, caKeyPEM)
	if err != nil {
		return err
	}
	tlsConfig, err := controllerTLSConfig(cfg.TLS, caPEM)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := controller.Open(ctx, cfg.Controller.DatabaseFile)
	if err != nil {
		return err
	}
	defer store.Close()
	authState, err := store.AdministratorAuthState(ctx)
	if err != nil {
		return fmt.Errorf("read administrator authentication state: %w", err)
	}
	adminAuthorizer, err := adminCredential.authorizer(authState.RootServicePrincipalID)
	if err != nil {
		return err
	}
	service, err := controllerservice.New(controllerservice.Options{
		Store: store, CACertificate: ca, CAKey: caKey, IssuerChain: issuerChain,
		LeafValidity: cfg.Controller.LeafValidity.Duration(), AdminAuthorizer: adminAuthorizer,
	})
	if err != nil {
		return err
	}
	var bootstrapServer *http.Server
	var bootstrapListener net.Listener
	var bootstrapServeErr <-chan error
	var bootstrapHandler http.Handler
	if cfg.Bootstrap.NetworkID != "" {
		networkID, parseErr := identity.ParseNetworkID(cfg.Bootstrap.NetworkID)
		if parseErr != nil {
			return parseErr
		}
		if _, lookupErr := store.Network(ctx, networkID); lookupErr != nil {
			return fmt.Errorf("bootstrap network: %w", lookupErr)
		}
		controllerIdentity, identityErr := identity.AuthenticatedIdentityFromCertificate(tlsConfig.Certificates[0].Leaf)
		if identityErr != nil {
			return identityErr
		}
		if controllerIdentity.NetworkID != networkID {
			return errors.New("bootstrap network does not match the controller certificate network identity")
		}
		artifacts := make([]bootstrap.Artifact, 0, len(cfg.Bootstrap.Artifacts))
		for _, artifact := range cfg.Bootstrap.Artifacts {
			artifacts = append(artifacts, bootstrap.Artifact{
				OS: artifact.OS, Arch: artifact.Arch, URL: artifact.URL,
				SHA256: artifact.SHA256, SizeBytes: artifact.SizeBytes,
			})
		}
		bootstrapMetadata, bootstrapErr := bootstrap.NewServer(bootstrap.ServerOptions{
			Relays: store, NetworkID: networkID,
			ControllerEndpoint:   cfg.Bootstrap.ControllerEndpoint,
			ControllerQUIC:       cfg.Bootstrap.ControllerQUICEndpoint,
			ControllerServerName: cfg.Bootstrap.ControllerServerName,
			ControllerServiceID:  controllerIdentity.SubjectID,
			CAPEM:                string(caPEM), Artifacts: artifacts,
		})
		if bootstrapErr != nil {
			return bootstrapErr
		}
		// Keep the optional direct public listener metadata-only. One-time
		// Connector bundles are exposed through the relay's public HTTPS
		// listener, which rate-limits the request before fetching the bundle
		// over the authenticated controller connection.
		bootstrapHandler = bootstrapMetadata.Handler()
		if cfg.Bootstrap.Listen != "" {
			publicCertificate, certificateErr := tls.LoadX509KeyPair(cfg.Bootstrap.CertificateFile, cfg.Bootstrap.PrivateKeyFile)
			if certificateErr != nil {
				return fmt.Errorf("load bootstrap Web PKI certificate and key: %w", certificateErr)
			}
			bootstrapServer = &http.Server{
				Addr: cfg.Bootstrap.Listen, Handler: bootstrapHandler,
				TLSConfig:         &tls.Config{Certificates: []tls.Certificate{publicCertificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
				ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
				WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			}
			bootstrapListener, err = net.Listen("tcp", cfg.Bootstrap.Listen)
			if err != nil {
				return fmt.Errorf("listen for public bootstrap metadata: %w", err)
			}
			defer bootstrapListener.Close()
			bootstrapErrors := make(chan error, 1)
			bootstrapServeErr = bootstrapErrors
			go func() { bootstrapErrors <- bootstrapServer.ServeTLS(bootstrapListener, "", "") }()
		}
	}
	server := service.NewHTTPServer(cfg.Controller.Listen, tlsConfig)
	if consoleCertificate != "" {
		if err := addConsoleCertificate(server.TLSConfig, consoleCertificate, consolePrivateKey, consoleServerName); err != nil {
			return err
		}
	}
	if bootstrapHandler != nil {
		privateHandler := server.Handler
		server.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == bootstrap.WellKnownPath {
				bootstrapHandler.ServeHTTP(writer, request)
				return
			}
			privateHandler.ServeHTTP(writer, request)
		})
	}
	if consoleDir != "" {
		consoleHandler, consoleErr := controllerservice.ConsoleHandler(server.Handler, consoleDir)
		if consoleErr != nil {
			return consoleErr
		}
		server.Handler = consoleHandler
	}
	quicServer, err := service.ListenQUIC(cfg.Controller.QUICListen, tlsConfig)
	if err != nil {
		return err
	}
	defer quicServer.Close()
	listener, err := net.Listen("tcp", cfg.Controller.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeTLS(listener, "", "") }()
	quicServeErr := make(chan error, 1)
	go func() { quicServeErr <- quicServer.Serve(ctx) }()
	ephemeralExitSweepErr := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				ephemeralExitSweepErr <- ctx.Err()
				return
			case <-ticker.C:
				if _, sweepErr := store.ExpireDisconnectedEphemeralExits(ctx, controller.MaxExpireBatch); sweepErr != nil {
					ephemeralExitSweepErr <- sweepErr
					return
				}
			}
		}
	}()
	diagnosticsDone, err := observability.Start(ctx, observability.Config{Listen: diagnostics, Snapshot: func() map[string]uint64 {
		metrics := service.Metrics()
		return map[string]uint64{
			"controller_up":                1,
			"controller_requests_total":    metrics.Requests,
			"successful_responses_total":   metrics.SuccessfulResponses,
			"malformed_input_total":        metrics.MalformedInput,
			"authorization_failures_total": metrics.AuthorizationFailures,
			"internal_failures_total":      metrics.InternalFailures,
		}
	}})
	if err != nil {
		_ = server.Close()
		_ = quicServer.Close()
		<-serveErr
		return err
	}
	bootstrapAddress := "disabled"
	if bootstrapListener != nil {
		bootstrapAddress = bootstrapListener.Addr().String()
	}
	fmt.Printf("laneway-controller HTTPS=%s QUIC=%s bootstrap=%s database=%s\n", listener.Addr(), quicServer.Addr(), bootstrapAddress, cfg.Controller.DatabaseFile)
	select {
	case err := <-serveErr:
		_ = quicServer.Close()
		if bootstrapServer != nil {
			_ = bootstrapServer.Close()
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-quicServeErr:
		_ = server.Close()
		if bootstrapServer != nil {
			_ = bootstrapServer.Close()
		}
		<-serveErr
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case err := <-ephemeralExitSweepErr:
		_ = server.Close()
		_ = quicServer.Close()
		if bootstrapServer != nil {
			_ = bootstrapServer.Close()
		}
		<-serveErr
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("expire disconnected ephemeral Exit leases: %w", err)
	case err := <-bootstrapServeErr:
		_ = server.Close()
		_ = quicServer.Close()
		<-serveErr
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if bootstrapServer != nil {
			if err := bootstrapServer.Shutdown(shutdownCtx); err != nil {
				return err
			}
		}
		_ = quicServer.Close()
		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return ctx.Err()
	case diagnosticsErr := <-diagnosticsDone:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if bootstrapServer != nil {
			if err := bootstrapServer.Shutdown(shutdownCtx); err != nil {
				return err
			}
		}
		_ = quicServer.Close()
		serveError := <-serveErr
		if diagnosticsErr != nil {
			return diagnosticsErr
		}
		if serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
			return serveError
		}
		return nil
	}
}

func addConsoleCertificate(config *tls.Config, certificateFile, privateKeyFile, serverName string) error {
	if config == nil || len(config.Certificates) == 0 {
		return errors.New("configure console certificate: controller HTTPS certificate is missing")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return fmt.Errorf("load console certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return errors.New("console certificate chain is empty")
	}
	now := time.Now()
	chain := make([]*x509.Certificate, 0, len(certificate.Certificate))
	for index, certificateDER := range certificate.Certificate {
		parsed, parseErr := x509.ParseCertificate(certificateDER)
		if parseErr != nil {
			return fmt.Errorf("parse console certificate chain entry %d: %w", index, parseErr)
		}
		if index == 0 {
			certificate.Leaf = parsed
		}
		chain = append(chain, parsed)
		if !browserCompatibleSignatureAlgorithm(parsed.SignatureAlgorithm) {
			return fmt.Errorf("console certificate chain entry %d uses unsupported signature algorithm %s", index, parsed.SignatureAlgorithm)
		}
		if now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return fmt.Errorf("console certificate chain entry %d is not currently valid", index)
		}
		if index > 0 && !parsed.IsCA {
			return fmt.Errorf("console certificate chain entry %d is not a CA certificate", index)
		}
	}
	for index := 0; index < len(chain)-1; index++ {
		if err := chain[index].CheckSignatureFrom(chain[index+1]); err != nil {
			return fmt.Errorf("console certificate chain entries %d and %d are not linked: %w", index, index+1, err)
		}
	}
	last := chain[len(chain)-1]
	if last.IsCA && last.CheckSignatureFrom(last) == nil {
		return errors.New("console certificate chain must omit its self-signed root")
	}
	leaf := certificate.Leaf
	if leaf.IsCA {
		return errors.New("console certificate must be a leaf certificate")
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA && leaf.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf("console certificate public key must be ECDSA or RSA, got %s", leaf.PublicKeyAlgorithm)
	}
	switch publicKey := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if publicKey.Curve == nil || publicKey.Curve.Params().BitSize < 256 {
			return errors.New("console certificate ECDSA public key must use a curve of at least 256 bits")
		}
	case *rsa.PublicKey:
		if publicKey.N.BitLen() < 2048 {
			return errors.New("console certificate RSA public key must be at least 2048 bits")
		}
	default:
		return fmt.Errorf("console certificate has unsupported public key type %T", leaf.PublicKey)
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("console certificate is not valid for digital signatures")
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return fmt.Errorf("console certificate does not cover %q: %w", serverName, err)
	}
	if !allowsServerAuthentication(leaf.ExtKeyUsage) {
		return errors.New("console certificate is not valid for TLS server authentication")
	}

	// The HTTP server selects the first chain compatible with the ClientHello.
	// Laneway clients that advertise Ed25519 continue to receive the controller
	// identity certificate. Browsers that do not advertise Ed25519 can select
	// this ECDSA/RSA fallback. QUIC uses the original, unmodified TLS config.
	config.Certificates = append(config.Certificates, certificate)
	return nil
}

func browserCompatibleSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

func allowsServerAuthentication(usages []x509.ExtKeyUsage) bool {
	if len(usages) == 0 {
		return true
	}
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func controllerTLSConfig(cfg config.TLS, caPEM []byte) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load controller certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New("controller certificate chain is empty")
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse controller certificate: %w", err)
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(certificate.Leaf)
	if err != nil {
		return nil, err
	}
	if err := authenticated.RequireRole(identity.IdentityRoleController); err != nil {
		return nil, err
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA file contains no valid certificates")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate}, ClientCAs: clientCAs,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	}, nil
}

type adminBearerCredential struct {
	authorization []byte
}

func adminBearerCredentialFromFile(path string) (*adminBearerCredential, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open admin token: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxAdminTokenFile+1))
	if err != nil {
		return nil, fmt.Errorf("read admin token: %w", err)
	}
	defer clear(contents)
	if len(contents) > maxAdminTokenFile {
		return nil, errors.New("admin token file is too large")
	}
	token := bytes.TrimSpace(contents)
	if len(token) < 32 {
		return nil, errors.New("admin token must contain at least 32 characters")
	}
	authorization := make([]byte, len("Bearer ")+len(token))
	copy(authorization, "Bearer ")
	copy(authorization[len("Bearer "):], token)
	return &adminBearerCredential{authorization: authorization}, nil
}

func (credential *adminBearerCredential) clear() {
	if credential == nil {
		return
	}
	clear(credential.authorization)
	credential.authorization = nil
}

func (credential *adminBearerCredential) authorizer(servicePrincipalID identity.ID) (controllerservice.AdminAuthorizer, error) {
	if credential == nil || len(credential.authorization) == 0 {
		return nil, errors.New("admin bearer credential is empty")
	}
	if servicePrincipalID.IsZero() {
		return nil, errors.New("admin bearer service principal must be nonzero")
	}
	want := credential.authorization
	actor := adminauth.IDActor(adminauth.ActorServicePrincipal, servicePrincipalID)
	return func(r *http.Request) (adminauth.Actor, error) {
		got := []byte(r.Header.Get("Authorization"))
		matches := len(got) == len(want) && subtle.ConstantTimeCompare(got, want) == 1
		clear(got)
		if !matches {
			return adminauth.Actor{}, controllerservice.ErrUnauthenticated
		}
		return actor, nil
	}, nil
}
