// rustnodecontroller runs the production Go controller service with a short,
// explicitly configured snapshot lease for the privileged Rust-node gate.
// It is an integration fixture, not a second controller implementation.
package main

import (
	"context"
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
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerservice"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

const maxAdminTokenBytes = 4096

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "rustnodecontroller:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "", "HTTPS listen address")
	quicListen := flag.String("quic-listen", "", "mTLS QUIC control listen address")
	database := flag.String("database", "", "controller SQLite database")
	caCertificate := flag.String("ca-cert", "", "CA certificate bundle")
	caKey := flag.String("ca-key", "", "CA private key")
	controllerCertificate := flag.String("controller-cert", "", "controller certificate")
	controllerKey := flag.String("controller-key", "", "controller private key")
	adminTokenFile := flag.String("admin-token-file", "", "admin bearer token file")
	snapshotValidity := flag.Duration("snapshot-validity", 2*time.Second, "node and relay snapshot lease")
	initialNodeDelay := flag.Duration("initial-node-delay", 0, "hold the first node configuration response")
	flag.Parse()
	if flag.NArg() != 0 || *listen == "" || *database == "" || *caCertificate == "" ||
		*caKey == "" || *controllerCertificate == "" || *controllerKey == "" ||
		*adminTokenFile == "" {
		return errors.New("all path and listen flags are required and positional arguments are forbidden")
	}
	if *snapshotValidity <= 0 || *snapshotValidity > 30*time.Second {
		return errors.New("snapshot-validity must be in (0,30s] for this integration fixture")
	}
	if *initialNodeDelay < 0 || *initialNodeDelay > 5*time.Second {
		return errors.New("initial-node-delay must be in [0,5s]")
	}

	issuerPEM, err := os.ReadFile(*caCertificate)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(*caKey)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	issuer, signer, issuerChain, err := pki.ParseAuthorityBundle(issuerPEM, keyPEM)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(*controllerCertificate, *controllerKey)
	if err != nil {
		return fmt.Errorf("load controller certificate: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return errors.New("controller certificate chain is empty")
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse controller certificate: %w", err)
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(certificate.Leaf)
	if err != nil {
		return err
	}
	if err := authenticated.RequireRole(identity.IdentityRoleController); err != nil {
		return err
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(issuerPEM) {
		return errors.New("CA file contains no certificates")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := controller.Open(ctx, *database)
	if err != nil {
		return err
	}
	defer store.Close()
	authState, err := store.AdministratorAuthState(ctx)
	if err != nil {
		return fmt.Errorf("read administrator authentication state: %w", err)
	}
	authorizeAdmin, err := adminAuthorizer(*adminTokenFile, authState.RootServicePrincipalID)
	if err != nil {
		return err
	}
	service, err := controllerservice.New(controllerservice.Options{
		Store:            store,
		CACertificate:    issuer,
		CAKey:            signer,
		IssuerChain:      issuerChain,
		LeafValidity:     time.Hour,
		AdminAuthorizer:  authorizeAdmin,
		SnapshotValidity: *snapshotValidity,
	})
	if err != nil {
		return err
	}
	server := service.NewHTTPServer(*listen, tlsConfig)
	middleware := func(next http.Handler) http.Handler { return observeNodeConfiguration(next, *initialNodeDelay) }
	server.Handler = middleware(service.Handler())
	var quicServer *controllerservice.QUICServer
	if *quicListen != "" {
		quicServer, err = service.ListenQUICWithMiddleware(*quicListen, tlsConfig, middleware)
		if err != nil {
			return err
		}
		defer quicServer.Close()
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	serveError := make(chan error, 1)
	go func() { serveError <- server.ServeTLS(listener, "", "") }()
	quicError := make(chan error, 1)
	if quicServer != nil {
		go func() { quicError <- quicServer.Serve(ctx) }()
	}
	fmt.Printf("rust-node test controller listening on %s QUIC=%s lease=%s\n", listener.Addr(), *quicListen, *snapshotValidity)
	select {
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-quicError:
		_ = server.Close()
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		if quicServer != nil {
			_ = quicServer.Close()
		}
		err := <-serveError
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return ctx.Err()
	}
}

func observeNodeConfiguration(next http.Handler, initialDelay time.Duration) http.Handler {
	var held atomic.Bool
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/configuration" {
			next.ServeHTTP(response, request)
			return
		}
		if initialDelay > 0 && held.CompareAndSwap(false, true) {
			fmt.Printf("holding initial node configuration request for %s\n", initialDelay)
			time.Sleep(initialDelay)
		}
		observed := &statusResponseWriter{ResponseWriter: response}
		next.ServeHTTP(observed, request)
		status := observed.status
		if status == 0 {
			status = http.StatusOK
		}
		fmt.Printf("node configuration response status=%d\n", status)
	})
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Write(contents []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(contents)
}

func adminAuthorizer(path string, servicePrincipalID identity.ID) (controllerservice.AdminAuthorizer, error) {
	if servicePrincipalID.IsZero() {
		return nil, errors.New("admin bearer service principal must be nonzero")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open admin token: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxAdminTokenBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read admin token: %w", err)
	}
	if len(contents) > maxAdminTokenBytes {
		return nil, errors.New("admin token exceeds fixture limit")
	}
	token := strings.TrimSpace(string(contents))
	if len(token) < 32 {
		return nil, errors.New("admin token must contain at least 32 characters")
	}
	want := []byte("Bearer " + token)
	actor := adminauth.IDActor(adminauth.ActorServicePrincipal, servicePrincipalID)
	return func(request *http.Request) (adminauth.Actor, error) {
		got := []byte(request.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			return adminauth.Actor{}, controllerservice.ErrUnauthenticated
		}
		return actor, nil
	}, nil
}
