package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/nodeapp"
	"laneway.dev/laneway/internal/wireguard"
)

const connectSessionMaxBytes = 512 << 10

// The pipe contains credentials for exactly one authenticated user session.
// The Rust frontend owns enrollment, persisted state, and rotation.
type connectSession struct {
	Metadata            bootstrap.Metadata `json:"metadata"`
	CAPEM               []byte             `json:"ca_pem"`
	CertificatePEM      []byte             `json:"certificate_pem"`
	PrivateKeyPEM       []byte             `json:"private_key_pem"`
	WireguardPrivateKey []byte             `json:"wireguard_private_key"`
	NetworkID           string             `json:"network_id"`
	NodeID              string             `json:"node_id"`
	LeaseExpiresAt      int64              `json:"lease_expires_at"`
	SavedLogin          bool               `json:"saved_login"`
	Routes              []string           `json:"routes"`
	Exit                string             `json:"exit"`
	FailureMode         string             `json:"failure_mode"`
	DNS                 []string           `json:"dns"`
	LocalLAN            []string           `json:"local_lan"`
}

func runConnectSessionPreflight(args []string) error {
	if len(args) != 0 || os.Geteuid() <= 0 || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return errors.New("the connect session runtime requires an ordinary Linux or macOS user")
	}
	return preflightConnectSessionHelper()
}

func readConnectSession(reader io.Reader) (connectSession, error) {
	var size [4]byte
	const invalid = "invalid private connect session frame"
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return connectSession{}, errors.New(invalid)
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > connectSessionMaxBytes {
		return connectSession{}, errors.New(invalid)
	}
	payload := make([]byte, length)
	defer clear(payload)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return connectSession{}, errors.New(invalid)
	}
	var session connectSession
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&session); err != nil {
		session.clear()
		return connectSession{}, errors.New(invalid)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		session.clear()
		return connectSession{}, errors.New(invalid)
	}
	return session, nil
}

func (s *connectSession) clear() {
	clear(s.CAPEM)
	clear(s.CertificatePEM)
	clear(s.PrivateKeyPEM)
	clear(s.WireguardPrivateKey)
}

func (s *connectSession) validateCredentials(now time.Time) (connectEnrollment, error) {
	if s.Metadata.Validate(now) != nil || validatePlatformArtifact(s.Metadata) != nil || s.Metadata.NetworkID != s.NetworkID ||
		!bytes.Equal(s.CAPEM, []byte(s.Metadata.Trust.CAPEM)) {
		return connectEnrollment{}, errors.New("invalid or mismatched connect session bootstrap")
	}
	network, err := identity.ParseNetworkID(s.NetworkID)
	if err != nil {
		return connectEnrollment{}, errors.New("invalid connect session network identity")
	}
	node, err := identity.ParseNodeID(s.NodeID)
	if err != nil || node.IsZero() {
		return connectEnrollment{}, errors.New("invalid connect session node identity")
	}
	pair, err := tls.X509KeyPair(s.CertificatePEM, s.PrivateKeyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return connectEnrollment{}, errors.New("invalid connect session certificate or private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return connectEnrollment{}, errors.New("invalid connect session certificate")
	}
	authenticated, err := identity.IdentityFromCertificate(leaf)
	if err != nil || authenticated.NetworkID != network || authenticated.NodeID != node {
		return connectEnrollment{}, errors.New("connect session certificate identity mismatch")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CAPEM) {
		return connectEnrollment{}, errors.New("invalid connect session trust bundle")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return connectEnrollment{}, errors.New("invalid connect session certificate chain")
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return connectEnrollment{}, errors.New("untrusted or expired connect session certificate")
	}
	if _, _, err := wireguard.ParsePrivateKey(s.WireguardPrivateKey); err != nil {
		return connectEnrollment{}, errors.New("invalid connect session WireGuard key")
	}
	class := lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER
	var lease time.Time
	if s.SavedLogin {
		if s.LeaseExpiresAt != 0 {
			return connectEnrollment{}, errors.New("saved connect session has an ephemeral lease")
		}
	} else {
		class = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
		lease = time.Unix(s.LeaseExpiresAt, 0).UTC()
		if !lease.After(now) || leaf.NotAfter.After(lease) {
			return connectEnrollment{}, errors.New("invalid ephemeral connect session lease")
		}
	}
	return connectEnrollment{identity: authenticated, class: class, leaseExpiresAt: lease}, nil
}

func runConnectSession(args []string) error {
	if err := runConnectSessionPreflight(args); err != nil {
		return err
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("connect session requires a private stdin pipe")
	}
	session, err := readConnectSession(os.Stdin)
	if err != nil {
		return err
	}
	defer session.clear()

	enrollment, err := session.validateCredentials(time.Now())
	if err != nil {
		return err
	}
	if (session.FailureMode != "closed" && session.FailureMode != "open") ||
		(session.Exit == "" && (session.FailureMode != "closed" || len(session.DNS) != 0 || len(session.LocalLAN) != 0)) ||
		(runtime.GOOS != "linux" && (session.Exit != "" || len(session.DNS) != 0 || len(session.LocalLAN) != 0)) {
		return errors.New("unsupported connect session route or exit options")
	}
	routes, err := parseConnectPrefixes(session.Routes, false)
	if err != nil {
		return errors.New("invalid connect session routes")
	}
	localLAN, err := parseConnectPrefixes(session.LocalLAN, false)
	if err != nil {
		return errors.New("invalid connect session bypass routes")
	}
	dns, err := parseConnectAddresses(session.DNS)
	if err != nil {
		return errors.New("invalid connect session DNS addresses")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// The parent holds its pipe writer for the lifetime of the session.
		// Closing it, including on process loss, triggers ordinary cleanup.
		var unused [1]byte
		_, _ = os.Stdin.Read(unused[:])
		cancel()
	}()

	runtimeDir, err := os.MkdirTemp("", "laneway-connect-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runtimeDir)
	credentials := new(runtimeCredentialFiles)
	defer credentials.close()
	input := foregroundConnect{
		metadata: session.Metadata, enrollment: enrollment, runtimeDir: runtimeDir,
		routes: routes, localLAN: localLAN, dns: dns, saved: session.SavedLogin,
		options: connectPlatformOptions{exitSelector: session.Exit, failureMode: session.FailureMode},
		validateSnapshot: func(snapshot *lanewayv1.NodeConfiguration) error {
			if snapshot == nil || snapshot.GetEnrollmentClass() != enrollment.class ||
				snapshot.GetIdentityLeaseExpiresAtUnixSeconds() != uint64(session.LeaseExpiresAt) {
				return errors.New("controller configuration does not match the authorized user session")
			}
			return nil
		},
	}
	for _, part := range []struct {
		label       string
		value       []byte
		destination *string
	}{
		{"ca", session.CAPEM, &input.caPath},
		{"certificate", session.CertificatePEM, &input.certPath},
		{"private-key", session.PrivateKeyPEM, &input.keyPath},
		{"wireguard-key", session.WireguardPrivateKey, &input.wireGuardKeyPath},
	} {
		*part.destination, err = credentials.add(runtimeDir, part.label, part.value)
		if err != nil {
			return fmt.Errorf("prepare private session credentials: %w", err)
		}
	}
	session.clear()
	prepared, err := prepareConnect(ctx, input)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if err := credentials.rewind(); err != nil {
		return err
	}
	err = nodeapp.RunForeground(ctx, prepared.config, nodeapp.ForegroundOptions{
		NetworkOpener: helperNetworkOpener, Status: prepared.status, FilterConfiguration: prepared.filter,
		RewindCredentials: credentials.rewind,
	})
	if err == nil {
		fmt.Println("laneway disconnected; temporary networking restored")
	}
	return err
}
