// Package controllerservice exposes the durable controller store through a
// bounded HTTPS bootstrap/management API and reliable mTLS QUIC control API.
// Node private keys never enter this package: enrollment and renewal accept
// only signed PKCS#10 certificate requests.
package controllerservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

const (
	DefaultMaxBodyBytes     int64 = 128 << 10
	maxCSRBytes                   = 64 << 10
	DefaultSnapshotValidity       = 5 * time.Minute
	MaxSnapshotValidity           = 24 * time.Hour
	SnapshotValidityHeader        = "X-Laneway-Configuration-Valid-Until"
)

type Options struct {
	Store         *controller.Store
	CACertificate *x509.Certificate
	CAKey         crypto.Signer
	// IssuerChain is issuer-first and may end in the out-of-band trust root.
	// Enrollment responses omit the self-signed root.
	IssuerChain      []*x509.Certificate
	LeafValidity     time.Duration
	MaxBodyBytes     int64
	AdminAuthorizer  AdminAuthorizer
	NodeAuthorizer   NodeAuthorizer
	Now              func() time.Time
	SnapshotValidity time.Duration
}

type Service struct {
	store                 *controller.Store
	ca                    *x509.Certificate
	caKey                 crypto.Signer
	issuerChain           []*x509.Certificate
	validity              time.Duration
	maxBody               int64
	authorizeAdm          AdminAuthorizer
	authorizeNode         NodeAuthorizer
	verifyPeerCertificate bool
	now                   func() time.Time
	snapshotValidity      time.Duration
	enrollmentLimiter     *enrollmentRateLimiter
	handler               http.Handler
	metrics               serviceMetrics
}

type serviceMetrics struct {
	requests              atomic.Uint64
	successfulResponses   atomic.Uint64
	malformedInput        atomic.Uint64
	authorizationFailures atomic.Uint64
	internalFailures      atomic.Uint64
}

// Metrics is a bounded-cardinality point-in-time controller snapshot. All
// fields are monotonically increasing for one process lifetime.
type Metrics struct {
	Requests              uint64
	SuccessfulResponses   uint64
	MalformedInput        uint64
	AuthorizationFailures uint64
	InternalFailures      uint64
}

func New(opts Options) (*Service, error) {
	if opts.Store == nil || opts.CACertificate == nil || opts.CAKey == nil || !opts.CACertificate.IsCA {
		return nil, errors.New("controller service requires a store and valid CA signer")
	}
	caPublic, err := x509.MarshalPKIXPublicKey(opts.CACertificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CA public key: %w", err)
	}
	signerPublic, err := x509.MarshalPKIXPublicKey(opts.CAKey.Public())
	if err != nil || !bytes.Equal(caPublic, signerPublic) {
		return nil, errors.New("controller service CA certificate and key do not match")
	}
	if opts.LeafValidity == 0 {
		opts.LeafValidity = pki.DefaultLeafValidity
	}
	issuerChain, err := validateIssuerChain(opts.CACertificate, opts.IssuerChain)
	if err != nil {
		return nil, err
	}
	if opts.LeafValidity <= 0 {
		return nil, errors.New("controller service leaf validity must be positive")
	}
	if opts.SnapshotValidity == 0 {
		opts.SnapshotValidity = DefaultSnapshotValidity
	}
	if opts.SnapshotValidity <= 0 || opts.SnapshotValidity > MaxSnapshotValidity {
		return nil, fmt.Errorf("controller snapshot validity must be in (0,%s]", MaxSnapshotValidity)
	}
	if opts.MaxBodyBytes == 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.MaxBodyBytes < 1024 {
		return nil, errors.New("controller service body limit is too small")
	}
	if opts.AdminAuthorizer == nil {
		// Administrative access is fail-closed until explicitly configured.
		opts.AdminAuthorizer = func(*http.Request) error { return ErrUnauthenticated }
	}
	verifyPeerCertificate := opts.NodeAuthorizer == nil
	if opts.NodeAuthorizer == nil {
		opts.NodeAuthorizer = identityFromMTLS
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	s := &Service{
		store: opts.Store, ca: opts.CACertificate, caKey: opts.CAKey, issuerChain: issuerChain, validity: opts.LeafValidity,
		maxBody: opts.MaxBodyBytes, authorizeAdm: opts.AdminAuthorizer,
		authorizeNode: opts.NodeAuthorizer, verifyPeerCertificate: verifyPeerCertificate, now: opts.Now,
		snapshotValidity:  opts.SnapshotValidity,
		enrollmentLimiter: newEnrollmentRateLimiter(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("POST /v1/admin/enrollment-tokens", s.issueToken)
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/renew", s.renew)
	mux.HandleFunc("POST /v1/configuration", s.configuration)
	mux.HandleFunc("POST /v1/relay/configuration", s.relayConfiguration)
	mux.HandleFunc("GET /v1/revocations/{serial}", s.revocation)
	mux.HandleFunc("POST /v1/admin/networks", s.createNetwork)
	mux.HandleFunc("GET /v1/admin/networks", s.readNetworks)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}", s.readNetwork)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/nodes", s.readNodes)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/relays", s.readRelays)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/acl-rules", s.readACLRules)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/certificates", s.readCertificates)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/routes", s.readRoutes)
	mux.HandleFunc("GET /v1/admin/networks/{network_id}/audit", s.readAudit)
	mux.HandleFunc("POST /v1/routes", s.advertiseRoute)
	mux.HandleFunc("DELETE /v1/routes/{route_id}", s.withdrawRoute)
	mux.HandleFunc("POST /v1/admin/routes/{route_id}/approve", s.approveRoute)
	mux.HandleFunc("POST /v1/admin/networks/{network_id}/acl-rules", s.addACLRule)
	mux.HandleFunc("DELETE /v1/admin/acl-rules/{rule_id}", s.deleteACLRule)
	mux.HandleFunc("POST /v1/admin/nodes/{node_id}/revoke", s.revokeNode)
	mux.HandleFunc("POST /v1/admin/networks/{network_id}/certificates/{serial}/revoke", s.revokeCertificate)
	mux.HandleFunc("PUT /v1/admin/nodes/{node_id}/capabilities", s.setNodeCapabilities)
	mux.HandleFunc("POST /v1/admin/networks/{network_id}/relays", s.registerRelay)
	mux.HandleFunc("POST /v1/admin/relays/{relay_id}/disable", s.disableRelay)
	mux.HandleFunc("PUT /v1/admin/relays/{relay_id}", s.updateRelay)
	s.handler = s.observe(securityHeaders(mux))
	return s, nil
}

func (s *Service) Handler() http.Handler { return s.handler }

func (s *Service) Metrics() Metrics {
	if s == nil {
		return Metrics{}
	}
	return Metrics{
		Requests:              s.metrics.requests.Load(),
		SuccessfulResponses:   s.metrics.successfulResponses.Load(),
		MalformedInput:        s.metrics.malformedInput.Load(),
		AuthorizationFailures: s.metrics.authorizationFailures.Load(),
		InternalFailures:      s.metrics.internalFailures.Load(),
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

func (s *Service) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		s.metrics.requests.Add(1)
		observed := &statusWriter{ResponseWriter: writer}
		next.ServeHTTP(observed, request)
		status := observed.status
		if status == 0 {
			status = http.StatusOK
		}
		switch {
		case status >= 200 && status < 400:
			s.metrics.successfulResponses.Add(1)
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			s.metrics.authorizationFailures.Add(1)
		case status >= 400 && status < 500:
			s.metrics.malformedInput.Add(1)
		case status >= 500:
			s.metrics.internalFailures.Add(1)
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Service) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

type tokenRequest struct {
	NetworkID              string `json:"network_id"`
	Label                  string `json:"label"`
	ExpiresAtUnix          int64  `json:"expires_at_unix_seconds"`
	EnrollmentClass        string `json:"enrollment_class,omitempty"`
	SessionLifetimeSeconds int64  `json:"session_lifetime_seconds,omitempty"`
	RequestedName          string `json:"requested_name,omitempty"`
}

type tokenResponse struct {
	TokenID                string `json:"token_id"`
	EnrollmentToken        string `json:"enrollment_token"`
	ExpiresAtUnix          int64  `json:"expires_at_unix_seconds"`
	EnrollmentClass        string `json:"enrollment_class"`
	SessionLifetimeSeconds int64  `json:"session_lifetime_seconds,omitempty"`
	RequestedName          string `json:"requested_name,omitempty"`
}

func (s *Service) issueToken(w http.ResponseWriter, r *http.Request) {
	if err := s.authorizeAdm(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	var req tokenRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	networkID, err := identity.ParseNetworkID(req.NetworkID)
	if err != nil {
		s.writeError(w, malformed("invalid network_id"), false)
		return
	}
	class := controller.EnrollmentClass(req.EnrollmentClass)
	if class == "" {
		class = controller.EnrollmentClassDurable
	}
	token, err := s.store.IssueEnrollmentTokenWithOptions(r.Context(), networkID, req.Label, time.Unix(req.ExpiresAtUnix, 0), controller.EnrollmentTokenOptions{
		Class: class, SessionLifetime: time.Duration(req.SessionLifetimeSeconds) * time.Second, RequestedName: req.RequestedName,
	})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, tokenResponse{TokenID: token.ID.String(), EnrollmentToken: token.Secret, ExpiresAtUnix: token.ExpiresAt.Unix(),
		EnrollmentClass: string(token.EnrollmentClass), SessionLifetimeSeconds: int64(token.SessionLifetime / time.Second), RequestedName: token.RequestedName})
}

func (s *Service) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.enrollmentLimiter.allow(r.RemoteAddr, s.now()) {
		w.Header().Set("Retry-After", "1")
		s.writeProtocolError(w, http.StatusTooManyRequests, lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED, "enrollment rate limit exceeded; retry later", true)
		return
	}
	req := new(lanewayv1.EnrollmentRequest)
	if err := s.decodeProto(w, r, req); err != nil {
		s.writeError(w, err, true)
		return
	}
	csr, err := parseCSR(req.GetPkcs10CsrDer())
	if err != nil {
		s.writeError(w, malformed(err.Error()), true)
		return
	}
	var expectedNetwork identity.NetworkID
	if len(req.GetExpectedNetworkId()) != 0 {
		if len(req.GetExpectedNetworkId()) != identity.IDSize {
			s.writeError(w, malformed("expected_network_id must be a NetworkID"), true)
			return
		}
		copy(expectedNetwork[:], req.GetExpectedNetworkId())
		if expectedNetwork.IsZero() {
			s.writeError(w, malformed("expected_network_id must be nonzero"), true)
			return
		}
	}
	// CSR validation happens before opening the enrollment transaction. Signing
	// and certificate persistence then participate in the same transaction as
	// token consumption, node creation, and overlay allocation.
	var cert *x509.Certificate
	issuer := func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
		issued, issueErr := s.issueCertificate(node, csr)
		if issueErr != nil {
			return controller.CertificateMaterial{}, issueErr
		}
		cert = issued
		return controller.CertificateMaterial{
			Serial: issued.SerialNumber.Bytes(), DER: issued.Raw,
			NotBefore: issued.NotBefore, NotAfter: issued.NotAfter,
		}, nil
	}
	var enrollment controller.Enrollment
	if expectedNetwork.IsZero() {
		enrollment, err = s.store.EnrollNodeWithCertificate(r.Context(), req.GetEnrollmentToken(), req.GetRequestedName(), 0, issuer)
	} else {
		enrollment, err = s.store.EnrollNodeWithCertificateForNetwork(r.Context(), req.GetEnrollmentToken(), req.GetRequestedName(), 0, expectedNetwork, issuer)
	}
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	node := enrollment.Node
	resp := &lanewayv1.EnrollmentResponse{
		NetworkId: append([]byte(nil), node.NetworkID[:]...), NodeId: append([]byte(nil), node.ID[:]...),
		CertificateChain: s.certificateChain(cert), OverlayAddresses: nodeOverlayAddresses(node), EnrollmentClass: enrollmentClassProto(node.EnrollmentClass),
	}
	if node.LeaseExpiresAt != nil {
		resp.LeaseExpiresAtUnixSeconds = uint64(node.LeaseExpiresAt.Unix())
	}
	s.writeProto(w, http.StatusCreated, resp)
}

func (s *Service) renew(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	req := new(lanewayv1.RenewalRequest)
	if err := s.decodeProto(w, r, req); err != nil {
		s.writeError(w, err, true)
		return
	}
	csr, err := parseCSR(req.GetPkcs10CsrDer())
	if err != nil {
		s.writeError(w, malformed(err.Error()), true)
		return
	}
	if _, err := s.store.ExpireEphemeral(r.Context(), controller.MaxExpireBatch); err != nil {
		s.writeError(w, err, true)
		return
	}
	node, err := s.store.Node(r.Context(), caller.NodeID)
	if err != nil || node.NetworkID != caller.NetworkID || node.RevokedAt != nil {
		s.writeError(w, ErrPermissionDenied, true)
		return
	}
	cert, err := s.issueAndPersist(r.Context(), node, csr)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	s.writeProto(w, http.StatusOK, &lanewayv1.RenewalResponse{CertificateChain: s.certificateChain(cert)})
}

func parseCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > maxCSRBytes {
		return nil, errors.New("PKCS#10 CSR must be 1..65536 bytes")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, errors.New("invalid PKCS#10 CSR")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("invalid PKCS#10 CSR signature")
	}
	if csr.PublicKey == nil {
		return nil, errors.New("PKCS#10 CSR has no public key")
	}
	return csr, nil
}

func (s *Service) issueAndPersist(ctx context.Context, node controller.Node, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	cert, err := s.issueCertificate(node, csr)
	if err != nil {
		return nil, err
	}
	if _, err := s.store.AddCertificate(ctx, node.NetworkID, node.ID, cert.SerialNumber.Bytes(), cert.Raw, cert.NotBefore, cert.NotAfter); err != nil {
		return nil, fmt.Errorf("persist issued certificate: %w", err)
	}
	return cert, nil
}

func (s *Service) issueCertificate(node controller.Node, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	now := s.now().UTC().Truncate(time.Second)
	notAfter := now.Add(s.validity)
	if notAfter.After(s.ca.NotAfter) {
		notAfter = s.ca.NotAfter
	}
	if node.LeaseExpiresAt != nil && notAfter.After(*node.LeaseExpiresAt) {
		notAfter = *node.LeaseExpiresAt
	}
	if !notAfter.After(now) {
		return nil, errors.New("controller CA has expired")
	}
	uri, err := (identity.NodeIdentity{NetworkID: node.NetworkID, NodeID: node.ID}).URI()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "laneway-node-" + node.ID.String()},
		NotBefore:    now.Add(-time.Minute), NotAfter: notAfter,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, s.ca, csr.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("issue node certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	return cert, nil
}

func enrollmentClassProto(class controller.EnrollmentClass) lanewayv1.EnrollmentClass {
	switch class {
	case controller.EnrollmentClassDurable:
		return lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
	case controller.EnrollmentClassEphemeral:
		return lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
	case controller.EnrollmentClassRemembered:
		return lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER
	default:
		return lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_UNSPECIFIED
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func validateIssuerChain(issuer *x509.Certificate, configured []*x509.Certificate) ([]*x509.Certificate, error) {
	chain := append([]*x509.Certificate(nil), configured...)
	if len(chain) == 0 {
		chain = []*x509.Certificate{issuer}
	}
	if chain[0] == nil || !bytes.Equal(chain[0].Raw, issuer.Raw) {
		return nil, errors.New("controller service issuer chain must start with the signing CA")
	}
	for i, certificate := range chain {
		if certificate == nil || !certificate.IsCA {
			return nil, errors.New("controller service issuer chain contains a non-CA certificate")
		}
		if i+1 < len(chain) && certificate.CheckSignatureFrom(chain[i+1]) != nil {
			return nil, errors.New("controller service issuer chain is not ordered issuer-first")
		}
	}
	return chain, nil
}

func (s *Service) certificateChain(cert *x509.Certificate) *lanewayv1.CertificateChain {
	certificates := [][]byte{append([]byte(nil), cert.Raw...)}
	certificates = append(certificates, pki.IssuerChainDER(s.issuerChain)...)
	return &lanewayv1.CertificateChain{CertificatesDer: certificates, NotAfterUnixSeconds: uint64(cert.NotAfter.Unix())}
}

func (s *Service) authenticatedNode(r *http.Request) (identity.NodeIdentity, error) {
	nodeIdentity, err := s.authorizeNode(r)
	if err != nil {
		return identity.NodeIdentity{}, err
	}
	if err := nodeIdentity.Validate(); err != nil {
		return identity.NodeIdentity{}, ErrUnauthenticated
	}
	node, err := s.store.Node(r.Context(), nodeIdentity.NodeID)
	if err != nil || node.NetworkID != nodeIdentity.NetworkID || node.RevokedAt != nil {
		return identity.NodeIdentity{}, ErrPermissionDenied
	}
	// The default mTLS path additionally checks the exact presented certificate
	// against durable revocation state. Custom authorizers own equivalent
	// credential revocation semantics.
	if s.verifyPeerCertificate {
		cert := peerCertificate(r)
		if cert == nil {
			return identity.NodeIdentity{}, ErrUnauthenticated
		}
		if !s.certificateCurrentlyValid(cert) {
			return identity.NodeIdentity{}, ErrPermissionDenied
		}
		record, err := s.store.CertificateBySerial(r.Context(), cert.SerialNumber.Bytes())
		if err != nil || record.NetworkID != nodeIdentity.NetworkID || record.NodeID != nodeIdentity.NodeID || record.RevokedAt != nil {
			return identity.NodeIdentity{}, ErrPermissionDenied
		}
	}
	return nodeIdentity, nil
}

func (s *Service) certificateCurrentlyValid(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	now := s.now().UTC()
	return !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}

func (s *Service) configuration(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	req := new(lanewayv1.ConfigurationRequest)
	if err := s.decodeProto(w, r, req); err != nil {
		s.writeError(w, err, true)
		return
	}
	if _, _, err := s.store.ExpireApprovedRoutes(r.Context(), caller.NetworkID, s.now()); err != nil {
		s.writeError(w, err, true)
		return
	}
	if _, err := s.store.ExpireEphemeral(r.Context(), controller.MaxExpireBatch); err != nil {
		s.writeError(w, err, true)
		return
	}
	network, err := s.store.Network(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	node, err := s.store.Node(r.Context(), caller.NodeID)
	if err != nil || node.RevokedAt != nil {
		s.writeError(w, ErrPermissionDenied, true)
		return
	}
	validUntil := s.now().Add(s.snapshotValidity).UTC().Unix()
	if node.LeaseExpiresAt != nil && node.LeaseExpiresAt.Unix() < validUntil {
		validUntil = node.LeaseExpiresAt.Unix()
	}
	nextEphemeralExpiry, err := s.store.NextEphemeralExpiry(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	if nextEphemeralExpiry != nil && nextEphemeralExpiry.Unix() < validUntil {
		validUntil = nextEphemeralExpiry.Unix()
	}
	if req.GetKnownConfigurationEpoch() == network.ConfigurationEpoch {
		w.Header().Set(SnapshotValidityHeader, strconv.FormatInt(validUntil, 10))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if req.GetKnownConfigurationEpoch() > network.ConfigurationEpoch {
		s.writeProtocolError(w, http.StatusConflict, lanewayv1.ErrorCode_ERROR_CODE_STALE_EPOCH, "known configuration epoch is ahead of controller", false)
		return
	}
	overlayRoutes, err := s.store.OverlayRoutes(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	advertisedRoutes, err := s.store.ApprovedRoutes(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	routes := append(overlayRoutes, advertisedRoutes...)
	rules, err := s.store.EnabledACLRules(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	revokedSerials, err := s.store.RevokedCertificateSerials(r.Context(), caller.NetworkID, s.now())
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	peers, err := s.store.ActiveNodes(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	resp, err := buildConfiguration(network, node, peers, routes, rules, revokedSerials, uint64(validUntil))
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	relays, err := s.store.ActiveRelays(r.Context(), caller.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	for _, relay := range relays {
		resp.Relays = append(resp.Relays, &lanewayv1.RelayEndpoint{
			ServiceId: append([]byte(nil), relay.ServiceID[:]...), Name: relay.Name, Endpoint: relay.Endpoint,
		})
	}
	resp.CertificateHealth = certificateHealth(peerCertificate(r), revokedSerials)
	s.writeProto(w, http.StatusOK, resp)
}

func buildConfiguration(network controller.Network, node controller.Node, nodes []controller.Node, routes []controller.Route, rules []controller.ACLRule, revokedSerials [][]byte, validUntil uint64) (*lanewayv1.NodeConfiguration, error) {
	routeSnapshot := &lanewayv1.RouteSnapshot{NetworkId: append([]byte(nil), network.ID[:]...), ConfigurationEpoch: network.ConfigurationEpoch}
	for _, route := range routes {
		kind := lanewayv1.RouteKind_ROUTE_KIND_UNSPECIFIED
		mode := lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_UNSPECIFIED
		switch route.Kind {
		case controller.RouteKindOverlay:
			kind = lanewayv1.RouteKind_ROUTE_KIND_OVERLAY
		case controller.RouteKindSubnet:
			kind = lanewayv1.RouteKind_ROUTE_KIND_SUBNET
		case controller.RouteKindExit:
			kind = lanewayv1.RouteKind_ROUTE_KIND_EXIT
		}
		switch route.Mode {
		case controller.RouteModeNAT:
			mode = lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT
		case controller.RouteModeRouted:
			mode = lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_ROUTED
		}
		routeSnapshot.Routes = append(routeSnapshot.Routes, &lanewayv1.Route{
			Destination: prefixMessage(route.Prefix), ViaNodeId: append([]byte(nil), route.NodeID[:]...),
			Kind: kind, Metric: route.Metric, RouteId: append([]byte(nil), route.ID[:]...), Mode: mode,
		})
	}
	policy, err := buildPolicySnapshot(network, rules)
	if err != nil {
		return nil, err
	}
	peers := make([]*lanewayv1.NodePeer, 0, len(nodes))
	for _, peer := range nodes {
		peers = append(peers, &lanewayv1.NodePeer{
			NodeId: append([]byte(nil), peer.ID[:]...), Name: peer.Name,
			OverlayAddresses: nodeOverlayAddresses(peer),
		})
	}
	exitNodes := make([][]byte, 0)
	seenExit := make(map[identity.NodeID]struct{})
	for _, route := range routes {
		if route.Kind == controller.RouteKindExit {
			if _, exists := seenExit[route.NodeID]; !exists {
				seenExit[route.NodeID] = struct{}{}
				exitNodes = append(exitNodes, append([]byte(nil), route.NodeID[:]...))
			}
		}
	}
	response := &lanewayv1.NodeConfiguration{
		ConfigurationEpoch: network.ConfigurationEpoch,
		OverlayAddresses:   nodeOverlayAddresses(node),
		Routes:             routeSnapshot, Policy: policy, EnabledCapabilities: node.EnabledCapabilities,
		ValidUntilUnixSeconds: validUntil, RevokedCertificateSerials: cloneByteSlices(revokedSerials), Peers: peers,
		CandidateExchange: &lanewayv1.CandidateExchangePolicy{Enabled: true, MaxCandidates: 8, CandidateTtlSeconds: 120},
		ExitPolicy:        &lanewayv1.ExitNodePolicy{AuthorizedNodeIds: exitNodes},
		EnrollmentClass:   enrollmentClassProto(node.EnrollmentClass),
	}
	if node.LeaseExpiresAt != nil {
		response.IdentityLeaseExpiresAtUnixSeconds = uint64(node.LeaseExpiresAt.Unix())
	}
	return response, nil
}

func certificateHealth(cert *x509.Certificate, revokedSerials [][]byte) *lanewayv1.CertificateHealth {
	if cert == nil {
		return nil
	}
	var serial []byte
	if cert.SerialNumber != nil {
		serial = append([]byte(nil), cert.SerialNumber.Bytes()...)
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	renewAfter := cert.NotBefore.Add(lifetime * 2 / 3)
	return &lanewayv1.CertificateHealth{
		PresentedSerial:     serial,
		NotAfterUnixSeconds: uint64(cert.NotAfter.Unix()), RenewAfterUnixSeconds: uint64(renewAfter.Unix()),
		Revoked: slices.ContainsFunc(revokedSerials, func(revoked []byte) bool { return bytes.Equal(revoked, serial) }),
	}
}

func nodeOverlayAddresses(node controller.Node) [][]byte {
	addresses := [][]byte{append([]byte(nil), node.IPv4Address.AsSlice()...)}
	if node.IPv6Address.IsValid() {
		addresses = append(addresses, append([]byte(nil), node.IPv6Address.AsSlice()...))
	}
	return addresses
}

func buildPolicySnapshot(network controller.Network, rules []controller.ACLRule) (*lanewayv1.PolicySnapshot, error) {
	policy := &lanewayv1.PolicySnapshot{
		NetworkId: append([]byte(nil), network.ID[:]...), ConfigurationEpoch: network.ConfigurationEpoch,
		DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
	}
	for _, rule := range rules {
		selector := new(lanewayv1.TrafficSelector)
		if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(rule.SelectorJSON), selector); err != nil {
			return nil, fmt.Errorf("decode stored ACL selector: %w", err)
		}
		action := lanewayv1.PolicyAction_POLICY_ACTION_DENY
		if rule.Action == controller.ACLActionAccept {
			action = lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT
		}
		policy.Rules = append(policy.Rules, &lanewayv1.PolicyRule{
			RuleId: append([]byte(nil), rule.ID[:]...), Priority: rule.Priority, Action: action,
			Selector: selector, Description: rule.Description,
		})
	}
	return policy, nil
}

func (s *Service) relayConfiguration(w http.ResponseWriter, r *http.Request) {
	relayIdentity, err := authenticatedRelay(r)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	if !s.certificateCurrentlyValid(peerCertificate(r)) {
		s.writeError(w, ErrPermissionDenied, true)
		return
	}
	if err := s.store.AuthorizeRelay(r.Context(), relayIdentity.NetworkID, relayIdentity.SubjectID); err != nil {
		if errors.Is(err, controller.ErrNotFound) {
			err = ErrPermissionDenied
		}
		s.writeError(w, err, true)
		return
	}
	request := new(lanewayv1.RelayConfigurationRequest)
	if err := s.decodeProto(w, r, request); err != nil {
		s.writeError(w, err, true)
		return
	}
	if _, _, err := s.store.ExpireApprovedRoutes(r.Context(), relayIdentity.NetworkID, s.now()); err != nil {
		s.writeError(w, err, true)
		return
	}
	if _, err := s.store.ExpireEphemeral(r.Context(), controller.MaxExpireBatch); err != nil {
		s.writeError(w, err, true)
		return
	}
	network, err := s.store.Network(r.Context(), relayIdentity.NetworkID)
	if err != nil {
		s.writeError(w, ErrPermissionDenied, true)
		return
	}
	validUntil := s.now().Add(s.snapshotValidity).UTC().Unix()
	nextEphemeralExpiry, err := s.store.NextEphemeralExpiry(r.Context(), relayIdentity.NetworkID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	if nextEphemeralExpiry != nil && nextEphemeralExpiry.Unix() < validUntil {
		validUntil = nextEphemeralExpiry.Unix()
	}
	if request.GetKnownConfigurationEpoch() == network.ConfigurationEpoch {
		w.Header().Set(SnapshotValidityHeader, strconv.FormatInt(validUntil, 10))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if request.GetKnownConfigurationEpoch() > network.ConfigurationEpoch {
		s.writeProtocolError(w, http.StatusConflict, lanewayv1.ErrorCode_ERROR_CODE_STALE_EPOCH, "known configuration epoch is ahead of controller", false)
		return
	}
	authorizations, err := s.store.RelayAuthorizations(r.Context(), network.ID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	rules, err := s.store.EnabledACLRules(r.Context(), network.ID)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	revokedSerials, err := s.store.RevokedCertificateSerials(r.Context(), network.ID, s.now())
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	policySnapshot, err := buildPolicySnapshot(network, rules)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	response := &lanewayv1.RelayConfiguration{
		NetworkId: append([]byte(nil), network.ID[:]...), ConfigurationEpoch: network.ConfigurationEpoch,
		Policy: policySnapshot, ValidUntilUnixSeconds: uint64(validUntil),
		RevokedCertificateSerials: cloneByteSlices(revokedSerials),
		CertificateHealth:         certificateHealth(peerCertificate(r), revokedSerials),
	}
	for _, authorization := range authorizations {
		peer := &lanewayv1.RelayPeerAuthorization{NodeId: append([]byte(nil), authorization.NodeID[:]...)}
		for _, address := range authorization.OverlayAddresses {
			peer.OverlayAddresses = append(peer.OverlayAddresses, append([]byte(nil), address.AsSlice()...))
		}
		for _, prefix := range authorization.Prefixes {
			peer.AuthorizedPrefixes = append(peer.AuthorizedPrefixes, prefixMessage(prefix))
		}
		response.Peers = append(response.Peers, peer)
	}
	s.writeProto(w, http.StatusOK, response)
}

func cloneByteSlices(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = append([]byte(nil), values[i]...)
	}
	return result
}

func authenticatedRelay(r *http.Request) (identity.AuthenticatedIdentity, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return identity.AuthenticatedIdentity{}, ErrUnauthenticated
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(r.TLS.VerifiedChains[0][0])
	if err != nil || authenticated.RequireRole(identity.IdentityRoleRelay) != nil {
		return identity.AuthenticatedIdentity{}, ErrUnauthenticated
	}
	return authenticated, nil
}

func prefixMessage(prefix netip.Prefix) *lanewayv1.IpPrefix {
	return &lanewayv1.IpPrefix{Address: append([]byte(nil), prefix.Addr().AsSlice()...), PrefixLength: uint32(prefix.Bits())}
}

func (s *Service) revocation(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	serialText := r.PathValue("serial")
	if serialText == "" || len(serialText) > 64 || len(serialText)%2 != 0 || strings.ToLower(serialText) != serialText {
		s.writeError(w, malformed("serial must be canonical lowercase hexadecimal"), true)
		return
	}
	serial, err := hex.DecodeString(serialText)
	if err != nil {
		s.writeError(w, malformed("serial must be canonical lowercase hexadecimal"), true)
		return
	}
	record, err := s.store.CertificateBySerial(r.Context(), serial)
	if err != nil {
		s.writeError(w, err, true)
		return
	}
	if record.NetworkID != caller.NetworkID {
		s.writeError(w, controller.ErrNotFound, true)
		return
	}
	if record.RevokedAt == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.writeProto(w, http.StatusOK, &lanewayv1.CertificateRevocation{
		CertificateSerial: append([]byte(nil), record.Serial...), NodeId: append([]byte(nil), record.NodeID[:]...),
		RevokedUnixSeconds: uint64(record.RevokedAt.Unix()), Reason: record.RevocationReason,
	})
}

type requestError struct {
	status    int
	code      lanewayv1.ErrorCode
	detail    string
	retryable bool
}

func (e *requestError) Error() string { return e.detail }
func malformed(detail string) error {
	return &requestError{status: http.StatusBadRequest, code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, detail: detail}
}

func requireProtoContentType(r *http.Request) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/x-protobuf" && media != "application/protobuf") {
		return &requestError{status: http.StatusUnsupportedMediaType, code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, detail: "Content-Type must be application/x-protobuf"}
	}
	return nil
}

func (s *Service) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, &requestError{status: http.StatusRequestEntityTooLarge, code: lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED, detail: "request body exceeds limit"}
		}
		return nil, malformed("could not read request body")
	}
	return data, nil
}

func (s *Service) decodeProto(w http.ResponseWriter, r *http.Request, message proto.Message) error {
	if err := requireProtoContentType(r); err != nil {
		return err
	}
	data, err := s.readBody(w, r)
	if err != nil {
		return err
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, message); err != nil {
		return malformed("malformed protobuf request")
	}
	return nil
}

func (s *Service) decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return &requestError{status: http.StatusUnsupportedMediaType, code: lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, detail: "Content-Type must be application/json"}
	}
	data, err := s.readBody(w, r)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return malformed("malformed JSON request")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return malformed("request must contain one JSON value")
	}
	return nil
}

func (s *Service) writeProto(w http.ResponseWriter, status int, message proto.Message) {
	data, err := proto.Marshal(message)
	if err != nil {
		s.writeProtocolError(w, http.StatusInternalServerError, lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, "internal controller error", true)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (s *Service) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Service) writeError(w http.ResponseWriter, err error, protobuf bool) {
	status, code, detail, retryable := http.StatusInternalServerError, lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, "internal controller error", true
	var requestErr *requestError
	switch {
	case errors.As(err, &requestErr):
		status, code, detail, retryable = requestErr.status, requestErr.code, requestErr.detail, requestErr.retryable
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, controller.ErrTokenInvalid):
		status, code, detail, retryable = http.StatusUnauthorized, lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, "authentication failed", false
	case errors.Is(err, controller.ErrTokenExpired):
		status, code, detail, retryable = http.StatusUnauthorized, lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, "enrollment code has expired", false
	case errors.Is(err, ErrPermissionDenied):
		status, code, detail, retryable = http.StatusForbidden, lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "permission denied", false
	case errors.Is(err, controller.ErrTokenNetwork):
		status, code, detail, retryable = http.StatusForbidden, lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "enrollment code belongs to a different network", false
	case errors.Is(err, controller.ErrTokenName):
		status, code, detail, retryable = http.StatusForbidden, lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "enrollment code is bound to a different device name", false
	case errors.Is(err, controller.ErrNotFound):
		status, code, detail, retryable = http.StatusNotFound, lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, "record not found", false
	case errors.Is(err, controller.ErrTokenConsumed):
		status, code, detail, retryable = http.StatusConflict, lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "enrollment code has already been used", false
	case errors.Is(err, controller.ErrConflict), errors.Is(err, controller.ErrAlreadyApproved):
		status, code, detail, retryable = http.StatusConflict, lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "request conflicts with controller state", false
	case errors.Is(err, controller.ErrInvalid):
		status, code, detail, retryable = http.StatusBadRequest, lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, "invalid request", false
	}
	if protobuf {
		s.writeProtocolError(w, status, code, detail, retryable)
		return
	}
	s.writeJSON(w, status, map[string]any{"code": code.String(), "detail": detail, "retryable": retryable})
}

func (s *Service) writeProtocolError(w http.ResponseWriter, status int, code lanewayv1.ErrorCode, detail string, retryable bool) {
	s.writeProto(w, status, &lanewayv1.ProtocolError{Code: code, Detail: detail, Retryable: retryable})
}
