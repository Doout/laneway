package controllerservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/protocol"
)

type fixture struct {
	store   *controller.Store
	network controller.Network
	service *Service
}

func newFixture(t *testing.T, maxBody int64, nodeAuth NodeAuthorizer) fixture {
	t.Helper()
	store, err := controller.Open(context.Background(), filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	network, err := store.CreateNetwork(context.Background(), "test", netip.MustParsePrefix("10.44.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	material, ca, err := pki.NewAuthority("test controller CA", now.Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		Store: store, CACertificate: ca, CAKey: material.PrivateKey, LeafValidity: 24 * time.Hour,
		MaxBodyBytes: maxBody, AdminAuthorizer: func(*http.Request) error { return nil },
		NodeAuthorizer: nodeAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{store: store, network: network, service: service}
}

func TestOperationalMetricsClassifySuccessMalformedAndAuthorizationFailure(t *testing.T) {
	f := newFixture(t, 0, nil)

	health := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	missing := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/v1/not-a-route", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}

	f.service.authorizeAdm = func(*http.Request) error { return ErrUnauthenticated }
	denied := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("denied status = %d", denied.Code)
	}

	if got := f.service.Metrics(); got.Requests != 3 || got.SuccessfulResponses != 1 || got.MalformedInput != 1 ||
		got.AuthorizationFailures != 1 || got.InternalFailures != 0 {
		t.Fatalf("metrics = %+v", got)
	}
}

func TestAdministrativeInventoryAndRelayLifecycle(t *testing.T) {
	f := newFixture(t, 0, nil)
	token := issueToken(t, f, time.Now().Add(time.Hour))
	enrollment, _ := enroll(t, f, token, csrDER(t, ""), "inventory-node")
	if enrollment.GetNodeId() == nil {
		t.Fatal("inventory enrollment omitted node")
	}
	if _, _, err := f.store.AddACLRule(context.Background(), f.network.ID, 7, controller.ACLActionAccept, `{}`, "inventory rule"); err != nil {
		t.Fatal(err)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	relay, _, err := f.store.RegisterRelay(context.Background(), f.network.ID, serviceID, nil, "inventory-relay", "relay.example:4433")
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/v1/admin/networks?limit=10",
		"/v1/admin/networks/" + f.network.ID.String() + "/nodes?limit=10",
		"/v1/admin/networks/" + f.network.ID.String() + "/relays?limit=10",
		"/v1/admin/networks/" + f.network.ID.String() + "/acl-rules?limit=10",
		"/v1/admin/networks/" + f.network.ID.String() + "/certificates?limit=10",
	} {
		response := httptest.NewRecorder()
		f.service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
			t.Fatalf("inventory %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}

	updateBody := bytes.NewBufferString(`{"name":"inventory-relay-updated","endpoint":"relay2.example:4433","enabled":false}`)
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/relays/"+relay.ID.String(), updateBody)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatalf("disable through update status=%d body=%s", response.Code, response.Body.String())
	}
	updateBody = bytes.NewBufferString(`{"name":"inventory-relay-updated","endpoint":"relay2.example:4433","enabled":true}`)
	request = httptest.NewRequest(http.MethodPut, "/v1/admin/relays/"+relay.ID.String(), updateBody)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	f.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"enabled":true`) {
		t.Fatalf("re-enable relay status=%d body=%s", response.Code, response.Body.String())
	}
}

func csrDER(t *testing.T, requestedURI string) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted identity"}, DNSNames: []string{"attacker.example"}}
	if requestedURI != "" {
		u, err := url.Parse(requestedURI)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, private)
	if err != nil {
		t.Fatal(err)
	}
	if len(public) == 0 {
		t.Fatal("empty public key")
	}
	return der
}

func protobufRequest(t *testing.T, handler http.Handler, method, path string, message proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func mtlsRequest(t *testing.T, handler http.Handler, method, path string, message proto.Message, certificate *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	clone := *certificate
	certificate = &clone
	if certificate.NotAfter.IsZero() {
		certificate.NotBefore = time.Now().Add(-time.Hour)
		certificate.NotAfter = time.Now().Add(time.Hour)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, req)
	return result
}

func issueToken(t *testing.T, f fixture, expiry time.Time) string {
	t.Helper()
	reqBody, err := json.Marshal(tokenRequest{NetworkID: f.network.ID.String(), Label: "test", ExpiresAtUnix: expiry.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/enrollment-tokens", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	result := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(result, req)
	if result.Code != http.StatusCreated {
		t.Fatalf("issue token status=%d body=%s", result.Code, result.Body.String())
	}
	var response tokenResponse
	if err := json.Unmarshal(result.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.EnrollmentToken == "" || response.TokenID == "" {
		t.Fatal("token response omitted secret or ID")
	}
	return response.EnrollmentToken
}

func enroll(t *testing.T, f fixture, token string, csr []byte, name string) (*lanewayv1.EnrollmentResponse, *httptest.ResponseRecorder) {
	t.Helper()
	result := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/enroll", &lanewayv1.EnrollmentRequest{
		EnrollmentToken: token, Pkcs10CsrDer: csr, RequestedName: name,
	})
	if result.Code != http.StatusCreated {
		return nil, result
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := proto.Unmarshal(result.Body.Bytes(), response); err != nil {
		t.Fatal(err)
	}
	return response, result
}

func parseLeaf(t *testing.T, chain *lanewayv1.CertificateChain) *x509.Certificate {
	t.Helper()
	if chain == nil || len(chain.CertificatesDer) != 1 {
		t.Fatalf("unexpected certificate chain: %+v", chain)
	}
	cert, err := x509.ParseCertificate(chain.CertificatesDer[0])
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEnrollmentUsesCSRKeyButOverridesIdentityAndRejectsReplay(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	token := issueToken(t, f, time.Now().Add(time.Hour))
	csr := csrDER(t, "spiffe://laneway/network/11111111111111111111111111111111/node/22222222222222222222222222222222")
	response, result := enroll(t, f, token, csr, "alpha")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%x", result.Code, result.Body.Bytes())
	}
	leaf := parseLeaf(t, response.CertificateChain)
	gotIdentity, err := identity.IdentityFromCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.NetworkId, gotIdentity.NetworkID[:]) || !bytes.Equal(response.NodeId, gotIdentity.NodeID[:]) {
		t.Fatalf("certificate identity does not match response: %+v", gotIdentity)
	}
	if len(response.GetOverlayAddresses()) != 1 {
		t.Fatalf("enrollment omitted controller overlay assignment: %+v", response)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.URIs) != 1 || leaf.Subject.CommonName == "untrusted identity" {
		t.Fatalf("untrusted CSR identity fields copied: subject=%q DNS=%v URIs=%v", leaf.Subject.CommonName, leaf.DNSNames, leaf.URIs)
	}
	_, replay := enroll(t, f, token, csr, "alpha-replay")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay status=%d want %d", replay.Code, http.StatusConflict)
	}
}

func TestEphemeralEnrollmentCertificateAndResponseAreLeaseBound(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	token, err := f.store.IssueEnrollmentTokenWithOptions(context.Background(), f.network.ID, "ephemeral-user", time.Now().Add(time.Minute), controller.EnrollmentTokenOptions{
		Class: controller.EnrollmentClassEphemeral, SessionLifetime: controller.MinEphemeralLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	csrBytes := csrDER(t, "")
	response, result := enroll(t, f, token.Secret, csrBytes, "ephemeral-user")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%x", result.Code, result.Body.Bytes())
	}
	wantExpiry := time.Unix(int64(response.GetLeaseExpiresAtUnixSeconds()), 0).UTC()
	if response.GetEnrollmentClass() != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER || response.GetLeaseExpiresAtUnixSeconds() != uint64(wantExpiry.Unix()) {
		t.Fatalf("ephemeral response=%+v", response)
	}
	leaf := parseLeaf(t, response.GetCertificateChain())
	if !leaf.NotAfter.Equal(wantExpiry) || response.GetCertificateChain().GetNotAfterUnixSeconds() != uint64(wantExpiry.Unix()) {
		t.Fatalf("certificate expiry=%s chain=%d want=%s", leaf.NotAfter, response.GetCertificateChain().GetNotAfterUnixSeconds(), wantExpiry)
	}
	var nodeID identity.NodeID
	copy(nodeID[:], response.GetNodeId())
	node, err := f.store.Node(context.Background(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := buildConfiguration(f.network, node, []controller.Node{node}, nil, nil, nil, uint64(wantExpiry.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.GetEnrollmentClass() != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER || configuration.GetIdentityLeaseExpiresAtUnixSeconds() != uint64(wantExpiry.Unix()) {
		t.Fatalf("configuration lease metadata=%+v", configuration)
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return wantExpiry.Add(-time.Second) }
	renewed, err := f.service.issueCertificate(node, csr)
	if err != nil || !renewed.NotAfter.Equal(wantExpiry) {
		t.Fatalf("renewal at boundary cert=%+v err=%v", renewed, err)
	}
	f.service.now = func() time.Time { return wantExpiry }
	if _, err := f.service.issueCertificate(node, csr); err == nil {
		t.Fatal("renewal at exact lease expiry unexpectedly succeeded")
	}
}

func TestEnrollmentSigningFailureRollsBackTokenNodeAndAddress(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	token := issueToken(t, f, time.Now().Add(time.Hour))
	csr := csrDER(t, "")
	originalNow := f.service.now
	f.service.now = func() time.Time { return f.service.ca.NotAfter }
	_, failed := enroll(t, f, token, csr, "retry-after-signing-failure")
	if failed.Code < 500 {
		t.Fatalf("expired CA enrollment status=%d body=%s", failed.Code, failed.Body.String())
	}

	f.service.now = originalNow
	response, retried := enroll(t, f, token, csr, "retry-after-signing-failure")
	if retried.Code != http.StatusCreated {
		t.Fatalf("token or node was not rolled back: status=%d body=%s", retried.Code, retried.Body.String())
	}
	if got, want := net.IP(response.GetOverlayAddresses()[0]).String(), "10.44.0.1"; got != want {
		t.Fatalf("address allocation leaked across rollback: got %s want %s", got, want)
	}
}

func TestDualStackEnrollmentReturnsBothOverlayFamilies(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	dual, err := f.store.CreateNetworkDualStack(
		context.Background(),
		"dual-stack",
		netip.MustParsePrefix("10.46.0.0/24"),
		netip.MustParsePrefix("fd46::/120"),
	)
	if err != nil {
		t.Fatal(err)
	}
	f.network = dual
	response, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "dual-node")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%x", result.Code, result.Body.Bytes())
	}
	if len(response.GetOverlayAddresses()) != 2 {
		t.Fatalf("overlay addresses = %x, want IPv4 and IPv6", response.GetOverlayAddresses())
	}
	var hasIPv4, hasIPv6 bool
	for _, encoded := range response.GetOverlayAddresses() {
		address, ok := netip.AddrFromSlice(encoded)
		if !ok {
			t.Fatalf("invalid overlay address bytes %x", encoded)
		}
		hasIPv4 = hasIPv4 || address.Is4()
		hasIPv6 = hasIPv6 || address.Is6()
	}
	if !hasIPv4 || !hasIPv6 {
		t.Fatalf("overlay families IPv4=%t IPv6=%t", hasIPv4, hasIPv6)
	}
}

func TestExpiredTokenAndMalformedCSRDoesNotConsumeToken(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	expiredToken := issueToken(t, f, time.Now().Add(time.Second))
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)) + 50*time.Millisecond)
	_, expired := enroll(t, f, expiredToken, csrDER(t, ""), "expired")
	if expired.Code != http.StatusUnauthorized {
		t.Fatalf("expired status=%d", expired.Code)
	}

	validToken := issueToken(t, f, time.Now().Add(time.Hour))
	_, malformedResult := enroll(t, f, validToken, []byte{0x30, 0x00}, "malformed")
	if malformedResult.Code != http.StatusBadRequest {
		t.Fatalf("malformed CSR status=%d", malformedResult.Code)
	}
	_, validResult := enroll(t, f, validToken, csrDER(t, ""), "valid-after-malformed")
	if validResult.Code != http.StatusCreated {
		t.Fatalf("token consumed by malformed CSR: status=%d", validResult.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	f := newFixture(t, 1024, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(strings.Repeat("x", 2048)))
	req.Header.Set("Content-Type", "application/x-protobuf")
	result := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(result, req)
	if result.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want %d", result.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestRenewalPreservesAuthenticatedIdentity(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	token := issueToken(t, f, time.Now().Add(time.Hour))
	response, result := enroll(t, f, token, csrDER(t, ""), "renewing")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d", result.Code)
	}
	copy(authenticated.NetworkID[:], response.NetworkId)
	copy(authenticated.NodeID[:], response.NodeId)
	renewal := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/renew", &lanewayv1.RenewalRequest{
		Pkcs10CsrDer: csrDER(t, "spiffe://laneway/network/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/node/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	})
	if renewal.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%x", renewal.Code, renewal.Body.Bytes())
	}
	responseRenewal := new(lanewayv1.RenewalResponse)
	if err := proto.Unmarshal(renewal.Body.Bytes(), responseRenewal); err != nil {
		t.Fatal(err)
	}
	got, err := identity.IdentityFromCertificate(parseLeaf(t, responseRenewal.CertificateChain))
	if err != nil {
		t.Fatal(err)
	}
	if got != authenticated {
		t.Fatalf("renewed identity=%+v want %+v", got, authenticated)
	}
}

func TestEnrollmentAndRenewalReturnIntermediateChainForRootTrust(t *testing.T) {
	store, err := controller.Open(context.Background(), filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	network, err := store.CreateNetwork(context.Background(), "intermediate", netip.MustParsePrefix("10.45.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	rootMaterial, root, err := pki.NewAuthority("offline root", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey, "online controller issuer", now, 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var authenticated identity.NodeIdentity
	service, err := New(Options{
		Store: store, CACertificate: issuer, CAKey: issuerMaterial.PrivateKey,
		IssuerChain: []*x509.Certificate{issuer, root}, LeafValidity: 24 * time.Hour,
		AdminAuthorizer: func(*http.Request) error { return nil },
		NodeAuthorizer:  func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{store: store, network: network, service: service}
	token := issueToken(t, f, time.Now().Add(time.Hour))
	enrollment, result := enroll(t, f, token, csrDER(t, ""), "intermediate-node")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%x", result.Code, result.Body.Bytes())
	}
	verifyRootTrustedResponseChain(t, enrollment.GetCertificateChain(), root, issuer)
	copy(authenticated.NetworkID[:], enrollment.GetNetworkId())
	copy(authenticated.NodeID[:], enrollment.GetNodeId())

	renewalResult := protobufRequest(t, service.Handler(), http.MethodPost, "/v1/renew", &lanewayv1.RenewalRequest{Pkcs10CsrDer: csrDER(t, "")})
	if renewalResult.Code != http.StatusOK {
		t.Fatalf("renew status=%d body=%x", renewalResult.Code, renewalResult.Body.Bytes())
	}
	renewal := new(lanewayv1.RenewalResponse)
	if err := proto.Unmarshal(renewalResult.Body.Bytes(), renewal); err != nil {
		t.Fatal(err)
	}
	verifyRootTrustedResponseChain(t, renewal.GetCertificateChain(), root, issuer)
}

func verifyRootTrustedResponseChain(t *testing.T, chain *lanewayv1.CertificateChain, root, issuer *x509.Certificate) {
	t.Helper()
	if chain == nil || len(chain.GetCertificatesDer()) != 2 {
		t.Fatalf("response chain length = %d, want leaf + intermediate", len(chain.GetCertificatesDer()))
	}
	leaf, err := x509.ParseCertificate(chain.GetCertificatesDer()[0])
	if err != nil {
		t.Fatal(err)
	}
	returnedIssuer, err := x509.ParseCertificate(chain.GetCertificatesDer()[1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(returnedIssuer.Raw, issuer.Raw) {
		t.Fatal("response returned the wrong issuer")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(returnedIssuer)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify response chain with root-only trust: %v", err)
	}
}

func TestConfigurationEpochRoutesAndPolicy(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	token := issueToken(t, f, time.Now().Add(time.Hour))
	response, result := enroll(t, f, token, csrDER(t, ""), "configured")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d", result.Code)
	}
	copy(authenticated.NetworkID[:], response.NetworkId)
	copy(authenticated.NodeID[:], response.NodeId)

	initial := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{})
	if initial.Code != http.StatusOK {
		t.Fatalf("initial config status=%d", initial.Code)
	}
	config := new(lanewayv1.NodeConfiguration)
	if err := proto.Unmarshal(initial.Body.Bytes(), config); err != nil {
		t.Fatal(err)
	}
	if config.ConfigurationEpoch != 2 || len(config.OverlayAddresses) != 1 || len(config.GetRoutes().GetRoutes()) != 1 ||
		len(config.GetPeers()) != 1 || config.GetPeers()[0].GetName() != "configured" || string(config.GetPeers()[0].GetNodeId()) != string(authenticated.NodeID[:]) ||
		config.Policy.GetDefaultAction() != lanewayv1.PolicyAction_POLICY_ACTION_DENY || config.GetValidUntilUnixSeconds() <= uint64(time.Now().Unix()) {
		t.Fatalf("initial config=%+v", config)
	}
	unchanged := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: 2})
	if unchanged.Code != http.StatusNotModified {
		t.Fatalf("unchanged status=%d", unchanged.Code)
	}
	if unchanged.Header().Get(SnapshotValidityHeader) == "" {
		t.Fatal("not-modified response omitted renewed snapshot validity")
	}
	_, epoch, err := f.store.AddACLRule(context.Background(), f.network.ID, 10, controller.ACLActionAccept, `{}`, "allow")
	if err != nil || epoch != 3 {
		t.Fatalf("add ACL epoch=%d err=%v", epoch, err)
	}
	epoch, err = f.store.SetNodeCapabilities(context.Background(), authenticated.NodeID, protocol.CapabilitySubnetRouterV1)
	if err != nil || epoch != 4 {
		t.Fatalf("enable subnet capability epoch=%d err=%v", epoch, err)
	}
	advertised, err := f.store.AdvertiseRoute(context.Background(), authenticated.NodeID, netip.MustParsePrefix("192.0.2.0/24"), controller.RouteKindSubnet, controller.RouteModeNAT, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err = f.store.ApproveRoute(context.Background(), advertised.ID)
	if err != nil || epoch != 5 {
		t.Fatalf("approve route epoch=%d err=%v", epoch, err)
	}
	updated := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: 2})
	if updated.Code != http.StatusOK {
		t.Fatalf("updated status=%d", updated.Code)
	}
	if err := proto.Unmarshal(updated.Body.Bytes(), config); err != nil {
		t.Fatal(err)
	}
	if config.ConfigurationEpoch != 5 || config.GetEnabledCapabilities() != uint64(protocol.CapabilitySubnetRouterV1) || len(config.Policy.Rules) != 1 || config.Policy.Rules[0].Action != lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT || len(config.Routes.Routes) != 2 {
		t.Fatalf("updated config=%+v", config)
	}
	if route := config.Routes.Routes[1]; route.GetKind() != lanewayv1.RouteKind_ROUTE_KIND_SUBNET ||
		route.GetMode() != lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT {
		t.Fatalf("subnet route mode not preserved in snapshot: %+v", route)
	}
}

func TestEveryNodeSnapshotIsCappedByEarliestEphemeralLease(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	durable, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "durable-peer")
	if result.Code != http.StatusCreated {
		t.Fatalf("durable enrollment status=%d", result.Code)
	}
	copy(authenticated.NetworkID[:], durable.GetNetworkId())
	copy(authenticated.NodeID[:], durable.GetNodeId())
	token, err := f.store.IssueEnrollmentTokenWithOptions(context.Background(), f.network.ID, "short-user", time.Now().Add(time.Minute), controller.EnrollmentTokenOptions{
		Class: controller.EnrollmentClassEphemeral, SessionLifetime: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, result := enroll(t, f, token.Secret, csrDER(t, ""), "short-user")
	if result.Code != http.StatusCreated {
		t.Fatalf("ephemeral enrollment status=%d body=%x", result.Code, result.Body.Bytes())
	}
	f.service.snapshotValidity = time.Hour
	configuration := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{})
	if configuration.Code != http.StatusOK {
		t.Fatalf("configuration status=%d body=%x", configuration.Code, configuration.Body.Bytes())
	}
	want := strconv.FormatUint(ephemeral.GetLeaseExpiresAtUnixSeconds(), 10)
	var body lanewayv1.NodeConfiguration
	if err := proto.Unmarshal(configuration.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := strconv.FormatUint(body.GetValidUntilUnixSeconds(), 10); got != want {
		t.Fatalf("snapshot deadline=%s want earliest ephemeral lease %s", got, want)
	}
	unchanged := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: body.GetConfigurationEpoch()})
	if unchanged.Code != http.StatusNotModified || unchanged.Header().Get(SnapshotValidityHeader) != want {
		t.Fatalf("unchanged status=%d deadline=%s want=%s", unchanged.Code, unchanged.Header().Get(SnapshotValidityHeader), want)
	}
}

func TestConfigurationEndpointsExpireRoutesBeforeConditionalResponse(t *testing.T) {
	t.Run("node", func(t *testing.T) {
		base := time.Now().UTC().Truncate(time.Second)
		var authenticated identity.NodeIdentity
		f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
		f.service.now = func() time.Time { return base }
		token := issueToken(t, f, base.Add(time.Hour))
		enrollment, result := enroll(t, f, token, csrDER(t, ""), "expiring-node")
		if result.Code != http.StatusCreated {
			t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
		}
		copy(authenticated.NetworkID[:], enrollment.GetNetworkId())
		copy(authenticated.NodeID[:], enrollment.GetNodeId())
		if _, err := f.store.SetNodeCapabilities(context.Background(), authenticated.NodeID, protocol.CapabilitySubnetRouterV1); err != nil {
			t.Fatal(err)
		}
		validUntil := base.Add(time.Minute)
		route, err := f.store.AdvertiseRoute(context.Background(), authenticated.NodeID, netip.MustParsePrefix("192.0.2.0/24"), controller.RouteKindSubnet, controller.RouteModeNAT, 1, &validUntil)
		if err != nil {
			t.Fatal(err)
		}
		knownEpoch, err := f.store.ApproveRoute(context.Background(), route.ID)
		if err != nil {
			t.Fatal(err)
		}
		f.service.now = func() time.Time { return validUntil }
		responseRecorder := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration",
			&lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: knownEpoch})
		if responseRecorder.Code != http.StatusOK {
			t.Fatalf("expired node config status=%d body=%s", responseRecorder.Code, responseRecorder.Body.String())
		}
		response := new(lanewayv1.NodeConfiguration)
		if err := proto.Unmarshal(responseRecorder.Body.Bytes(), response); err != nil {
			t.Fatal(err)
		}
		if response.GetConfigurationEpoch() != knownEpoch+1 || len(response.GetRoutes().GetRoutes()) != 1 {
			t.Fatalf("expired node configuration=%+v", response)
		}
		unchanged := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration",
			&lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: knownEpoch + 1})
		if unchanged.Code != http.StatusNotModified {
			t.Fatalf("post-expiry node status=%d body=%s", unchanged.Code, unchanged.Body.String())
		}
	})

	t.Run("relay", func(t *testing.T) {
		base := time.Now().UTC().Truncate(time.Second)
		f := newFixture(t, DefaultMaxBodyBytes, nil)
		f.service.now = func() time.Time { return base }
		token := issueToken(t, f, base.Add(time.Hour))
		enrollment, result := enroll(t, f, token, csrDER(t, ""), "expiring-relay-peer")
		if result.Code != http.StatusCreated {
			t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
		}
		var nodeID identity.NodeID
		copy(nodeID[:], enrollment.GetNodeId())
		if _, err := f.store.SetNodeCapabilities(context.Background(), nodeID, protocol.CapabilitySubnetRouterV1); err != nil {
			t.Fatal(err)
		}
		validUntil := base.Add(time.Minute)
		route, err := f.store.AdvertiseRoute(context.Background(), nodeID, netip.MustParsePrefix("198.51.100.0/24"), controller.RouteKindSubnet, controller.RouteModeRouted, 1, &validUntil)
		if err != nil {
			t.Fatal(err)
		}
		knownEpoch, err := f.store.ApproveRoute(context.Background(), route.ID)
		if err != nil {
			t.Fatal(err)
		}
		serviceID, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		_, knownEpoch, err = f.store.RegisterRelay(context.Background(), f.network.ID, serviceID, nil, "expiring-relay", "relay.example:443")
		if err != nil {
			t.Fatal(err)
		}
		uri, err := (pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleRelay}).URI()
		if err != nil {
			t.Fatal(err)
		}
		relayCertificate := &x509.Certificate{URIs: []*url.URL{uri}}
		f.service.now = func() time.Time { return validUntil }
		responseRecorder := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
			&lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: knownEpoch}, relayCertificate)
		if responseRecorder.Code != http.StatusOK {
			t.Fatalf("expired relay config status=%d body=%s", responseRecorder.Code, responseRecorder.Body.String())
		}
		response := new(lanewayv1.RelayConfiguration)
		if err := proto.Unmarshal(responseRecorder.Body.Bytes(), response); err != nil {
			t.Fatal(err)
		}
		if response.GetConfigurationEpoch() != knownEpoch+1 || len(response.GetPeers()) != 1 || len(response.GetPeers()[0].GetAuthorizedPrefixes()) != 1 {
			t.Fatalf("expired relay configuration=%+v", response)
		}
		unchanged := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
			&lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: knownEpoch + 1}, relayCertificate)
		if unchanged.Code != http.StatusNotModified {
			t.Fatalf("post-expiry relay status=%d body=%s", unchanged.Code, unchanged.Body.String())
		}
	})
}

func TestMTLSAuthorizationAndRevocationStatus(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	tokenOne := issueToken(t, f, time.Now().Add(time.Hour))
	responseOne, result := enroll(t, f, tokenOne, csrDER(t, ""), "node-one")
	if result.Code != http.StatusCreated {
		t.Fatalf("first enroll status=%d", result.Code)
	}
	certOne := parseLeaf(t, responseOne.CertificateChain)
	tokenTwo := issueToken(t, f, time.Now().Add(time.Hour))
	responseTwo, result := enroll(t, f, tokenTwo, csrDER(t, ""), "node-two")
	if result.Code != http.StatusCreated {
		t.Fatalf("second enroll status=%d", result.Code)
	}
	certTwo := parseLeaf(t, responseTwo.CertificateChain)

	serialPath := "/v1/revocations/" + hex.EncodeToString(certOne.SerialNumber.Bytes())
	active := mtlsRequest(t, f.service.Handler(), http.MethodGet, serialPath, &lanewayv1.ConfigurationRequest{}, certTwo)
	if active.Code != http.StatusNoContent {
		t.Fatalf("active revocation status=%d body=%x", active.Code, active.Body.Bytes())
	}
	record, err := f.store.CertificateBySerial(context.Background(), certOne.SerialNumber.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeCertificate(context.Background(), record.ID, "superseded"); err != nil {
		t.Fatal(err)
	}
	revoked := mtlsRequest(t, f.service.Handler(), http.MethodGet, serialPath, &lanewayv1.ConfigurationRequest{}, certTwo)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoked status=%d body=%x", revoked.Code, revoked.Body.Bytes())
	}
	status := new(lanewayv1.CertificateRevocation)
	if err := proto.Unmarshal(revoked.Body.Bytes(), status); err != nil {
		t.Fatal(err)
	}
	if status.Reason != "superseded" || !bytes.Equal(status.NodeId, responseOne.NodeId) {
		t.Fatalf("revocation=%+v", status)
	}
	configurationResult := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{}, certTwo)
	if configurationResult.Code != http.StatusOK {
		t.Fatalf("configuration after certificate revocation status=%d body=%s", configurationResult.Code, configurationResult.Body.String())
	}
	configuration := new(lanewayv1.NodeConfiguration)
	if err := proto.Unmarshal(configurationResult.Body.Bytes(), configuration); err != nil {
		t.Fatal(err)
	}
	if len(configuration.GetRevokedCertificateSerials()) != 1 || !bytes.Equal(configuration.GetRevokedCertificateSerials()[0], certOne.SerialNumber.Bytes()) {
		t.Fatalf("revoked serial snapshot=%x", configuration.GetRevokedCertificateSerials())
	}
	denied := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{}, certOne)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("revoked certificate config status=%d", denied.Code)
	}
}

func TestConfigurationIncludesEveryActiveOverlayHostRoute(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, DefaultMaxBodyBytes, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	first, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "overlay-one")
	if result.Code != http.StatusCreated {
		t.Fatalf("first enrollment status=%d", result.Code)
	}
	second, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "overlay-two")
	if result.Code != http.StatusCreated {
		t.Fatalf("second enrollment status=%d", result.Code)
	}
	copy(authenticated.NetworkID[:], first.GetNetworkId())
	copy(authenticated.NodeID[:], first.GetNodeId())
	response := protobufRequest(t, f.service.Handler(), http.MethodPost, "/v1/configuration", &lanewayv1.ConfigurationRequest{})
	if response.Code != http.StatusOK {
		t.Fatalf("configuration status=%d", response.Code)
	}
	configuration := new(lanewayv1.NodeConfiguration)
	if err := proto.Unmarshal(response.Body.Bytes(), configuration); err != nil {
		t.Fatal(err)
	}
	owners := make(map[string]bool)
	for _, route := range configuration.GetRoutes().GetRoutes() {
		if route.GetKind() == lanewayv1.RouteKind_ROUTE_KIND_OVERLAY && route.GetDestination().GetPrefixLength() == 32 {
			owners[hex.EncodeToString(route.GetViaNodeId())] = true
		}
	}
	if len(owners) != 2 || !owners[hex.EncodeToString(first.GetNodeId())] || !owners[hex.EncodeToString(second.GetNodeId())] {
		t.Fatalf("overlay route owners=%v configuration=%+v", owners, configuration)
	}
	if configuration.GetConfigurationEpoch() != 3 {
		t.Fatalf("enrollment epoch=%d want 3", configuration.GetConfigurationEpoch())
	}
}

func TestRelayConfigurationUsesRelayIdentityAndNetworkSnapshot(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	token := issueToken(t, f, time.Now().Add(time.Hour))
	enrollment, result := enroll(t, f, token, csrDER(t, ""), "relay-peer")
	if result.Code != http.StatusCreated {
		t.Fatalf("enrollment status=%d body=%s", result.Code, result.Body.String())
	}
	var nodeID identity.NodeID
	copy(nodeID[:], enrollment.GetNodeId())
	if _, err := f.store.SetNodeCapabilities(context.Background(), nodeID, protocol.CapabilitySubnetRouterV1); err != nil {
		t.Fatal(err)
	}
	route, err := f.store.AdvertiseRoute(context.Background(), nodeID, netip.MustParsePrefix("192.168.50.0/24"),
		controller.RouteKindSubnet, controller.RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ApproveRoute(context.Background(), route.ID); err != nil {
		t.Fatal(err)
	}
	nodeCertificate, err := x509.ParseCertificate(enrollment.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		t.Fatal(err)
	}
	record, err := f.store.CertificateBySerial(context.Background(), nodeCertificate.SerialNumber.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RevokeCertificate(context.Background(), record.ID, "relay snapshot test"); err != nil {
		t.Fatal(err)
	}
	serviceID, _ := identity.NewID()
	relay, _, err := f.store.RegisterRelay(context.Background(), f.network.ID, serviceID, nil, "relay-config", "relay.example:443")
	if err != nil {
		t.Fatal(err)
	}
	uri, err := (pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleRelay}).URI()
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate := &x509.Certificate{URIs: []*url.URL{uri}}
	unknownServiceID, _ := identity.NewID()
	unknownURI, _ := (pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: unknownServiceID, Role: pki.RoleRelay}).URI()
	unknown := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{}, &x509.Certificate{URIs: []*url.URL{unknownURI}})
	if unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown relay status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	responseRecorder := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{}, relayCertificate)
	if responseRecorder.Code != http.StatusOK {
		t.Fatalf("relay config status=%d body=%s", responseRecorder.Code, responseRecorder.Body.String())
	}
	response := new(lanewayv1.RelayConfiguration)
	if err := proto.Unmarshal(responseRecorder.Body.Bytes(), response); err != nil {
		t.Fatal(err)
	}
	if len(response.GetPeers()) != 1 || len(response.GetPeers()[0].GetOverlayAddresses()) != 1 ||
		len(response.GetPeers()[0].GetAuthorizedPrefixes()) != 2 || response.GetPolicy() == nil ||
		len(response.GetRevokedCertificateSerials()) != 1 || !bytes.Equal(response.GetRevokedCertificateSerials()[0], nodeCertificate.SerialNumber.Bytes()) {
		t.Fatalf("relay configuration = %#v", response)
	}
	unchanged := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: response.GetConfigurationEpoch()}, relayCertificate)
	if unchanged.Code != http.StatusNotModified {
		t.Fatalf("unchanged status=%d body=%s", unchanged.Code, unchanged.Body.String())
	}
	disabledEpoch, err := f.store.DisableRelay(context.Background(), relay.ID)
	if err != nil {
		t.Fatal(err)
	}
	disabled := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: disabledEpoch}, relayCertificate)
	if disabled.Code != http.StatusForbidden {
		t.Fatalf("disabled relay status=%d body=%s", disabled.Code, disabled.Body.String())
	}
	denied := mtlsRequest(t, f.service.Handler(), http.MethodPost, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{}, nodeCertificate)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("node role status=%d body=%s", denied.Code, denied.Body.String())
	}
}
