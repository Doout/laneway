// Package controllerclient implements HTTPS enrollment/management and the
// bounded reliable mTLS QUIC client used for authenticated renewal and
// controller configuration snapshots.
package controllerclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"google.golang.org/protobuf/proto"
)

const (
	MaxResponseBytes       = 1 << 20
	MaxJSONRequestBytes    = 128 << 10
	maxAdminTokenBytes     = 8 << 10
	maxLifecycleReplyBytes = 8 << 10
	snapshotValidityHeader = "X-Laneway-Configuration-Valid-Until"
)

type Options struct {
	Endpoint string
	// QUICEndpoint is the host:port of the reliable authenticated control
	// listener. Enrollment and administrative HTTPS calls remain on Endpoint.
	QUICEndpoint string
	// QUICDialAddress optionally pins QUIC UDP dialing to a numeric IP:port
	// while QUICEndpoint and ServerName remain authoritative for identity.
	QUICDialAddress string
	CAFile          string
	// CAPEM supplies an authenticated in-memory trust bundle, primarily from
	// public-Web-PKI bootstrap discovery. Exactly one of CAFile and CAPEM is
	// required so an untrusted file cannot silently override discovered trust.
	CAPEM             []byte
	CertificateFile   string
	PrivateKeyFile    string
	ServerName        string
	ExpectedNetworkID identity.NetworkID
	ExpectedServiceID identity.ID
	// DialAddress pins all HTTP connection attempts to a numeric IP:port.
	// Endpoint remains authoritative for URL Host, SNI, and identity checks.
	DialAddress    string
	AdminTokenFile string
	Timeout        time.Duration
	// EphemeralExitLeaseGeneration is the non-secret generation returned by
	// the one-time enrollment. It is meaningful only with an ephemeral Exit
	// certificate and is sent exclusively inside authenticated QUIC requests.
	EphemeralExitLeaseGeneration uint64
}

// BootstrapMetadata fetches the non-secret discovery document over the
// relay's already pinned, mutually authenticated controller connection.
func (c *Client) BootstrapMetadata(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+bootstrap.WellKnownPath, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap request: %w", err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, bootstrap.MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read controller bootstrap response: %w", err)
	}
	if len(contents) > bootstrap.MaxDocumentBytes {
		return nil, errors.New("controller bootstrap response exceeds limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller bootstrap returned %s", response.Status)
	}
	return contents, nil
}

// BootstrapBundle fetches and consumes one encrypted bootstrap wrapper over
// the relay's pinned controller connection. The decryption key is never sent
// to this API.
func (c *Client) BootstrapBundle(ctx context.Context, id string) ([]byte, error) {
	if _, valid := bootstrap.BundleIDFromPath(bootstrap.BundlePathPrefix + id); !valid {
		return nil, errors.New("controller bootstrap bundle ID is invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/v1/bootstrap-bundles/"+id, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/x-shellscript")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("controller bootstrap bundle request: %w", err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(response.Body, bootstrap.MaxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read controller bootstrap bundle response: %w", err)
	}
	if len(contents) > bootstrap.MaxBundleBytes {
		return nil, errors.New("controller bootstrap bundle response exceeds limit")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller bootstrap bundle returned %s", response.Status)
	}
	return contents, nil
}

// PublicConsole forwards one browser console or administrator request over the
// relay's authenticated controller connection. Node APIs, root bearer
// credentials, and public bootstrap paths are deliberately outside this
// boundary.
func (c *Client) PublicConsole(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("controller client: public console request is required")
	}
	path := request.URL.Path
	administrator := path == "/v1/admin" || strings.HasPrefix(path, "/v1/admin/")
	reserved := path == "/v1" || strings.HasPrefix(path, "/v1/") ||
		path == "/.well-known" || strings.HasPrefix(path, "/.well-known/")
	if !administrator && reserved {
		return nil, errors.New("controller client: public console request path is not allowed")
	}
	if len(request.Header.Values("Authorization")) != 0 || len(request.Header.Values("Proxy-Authorization")) != 0 {
		return nil, errors.New("controller client: public console request contains a forbidden credential")
	}
	upstreamURL, err := url.Parse(c.endpoint)
	if err != nil {
		return nil, errors.New("controller client: invalid configured endpoint")
	}
	forwarded := request.Clone(request.Context())
	forwarded.URL.Scheme = upstreamURL.Scheme
	forwarded.URL.Host = upstreamURL.Host
	forwarded.RequestURI = ""
	removeProxyHeaders(forwarded.Header)
	clientAddress, err := remoteAddress(request.RemoteAddr)
	if err != nil {
		return nil, errors.New("controller client: public console client address is invalid")
	}
	forwarded.Header.Set(adminauth.PublicClientAddressHeader, clientAddress.String())
	response, err := c.http.Do(forwarded)
	if err != nil {
		return nil, fmt.Errorf("controller public console request: %w", err)
	}
	removeProxyHeaders(response.Header)
	return response, nil
}

func removeProxyHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", adminauth.PublicClientAddressHeader,
	} {
		header.Del(name)
	}
}

func remoteAddress(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}

type Client struct {
	endpoint    string
	http        *http.Client
	adminBearer string
	quic        *quicControllerClient
}

// Close releases the reusable QUIC control session and idle HTTPS
// connections. Callers that hand an ephemeral identity to another process
// must close first so the controller can enforce one active session.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	if c.quic != nil {
		c.quic.close()
	}
	if transport, ok := c.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func New(options Options) (*Client, error) {
	endpoint, err := normalizeEndpoint(options.Endpoint)
	if err != nil {
		return nil, err
	}
	if options.ExpectedNetworkID.IsZero() || options.ExpectedServiceID.IsZero() {
		return nil, errors.New("controller client: expected controller network and service IDs are required")
	}
	if (options.CAFile == "") == (len(options.CAPEM) == 0) {
		return nil, errors.New("controller client: exactly one CA file or in-memory CA bundle is required")
	}
	caPEM := append([]byte(nil), options.CAPEM...)
	if options.CAFile != "" {
		caPEM, err = os.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("controller client: read CA: %w", err)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("controller client: CA file contains no certificates")
	}
	tlsConfig := &tls.Config{
		RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true, // Chain and identity verification are performed below.
		ServerName:         options.ServerName,
	}
	if options.CertificateFile != "" || options.PrivateKeyFile != "" {
		if options.CertificateFile == "" || options.PrivateKeyFile == "" {
			return nil, errors.New("controller client: both certificate and private key are required")
		}
		certificate, err := tls.LoadX509KeyPair(options.CertificateFile, options.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("controller client: load node credential: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("controller client: server sent no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("controller client: verify server chain: %w", err)
		}
		if options.ServerName != "" {
			if err := state.PeerCertificates[0].VerifyHostname(options.ServerName); err != nil {
				return fmt.Errorf("controller client: verify server name: %w", err)
			}
		}
		authenticated, err := identity.AuthenticatedIdentityFromCertificate(state.PeerCertificates[0])
		if err != nil {
			return err
		}
		if err := authenticated.RequireRole(identity.IdentityRoleController); err != nil {
			return err
		}
		if authenticated.NetworkID != options.ExpectedNetworkID || authenticated.SubjectID != options.ExpectedServiceID {
			return errors.New("controller client: controller certificate identity does not match the configured network and service IDs")
		}
		return nil
	}
	if options.Timeout == 0 {
		options.Timeout = 15 * time.Second
	}
	if options.Timeout < 0 {
		return nil, errors.New("controller client: timeout must be positive")
	}
	var dialContext func(context.Context, string, string) (net.Conn, error)
	if options.DialAddress != "" {
		if err := validatePinnedDialAddress(options.DialAddress); err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
		dialContext = pinnedDialContext(options.DialAddress, dialer.DialContext)
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig, DisableCompression: true, ForceAttemptHTTP2: true,
		MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: options.Timeout, DialContext: dialContext,
	}
	var adminBearer string
	if options.AdminTokenFile != "" {
		token, err := readAdminToken(options.AdminTokenFile)
		if err != nil {
			return nil, err
		}
		adminBearer = "Bearer " + token
	}
	var control *quicControllerClient
	if options.QUICEndpoint != "" {
		if len(tlsConfig.Certificates) == 0 {
			return nil, errors.New("controller client: QUIC control requires a client certificate")
		}
		control, err = newQUICControllerClient(options.QUICEndpoint, options.QUICDialAddress, tlsConfig, options.Timeout, options.EphemeralExitLeaseGeneration)
		if err != nil {
			return nil, err
		}
	}
	return &Client{endpoint: endpoint, http: &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, adminBearer: adminBearer, quic: control}, nil
}

func validatePinnedDialAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return errors.New("controller client: pinned dial address must be IP:port")
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.IsUnspecified() || parsed.IsMulticast() {
		return errors.New("controller client: pinned dial address must contain a usable IP")
	}
	return nil
}

func pinnedDialContext(address string, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, address)
	}
}

func readAdminToken(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("controller client: open admin token: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxAdminTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("controller client: read admin token: %w", err)
	}
	if len(contents) > maxAdminTokenBytes {
		return "", errors.New("controller client: admin token file is too large")
	}
	token := strings.TrimSpace(string(contents))
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("controller client: admin token must be one nonempty line")
	}
	return token, nil
}

func normalizeEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("controller client: endpoint must be an HTTPS origin")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("controller client: endpoint must not contain a path")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

// Enroll is the stable-v1 legacy enrollment path. It intentionally creates an
// unbound native-QUIC identity; hybrid-capable clients must use a network-bound
// method and provide their locally generated WireGuard public key.
func (c *Client) Enroll(ctx context.Context, token, name string, csrDER []byte) (*lanewayv1.EnrollmentResponse, error) {
	return c.enroll(ctx, token, name, csrDER, nil, identity.NetworkID{})
}

func (c *Client) EnrollForNetwork(ctx context.Context, token, name string, csrDER, wireGuardPublicKey []byte, expectedNetwork identity.NetworkID) (*lanewayv1.EnrollmentResponse, error) {
	if expectedNetwork.IsZero() {
		return nil, errors.New("controller client: expected enrollment network is required")
	}
	return c.enroll(ctx, token, name, csrDER, wireGuardPublicKey, expectedNetwork)
}

func (c *Client) EnrollForNetworkAndClass(ctx context.Context, token, name string, csrDER, wireGuardPublicKey []byte, expectedNetwork identity.NetworkID, expectedClass lanewayv1.EnrollmentClass) (*lanewayv1.EnrollmentResponse, error) {
	if expectedNetwork.IsZero() || (expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE &&
		expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER &&
		expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER) {
		return nil, errors.New("controller client: expected enrollment network and class are required")
	}
	request := &lanewayv1.EnrollmentRequest{
		EnrollmentToken: token, RequestedName: name, Pkcs10CsrDer: csrDER,
		ExpectedNetworkId: append([]byte(nil), expectedNetwork[:]...), ExpectedEnrollmentClass: expectedClass,
		WireguardPublicKey: append([]byte(nil), wireGuardPublicKey...),
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := c.post(ctx, "/v1/enroll", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) enroll(ctx context.Context, token, name string, csrDER, wireGuardPublicKey []byte, expectedNetwork identity.NetworkID) (*lanewayv1.EnrollmentResponse, error) {
	request := &lanewayv1.EnrollmentRequest{EnrollmentToken: token, RequestedName: name, Pkcs10CsrDer: csrDER, WireguardPublicKey: append([]byte(nil), wireGuardPublicKey...)}
	if !expectedNetwork.IsZero() {
		request.ExpectedNetworkId = append([]byte(nil), expectedNetwork[:]...)
		request.ExpectedEnrollmentClass = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := c.post(ctx, "/v1/enroll", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) Renew(ctx context.Context, csrDER, wireGuardPublicKey []byte) (*lanewayv1.RenewalResponse, error) {
	if c.quic != nil {
		return c.quic.renew(ctx, csrDER, wireGuardPublicKey)
	}
	response := new(lanewayv1.RenewalResponse)
	if err := c.post(ctx, "/v1/renew", &lanewayv1.RenewalRequest{Pkcs10CsrDer: csrDER, WireguardPublicKey: append([]byte(nil), wireGuardPublicKey...)}, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) Configuration(ctx context.Context, knownEpoch uint64) (*lanewayv1.NodeConfiguration, bool, error) {
	if c.quic != nil {
		return c.quic.configuration(ctx, knownEpoch)
	}
	response := new(lanewayv1.NodeConfiguration)
	notModified, err := c.postStatus(ctx, "/v1/configuration", &lanewayv1.ConfigurationRequest{KnownConfigurationEpoch: knownEpoch}, response)
	return response, notModified, err
}

func (c *Client) RelayConfiguration(ctx context.Context, knownEpoch uint64) (*lanewayv1.RelayConfiguration, bool, error) {
	if c.quic != nil {
		return c.quic.relayConfiguration(ctx, knownEpoch)
	}
	response := new(lanewayv1.RelayConfiguration)
	notModified, err := c.postStatus(ctx, "/v1/relay/configuration",
		&lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: knownEpoch}, response)
	return response, notModified, err
}

// Network is the stable JSON representation returned by the management API.
type Network struct {
	NetworkID          string `json:"network_id"`
	Name               string `json:"name"`
	IPv4Pool           string `json:"ipv4_pool"`
	IPv6Pool           string `json:"ipv6_pool,omitempty"`
	ConfigurationEpoch uint64 `json:"configuration_epoch"`
	CreatedAtUnix      int64  `json:"created_at_unix_seconds"`
}

type EnrollmentToken struct {
	TokenID                string `json:"token_id"`
	EnrollmentToken        string `json:"enrollment_token"`
	ExpiresAtUnix          int64  `json:"expires_at_unix_seconds"`
	EnrollmentClass        string `json:"enrollment_class"`
	SessionLifetimeSeconds int64  `json:"session_lifetime_seconds,omitempty"`
	RequestedName          string `json:"requested_name,omitempty"`
	EnabledCapabilities    uint64 `json:"enabled_capabilities,omitempty"`
}

type EnrollmentTokenOptions struct {
	Class               string
	SessionLifetime     time.Duration
	RequestedName       string
	EnabledCapabilities uint64
}

type Route struct {
	RouteID                string `json:"route_id"`
	NetworkID              string `json:"network_id"`
	NodeID                 string `json:"node_id"`
	Prefix                 string `json:"prefix"`
	Kind                   string `json:"kind"`
	Mode                   string `json:"mode"`
	Metric                 uint32 `json:"metric"`
	State                  string `json:"state"`
	ValidUntilUnixSeconds  *int64 `json:"valid_until_unix_seconds,omitempty"`
	CreatedAtUnixSeconds   int64  `json:"created_at_unix_seconds"`
	ApprovedAtUnixSeconds  *int64 `json:"approved_at_unix_seconds,omitempty"`
	WithdrawnAtUnixSeconds *int64 `json:"withdrawn_at_unix_seconds,omitempty"`
}

type Epoch struct {
	ConfigurationEpoch uint64 `json:"configuration_epoch"`
}

type Relay struct {
	RelayID            string  `json:"relay_id"`
	NetworkID          string  `json:"network_id"`
	ServiceID          string  `json:"service_id"`
	NodeID             *string `json:"node_id,omitempty"`
	Name               string  `json:"name"`
	Endpoint           string  `json:"endpoint"`
	Enabled            bool    `json:"enabled"`
	CreatedAtUnix      int64   `json:"created_at_unix_seconds"`
	ConfigurationEpoch uint64  `json:"configuration_epoch"`
}

type Node struct {
	NodeID                    string `json:"node_id"`
	NetworkID                 string `json:"network_id"`
	Name                      string `json:"name"`
	EnabledCapabilities       uint64 `json:"enabled_capabilities"`
	IPv4Address               string `json:"ipv4_address,omitempty"`
	IPv6Address               string `json:"ipv6_address,omitempty"`
	CreatedAtUnixSeconds      int64  `json:"created_at_unix_seconds"`
	RevokedAtUnixSeconds      *int64 `json:"revoked_at_unix_seconds,omitempty"`
	EnrollmentClass           string `json:"enrollment_class"`
	LeaseExpiresAtUnixSeconds *int64 `json:"lease_expires_at_unix_seconds,omitempty"`
}

type Certificate struct {
	CertificateID        string `json:"certificate_id"`
	NetworkID            string `json:"network_id"`
	NodeID               string `json:"node_id"`
	Serial               string `json:"serial"`
	NotBeforeUnixSeconds int64  `json:"not_before_unix_seconds"`
	NotAfterUnixSeconds  int64  `json:"not_after_unix_seconds"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	RevokedAtUnixSeconds *int64 `json:"revoked_at_unix_seconds,omitempty"`
	RevocationReason     string `json:"revocation_reason,omitempty"`
}

type ACLRule struct {
	RuleID             string          `json:"rule_id"`
	NetworkID          string          `json:"network_id"`
	Priority           uint32          `json:"priority"`
	Action             string          `json:"action"`
	Selector           json.RawMessage `json:"selector"`
	Description        string          `json:"description"`
	Enabled            bool            `json:"enabled"`
	ConfigurationEpoch uint64          `json:"configuration_epoch"`
}

type AuditEvent struct {
	EventID              string          `json:"event_id"`
	NetworkID            string          `json:"network_id"`
	ActorKind            string          `json:"actor_kind"`
	ActorID              *string         `json:"actor_id,omitempty"`
	ActorNodeID          *string         `json:"actor_node_id,omitempty"`
	Action               string          `json:"action"`
	TargetType           string          `json:"target_type"`
	TargetID             *string         `json:"target_id,omitempty"`
	Details              json.RawMessage `json:"details"`
	CreatedAtUnixSeconds int64           `json:"created_at_unix_seconds"`
}

func (c *Client) CreateNetwork(ctx context.Context, name string, pool netip.Prefix) (*Network, error) {
	return c.CreateNetworkDualStack(ctx, name, pool, netip.Prefix{})
}

func (c *Client) CreateNetworkDualStack(ctx context.Context, name string, pool, ipv6Pool netip.Prefix) (*Network, error) {
	return c.createNetworkDualStack(ctx, identity.NetworkID{}, name, pool, ipv6Pool)
}

// CreateNetworkDualStackWithID uses an administrator-generated immutable ID,
// allowing the controller certificate and initial network row to share one ID
// without a bootstrap certificate rotation.
func (c *Client) CreateNetworkDualStackWithID(ctx context.Context, networkID identity.NetworkID, name string, pool, ipv6Pool netip.Prefix) (*Network, error) {
	if networkID.IsZero() {
		return nil, errors.New("controller client: network ID is required")
	}
	return c.createNetworkDualStack(ctx, networkID, name, pool, ipv6Pool)
}

func (c *Client) createNetworkDualStack(ctx context.Context, networkID identity.NetworkID, name string, pool, ipv6Pool netip.Prefix) (*Network, error) {
	if name == "" || !pool.IsValid() || !pool.Addr().Is4() || pool != pool.Masked() {
		return nil, errors.New("controller client: network name and canonical IPv4 pool are required")
	}
	if ipv6Pool.IsValid() && (ipv6Pool.Addr().Is4() || ipv6Pool.Addr().Is4In6() || ipv6Pool != ipv6Pool.Masked()) {
		return nil, errors.New("controller client: IPv6 pool must be canonical")
	}
	response := new(Network)
	request := struct {
		NetworkID string `json:"network_id,omitempty"`
		Name      string `json:"name"`
		IPv4Pool  string `json:"ipv4_pool"`
		IPv6Pool  string `json:"ipv6_pool,omitempty"`
	}{Name: name, IPv4Pool: pool.String()}
	if !networkID.IsZero() {
		request.NetworkID = networkID.String()
	}
	if ipv6Pool.IsValid() {
		request.IPv6Pool = ipv6Pool.String()
	}
	err := c.json(ctx, http.MethodPost, "/v1/admin/networks", request, response, true)
	return response, err
}

func (c *Client) Network(ctx context.Context, id identity.NetworkID) (*Network, error) {
	response := new(Network)
	err := c.json(ctx, http.MethodGet, "/v1/admin/networks/"+id.String(), nil, response, true)
	return response, err
}

func (c *Client) Networks(ctx context.Context, limit int) ([]Network, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: network limit must be from 1 through 1000")
	}
	response := struct {
		Networks []Network `json:"networks"`
	}{}
	err := c.json(ctx, http.MethodGet, "/v1/admin/networks?limit="+strconv.Itoa(limit), nil, &response, true)
	return response.Networks, err
}

func (c *Client) Nodes(ctx context.Context, networkID identity.NetworkID, limit int) ([]Node, error) {
	if networkID.IsZero() || limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: network and node limit 1..1000 are required")
	}
	response := struct {
		Nodes []Node `json:"nodes"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/nodes?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Nodes, err
}

func (c *Client) IssueEnrollmentToken(ctx context.Context, networkID identity.NetworkID, label string, expiresAt time.Time) (*EnrollmentToken, error) {
	return c.IssueEnrollmentTokenWithOptions(ctx, networkID, label, expiresAt, EnrollmentTokenOptions{Class: "durable"})
}

func (c *Client) IssueEnrollmentTokenWithOptions(ctx context.Context, networkID identity.NetworkID, label string, expiresAt time.Time, options EnrollmentTokenOptions) (*EnrollmentToken, error) {
	if networkID.IsZero() || label == "" || expiresAt.IsZero() {
		return nil, errors.New("controller client: network ID, label, and expiry are required")
	}
	response := new(EnrollmentToken)
	if options.Class == "" {
		options.Class = "durable"
	}
	if (options.Class != "durable" && options.Class != "ephemeral" && options.Class != "remembered") || options.SessionLifetime < 0 || (options.Class != "ephemeral" && options.SessionLifetime != 0) {
		return nil, errors.New("controller client: invalid enrollment class or session lifetime")
	}
	err := c.json(ctx, http.MethodPost, "/v1/admin/enrollment-tokens", struct {
		NetworkID              string `json:"network_id"`
		Label                  string `json:"label"`
		ExpiresAtUnix          int64  `json:"expires_at_unix_seconds"`
		EnrollmentClass        string `json:"enrollment_class"`
		SessionLifetimeSeconds int64  `json:"session_lifetime_seconds,omitempty"`
		RequestedName          string `json:"requested_name,omitempty"`
		EnabledCapabilities    uint64 `json:"enabled_capabilities,omitempty"`
	}{networkID.String(), label, expiresAt.Unix(), options.Class, int64(options.SessionLifetime / time.Second), options.RequestedName, options.EnabledCapabilities}, response, true)
	return response, err
}

type BootstrapBundle struct {
	BundleID      string `json:"bundle_id"`
	PublicPath    string `json:"public_path"`
	ExpiresAtUnix int64  `json:"expires_at_unix_seconds"`
}

func (c *Client) CreateBootstrapBundle(ctx context.Context, payload []byte, expiresAt time.Time) (*BootstrapBundle, error) {
	if len(payload) == 0 || len(payload) > bootstrap.MaxBundleBytes || expiresAt.IsZero() {
		return nil, errors.New("controller client: bounded bootstrap payload and expiry are required")
	}
	response := new(BootstrapBundle)
	err := c.json(ctx, http.MethodPost, "/v1/admin/bootstrap-bundles", struct {
		Payload       string `json:"payload"`
		ExpiresAtUnix int64  `json:"expires_at_unix_seconds"`
	}{string(payload), expiresAt.Unix()}, response, true)
	if err != nil {
		return nil, err
	}
	if response.BundleID == "" || response.PublicPath != bootstrap.BundlePathPrefix+response.BundleID || response.ExpiresAtUnix != expiresAt.Unix() {
		return nil, errors.New("controller client: invalid bootstrap bundle response")
	}
	return response, nil
}

func (c *Client) AdvertiseRoute(ctx context.Context, prefix netip.Prefix, kind, mode string, metric uint32, validUntil *time.Time) (*Route, error) {
	if !prefix.IsValid() || prefix != prefix.Masked() || (kind != "subnet" && kind != "exit") || (mode != "nat" && mode != "routed") {
		return nil, errors.New("controller client: route requires a canonical prefix, valid kind, and valid mode")
	}
	var validUntilUnix int64
	if validUntil != nil {
		validUntilUnix = validUntil.Unix()
	}
	response := new(Route)
	err := c.json(ctx, http.MethodPost, "/v1/routes", struct {
		Prefix         string `json:"prefix"`
		Kind           string `json:"kind"`
		Mode           string `json:"mode"`
		Metric         uint32 `json:"metric"`
		ValidUntilUnix int64  `json:"valid_until_unix_seconds,omitempty"`
	}{prefix.String(), kind, mode, metric, validUntilUnix}, response, false)
	return response, err
}

func (c *Client) WithdrawRoute(ctx context.Context, routeID identity.ID) (*Epoch, error) {
	response := new(Epoch)
	err := c.json(ctx, http.MethodDelete, "/v1/routes/"+routeID.String(), nil, response, false)
	return response, err
}

func (c *Client) ApproveRoute(ctx context.Context, routeID identity.ID) (*Epoch, error) {
	response := new(Epoch)
	err := c.json(ctx, http.MethodPost, "/v1/admin/routes/"+routeID.String()+"/approve", nil, response, true)
	return response, err
}

func (c *Client) AdminWithdrawRoute(ctx context.Context, routeID identity.ID) (*Epoch, error) {
	response := new(Epoch)
	err := c.json(ctx, http.MethodPost, "/v1/admin/routes/"+routeID.String()+"/withdraw", nil, response, true)
	return response, err
}

func (c *Client) AssignRoute(ctx context.Context, networkID identity.NetworkID, nodeID identity.NodeID, prefix netip.Prefix, mode string, metric uint32) (*Route, error) {
	if networkID.IsZero() || nodeID.IsZero() || !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 || (mode != "nat" && mode != "routed") {
		return nil, errors.New("controller client: assigned route requires network, node, canonical non-default prefix, and valid mode")
	}
	response := new(Route)
	err := c.json(ctx, http.MethodPost, "/v1/admin/routes/assign", struct {
		NetworkID string `json:"network_id"`
		NodeID    string `json:"node_id"`
		Prefix    string `json:"prefix"`
		Mode      string `json:"mode"`
		Metric    uint32 `json:"metric"`
	}{networkID.String(), nodeID.String(), prefix.String(), mode, metric}, response, true)
	return response, err
}

func (c *Client) SetNodeCapabilities(ctx context.Context, nodeID identity.NodeID, capabilities uint64) (*Epoch, error) {
	if nodeID.IsZero() {
		return nil, errors.New("controller client: node ID is required")
	}
	response := new(Epoch)
	err := c.json(ctx, http.MethodPut, "/v1/admin/nodes/"+nodeID.String()+"/capabilities", struct {
		EnabledCapabilities uint64 `json:"enabled_capabilities"`
	}{capabilities}, response, true)
	return response, err
}

func (c *Client) Routes(ctx context.Context, networkID identity.NetworkID, limit int) ([]Route, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: route limit must be from 1 through 1000")
	}
	response := struct {
		Routes []Route `json:"routes"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/routes?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Routes, err
}

func (c *Client) AddACLRule(ctx context.Context, networkID identity.NetworkID, priority uint32, action string, selector json.RawMessage, description string) (*ACLRule, error) {
	if (action != "accept" && action != "deny") || !json.Valid(selector) {
		return nil, errors.New("controller client: ACL action and selector are invalid")
	}
	response := new(ACLRule)
	err := c.json(ctx, http.MethodPost, "/v1/admin/networks/"+networkID.String()+"/acl-rules", struct {
		Priority    uint32          `json:"priority"`
		Action      string          `json:"action"`
		Selector    json.RawMessage `json:"selector"`
		Description string          `json:"description"`
	}{priority, action, selector, description}, response, true)
	return response, err
}

func (c *Client) ACLRules(ctx context.Context, networkID identity.NetworkID, limit int) ([]ACLRule, error) {
	if networkID.IsZero() || limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: network and ACL limit 1..1000 are required")
	}
	response := struct {
		Rules []ACLRule `json:"acl_rules"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/acl-rules?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Rules, err
}

func (c *Client) DeleteACLRule(ctx context.Context, ruleID identity.ID) (*Epoch, error) {
	response := new(Epoch)
	err := c.json(ctx, http.MethodDelete, "/v1/admin/acl-rules/"+ruleID.String(), nil, response, true)
	return response, err
}

func (c *Client) UpdateACLRule(ctx context.Context, ruleID identity.ID, priority uint32, action string, selector json.RawMessage, description string, enabled bool) (*ACLRule, error) {
	if ruleID.IsZero() || (action != "accept" && action != "deny") || !json.Valid(selector) {
		return nil, errors.New("controller client: rule ID, ACL action, and selector are invalid")
	}
	response := new(ACLRule)
	err := c.json(ctx, http.MethodPut, "/v1/admin/acl-rules/"+ruleID.String(), struct {
		Priority    uint32          `json:"priority"`
		Action      string          `json:"action"`
		Selector    json.RawMessage `json:"selector"`
		Description string          `json:"description"`
		Enabled     bool            `json:"enabled"`
	}{priority, action, selector, description, enabled}, response, true)
	return response, err
}

func (c *Client) RevokeNode(ctx context.Context, nodeID identity.NodeID, reason string) (*Epoch, error) {
	response := new(Epoch)
	err := c.json(ctx, http.MethodPost, "/v1/admin/nodes/"+nodeID.String()+"/revoke", struct {
		Reason string `json:"reason"`
	}{reason}, response, true)
	return response, err
}

func (c *Client) RevokeCertificate(ctx context.Context, networkID identity.NetworkID, serial []byte, reason string) (*Epoch, error) {
	if networkID.IsZero() || len(serial) < 1 || len(serial) > 32 || serial[0] == 0 || reason != strings.TrimSpace(reason) || reason == "" {
		return nil, errors.New("controller client: certificate network, canonical serial, and reason are required")
	}
	response := new(Epoch)
	path := "/v1/admin/networks/" + networkID.String() + "/certificates/" + fmt.Sprintf("%x", serial) + "/revoke"
	err := c.json(ctx, http.MethodPost, path, struct {
		Reason string `json:"reason"`
	}{reason}, response, true)
	return response, err
}

func (c *Client) Certificates(ctx context.Context, networkID identity.NetworkID, limit int) ([]Certificate, error) {
	if networkID.IsZero() || limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: network and certificate limit 1..1000 are required")
	}
	response := struct {
		Certificates []Certificate `json:"certificates"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/certificates?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Certificates, err
}

func (c *Client) RegisterRelay(ctx context.Context, networkID identity.NetworkID, serviceID identity.ID, nodeID *identity.NodeID, name, endpoint string) (*Relay, error) {
	if networkID.IsZero() || serviceID.IsZero() || name == "" || endpoint == "" {
		return nil, errors.New("controller client: relay network, service ID, name, and endpoint are required")
	}
	request := struct {
		ServiceID string `json:"service_id"`
		NodeID    string `json:"node_id,omitempty"`
		Name      string `json:"name"`
		Endpoint  string `json:"endpoint"`
	}{ServiceID: serviceID.String(), Name: name, Endpoint: endpoint}
	if nodeID != nil {
		if nodeID.IsZero() {
			return nil, errors.New("controller client: relay node ID must not be zero")
		}
		request.NodeID = nodeID.String()
	}
	response := new(Relay)
	err := c.json(ctx, http.MethodPost, "/v1/admin/networks/"+networkID.String()+"/relays", request, response, true)
	return response, err
}

func (c *Client) DisableRelay(ctx context.Context, relayID identity.ID) (*Epoch, error) {
	if relayID.IsZero() {
		return nil, errors.New("controller client: relay ID is required")
	}
	response := new(Epoch)
	err := c.json(ctx, http.MethodPost, "/v1/admin/relays/"+relayID.String()+"/disable", nil, response, true)
	return response, err
}

func (c *Client) UpdateRelay(ctx context.Context, relayID identity.ID, name, endpoint string, enabled bool) (*Relay, error) {
	if relayID.IsZero() || name == "" || endpoint == "" {
		return nil, errors.New("controller client: relay ID, name, and endpoint are required")
	}
	response := new(Relay)
	err := c.json(ctx, http.MethodPut, "/v1/admin/relays/"+relayID.String(), struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
		Enabled  bool   `json:"enabled"`
	}{name, endpoint, enabled}, response, true)
	return response, err
}

func (c *Client) Relays(ctx context.Context, networkID identity.NetworkID, limit int) ([]Relay, error) {
	if networkID.IsZero() || limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: network and relay limit 1..1000 are required")
	}
	response := struct {
		Relays []Relay `json:"relays"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/relays?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Relays, err
}

func (c *Client) Audit(ctx context.Context, networkID identity.NetworkID, limit int) ([]AuditEvent, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("controller client: audit limit must be from 1 through 1000")
	}
	response := struct {
		Events []AuditEvent `json:"events"`
	}{}
	path := "/v1/admin/networks/" + networkID.String() + "/audit?limit=" + strconv.Itoa(limit)
	err := c.json(ctx, http.MethodGet, path, nil, &response, true)
	return response.Events, err
}

// BootstrapFirstAdministrator issues and immediately consumes a bootstrap
// grant. The one-use grant never leaves this process, and the password is sent
// only by the explicitly unauthenticated request over the pinned controller
// connection. The method takes ownership of password and clears it before
// returning.
func (c *Client) BootstrapFirstAdministrator(ctx context.Context, username string, password []byte) error {
	defer clear(password)
	if !adminauth.ValidateUsername(username) {
		return errors.New("controller client: valid administrator username is required")
	}
	if err := validateLifecyclePassword(password); err != nil {
		return err
	}
	grant, err := c.issueAdministratorLifecycleGrant(ctx, "/v1/admin/auth/bootstrap-grants")
	if err != nil {
		return err
	}
	defer clear(grant)
	payload, err := administratorLifecyclePayload(grant, username, password)
	if err != nil {
		return err
	}
	defer clear(payload)
	return c.consumeAdministratorLifecycleGrant(ctx, "/v1/admin/auth/bootstrap", payload)
}

// RecoverAdministratorOwner resolves an exact canonical owner username before
// issuing and consuming its one-use recovery grant. Recovery never guesses a
// principal from list ordering. The method takes ownership of password and
// clears it before returning.
func (c *Client) RecoverAdministratorOwner(ctx context.Context, username string, password []byte) error {
	defer clear(password)
	if !adminauth.ValidateUsername(username) {
		return errors.New("controller client: valid administrator username is required")
	}
	if err := validateLifecyclePassword(password); err != nil {
		return err
	}
	principalID, err := c.administratorOwnerByUsername(ctx, username)
	if err != nil {
		return err
	}
	grant, err := c.issueAdministratorLifecycleGrant(ctx,
		"/v1/admin/administrators/"+principalID.String()+"/recovery-grants")
	if err != nil {
		return err
	}
	defer clear(grant)
	payload, err := administratorLifecyclePayload(grant, "", password)
	if err != nil {
		return err
	}
	defer clear(payload)
	return c.consumeAdministratorLifecycleGrant(ctx, "/v1/admin/auth/recover", payload)
}

func validateLifecyclePassword(password []byte) error {
	if err := adminauth.ValidatePassword(password); err != nil {
		return err
	}
	if !utf8.Valid(password) {
		return errors.New("controller client: administrator password must be valid UTF-8")
	}
	return nil
}

type lifecycleAdministrator struct {
	PrincipalID                  string         `json:"principal_id"`
	Username                     string         `json:"username"`
	Role                         adminauth.Role `json:"role"`
	Enabled                      bool           `json:"enabled"`
	AllNetworks                  bool           `json:"all_networks"`
	NetworkIDs                   []string       `json:"network_ids"`
	CreatedAtUnixSeconds         int64          `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds         int64          `json:"updated_at_unix_seconds"`
	DisabledAtUnixSeconds        *int64         `json:"disabled_at_unix_seconds,omitempty"`
	PasswordUpdatedAtUnixSeconds int64          `json:"password_updated_at_unix_seconds"`
}

func (c *Client) administratorOwnerByUsername(ctx context.Context, username string) (identity.ID, error) {
	status, header, contents, err := c.administratorLifecycleRequest(ctx, http.MethodGet,
		"/v1/admin/administrators?username="+url.QueryEscape(username), nil, lifecycleRootCredential, maxLifecycleReplyBytes)
	if err != nil {
		return identity.ID{}, err
	}
	defer clear(contents)
	if status != http.StatusOK {
		return identity.ID{}, fmt.Errorf("controller administrator lookup returned unexpected HTTP status %d", status)
	}
	if err := requireLifecycleJSON(header); err != nil {
		return identity.ID{}, err
	}
	administrators, err := decodeLifecycleAdministrators(contents)
	if err != nil {
		return identity.ID{}, err
	}
	if len(administrators) != 1 {
		return identity.ID{}, errors.New("controller administrator recovery target was not found uniquely")
	}
	var result identity.ID
	matches := 0
	for _, administrator := range administrators {
		principalID, validationErr := validateLifecycleAdministrator(administrator)
		if validationErr != nil {
			return identity.ID{}, validationErr
		}
		if administrator.Username != username {
			continue
		}
		matches++
		if administrator.Role != adminauth.RoleOwner {
			return identity.ID{}, errors.New("controller administrator recovery target is invalid")
		}
		result = principalID
	}
	if matches != 1 {
		return identity.ID{}, errors.New("controller administrator recovery target was not found uniquely")
	}
	return result, nil
}

func decodeLifecycleAdministrators(contents []byte) ([]lifecycleAdministrator, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("controller administrator lookup returned malformed JSON")
	}
	var administrators []lifecycleAdministrator
	seenAdministrators := false
	for decoder.More() {
		key, err := lifecycleJSONStringToken(decoder)
		if err != nil || key != "administrators" || seenAdministrators {
			return nil, errors.New("controller administrator lookup returned malformed JSON")
		}
		seenAdministrators = true
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return nil, errors.New("controller administrator lookup returned malformed JSON")
		}
		for decoder.More() {
			if len(administrators) == 1 {
				return nil, errors.New("controller administrator recovery target was not found uniquely")
			}
			administrator, err := decodeLifecycleAdministrator(decoder)
			if err != nil {
				return nil, err
			}
			administrators = append(administrators, administrator)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, errors.New("controller administrator lookup returned malformed JSON")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !seenAdministrators {
		return nil, errors.New("controller administrator lookup returned malformed JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("controller administrator lookup returned malformed JSON")
	}
	return administrators, nil
}

func decodeLifecycleAdministrator(decoder *json.Decoder) (lifecycleAdministrator, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return lifecycleAdministrator{}, errors.New("controller administrator lookup returned malformed JSON")
	}
	const (
		principalIDField uint16 = 1 << iota
		usernameField
		roleField
		enabledField
		allNetworksField
		networkIDsField
		createdAtField
		updatedAtField
		disabledAtField
		passwordUpdatedAtField
	)
	const requiredFields = principalIDField | usernameField | roleField | enabledField | allNetworksField |
		networkIDsField | createdAtField | updatedAtField | passwordUpdatedAtField
	var administrator lifecycleAdministrator
	var seen uint16
	for decoder.More() {
		key, err := lifecycleJSONStringToken(decoder)
		if err != nil {
			return lifecycleAdministrator{}, errors.New("controller administrator lookup returned malformed JSON")
		}
		var bit uint16
		switch key {
		case "principal_id":
			bit = principalIDField
			administrator.PrincipalID, err = lifecycleJSONStringToken(decoder)
		case "username":
			bit = usernameField
			administrator.Username, err = lifecycleJSONStringToken(decoder)
		case "role":
			bit = roleField
			var role string
			role, err = lifecycleJSONStringToken(decoder)
			administrator.Role = adminauth.Role(role)
		case "enabled":
			bit = enabledField
			administrator.Enabled, err = lifecycleJSONBoolToken(decoder)
		case "all_networks":
			bit = allNetworksField
			administrator.AllNetworks, err = lifecycleJSONBoolToken(decoder)
		case "network_ids":
			bit = networkIDsField
			administrator.NetworkIDs, err = lifecycleJSONStringArray(decoder)
		case "created_at_unix_seconds":
			bit = createdAtField
			administrator.CreatedAtUnixSeconds, err = lifecycleJSONInt64Token(decoder)
		case "updated_at_unix_seconds":
			bit = updatedAtField
			administrator.UpdatedAtUnixSeconds, err = lifecycleJSONInt64Token(decoder)
		case "disabled_at_unix_seconds":
			bit = disabledAtField
			administrator.DisabledAtUnixSeconds, err = lifecycleJSONOptionalInt64Token(decoder)
		case "password_updated_at_unix_seconds":
			bit = passwordUpdatedAtField
			administrator.PasswordUpdatedAtUnixSeconds, err = lifecycleJSONInt64Token(decoder)
		default:
			return lifecycleAdministrator{}, errors.New("controller administrator lookup returned malformed JSON")
		}
		if err != nil || seen&bit != 0 {
			return lifecycleAdministrator{}, errors.New("controller administrator lookup returned malformed JSON")
		}
		seen |= bit
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || seen&requiredFields != requiredFields {
		return lifecycleAdministrator{}, errors.New("controller administrator lookup returned malformed JSON")
	}
	return administrator, nil
}

func lifecycleJSONStringToken(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	value, ok := token.(string)
	if !ok {
		return "", errors.New("expected JSON string")
	}
	return value, nil
}

func lifecycleJSONBoolToken(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	value, ok := token.(bool)
	if !ok {
		return false, errors.New("expected JSON boolean")
	}
	return value, nil
}

func lifecycleJSONInt64Token(decoder *json.Decoder) (int64, error) {
	token, err := decoder.Token()
	if err != nil {
		return 0, err
	}
	value, ok := token.(json.Number)
	if !ok {
		return 0, errors.New("expected JSON integer")
	}
	return strconv.ParseInt(value.String(), 10, 64)
}

func lifecycleJSONOptionalInt64Token(decoder *json.Decoder) (*int64, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	value, ok := token.(json.Number)
	if !ok {
		return nil, errors.New("expected JSON integer or null")
	}
	parsed, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func lifecycleJSONStringArray(decoder *json.Decoder) ([]string, error) {
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, errors.New("expected JSON string array")
	}
	values := make([]string, 0)
	for decoder.More() {
		value, err := lifecycleJSONStringToken(decoder)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, errors.New("expected JSON string array")
	}
	return values, nil
}

func validateLifecycleAdministrator(administrator lifecycleAdministrator) (identity.ID, error) {
	principalID, err := identity.ParseID(administrator.PrincipalID)
	if err != nil || !adminauth.ValidateUsername(administrator.Username) || !administrator.Role.Valid() ||
		administrator.Role == adminauth.RoleOwner && !administrator.AllNetworks ||
		administrator.AllNetworks && len(administrator.NetworkIDs) != 0 || administrator.CreatedAtUnixSeconds <= 0 ||
		administrator.UpdatedAtUnixSeconds <= 0 || administrator.PasswordUpdatedAtUnixSeconds <= 0 {
		return identity.ID{}, errors.New("controller administrator lookup returned an invalid principal")
	}
	seenNetworks := make(map[identity.NetworkID]struct{}, len(administrator.NetworkIDs))
	for _, value := range administrator.NetworkIDs {
		networkID, parseErr := identity.ParseNetworkID(value)
		if parseErr != nil {
			return identity.ID{}, errors.New("controller administrator lookup returned an invalid principal")
		}
		if _, duplicate := seenNetworks[networkID]; duplicate {
			return identity.ID{}, errors.New("controller administrator lookup returned an invalid principal")
		}
		seenNetworks[networkID] = struct{}{}
	}
	return principalID, nil
}

func (c *Client) issueAdministratorLifecycleGrant(ctx context.Context, path string) ([]byte, error) {
	status, header, contents, err := c.administratorLifecycleRequest(ctx, http.MethodPost, path, nil,
		lifecycleRootCredential, maxLifecycleReplyBytes)
	if err != nil {
		return nil, err
	}
	defer clear(contents)
	if status != http.StatusCreated {
		return nil, fmt.Errorf("controller administrator grant issuance returned unexpected HTTP status %d", status)
	}
	if err := requireLifecycleJSON(header); err != nil {
		return nil, err
	}
	grant, expiresAt, err := decodeAdministratorLifecycleGrant(contents)
	if err != nil {
		return nil, err
	}
	if expiresAt.Unix() <= 0 {
		clear(grant)
		return nil, errors.New("controller administrator grant returned an invalid expiry")
	}
	return grant, nil
}

func (c *Client) consumeAdministratorLifecycleGrant(ctx context.Context, path string, payload []byte) error {
	status, _, contents, err := c.administratorLifecycleRequest(ctx, http.MethodPost, path, payload,
		lifecycleUnauthenticatedCredential, maxLifecycleReplyBytes)
	if err != nil {
		return err
	}
	defer clear(contents)
	if status != http.StatusNoContent {
		return fmt.Errorf("controller administrator grant consumption returned unexpected HTTP status %d", status)
	}
	if len(contents) != 0 {
		return errors.New("controller administrator grant no-content response contained a body")
	}
	return nil
}

func administratorLifecyclePayload(grant []byte, username string, password []byte) ([]byte, error) {
	if len(grant) == 0 || !utf8.Valid(password) {
		return nil, errors.New("controller client: invalid administrator lifecycle secret")
	}
	payload := make([]byte, 0, len(grant)+len(username)+len(password)+64)
	payload = append(payload, '{', '"', 'g', 'r', 'a', 'n', 't', '"', ':')
	var err error
	payload, err = appendLifecycleJSONString(payload, grant)
	if err != nil {
		clear(payload)
		return nil, err
	}
	if username != "" {
		payload = append(payload, ',', '"', 'u', 's', 'e', 'r', 'n', 'a', 'm', 'e', '"', ':')
		payload, err = appendLifecycleJSONString(payload, []byte(username))
		if err != nil {
			clear(payload)
			return nil, err
		}
	}
	payload = append(payload, ',', '"', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '"', ':')
	payload, err = appendLifecycleJSONString(payload, password)
	if err != nil {
		clear(payload)
		return nil, err
	}
	payload = append(payload, '}')
	if len(payload) > MaxJSONRequestBytes {
		clear(payload)
		return nil, errors.New("controller administrator lifecycle request exceeds limit")
	}
	return payload, nil
}

func appendLifecycleJSONString(destination, value []byte) ([]byte, error) {
	if !utf8.Valid(value) {
		return destination, errors.New("controller administrator lifecycle value must be valid UTF-8")
	}
	const hexadecimal = "0123456789abcdef"
	destination = append(destination, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			destination = append(destination, '\\', character)
		case '\b':
			destination = append(destination, '\\', 'b')
		case '\f':
			destination = append(destination, '\\', 'f')
		case '\n':
			destination = append(destination, '\\', 'n')
		case '\r':
			destination = append(destination, '\\', 'r')
		case '\t':
			destination = append(destination, '\\', 't')
		default:
			if character < 0x20 {
				destination = append(destination, '\\', 'u', '0', '0', hexadecimal[character>>4], hexadecimal[character&0xf])
			} else {
				destination = append(destination, character)
			}
		}
	}
	return append(destination, '"'), nil
}

func decodeAdministratorLifecycleGrant(contents []byte) ([]byte, time.Time, error) {
	cursor := lifecycleJSONCursor{input: contents}
	if !cursor.consume('{') {
		return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
	}
	var grant []byte
	var expiresAtUnix int64
	seenGrant, seenExpiry := false, false
	for !cursor.peek('}') {
		key, ok := cursor.canonicalKey()
		if !ok || !cursor.consume(':') {
			clear(grant)
			return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
		}
		switch key {
		case "grant":
			if seenGrant {
				clear(grant)
				return nil, time.Time{}, errors.New("controller administrator grant response contains duplicate fields")
			}
			seenGrant = true
			encoded, ok := cursor.canonicalStringBytes()
			if !ok {
				return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
			}
			var err error
			grant, err = canonicalAdministratorGrant(encoded)
			if err != nil {
				return nil, time.Time{}, err
			}
		case "expires_at_unix_seconds":
			if seenExpiry {
				clear(grant)
				return nil, time.Time{}, errors.New("controller administrator grant response contains duplicate fields")
			}
			seenExpiry = true
			var ok bool
			expiresAtUnix, ok = cursor.int64()
			if !ok {
				clear(grant)
				return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
			}
		default:
			clear(grant)
			return nil, time.Time{}, errors.New("controller administrator grant response contains an unknown field")
		}
		if cursor.peek('}') {
			break
		}
		if !cursor.consume(',') || cursor.peek('}') {
			clear(grant)
			return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
		}
	}
	if !cursor.consume('}') || !cursor.eof() || !seenGrant || !seenExpiry || expiresAtUnix <= 0 {
		clear(grant)
		return nil, time.Time{}, errors.New("controller administrator grant response is malformed")
	}
	return grant, time.Unix(expiresAtUnix, 0).UTC(), nil
}

func canonicalAdministratorGrant(encoded []byte) ([]byte, error) {
	if len(encoded) != 43 {
		return nil, errors.New("controller administrator grant response contains an invalid grant")
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	defer clear(decoded)
	written, err := base64.RawURLEncoding.Strict().Decode(decoded, encoded)
	if err != nil || written != 32 {
		return nil, errors.New("controller administrator grant response contains an invalid grant")
	}
	return append([]byte(nil), encoded...), nil
}

// lifecycleJSONCursor parses the small grant response directly over the
// caller-owned mutable buffer. It deliberately supports only the canonical
// string and integer forms used by this contract, so the one-use grant is
// never copied into an inaccessible encoding/json decoder buffer.
type lifecycleJSONCursor struct {
	input  []byte
	offset int
}

func (c *lifecycleJSONCursor) whitespace() {
	for c.offset < len(c.input) {
		switch c.input[c.offset] {
		case ' ', '\t', '\n', '\r':
			c.offset++
		default:
			return
		}
	}
}

func (c *lifecycleJSONCursor) consume(expected byte) bool {
	c.whitespace()
	if c.offset >= len(c.input) || c.input[c.offset] != expected {
		return false
	}
	c.offset++
	return true
}

func (c *lifecycleJSONCursor) peek(expected byte) bool {
	c.whitespace()
	return c.offset < len(c.input) && c.input[c.offset] == expected
}

func (c *lifecycleJSONCursor) canonicalKey() (string, bool) {
	value, ok := c.canonicalStringBytes()
	if !ok {
		return "", false
	}
	return string(value), true
}

func (c *lifecycleJSONCursor) canonicalStringBytes() ([]byte, bool) {
	c.whitespace()
	if c.offset >= len(c.input) || c.input[c.offset] != '"' {
		return nil, false
	}
	start := c.offset + 1
	for c.offset = start; c.offset < len(c.input); c.offset++ {
		value := c.input[c.offset]
		if value == '"' {
			result := c.input[start:c.offset]
			c.offset++
			return result, true
		}
		if value == '\\' || value < 0x20 || value >= 0x80 {
			return nil, false
		}
	}
	return nil, false
}

func (c *lifecycleJSONCursor) int64() (int64, bool) {
	c.whitespace()
	start := c.offset
	if c.offset < len(c.input) && c.input[c.offset] == '-' {
		c.offset++
	}
	digits := c.offset
	for c.offset < len(c.input) && c.input[c.offset] >= '0' && c.input[c.offset] <= '9' {
		c.offset++
	}
	if c.offset == digits || c.offset-digits > 1 && c.input[digits] == '0' {
		return 0, false
	}
	parsed, err := strconv.ParseInt(string(c.input[start:c.offset]), 10, 64)
	return parsed, err == nil
}

func (c *lifecycleJSONCursor) eof() bool {
	c.whitespace()
	return c.offset == len(c.input)
}

type lifecycleCredentialKind uint8

const (
	lifecycleRootCredential lifecycleCredentialKind = iota + 1
	lifecycleUnauthenticatedCredential
)

// administratorLifecycleRequest is deliberately independent from json. It
// never retains a cookie jar, never follows redirects, bounds every response,
// and never reflects a sensitive response body into an error.
func (c *Client) administratorLifecycleRequest(ctx context.Context, method, path string, payload []byte,
	credential lifecycleCredentialKind, responseLimit int64) (int, http.Header, []byte, error) {
	if c == nil || c.http == nil || c.endpoint == "" {
		return 0, nil, nil, errors.New("controller client: client is not initialized")
	}
	if credential != lifecycleRootCredential && credential != lifecycleUnauthenticatedCredential {
		return 0, nil, nil, errors.New("controller client: invalid administrator lifecycle credential mode")
	}
	if credential == lifecycleRootCredential && c.adminBearer == "" {
		return 0, nil, nil, errors.New("controller client: admin token is required")
	}
	if len(payload) > MaxJSONRequestBytes {
		return 0, nil, nil, errors.New("controller administrator lifecycle request exceeds limit")
	}
	if responseLimit < 0 || responseLimit > MaxResponseBytes {
		return 0, nil, nil, errors.New("controller client: invalid administrator lifecycle response limit")
	}
	var body io.ReadCloser
	if payload != nil {
		body = io.NopCloser(bytes.NewReader(payload))
	}
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return 0, nil, nil, errors.New("controller administrator lifecycle request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(payload))
		request.GetBody = nil
	}
	if credential == lifecycleRootCredential {
		request.Header.Set("Authorization", c.adminBearer)
	} else {
		request.Header.Set("Origin", c.endpoint)
	}
	client := *c.http
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("controller administrator lifecycle request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent && response.ContentLength > 0 {
		return 0, nil, nil, errors.New("controller administrator lifecycle no-content response declared a body")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		clear(contents)
		return 0, nil, nil, errors.New("controller administrator lifecycle response could not be read")
	}
	if int64(len(contents)) > responseLimit {
		clear(contents)
		return 0, nil, nil, errors.New("controller administrator lifecycle response exceeds limit")
	}
	cacheControl := response.Header.Values("Cache-Control")
	if len(cacheControl) != 1 || !strings.EqualFold(strings.TrimSpace(cacheControl[0]), "no-store") {
		clear(contents)
		return 0, nil, nil, errors.New("controller administrator lifecycle response omitted cache protection")
	}
	if len(response.Header.Values("Set-Cookie")) != 0 {
		clear(contents)
		return 0, nil, nil, errors.New("controller administrator lifecycle response attempted to set a cookie")
	}
	return response.StatusCode, response.Header.Clone(), contents, nil
}

func requireLifecycleJSON(header http.Header) error {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return errors.New("controller administrator lifecycle response omitted its JSON content type")
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return errors.New("controller administrator lifecycle response used an invalid content type")
	}
	return nil
}

// RootAuthenticationAccepted probes only the static root administrator
// credential. It distinguishes the contract's exact success and rejection
// statuses so token rotation never treats an unrelated failure as proof that
// the previous credential was revoked.
func (c *Client) RootAuthenticationAccepted(ctx context.Context) (bool, error) {
	status, err := c.rootLifecycleRequest(ctx, http.MethodGet, "/v1/admin/auth/root")
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNoContent:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("controller root authentication returned unexpected HTTP status %d", status)
	}
}

func (c *Client) BeginRootTokenRotation(ctx context.Context, rotationID identity.ID) error {
	return c.rootTokenRotationPhase(ctx, rotationID, "begin")
}

func (c *Client) CompleteRootTokenRotation(ctx context.Context, rotationID identity.ID) error {
	return c.rootTokenRotationPhase(ctx, rotationID, "complete")
}

func (c *Client) rootTokenRotationPhase(ctx context.Context, rotationID identity.ID, phase string) error {
	if rotationID.IsZero() || phase != "begin" && phase != "complete" {
		return errors.New("controller client: valid root token rotation ID and phase are required")
	}
	path := "/v1/admin/auth/root-token-rotations/" + rotationID.String() + "/" + phase
	status, err := c.rootLifecycleRequest(ctx, http.MethodPost, path)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("controller root token rotation %s returned unexpected HTTP status %d", phase, status)
	}
	return nil
}

// rootLifecycleRequest deliberately bypasses json: lifecycle endpoints have
// status-only contracts, must not echo response details, and must never follow
// a redirect carrying the root bearer.
func (c *Client) rootLifecycleRequest(ctx context.Context, method, path string) (int, error) {
	status, _, contents, err := c.administratorLifecycleRequest(ctx, method, path, nil, lifecycleRootCredential,
		maxLifecycleReplyBytes)
	if err != nil {
		return 0, err
	}
	defer clear(contents)
	if status == http.StatusNoContent && len(contents) != 0 {
		return 0, errors.New("controller lifecycle no-content response contained a body")
	}
	return status, nil
}

func (c *Client) json(ctx context.Context, method, path string, request, response any, admin bool) error {
	var body io.Reader
	if request != nil {
		payload, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("encode controller request: %w", err)
		}
		if len(payload) > MaxJSONRequestBytes {
			return errors.New("controller request exceeds limit")
		}
		body = bytes.NewReader(payload)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return err
	}
	if request != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	httpRequest.Header.Set("Accept", "application/json")
	if admin {
		if c.adminBearer == "" {
			return errors.New("controller client: admin token is required")
		}
		httpRequest.Header.Set("Authorization", c.adminBearer)
	}
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("controller request: %w", err)
	}
	defer httpResponse.Body.Close()
	contents, err := io.ReadAll(io.LimitReader(httpResponse.Body, MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read controller response: %w", err)
	}
	if len(contents) > MaxResponseBytes {
		return errors.New("controller response exceeds limit")
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		var apiError struct {
			Code, Detail string
			Retryable    bool
		}
		if json.Unmarshal(contents, &apiError) == nil && apiError.Detail != "" {
			return fmt.Errorf("controller: %s: %s", apiError.Code, apiError.Detail)
		}
		return fmt.Errorf("controller returned %s", httpResponse.Status)
	}
	if response == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return fmt.Errorf("decode controller response: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("decode controller response: expected one JSON value")
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, request, response proto.Message) error {
	_, err := c.postStatus(ctx, path, request, response)
	return err
}

func (c *Client) postStatus(ctx context.Context, path string, request, response proto.Message) (bool, error) {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return false, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	httpRequest.Header.Set("Content-Type", "application/x-protobuf")
	httpRequest.Header.Set("Accept", "application/x-protobuf")
	httpResponse, err := c.http.Do(httpRequest)
	if err != nil {
		return false, fmt.Errorf("controller request: %w", err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode == http.StatusNotModified {
		value, err := strconv.ParseUint(httpResponse.Header.Get(snapshotValidityHeader), 10, 64)
		if err != nil || value == 0 {
			return false, errors.New("controller not-modified response omitted a valid snapshot deadline")
		}
		switch target := response.(type) {
		case *lanewayv1.NodeConfiguration:
			target.ValidUntilUnixSeconds = value
		case *lanewayv1.RelayConfiguration:
			target.ValidUntilUnixSeconds = value
		default:
			return false, errors.New("controller not-modified response used for an unsupported message")
		}
		return true, nil
	}
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, MaxResponseBytes+1))
	if err != nil {
		return false, fmt.Errorf("read controller response: %w", err)
	}
	if len(body) > MaxResponseBytes {
		return false, errors.New("controller response exceeds limit")
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		protocolError := new(lanewayv1.ProtocolError)
		if proto.Unmarshal(body, protocolError) == nil && protocolError.GetCode() != lanewayv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
			return false, fmt.Errorf("controller: %s: %s", protocolError.GetCode(), protocolError.GetDetail())
		}
		return false, fmt.Errorf("controller returned %s", httpResponse.Status)
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(body, response); err != nil {
		return false, fmt.Errorf("decode controller response: %w", err)
	}
	return false, nil
}
