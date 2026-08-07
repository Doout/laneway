// Package controllerclient implements HTTPS enrollment/management and the
// bounded reliable mTLS QUIC client used for authenticated renewal and
// controller configuration snapshots.
package controllerclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
)

const (
	MaxResponseBytes       = 1 << 20
	MaxJSONRequestBytes    = 128 << 10
	maxAdminTokenBytes     = 8 << 10
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
}

type Client struct {
	endpoint    string
	http        *http.Client
	adminBearer string
	quic        *quicControllerClient
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
		control, err = newQUICControllerClient(options.QUICEndpoint, options.QUICDialAddress, tlsConfig, options.Timeout)
		if err != nil {
			return nil, err
		}
	}
	return &Client{endpoint: endpoint, http: &http.Client{Transport: transport, Timeout: options.Timeout}, adminBearer: adminBearer, quic: control}, nil
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

func (c *Client) Enroll(ctx context.Context, token, name string, csrDER []byte) (*lanewayv1.EnrollmentResponse, error) {
	return c.enroll(ctx, token, name, csrDER, identity.NetworkID{})
}

func (c *Client) EnrollForNetwork(ctx context.Context, token, name string, csrDER []byte, expectedNetwork identity.NetworkID) (*lanewayv1.EnrollmentResponse, error) {
	if expectedNetwork.IsZero() {
		return nil, errors.New("controller client: expected enrollment network is required")
	}
	return c.enroll(ctx, token, name, csrDER, expectedNetwork)
}

func (c *Client) EnrollForNetworkAndClass(ctx context.Context, token, name string, csrDER []byte, expectedNetwork identity.NetworkID, expectedClass lanewayv1.EnrollmentClass) (*lanewayv1.EnrollmentResponse, error) {
	if expectedNetwork.IsZero() || (expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE &&
		expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER &&
		expectedClass != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER) {
		return nil, errors.New("controller client: expected enrollment network and class are required")
	}
	request := &lanewayv1.EnrollmentRequest{
		EnrollmentToken: token, RequestedName: name, Pkcs10CsrDer: csrDER,
		ExpectedNetworkId: append([]byte(nil), expectedNetwork[:]...), ExpectedEnrollmentClass: expectedClass,
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := c.post(ctx, "/v1/enroll", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) enroll(ctx context.Context, token, name string, csrDER []byte, expectedNetwork identity.NetworkID) (*lanewayv1.EnrollmentResponse, error) {
	request := &lanewayv1.EnrollmentRequest{EnrollmentToken: token, RequestedName: name, Pkcs10CsrDer: csrDER}
	if !expectedNetwork.IsZero() {
		request.ExpectedNetworkId = append([]byte(nil), expectedNetwork[:]...)
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := c.post(ctx, "/v1/enroll", request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) Renew(ctx context.Context, csrDER []byte) (*lanewayv1.RenewalResponse, error) {
	if c.quic != nil {
		return c.quic.renew(ctx, csrDER)
	}
	response := new(lanewayv1.RenewalResponse)
	if err := c.post(ctx, "/v1/renew", &lanewayv1.RenewalRequest{Pkcs10CsrDer: csrDER}, response); err != nil {
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
}

type EnrollmentTokenOptions struct {
	Class           string
	SessionLifetime time.Duration
	RequestedName   string
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
	}{networkID.String(), label, expiresAt.Unix(), options.Class, int64(options.SessionLifetime / time.Second), options.RequestedName}, response, true)
	return response, err
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
