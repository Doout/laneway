package controllerservice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"laneway.dev/laneway/internal/adminauth"
)

var (
	ErrMalformedAdminCredentials = errors.New("malformed administrator credentials")
	ErrMixedAdminCredentials     = errors.New("multiple administrator credential kinds")
	ErrBrowserOrigin             = errors.New("browser request origin rejected")
	ErrCSRF                      = errors.New("CSRF validation failed")
)

// CredentialKind identifies the credential boundary that authenticated an
// administrator request. It is deliberately independent from an
// administrator's role: a credential proves an actor, then every operation is
// authorized separately.
type CredentialKind string

const (
	CredentialNone                 CredentialKind = ""
	CredentialRootBearer           CredentialKind = "root_bearer"
	CredentialAdministratorSession CredentialKind = "administrator_session"
)

func (k CredentialKind) Valid() bool {
	return k == CredentialRootBearer || k == CredentialAdministratorSession
}

// RequestActor is the authenticated, server-derived actor for one request.
// Browser-provided labels and other presentation strings never enter this
// value. Principal is populated only for administrator sessions; the root
// bearer is represented as its durable service-principal actor.
type RequestActor struct {
	Credential        CredentialKind
	Subject           adminauth.Subject
	Principal         *adminauth.Principal
	CSRFHash          [sha256.Size]byte
	IdleLifetime      time.Duration
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

func (a RequestActor) Valid() bool {
	if !a.Credential.Valid() || !a.Subject.Valid() {
		return false
	}
	switch a.Credential {
	case CredentialRootBearer:
		return a.Subject.Kind() == adminauth.SubjectRootServicePrincipal && a.Principal == nil && zeroDigest(a.CSRFHash) &&
			a.IdleLifetime == 0 && a.IdleExpiresAt.IsZero() && a.AbsoluteExpiresAt.IsZero()
	case CredentialAdministratorSession:
		if a.Subject.Kind() != adminauth.SubjectAdministratorSession || a.Principal == nil || zeroDigest(a.CSRFHash) {
			return false
		}
		return a.Principal.Enabled && a.Principal.Valid() && a.Subject.ActorID() == a.Principal.ID &&
			a.IdleLifetime >= time.Minute && !a.IdleExpiresAt.IsZero() && !a.AbsoluteExpiresAt.IsZero() &&
			!a.IdleExpiresAt.After(a.AbsoluteExpiresAt)
	default:
		return false
	}
}

// AccessController authenticates a request and authorizes its operation and
// canonical network scope. A nil network identifies a global operation.
// Implementations must reload durable principal, session, revocation, role,
// and network-grant state for each call rather than trusting browser state.
type AccessController interface {
	Authenticate(context.Context, *http.Request) (RequestActor, error)
	Authorize(context.Context, RequestActor, adminauth.RoutePolicy, adminauth.DecisionTarget) (adminauth.Decision, error)
}

type routePolicyKey struct {
	method  string
	pattern string
}

type routePolicyRegistry struct {
	policies []adminauth.RoutePolicy
	byRoute  map[routePolicyKey]adminauth.RoutePolicy
}

var managementRouteRegistry = mustRoutePolicyRegistry(adminauth.ManagementRoutes())

func newRoutePolicyRegistry(policies []adminauth.RoutePolicy) (routePolicyRegistry, error) {
	registry := routePolicyRegistry{
		policies: make([]adminauth.RoutePolicy, 0, len(policies)),
		byRoute:  make(map[routePolicyKey]adminauth.RoutePolicy, len(policies)),
	}
	for _, policy := range policies {
		if !policy.Valid() || policy.Pattern != "/v1/admin" && !strings.HasPrefix(policy.Pattern, "/v1/admin/") {
			return routePolicyRegistry{}, fmt.Errorf("invalid management route policy: %s %s", policy.Method, policy.Pattern)
		}
		key := routePolicyKey{method: policy.Method, pattern: policy.Pattern}
		if _, exists := registry.byRoute[key]; exists {
			return routePolicyRegistry{}, fmt.Errorf("duplicate management route policy: %s %s", policy.Method, policy.Pattern)
		}
		registry.policies = append(registry.policies, policy)
		registry.byRoute[key] = policy
	}
	return registry, nil
}

func mustRoutePolicyRegistry(policies []adminauth.RoutePolicy) routePolicyRegistry {
	registry, err := newRoutePolicyRegistry(policies)
	if err != nil {
		panic(err)
	}
	return registry
}

// ManagementRoutePolicies returns a defensive copy of the policies that must
// accompany the controller's management routes.
func ManagementRoutePolicies() []adminauth.RoutePolicy {
	return append([]adminauth.RoutePolicy(nil), managementRouteRegistry.policies...)
}

// ManagementRoutePolicy resolves an exact net/http method-pattern pair. It is
// intended for route registration, not matching an already-expanded URL path.
func ManagementRoutePolicy(method, pattern string) (adminauth.RoutePolicy, bool) {
	policy, ok := managementRouteRegistry.byRoute[routePolicyKey{method: method, pattern: pattern}]
	return policy, ok
}

// DetectAdminCredential reports which supported credential transport is
// present without authenticating its secret. Supplying both transports is
// always rejected so a request cannot be interpreted differently by separate
// middleware layers.
func DetectAdminCredential(request *http.Request) (CredentialKind, error) {
	if request == nil {
		return CredentialNone, ErrMalformedAdminCredentials
	}
	authorization := request.Header.Values("Authorization")
	sessions := request.CookiesNamed(adminauth.SessionCookieName)
	if len(authorization) > 1 || len(sessions) > 1 {
		return CredentialNone, ErrMalformedAdminCredentials
	}
	if len(authorization) == 1 && len(sessions) == 1 {
		return CredentialNone, ErrMixedAdminCredentials
	}
	if len(authorization) == 1 {
		value := authorization[0]
		if value == "" || value != strings.TrimSpace(value) {
			return CredentialNone, ErrMalformedAdminCredentials
		}
		scheme, secret, found := strings.Cut(value, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || secret == "" ||
			strings.ContainsAny(secret, " \t\r\n,") {
			return CredentialNone, ErrMalformedAdminCredentials
		}
		return CredentialRootBearer, nil
	}
	if len(sessions) == 1 {
		if sessions[0].Value == "" {
			return CredentialNone, ErrMalformedAdminCredentials
		}
		return CredentialAdministratorSession, nil
	}
	return CredentialNone, nil
}

// BrowserMutationRequiresProtection identifies methods for which a browser
// session must pass both same-origin and CSRF checks. TRACE is intentionally
// treated as unsafe even though RFC 9110 classifies it as safe.
func BrowserMutationRequiresProtection(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// ValidateMutationProtection enforces browser protections for session-backed
// mutations while preserving header-bearer automation compatibility.
func ValidateMutationProtection(request *http.Request, actor RequestActor) error {
	if request == nil || !actor.Valid() {
		return ErrUnauthenticated
	}
	if !BrowserMutationRequiresProtection(request.Method) || actor.Credential == CredentialRootBearer {
		return nil
	}
	return ValidateBrowserMutation(request, actor.CSRFHash)
}

// ValidateBrowserMutation applies both origin and CSRF validation. Callers may
// invoke it for every browser request; safe methods are deliberately exempt.
func ValidateBrowserMutation(request *http.Request, expectedCSRFHash [sha256.Size]byte) error {
	if request == nil {
		return ErrBrowserOrigin
	}
	if !BrowserMutationRequiresProtection(request.Method) {
		return nil
	}
	if err := ValidateSameOrigin(request); err != nil {
		return err
	}
	return ValidateCSRF(request, expectedCSRFHash)
}

// ValidateSameOrigin requires a TLS same-origin Origin header. Fetch Metadata
// is an additional signal when supplied; cross-site, same-site, and duplicate
// values fail closed. The direct controller does not trust forwarding headers.
func ValidateSameOrigin(request *http.Request) error {
	if request == nil || request.TLS == nil || request.Host == "" {
		return ErrBrowserOrigin
	}
	origins := request.Header.Values("Origin")
	if len(origins) != 1 {
		return ErrBrowserOrigin
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Opaque != "" || origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return ErrBrowserOrigin
	}
	originHost, originPort, err := canonicalAuthority(origin.Host, "https")
	if err != nil {
		return ErrBrowserOrigin
	}
	requestHost, requestPort, err := canonicalAuthority(request.Host, "https")
	if err != nil || !strings.EqualFold(originHost, requestHost) || originPort != requestPort {
		return ErrBrowserOrigin
	}
	fetchSite := request.Header.Values("Sec-Fetch-Site")
	if len(fetchSite) > 1 || len(fetchSite) == 1 && fetchSite[0] != "same-origin" {
		return ErrBrowserOrigin
	}
	return nil
}

func canonicalAuthority(authority, scheme string) (string, string, error) {
	parsed, err := url.Parse(scheme + "://" + authority)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("invalid authority")
	}
	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return "", "", errors.New("invalid authority host")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = address.String()
	} else {
		host = strings.ToLower(host)
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	} else {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return "", "", errors.New("invalid authority port")
		}
		port = strconv.FormatUint(value, 10)
	}
	return host, port, nil
}

// ValidateCSRF requires one canonical token in both the cookie and header,
// exact equality between those values, and a match against the server-side
// session hash.
func ValidateCSRF(request *http.Request, expectedHash [sha256.Size]byte) error {
	if request == nil || zeroDigest(expectedHash) {
		return ErrCSRF
	}
	cookies := request.CookiesNamed(adminauth.CSRFCookieName)
	headers := request.Header.Values(adminauth.CSRFHeaderName)
	if len(cookies) != 1 || len(headers) != 1 || cookies[0].Value == "" || headers[0] == "" {
		return ErrCSRF
	}
	cookieToken, headerToken := cookies[0].Value, headers[0]
	if len(cookieToken) != len(headerToken) || subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 ||
		!adminauth.SecretMatches(adminauth.SecretCSRF, expectedHash, headerToken) {
		return ErrCSRF
	}
	return nil
}

func zeroDigest(value [sha256.Size]byte) bool {
	var zero [sha256.Size]byte
	return subtle.ConstantTimeCompare(value[:], zero[:]) == 1
}
