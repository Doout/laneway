// Package applicationauth defines the generic registered-application and OAuth
// contract used by external Laneway integrations.
package applicationauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	ClientIDPrefix      = "lnw_client_v1"
	ClientSecretPrefix  = "lnw_client_secret_v1"
	RegistrationPrefix  = "lnw_registration_v1"
	AuthorizationPrefix = "lnw_authorization_v1"
	RefreshTokenPrefix  = "lnw_refresh_v1"
	secretBytes         = 32
	MaxDisplayNameBytes = 128
	MaxURIBytes         = 2048
	MaxRedirectURIs     = 16
	MaxScopes           = 16
)

type SecretPurpose string

const (
	PurposeClientSecret      SecretPurpose = "client_secret"
	PurposeRegistrationCode  SecretPurpose = "registration_code"
	PurposeAuthorizationCode SecretPurpose = "authorization_code"
	PurposeRefreshToken      SecretPurpose = "refresh_token"
)

func (purpose SecretPurpose) valid() bool {
	return purpose == PurposeClientSecret || purpose == PurposeRegistrationCode ||
		purpose == PurposeAuthorizationCode || purpose == PurposeRefreshToken
}

type Manifest struct {
	Name                    string   `json:"name"`
	HomepageURI             string   `json:"homepage_uri"`
	SetupURI                string   `json:"setup_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

var scopeOperations = map[string]adminauth.Operation{
	"network.read":     adminauth.OperationNetworkRead,
	"node.read":        adminauth.OperationNodeRead,
	"enrollment.issue": adminauth.OperationEnrollmentIssue,
	"route.read":       adminauth.OperationRouteRead,
	"route.manage":     adminauth.OperationRouteManage,
}

func OperationForScope(scope string) (adminauth.Operation, bool) {
	operation, ok := scopeOperations[scope]
	return operation, ok
}

func ValidateScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > MaxScopes {
		return nil, errors.New("scope set must contain 1..16 values")
	}
	result := slices.Clone(scopes)
	slices.Sort(result)
	for index, scope := range result {
		if _, ok := OperationForScope(scope); !ok || index > 0 && scope == result[index-1] {
			return nil, errors.New("invalid or duplicate application scope")
		}
	}
	return result, nil
}

func ScopesSubset(candidate, ceiling []string) bool {
	for _, scope := range candidate {
		if !slices.Contains(ceiling, scope) {
			return false
		}
	}
	return true
}

func ValidateManifest(manifest Manifest, allowLoopbackHTTP bool) (Manifest, error) {
	if manifest.Name == "" || manifest.Name != strings.TrimSpace(manifest.Name) ||
		len(manifest.Name) > MaxDisplayNameBytes || strings.IndexByte(manifest.Name, 0) >= 0 || !utf8.ValidString(manifest.Name) ||
		manifest.TokenEndpointAuthMethod != "client_secret_basic" ||
		len(manifest.RedirectURIs) == 0 || len(manifest.RedirectURIs) > MaxRedirectURIs {
		return Manifest{}, errors.New("invalid application manifest")
	}
	var err error
	if manifest.HomepageURI, err = ValidateURI(manifest.HomepageURI, allowLoopbackHTTP); err != nil {
		return Manifest{}, fmt.Errorf("invalid homepage_uri: %w", err)
	}
	if manifest.SetupURI, err = ValidateURI(manifest.SetupURI, allowLoopbackHTTP); err != nil {
		return Manifest{}, fmt.Errorf("invalid setup_uri: %w", err)
	}
	redirects := make([]string, 0, len(manifest.RedirectURIs))
	for _, raw := range manifest.RedirectURIs {
		canonical, uriErr := ValidateURI(raw, allowLoopbackHTTP)
		if uriErr != nil || slices.Contains(redirects, canonical) {
			return Manifest{}, errors.New("invalid or duplicate redirect_uri")
		}
		redirects = append(redirects, canonical)
	}
	slices.Sort(redirects)
	scopes, err := ValidateScopes(manifest.Scopes)
	if err != nil {
		return Manifest{}, err
	}
	manifest.RedirectURIs, manifest.Scopes = redirects, scopes
	return manifest, nil
}

func ValidateURI(raw string, allowLoopbackHTTP bool) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > MaxURIBytes || strings.IndexByte(raw, 0) >= 0 {
		return "", errors.New("URI must be a bounded absolute URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("URI must be absolute and cannot contain user information or a fragment")
	}
	if strings.Contains(parsed.Hostname(), "*") {
		return "", errors.New("wildcard hosts are not allowed")
	}
	if parsed.Scheme != "https" {
		host := net.ParseIP(parsed.Hostname())
		loopback := strings.EqualFold(parsed.Hostname(), "localhost") || host != nil && host.IsLoopback()
		if !allowLoopbackHTTP || parsed.Scheme != "http" || !loopback {
			return "", errors.New("URI must use HTTPS")
		}
	}
	if parsed.String() != raw {
		return "", errors.New("URI must use its canonical representation")
	}
	return raw, nil
}

func ValidatePKCEChallenge(challenge string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == challenge
}

func VerifyPKCE(challenge, verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	encoded := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(challenge)) == 1
}

func ClientID(applicationID identity.ID) string {
	return ClientIDPrefix + "." + applicationID.String()
}

func ParseClientID(value string) (identity.ID, error) {
	return parsePublicID(value, ClientIDPrefix)
}

func NewSecret(purpose SecretPurpose, id identity.ID, random io.Reader) (string, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if !purpose.valid() || id.IsZero() {
		return "", zero, errors.New("invalid application secret purpose")
	}
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, secretBytes)
	defer clear(raw)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", zero, err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	prefix := prefixForPurpose(purpose)
	return prefix + "." + id.String() + "." + secret, digest(purpose, id, secret), nil
}

func ParseSecret(purpose SecretPurpose, value string) (identity.ID, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	parts := strings.Split(value, ".")
	if !purpose.valid() || len(parts) != 3 || parts[0] != prefixForPurpose(purpose) {
		return identity.ID{}, zero, errors.New("invalid application secret")
	}
	id, err := identity.ParseID(parts[1])
	decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	defer clear(decoded)
	if err != nil || decodeErr != nil || len(decoded) != secretBytes || base64.RawURLEncoding.EncodeToString(decoded) != parts[2] {
		return identity.ID{}, zero, errors.New("invalid application secret")
	}
	return id, digest(purpose, id, parts[2]), nil
}

func SecretMatches(purpose SecretPurpose, id identity.ID, stored [sha256.Size]byte, value string) bool {
	parsedID, candidate, err := ParseSecret(purpose, value)
	return err == nil && parsedID == id && subtle.ConstantTimeCompare(stored[:], candidate[:]) == 1
}

func prefixForPurpose(purpose SecretPurpose) string {
	switch purpose {
	case PurposeClientSecret:
		return ClientSecretPrefix
	case PurposeRegistrationCode:
		return RegistrationPrefix
	case PurposeAuthorizationCode:
		return AuthorizationPrefix
	case PurposeRefreshToken:
		return RefreshTokenPrefix
	default:
		return ""
	}
}

func parsePublicID(value, prefix string) (identity.ID, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 || parts[0] != prefix {
		return identity.ID{}, errors.New("invalid public identifier")
	}
	return identity.ParseID(parts[1])
}

func digest(purpose SecretPurpose, id identity.ID, secret string) [sha256.Size]byte {
	material := make([]byte, 0, 64+len(secret))
	material = append(material, "laneway-application-"...)
	material = append(material, purpose...)
	material = append(material, "-v1\x00"...)
	material = append(material, id[:]...)
	material = append(material, secret...)
	result := sha256.Sum256(material)
	clear(material)
	return result
}
