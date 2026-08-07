package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const SPIFFETrustDomain = "laneway"

var (
	ErrInvalidSPIFFEIdentity  = errors.New("invalid Laneway SPIFFE identity")
	ErrIdentitySANMissing     = errors.New("Laneway identity URI SAN missing")
	ErrMultipleIdentitySANs   = errors.New("multiple Laneway identity URI SANs")
	ErrUnexpectedIdentityRole = errors.New("unexpected Laneway identity role")
)

// IdentityRole is the authenticated workload profile encoded in a Laneway
// SPIFFE URI SAN.
type IdentityRole string

const (
	IdentityRoleNode       IdentityRole = "node"
	IdentityRoleRelay      IdentityRole = "relay"
	IdentityRoleController IdentityRole = "controller"
)

func (r IdentityRole) valid() bool {
	return r == IdentityRoleNode || r == IdentityRoleRelay || r == IdentityRoleController
}

// AuthenticatedIdentity is a role-aware identity authenticated from a
// certificate. SubjectID is a NodeID for the node role and a service ID for
// relay and controller roles.
type AuthenticatedIdentity struct {
	NetworkID NetworkID
	Role      IdentityRole
	SubjectID ID
}

func (id AuthenticatedIdentity) Validate() error {
	if id.NetworkID.IsZero() || id.SubjectID.IsZero() || !id.Role.valid() {
		return fmt.Errorf("%w: zero ID or unknown role", ErrInvalidSPIFFEIdentity)
	}
	return nil
}

func (id AuthenticatedIdentity) URI() (*url.URL, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme: "spiffe",
		Host:   SPIFFETrustDomain,
		Path:   "/network/" + id.NetworkID.String() + "/" + string(id.Role) + "/" + id.SubjectID.String(),
	}, nil
}

// RequireRole rejects identities from a different certificate profile.
func (id AuthenticatedIdentity) RequireRole(role IdentityRole) error {
	if !role.valid() || id.Role != role {
		return fmt.Errorf("%w: got %q, want %q", ErrUnexpectedIdentityRole, id.Role, role)
	}
	return nil
}

// NodeIdentity converts a node-role authenticated identity to the legacy node
// representation. The boolean is false for relay and controller identities.
func (id AuthenticatedIdentity) NodeIdentity() (NodeIdentity, bool) {
	if id.Role != IdentityRoleNode {
		return NodeIdentity{}, false
	}
	return NodeIdentity{NetworkID: id.NetworkID, NodeID: NodeID(id.SubjectID)}, true
}

type NodeIdentity struct {
	NetworkID NetworkID
	NodeID    NodeID
}

func (id NodeIdentity) Validate() error {
	if id.NetworkID.IsZero() || id.NodeID.IsZero() {
		return fmt.Errorf("%w: zero network or node ID", ErrInvalidSPIFFEIdentity)
	}
	return nil
}

func (id NodeIdentity) AuthenticatedIdentity() AuthenticatedIdentity {
	return AuthenticatedIdentity{
		NetworkID: id.NetworkID,
		Role:      IdentityRoleNode,
		SubjectID: ID(id.NodeID),
	}
}

func (id NodeIdentity) URI() (*url.URL, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id.AuthenticatedIdentity().URI()
}

func validateSPIFFEComponents(uri *url.URL) error {
	if uri == nil {
		return fmt.Errorf("%w: nil URI", ErrInvalidSPIFFEIdentity)
	}
	if uri.Scheme != "spiffe" || uri.Host != SPIFFETrustDomain || uri.User != nil ||
		uri.RawQuery != "" || uri.Fragment != "" || uri.Opaque != "" || uri.ForceQuery {
		return fmt.Errorf("%w: unexpected URI authority or components", ErrInvalidSPIFFEIdentity)
	}
	if uri.RawPath != "" && uri.EscapedPath() != uri.Path {
		return fmt.Errorf("%w: escaped path is not canonical", ErrInvalidSPIFFEIdentity)
	}
	return nil
}

// ParseAuthenticatedSPIFFEURI parses node, relay, and controller URI profiles.
func ParseAuthenticatedSPIFFEURI(uri *url.URL) (AuthenticatedIdentity, error) {
	if err := validateSPIFFEComponents(uri); err != nil {
		return AuthenticatedIdentity{}, err
	}
	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if !strings.HasPrefix(uri.Path, "/") || len(parts) != 4 || parts[0] != "network" {
		return AuthenticatedIdentity{}, fmt.Errorf("%w: expected /network/<id>/<role>/<id>", ErrInvalidSPIFFEIdentity)
	}
	networkID, err := ParseNetworkID(parts[1])
	if err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("%w: network ID: %v", ErrInvalidSPIFFEIdentity, err)
	}
	role := IdentityRole(parts[2])
	if !role.valid() {
		return AuthenticatedIdentity{}, fmt.Errorf("%w: unknown role %q", ErrInvalidSPIFFEIdentity, parts[2])
	}
	subjectID, err := ParseID(parts[3])
	if err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("%w: subject ID: %v", ErrInvalidSPIFFEIdentity, err)
	}
	return AuthenticatedIdentity{NetworkID: networkID, Role: role, SubjectID: subjectID}, nil
}

func ParseAuthenticatedSPIFFE(s string) (AuthenticatedIdentity, error) {
	u, err := url.Parse(s)
	if err != nil {
		return AuthenticatedIdentity{}, fmt.Errorf("%w: %v", ErrInvalidSPIFFEIdentity, err)
	}
	return ParseAuthenticatedSPIFFEURI(u)
}

// ParseSPIFFEURI retains the original node-only API.
func ParseSPIFFEURI(uri *url.URL) (NodeIdentity, error) {
	authenticated, err := ParseAuthenticatedSPIFFEURI(uri)
	if err != nil {
		return NodeIdentity{}, err
	}
	if err := authenticated.RequireRole(IdentityRoleNode); err != nil {
		return NodeIdentity{}, err
	}
	node, _ := authenticated.NodeIdentity()
	return node, nil
}

func ParseSPIFFE(s string) (NodeIdentity, error) {
	u, err := url.Parse(s)
	if err != nil {
		return NodeIdentity{}, fmt.Errorf("%w: %v", ErrInvalidSPIFFEIdentity, err)
	}
	return ParseSPIFFEURI(u)
}

// AuthenticatedIdentityFromCertificate extracts the sole Laneway URI SAN and
// preserves its role. Unrelated URI SANs are allowed, but a malformed URI in
// the Laneway trust domain is an authentication error.
func AuthenticatedIdentityFromCertificate(cert *x509.Certificate) (AuthenticatedIdentity, error) {
	if cert == nil {
		return AuthenticatedIdentity{}, ErrIdentitySANMissing
	}
	var found *AuthenticatedIdentity
	for _, uri := range cert.URIs {
		if uri == nil || uri.Host != SPIFFETrustDomain {
			continue
		}
		authenticated, err := ParseAuthenticatedSPIFFEURI(uri)
		if err != nil {
			return AuthenticatedIdentity{}, err
		}
		if found != nil {
			return AuthenticatedIdentity{}, ErrMultipleIdentitySANs
		}
		found = &authenticated
	}
	if found == nil {
		return AuthenticatedIdentity{}, ErrIdentitySANMissing
	}
	return *found, nil
}

// IdentityFromCertificate retains the original node-only API.
func IdentityFromCertificate(cert *x509.Certificate) (NodeIdentity, error) {
	authenticated, err := AuthenticatedIdentityFromCertificate(cert)
	if err != nil {
		return NodeIdentity{}, err
	}
	if err := authenticated.RequireRole(IdentityRoleNode); err != nil {
		return NodeIdentity{}, err
	}
	node, _ := authenticated.NodeIdentity()
	return node, nil
}

func (id NodeIdentity) ValidateClaim(networkID NetworkID, nodeID NodeID) error {
	if id.NetworkID != networkID || id.NodeID != nodeID {
		return fmt.Errorf("authenticated identity does not match claimed identity")
	}
	return nil
}
