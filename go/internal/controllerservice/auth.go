package controllerservice

import (
	"crypto/x509"
	"errors"
	"net/http"

	"laneway.dev/laneway/internal/identity"
)

var (
	ErrUnauthenticated  = errors.New("authentication required")
	ErrPermissionDenied = errors.New("permission denied")
)

// AdminAuthorizer is called before every administrative operation. Deployments
// can implement bearer-token, reverse-proxy, or mTLS administration without
// coupling those credentials to the service.
type AdminAuthorizer func(*http.Request) error

// NodeAuthorizer authenticates a request as a node. Returning an identity does
// not bypass the service's durable node and revocation checks.
type NodeAuthorizer func(*http.Request) (identity.NodeIdentity, error)

func identityFromMTLS(r *http.Request) (identity.NodeIdentity, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return identity.NodeIdentity{}, ErrUnauthenticated
	}
	return identity.IdentityFromCertificate(r.TLS.VerifiedChains[0][0])
}

func peerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
