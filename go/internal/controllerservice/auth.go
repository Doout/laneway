package controllerservice

import (
	"crypto/x509"
	"errors"
	"net/http"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

var (
	ErrUnauthenticated  = errors.New("authentication required")
	ErrPermissionDenied = errors.New("permission denied")
)

// AdminAuthorizer is the compatibility contract for the static root bearer.
// It must return only the stable root service-principal actor. Browser
// administrator sessions use AccessController and are not wired through this
// legacy management surface yet.
type AdminAuthorizer func(*http.Request) (adminauth.Actor, error)

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
