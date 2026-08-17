// Package transport provides Laneway's authenticated QUIC transport.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/revocation"
)

// ALPN is the TLS application protocol negotiated by Laneway peers.
const ALPN = "laneway-relay/1"

// LoadServerTLSConfig loads a server certificate, private key, and the CA used
// to authenticate client certificates. Certificates on both sides must carry a
// valid Laneway SPIFFE URI SAN.
func LoadServerTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	return LoadServerTLSConfigWithRevocations(caFile, certFile, keyFile, nil)
}

func LoadServerTLSConfigWithRevocations(caFile, certFile, keyFile string, revoked *revocation.Set) (*tls.Config, error) {
	caPool, certificate, err := loadCredentials(caFile, certFile, keyFile, identity.IdentityRoleRelay)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if _, err := peerIdentityWithRole(state, identity.IdentityRoleNode); err != nil {
			return fmt.Errorf("transport: verify client identity: %w", err)
		}
		if revoked != nil {
			if err := revoked.CheckCertificate(state.PeerCertificates[0]); err != nil {
				return fmt.Errorf("transport: verify client revocation: %w", err)
			}
		}
		return nil
	}
	return config, nil
}

// LoadClientTLSConfig loads a client certificate, private key, and the CA used
// to authenticate the server. The server is authenticated by its certificate
// chain and Laneway SPIFFE URI SAN instead of a DNS name, since nodes commonly
// connect to relays by an ephemeral IP address.
//
// Callers that also require DNS-name authentication may set ServerName on the
// returned config. It will be checked in addition to the Laneway identity.
func LoadClientTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	return LoadClientTLSConfigWithRevocations(caFile, certFile, keyFile, nil)
}

func LoadClientTLSConfigWithRevocations(caFile, certFile, keyFile string, revoked *revocation.Set) (*tls.Config, error) {
	caPool, certificate, err := loadCredentials(caFile, certFile, keyFile, identity.IdentityRoleNode)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true, // Verification is performed below using the configured CA.
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("transport: server sent no certificate")
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("transport: verify server certificate: %w", err)
		}
		if config.ServerName != "" {
			if err := state.PeerCertificates[0].VerifyHostname(config.ServerName); err != nil {
				return fmt.Errorf("transport: verify server name: %w", err)
			}
		}
		if _, err := peerIdentityWithRole(state, identity.IdentityRoleRelay); err != nil {
			return fmt.Errorf("transport: verify server identity: %w", err)
		}
		if revoked != nil {
			if err := revoked.CheckCertificate(state.PeerCertificates[0]); err != nil {
				return fmt.Errorf("transport: verify server revocation: %w", err)
			}
		}
		return nil
	}
	return config, nil
}

// RequirePeerService adds an exact role-aware service identity check after
// the TLS config's existing chain, key-usage, and role verification.
func RequirePeerService(config *tls.Config, expected identity.AuthenticatedIdentity) error {
	if config == nil || expected.Validate() != nil || expected.Role == identity.IdentityRoleNode || config.VerifyConnection == nil {
		return errors.New("transport: valid expected service identity and verifier are required")
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := previous(state); err != nil {
			return err
		}
		actual, err := identity.AuthenticatedIdentityFromCertificate(state.PeerCertificates[0])
		if err != nil {
			return err
		}
		if actual != expected {
			return errors.New("transport: peer service identity does not match the configured network and service IDs")
		}
		return nil
	}
	return nil
}

func loadCredentials(caFile, certFile, keyFile string, role identity.IdentityRole) (*x509.CertPool, tls.Certificate, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("transport: read CA certificate: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, tls.Certificate{}, errors.New("transport: CA file contains no valid certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("transport: load certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, tls.Certificate{}, errors.New("transport: certificate file contains no certificates")
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("transport: parse leaf certificate: %w", err)
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(certificate.Leaf)
	if err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("transport: local certificate identity: %w", err)
	}
	if err := authenticated.RequireRole(role); err != nil {
		return nil, tls.Certificate{}, fmt.Errorf("transport: local certificate identity: %w", err)
	}
	return caPool, certificate, nil
}

func peerIdentityWithRole(state tls.ConnectionState, role identity.IdentityRole) (identity.AuthenticatedIdentity, error) {
	if len(state.PeerCertificates) == 0 {
		return identity.AuthenticatedIdentity{}, errors.New("peer sent no certificate")
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(state.PeerCertificates[0])
	if err != nil {
		return identity.AuthenticatedIdentity{}, err
	}
	if err := authenticated.RequireRole(role); err != nil {
		return identity.AuthenticatedIdentity{}, err
	}
	return authenticated, nil
}
