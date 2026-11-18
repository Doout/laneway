//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

// Only the Rust PKI interoperability test sets these variables, in a new
// temporary directory. No controller or production key material is used.
func TestRustNodeIssuerFixture(t *testing.T) {
	dir := os.Getenv("LANEWAY_PKI_FIXTURE")
	if dir == "" {
		t.Skip("driven by node_issuer_go integration test")
	}
	now := time.Unix(1800000000, 0).UTC()
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	variants := []string{"ed25519", "ecdsa-p256", "ecdsa-p384", "rsa", "rsa-pss"}
	switch os.Getenv("LANEWAY_PKI_STEP") {
	case "prepare":
		material, root, err := pki.NewAuthority("Lab Root", now.Add(-time.Hour), 72*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		inter, _, err := pki.IssueIntermediate(root, material.PrivateKey, "Online Lab Issuer", now.Add(-time.Minute), 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for prefix, m := range map[string]pki.Material{"root": material, "inter": inter} {
			write(prefix+".crt", m.CertificateDER)
			pk, err := x509.MarshalPKCS8PrivateKey(m.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			write(prefix+".key", pk)
		}
		for _, variant := range variants {
			var key crypto.Signer
			switch variant {
			case "ed25519":
				_, key, err = ed25519.GenerateKey(rand.Reader)
			case "ecdsa-p256":
				key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			case "ecdsa-p384":
				key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			default:
				key, err = rsa.GenerateKey(rand.Reader, 2048)
			}
			if err != nil {
				t.Fatal(err)
			}
			claimed, _ := url.Parse("spiffe://laneway/network/11111111111111111111111111111111/relay/22222222222222222222222222222222")
			template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "not-an-authority", Organization: []string{"Requester"}},
				DNSNames: []string{"requested.example"}, IPAddresses: []net.IP{net.IPv4(192, 0, 2, 1)}, URIs: []*url.URL{claimed},
				ExtraExtensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}},
					{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: []byte{5, 0}},
				}}
			if variant == "rsa-pss" {
				template.SignatureAlgorithm = x509.SHA256WithRSAPSS
			}
			der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
			if err != nil {
				t.Fatal(err)
			}
			write(variant+".csr", der)
		}
	case "verify":
		root, err := x509.ParseCertificate(read("root.crt"))
		if err != nil {
			t.Fatal(err)
		}
		inter, err := x509.ParseCertificate(read("inter.crt"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		serials := map[string]bool{}
		for _, profile := range []string{"root", "inter", "lease"} {
			for _, variant := range variants {
				prefix := profile + "-" + variant
				leaf, err := x509.ParseCertificate(read(prefix + ".crt"))
				if err != nil {
					t.Fatal(err)
				}
				csr, err := x509.ParseCertificateRequest(read(variant + ".csr"))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
					t.Fatal("node key changed")
				}
				id, err := identity.IdentityFromCertificate(leaf)
				if err != nil || id.NetworkID.String() != "11111111111111111111111111111111" || id.NodeID.String() != "33333333333333333333333333333333" {
					t.Fatal("wrong issued identity")
				}
				if len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.Subject.Organization) != 0 ||
					leaf.Subject.CommonName != "laneway-node-"+id.NodeID.String() || !leaf.BasicConstraintsValid || leaf.IsCA ||
					leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 2 || len(leaf.UnknownExtKeyUsage) != 0 {
					t.Fatal("unexpected issued certificate profile")
				}
				for _, ext := range leaf.Extensions {
					if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}) {
						t.Fatal("request extension copied")
					}
				}
				intermediates := x509.NewCertPool()
				signingCA := root
				wantExpiry := now.Add(48 * time.Hour)
				if profile != "root" {
					chain := read(prefix + ".chain")
					if !bytes.Equal(chain, inter.Raw) {
						t.Fatal("wrong returned intermediate")
					}
					intermediates.AddCert(inter)
					signingCA = inter
					wantExpiry = inter.NotAfter
					if profile == "lease" {
						wantExpiry = now.Add(5 * time.Minute)
					}
				} else if len(read(prefix+".chain")) != 0 {
					t.Fatal("self-signed root returned")
				}
				if !leaf.NotBefore.Equal(now.Add(-time.Minute)) || !leaf.NotAfter.Equal(wantExpiry) ||
					!bytes.Equal(leaf.AuthorityKeyId, signingCA.SubjectKeyId) {
					t.Fatal("wrong certificate deadline or authority")
				}
				if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 || !bytes.Equal(leaf.SerialNumber.Bytes(), read(prefix+".serial")) || serials[leaf.SerialNumber.String()] {
					t.Fatal("invalid, mismatched or duplicate serial")
				}
				serials[leaf.SerialNumber.String()] = true
				for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
					if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	default:
		t.Fatal("invalid fixture step")
	}
}
