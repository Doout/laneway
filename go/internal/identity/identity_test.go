package identity

import (
	"crypto/x509"
	"errors"
	"net/url"
	"testing"
)

const (
	networkText = "000102030405060708090a0b0c0d0e0f"
	nodeText    = "101112131415161718191a1b1c1d1e1f"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestIDCanonicalText(t *testing.T) {
	id, err := ParseID(networkText)
	if err != nil {
		t.Fatal(err)
	}
	if got := id.String(); got != networkText {
		t.Fatalf("String %q", got)
	}
	for _, bad := range []string{
		"00010203-0405-0607-0809-0a0b0c0d0e0f",
		"000102030405060708090A0B0C0D0E0F",
		"00000000000000000000000000000000",
		"0x000102030405060708090a0b0c0d0e0f",
	} {
		if _, err := ParseID(bad); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("ParseID(%q): %v", bad, err)
		}
	}
}

func TestSPIFFEIdentityRoundTrip(t *testing.T) {
	network, _ := ParseNetworkID(networkText)
	node, _ := ParseNodeID(nodeText)
	want := NodeIdentity{NetworkID: network, NodeID: node}
	u, err := want.URI()
	if err != nil {
		t.Fatal(err)
	}
	const canonical = "spiffe://laneway/network/000102030405060708090a0b0c0d0e0f/node/101112131415161718191a1b1c1d1e1f"
	if u.String() != canonical {
		t.Fatalf("URI %q", u)
	}
	got, err := ParseSPIFFE(canonical)
	if err != nil || got != want {
		t.Fatalf("ParseSPIFFE: %#v %v", got, err)
	}
	if err := got.ValidateClaim(network, node); err != nil {
		t.Fatal(err)
	}
	other, _ := ParseNodeID("ffffffffffffffffffffffffffffffff")
	if err := got.ValidateClaim(network, other); err == nil {
		t.Fatal("mismatched claim accepted")
	}
}

func TestParseSPIFFERejectsNoncanonical(t *testing.T) {
	validPath := "/network/" + networkText + "/node/" + nodeText
	for _, raw := range []string{
		"spiffe://laneway/bad",
		"https://laneway" + validPath,
		"spiffe://Laneway" + validPath,
		"spiffe://laneway:443" + validPath,
		"spiffe://laneway" + validPath + "/",
		"spiffe://laneway/network/00010203-0405-0607-0809-0a0b0c0d0e0f/node/" + nodeText,
		"spiffe://laneway/network/000102030405060708090A0B0C0D0E0F/node/" + nodeText,
		"spiffe://laneway/network/%30" + networkText[1:] + "/node/" + nodeText,
		"spiffe://user@laneway" + validPath,
		"spiffe://laneway" + validPath + "?x=1",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseSPIFFE(raw); !errors.Is(err, ErrInvalidSPIFFEIdentity) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestIdentityFromCertificate(t *testing.T) {
	valid := "spiffe://laneway/network/" + networkText + "/node/" + nodeText
	unrelated := mustURL(t, "https://example.test/identity")
	got, err := IdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{unrelated, mustURL(t, valid)}})
	if err != nil || got.NodeID.String() != nodeText {
		t.Fatalf("extract: %#v %v", got, err)
	}
	if _, err := IdentityFromCertificate(&x509.Certificate{}); !errors.Is(err, ErrIdentitySANMissing) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := IdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{mustURL(t, valid), mustURL(t, valid)}}); !errors.Is(err, ErrMultipleIdentitySANs) {
		t.Fatalf("multiple: %v", err)
	}
	for _, malformed := range []string{"spiffe://laneway/bad", "https://laneway" + mustURL(t, valid).Path} {
		if _, err := IdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{mustURL(t, malformed)}}); !errors.Is(err, ErrInvalidSPIFFEIdentity) {
			t.Fatalf("malformed %q: %v", malformed, err)
		}
	}
}

func TestAuthenticatedIdentityProfiles(t *testing.T) {
	for _, role := range []IdentityRole{IdentityRoleNode, IdentityRoleRelay, IdentityRoleController} {
		raw := "spiffe://laneway/network/" + networkText + "/" + string(role) + "/" + nodeText
		got, err := ParseAuthenticatedSPIFFE(raw)
		if err != nil {
			t.Fatalf("ParseAuthenticatedSPIFFE(%s): %v", role, err)
		}
		if got.Role != role || got.NetworkID.String() != networkText || got.SubjectID.String() != nodeText {
			t.Fatalf("profile %s = %#v", role, got)
		}
		u, err := got.URI()
		if err != nil || u.String() != raw {
			t.Fatalf("profile %s URI = %v, %v", role, u, err)
		}
		fromCert, err := AuthenticatedIdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{mustURL(t, raw)}})
		if err != nil || fromCert != got {
			t.Fatalf("certificate profile %s = %#v, %v", role, fromCert, err)
		}
		node, ok := got.NodeIdentity()
		if role == IdentityRoleNode {
			if !ok || node.NodeID.String() != nodeText {
				t.Fatalf("node conversion = %#v, %v", node, ok)
			}
		} else if ok {
			t.Fatalf("service role %s converted to node", role)
		}
	}
}

func TestNodeAPIsRejectServiceRoles(t *testing.T) {
	for _, role := range []IdentityRole{IdentityRoleRelay, IdentityRoleController} {
		raw := "spiffe://laneway/network/" + networkText + "/" + string(role) + "/" + nodeText
		if _, err := ParseSPIFFE(raw); !errors.Is(err, ErrUnexpectedIdentityRole) {
			t.Fatalf("ParseSPIFFE(%s): %v", role, err)
		}
		cert := &x509.Certificate{URIs: []*url.URL{mustURL(t, raw)}}
		if _, err := IdentityFromCertificate(cert); !errors.Is(err, ErrUnexpectedIdentityRole) {
			t.Fatalf("IdentityFromCertificate(%s): %v", role, err)
		}
	}
}

func FuzzParseID(f *testing.F) {
	f.Add(networkText)
	f.Add("00010203-0405-0607-0809-0a0b0c0d0e0f")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseID(s)
		if err == nil {
			if id.String() != s || len(s) != 32 || id.IsZero() {
				t.Fatalf("accepted noncanonical ID %q", s)
			}
		}
	})
}

func FuzzParseSPIFFE(f *testing.F) {
	f.Add("spiffe://laneway/network/" + networkText + "/node/" + nodeText)
	f.Add("spiffe://laneway/bad")
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseSPIFFE(s) })
}
