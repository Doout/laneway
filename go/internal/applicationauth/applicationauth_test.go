package applicationauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func TestSecretPurposesAreSeparated(t *testing.T) {
	id, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	secret, digest, err := NewSecret(PurposeClientSecret, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !SecretMatches(PurposeClientSecret, id, digest, secret) {
		t.Fatal("client secret did not match")
	}
	if SecretMatches(PurposeRefreshToken, id, digest, secret) {
		t.Fatal("secret matched another purpose")
	}
}

func TestValidateManifestAndPKCE(t *testing.T) {
	manifest, err := ValidateManifest(Manifest{
		Name: "Example controller", HomepageURI: "https://client.example.com",
		SetupURI:     "https://client.example.com/setup",
		RedirectURIs: []string{"https://client.example.com/callback"},
		Scopes:       []string{"route.read", "network.read"}, TokenEndpointAuthMethod: "client_secret_basic",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Scopes[0] != "network.read" {
		t.Fatalf("scopes=%v", manifest.Scopes)
	}
	verifier := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !VerifyPKCE(challenge, verifier) {
		t.Fatal("valid verifier rejected")
	}
	if VerifyPKCE(challenge, verifier+"x") {
		t.Fatal("wrong verifier accepted")
	}
}

func TestLoopbackHTTPRequiresExplicitOptIn(t *testing.T) {
	if _, err := ValidateURI("http://127.0.0.1:3000/callback", false); err == nil {
		t.Fatal("HTTP accepted")
	}
	if _, err := ValidateURI("http://127.0.0.1:3000/callback", true); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateURI("http://client.example.com/callback", true); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
}
