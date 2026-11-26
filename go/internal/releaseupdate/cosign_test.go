package releaseupdate

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReleaseManifestVerifierDoesNotInheritTrustOverrides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture needs a POSIX shell")
	}
	for _, key := range []string{"SIGSTORE_ROOT_FILE", "TUF_ROOT", "COSIGN_REKOR_PUBLIC_KEY"} {
		t.Setenv(key, "untrusted")
	}
	work := t.TempDir()
	verifier := filepath.Join(work, "cosign")
	script := `#!/bin/sh
set -eu
test -z "${SIGSTORE_ROOT_FILE+x}${TUF_ROOT+x}${COSIGN_REKOR_PUBLIC_KEY+x}"
test "$1" = verify-blob
test "$2" = --bundle
test -f "$3"
test "$4" = --certificate-identity
test "$5" = expected-identity
test "$6" = --certificate-oidc-issuer
test "$7" = https://token.actions.githubusercontent.com
test -f "$8"
`
	if err := os.WriteFile(verifier, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	client := NewGitHubClient("Doout/laneway")
	defer client.Close()
	verify, err := client.ReleaseManifestVerifier(context.Background(), work, runtime.GOOS, runtime.GOARCH, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(context.Background(), "expected-identity", []byte("manifest"), []byte("bundle")); err != nil {
		t.Fatal(err)
	}
}
