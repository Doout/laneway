package releaseupdate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MacManifestVerifier verifies the release manifest with a user-installed
// Cosign or a pinned temporary copy. It never installs the verifier as root.
func (c *Client) MacManifestVerifier(ctx context.Context, directory, arch string) (ManifestVerifier, error) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		var checksum string
		switch arch {
		case "arm64":
			checksum = "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76"
		case "amd64":
			checksum = "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c"
		default:
			return nil, fmt.Errorf("no pinned Cosign verifier for macOS %s", arch)
		}
		cosign = filepath.Join(directory, "cosign-v3.1.3")
		asset := "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-darwin-" + arch
		digest, err := c.downloadFile(ctx, asset, cosign, 160<<20)
		if err != nil {
			return nil, fmt.Errorf("download pinned Cosign verifier: %w", err)
		}
		if hex.EncodeToString(digest) != checksum {
			_ = os.Remove(cosign)
			return nil, errors.New("pinned Cosign verifier failed checksum verification")
		}
	}
	return func(ctx context.Context, identity string, manifest, bundle []byte) error {
		manifestPath := filepath.Join(directory, "checksums.txt")
		bundlePath := filepath.Join(directory, "checksums.sigstore.json")
		if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
			return err
		}
		output, err := exec.CommandContext(ctx, cosign, "verify-blob", "--bundle", bundlePath,
			"--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
			manifestPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("Cosign: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}, nil
}
