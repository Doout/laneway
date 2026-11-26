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

// ReleaseManifestVerifier uses a trusted installed verifier selected by the
// caller, or downloads a checksum-pinned Cosign. Both use public Sigstore roots.
func (c *Client) ReleaseManifestVerifier(ctx context.Context, directory, platform, arch, cosign string) (ManifestVerifier, error) {
	if cosign == "" {
		checksums := map[string]string{
			"darwin-arm64": "5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76",
			"darwin-amd64": "2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c",
			"linux-amd64":  "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
			"linux-arm64":  "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a",
		}
		target := platform + "-" + arch
		checksum := checksums[target]
		if checksum == "" {
			return nil, fmt.Errorf("no pinned Cosign verifier for %s", target)
		}
		cosign = filepath.Join(directory, "cosign-v3.1.3")
		asset := "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-" + target
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
		command := exec.CommandContext(ctx, cosign, "verify-blob", "--bundle", bundlePath,
			"--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
			manifestPath)
		command.Env = []string{"HOME=" + directory}
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Cosign: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}, nil
}
