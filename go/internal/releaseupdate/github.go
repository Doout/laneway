// Package releaseupdate downloads checksum-verified client binaries from an
// immutable GitHub release.
package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const checksumManifestLimit = 1 << 20

var stableTagPattern = regexp.MustCompile("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")

type Client struct {
	baseURL        string
	repository     string
	httpClient     *http.Client
	locateVerifier func() (string, error)
}

type Release struct {
	Tag    string
	SHA256 string
}

// Asset identifies a release payload and its private staging destination.
type Asset struct {
	Name        string
	Destination string
	MaxBytes    int64
}

// DownloadLatestSigned resolves the tag once and authenticates its manifest
// before downloading any payload. The caller owns the staging directory.
func (c *Client) DownloadLatestSigned(ctx context.Context, assets ...Asset) (string, error) {
	return c.downloadLatestSigned(ctx, "", assets)
}

// StageLatestSigned retains the authenticated manifest and bundle alongside
// the downloaded assets for another local installer process to reverify.
func (c *Client) StageLatestSigned(ctx context.Context, stage string, assets ...Asset) (string, error) {
	if stage == "" {
		return "", errors.New("release update: staging directory is required")
	}
	return c.downloadLatestSigned(ctx, stage, assets)
}

func (c *Client) downloadLatestSigned(ctx context.Context, stage string, assets []Asset) (string, error) {
	if len(assets) == 0 {
		return "", errors.New("release update: no assets requested")
	}
	for _, asset := range assets {
		if !validAssetName(asset.Name) || asset.MaxBytes <= 0 {
			return "", errors.New("release update: invalid asset name or download limit")
		}
	}
	tag, err := c.latestTag(ctx)
	if err != nil {
		return "", err
	}
	manifest, err := c.downloadBytes(ctx, c.assetURL(tag, "checksums.txt"), checksumManifestLimit)
	if err != nil {
		return "", fmt.Errorf("release update: download checksum manifest: %w", err)
	}
	bundle, err := c.downloadBytes(ctx, c.assetURL(tag, "checksums.sigstore.json"), checksumManifestLimit)
	if err != nil {
		return "", fmt.Errorf("release update: download release signature: %w", err)
	}
	if err := c.verifySignature(ctx, tag, manifest, bundle); err != nil {
		return "", err
	}
	if stage != "" {
		for _, metadata := range []struct {
			name    string
			content []byte
		}{{"checksums.txt", manifest}, {"checksums.sigstore.json", bundle}} {
			file, err := os.OpenFile(filepath.Join(stage, metadata.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return "", err
			}
			_, writeErr := file.Write(metadata.content)
			if err := errors.Join(writeErr, file.Close()); err != nil {
				return "", err
			}
		}
	}
	for _, asset := range assets {
		if _, err := c.downloadVerifiedAsset(ctx, tag, manifest, asset); err != nil {
			return "", err
		}
	}
	return tag, nil
}

func (c *Client) verifySignature(ctx context.Context, tag string, manifest, bundle []byte) error {
	locate := c.locateVerifier
	if locate == nil {
		locate = cosignPath
	}
	verifier, err := locate()
	if err != nil {
		return fmt.Errorf("release update: cosign is required: %w", err)
	}
	tempBase := ""
	if os.Geteuid() == 0 {
		tempBase = "/tmp"
	}
	work, err := os.MkdirTemp(tempBase, "laneway-update-signature-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	manifestPath := filepath.Join(work, "checksums.txt")
	bundlePath := filepath.Join(work, "checksums.sigstore.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}
	verify := exec.CommandContext(ctx, verifier, "verify-blob", "--bundle", bundlePath,
		"--certificate-identity", "https://github.com/"+c.repository+"/.github/workflows/release.yml@refs/tags/"+tag,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", manifestPath)
	if verify.Err != nil {
		return fmt.Errorf("release update: cosign is required: %w", verify.Err)
	}
	verify.Env = []string{}
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		name = strings.ToUpper(name)
		if os.Geteuid() == 0 &&
			(name == "HOME" || name == "XDG_CACHE_HOME" || name == "XDG_CONFIG_HOME" || name == "TMPDIR" || name == "PATH") {
			continue
		}
		if !strings.HasPrefix(name, "COSIGN_") && !strings.HasPrefix(name, "SIGSTORE_") &&
			!strings.HasPrefix(name, "TUF_") {
			verify.Env = append(verify.Env, variable)
		}
	}
	if os.Geteuid() == 0 {
		verify.Env = append(verify.Env, "HOME="+work, "XDG_CACHE_HOME="+work, "XDG_CONFIG_HOME="+work, "TMPDIR="+work,
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin")
	}
	if output, err := verify.CombinedOutput(); err != nil {
		return fmt.Errorf("release update: release signature verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func NewGitHubClient(repository string) *Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableCompression:    true,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	return &Client{
		baseURL:    "https://github.com",
		repository: repository,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 5 || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
					return errors.New("release update: unsafe or excessive redirect")
				}
				return nil
			},
		},
	}
}

func (c *Client) Close() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *Client) DownloadLatest(ctx context.Context, asset, destination string, maxBytes int64) (Release, error) {
	if !validAssetName(asset) {
		return Release{}, errors.New("release update: invalid asset name")
	}
	if maxBytes <= 0 {
		return Release{}, errors.New("release update: invalid download limit")
	}
	tag, err := c.latestTag(ctx)
	if err != nil {
		return Release{}, err
	}
	manifest, err := c.downloadBytes(ctx, c.assetURL(tag, "checksums.txt"), checksumManifestLimit)
	if err != nil {
		return Release{}, fmt.Errorf("release update: download checksum manifest: %w", err)
	}
	return c.downloadVerifiedAsset(ctx, tag, manifest, Asset{Name: asset, Destination: destination, MaxBytes: maxBytes})
}

func (c *Client) downloadVerifiedAsset(ctx context.Context, tag string, manifest []byte, asset Asset) (Release, error) {
	expected, err := checksumForAsset(manifest, asset.Name)
	if err != nil {
		return Release{}, err
	}
	actual, err := c.downloadFile(ctx, c.assetURL(tag, asset.Name), asset.Destination, asset.MaxBytes)
	if err != nil {
		return Release{}, fmt.Errorf("release update: download %s: %w", asset.Name, err)
	}
	if !bytes.Equal(actual, expected) {
		_ = os.Remove(asset.Destination)
		return Release{}, errors.New("release update: downloaded client failed checksum verification")
	}
	return Release{Tag: tag, SHA256: hex.EncodeToString(actual)}, nil
}

func (c *Client) latestTag(ctx context.Context) (string, error) {
	latestURL := strings.TrimRight(c.baseURL, "/") + "/" + c.repository + "/releases/latest" +
		"?laneway_cache_bust=" + fmt.Sprint(time.Now().UnixNano())
	response, err := c.get(ctx, latestURL, "text/html")
	if err != nil {
		return "", fmt.Errorf("release update: resolve latest release: %w", err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
		return "", fmt.Errorf("release update: read latest release response: %w", err)
	}
	prefix := strings.TrimRight(c.baseURL, "/") + "/" + c.repository + "/releases/tag/"
	finalURL := response.Request.URL.String()
	if !strings.HasPrefix(finalURL, prefix) {
		return "", errors.New("release update: latest release redirected to an unexpected URL")
	}
	tag := strings.TrimPrefix(finalURL, prefix)
	if !stableTagPattern.MatchString(tag) {
		return "", errors.New("release update: latest release is not a stable semantic tag")
	}
	return tag, nil
}

func (c *Client) assetURL(tag, asset string) string {
	return strings.TrimRight(c.baseURL, "/") + "/" + c.repository + "/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(asset)
}

func (c *Client) downloadBytes(ctx context.Context, address string, limit int64) ([]byte, error) {
	response, err := c.get(ctx, address, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return nil, errors.New("response exceeds size limit")
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, errors.New("response exceeds size limit")
	}
	return contents, nil
}

func (c *Client) downloadFile(ctx context.Context, address, destination string, limit int64) (digest []byte, resultErr error) {
	if destination == "" || path.Base(destination) == "." || path.Base(destination) == "/" {
		return nil, errors.New("destination must name a file")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := output.Close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(destination)
		}
	}()
	response, err := c.get(ctx, address, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > limit {
		return nil, errors.New("response exceeds size limit")
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if written > limit {
		return nil, errors.New("response exceeds size limit")
	}
	if err := output.Sync(); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (c *Client) get(ctx context.Context, address, accept string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Pragma", "no-cache")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		response.Body.Close()
		return nil, errors.New("response was not a successful Web PKI authenticated download")
	}
	return response, nil
}

func checksumForAsset(manifest []byte, asset string) ([]byte, error) {
	var selected string
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			if selected != "" {
				return nil, fmt.Errorf("release update: checksum manifest contains duplicate %s entries", asset)
			}
			selected = fields[0]
		}
	}
	digest, err := hex.DecodeString(selected)
	if selected == "" || err != nil || len(digest) != sha256.Size || selected != strings.ToLower(selected) {
		return nil, fmt.Errorf("release update: checksum manifest has no canonical SHA-256 for %s", asset)
	}
	return digest, nil
}

func validAssetName(value string) bool {
	return value != "" && value == path.Base(value) && value != "." && !strings.Contains(value, "/") && !strings.Contains(value, "\\")
}
