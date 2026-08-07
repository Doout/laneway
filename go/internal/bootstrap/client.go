package bootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func DiscoveryURL(authority string) (string, error) {
	if !strings.Contains(authority, "://") {
		authority = "https://" + authority
	}
	parsed, err := httpsOrigin(authority)
	if err != nil {
		return "", fmt.Errorf("bootstrap: discovery authority: %w", err)
	}
	host := parsed.Hostname()
	if net.ParseIP(host) != nil {
		return "", errors.New("bootstrap: discovery requires a DNS name authenticated by public Web PKI")
	}
	if err := validateDNSName(strings.ToLower(strings.TrimSuffix(host, "."))); err != nil {
		return "", err
	}
	parsed.Path = WellKnownPath
	return parsed.String(), nil
}

func Fetch(ctx context.Context, authority string) (Metadata, error) {
	discoveryURL, err := DiscoveryURL(authority)
	if err != nil {
		return Metadata{}, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("bootstrap: redirects are not allowed")
		},
	}
	defer transport.CloseIdleConnections()
	return fetch(ctx, client, discoveryURL, time.Now().UTC())
}

func fetch(ctx context.Context, client *http.Client, discoveryURL string, now time.Time) (Metadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return Metadata{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Metadata{}, fmt.Errorf("bootstrap: fetch metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("bootstrap: metadata endpoint returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Metadata{}, errors.New("bootstrap: metadata response is not application/json")
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return Metadata{}, errors.New("bootstrap: metadata was not authenticated by Web PKI")
	}
	return Decode(response.Body, now)
}

func OriginHost(authority string) (string, error) {
	discoveryURL, err := DiscoveryURL(authority)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(discoveryURL)
	if err != nil {
		return "", err
	}
	return parsed.Hostname(), nil
}

// DownloadArtifact writes an authenticated release artifact without
// overwriting any existing path. It never extracts or executes the bytes.
func DownloadArtifact(ctx context.Context, artifact Artifact, destination string) error {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		DisableCompression:    true,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: safeArtifactRedirect}
	defer transport.CloseIdleConnections()
	return downloadArtifact(ctx, client, artifact, destination)
}

func safeArtifactRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 5 || request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
		return errors.New("bootstrap: unsafe or excessive artifact redirect")
	}
	return nil
}

func downloadArtifact(ctx context.Context, client *http.Client, artifact Artifact, destination string) (resultErr error) {
	artifactURL, err := url.Parse(artifact.URL)
	if err != nil || artifactURL.Scheme != "https" || artifactURL.Host == "" || artifactURL.User != nil || artifactURL.Fragment != "" {
		return errors.New("bootstrap: artifact URL must be authenticated HTTPS")
	}
	if destination == "" || filepath.Base(destination) == "." || filepath.Base(destination) == string(filepath.Separator) {
		return errors.New("bootstrap: artifact destination must name a file")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("bootstrap: artifact destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bootstrap: inspect artifact destination: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("bootstrap: download artifact: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return errors.New("bootstrap: artifact download was not a successful Web PKI authenticated response")
	}
	if response.ContentLength > artifact.SizeBytes {
		return errors.New("bootstrap: artifact response exceeds authenticated size")
	}
	parent := filepath.Dir(destination)
	temporary, err := os.CreateTemp(parent, ".laneway-artifact-*")
	if err != nil {
		return fmt.Errorf("bootstrap: create artifact temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, io.LimitReader(response.Body, artifact.SizeBytes+1)); err != nil {
		return fmt.Errorf("bootstrap: save artifact: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := VerifyArtifact(temporary, artifact); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Link provides portable no-replace publication. The temporary lives in
	// the same directory, so this cannot cross a filesystem boundary.
	if err := os.Link(temporaryPath, destination); err != nil {
		return fmt.Errorf("bootstrap: publish artifact without overwrite: %w", err)
	}
	return nil
}
