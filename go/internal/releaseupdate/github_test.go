package releaseupdate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloadLatest(t *testing.T) {
	binary := []byte("verified laneway binary")
	digest := sha256.Sum256(binary)
	var server *httptest.Server
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/Doout/laneway/releases/latest":
			if request.Header.Get("Cache-Control") != "no-cache" || request.Header.Get("Pragma") != "no-cache" {
				t.Errorf("latest release request permits cached response")
			}
			if request.URL.Query().Get("laneway_cache_bust") == "" {
				t.Error("latest release request does not bypass a cached redirect")
			}
			http.Redirect(response, request, server.URL+"/Doout/laneway/releases/tag/v1.2.3", http.StatusFound)
		case "/Doout/laneway/releases/tag/v1.2.3":
			response.WriteHeader(http.StatusOK)
		case "/Doout/laneway/releases/download/v1.2.3/checksums.txt":
			fmt.Fprintf(response, "%x  laneway_darwin_arm64\n", digest)
		case "/Doout/laneway/releases/download/v1.2.3/laneway_darwin_arm64":
			_, _ = response.Write(binary)
		default:
			http.NotFound(response, request)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	client := &Client{baseURL: server.URL, repository: "Doout/laneway", httpClient: server.Client()}
	destination := filepath.Join(t.TempDir(), "laneway")
	release, err := client.DownloadLatest(context.Background(), "laneway_darwin_arm64", destination, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v1.2.3" || release.SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("release = %+v", release)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(binary) {
		t.Fatalf("downloaded contents = %q", contents)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("downloaded mode = %o, want 700", info.Mode().Perm())
	}
}

func TestDownloadLatestRemovesChecksumMismatch(t *testing.T) {
	var server *httptest.Server
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/Doout/laneway/releases/latest":
			http.Redirect(response, request, server.URL+"/Doout/laneway/releases/tag/v1.2.3", http.StatusFound)
		case "/Doout/laneway/releases/tag/v1.2.3":
			response.WriteHeader(http.StatusOK)
		case "/Doout/laneway/releases/download/v1.2.3/checksums.txt":
			fmt.Fprintf(response, "%064d  laneway_darwin_arm64\n", 0)
		case "/Doout/laneway/releases/download/v1.2.3/laneway_darwin_arm64":
			_, _ = response.Write([]byte("different"))
		default:
			http.NotFound(response, request)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	client := &Client{baseURL: server.URL, repository: "Doout/laneway", httpClient: server.Client()}
	destination := filepath.Join(t.TempDir(), "laneway")
	_, err := client.DownloadLatest(context.Background(), "laneway_darwin_arm64", destination, 1024)
	if err == nil || !strings.Contains(err.Error(), "failed checksum verification") {
		t.Fatalf("DownloadLatest error = %v", err)
	}
	if _, statErr := os.Stat(destination); !os.IsNotExist(statErr) {
		t.Fatalf("checksum-mismatched destination still exists: %v", statErr)
	}
}

func TestChecksumForAssetRejectsDuplicate(t *testing.T) {
	manifest := []byte(strings.Repeat("a", 64) + "  client\n" + strings.Repeat("b", 64) + "  client\n")
	_, err := checksumForAsset(manifest, "client")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("checksumForAsset error = %v", err)
	}
}

func TestDownloadLatestSignedPair(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell verifier fixture")
	}
	cli := []byte("Go CLI")
	node := []byte("Rust daemon")
	bin := t.TempDir()
	verifier := `#!/bin/sh
set -eu
[ "$#" -eq 8 ]
[ "$1" = verify-blob ] && [ "$2" = --bundle ]
[ "$(cat "$3")" = detached-bundle ]
[ "$4" = --certificate-identity ]
[ "$5" = https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v1.2.3 ]
[ "$6" = --certificate-oidc-issuer ] && [ "$7" = https://token.actions.githubusercontent.com ]
[ -z "${COSIGN_INSECURE_IGNORE_TLOG+x}" ] && [ -z "${Cosign_fixture_override+x}" ]
grep -F 'lanewayd_linux_arm64' "$8" >/dev/null
[ "${VERIFY_FAILURE:-0}" = 0 ]
`
	if err := os.WriteFile(filepath.Join(bin, "cosign"), []byte(verifier), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("COSIGN_INSECURE_IGNORE_TLOG", "true")
	t.Setenv("Cosign_fixture_override", "true")

	for _, test := range []struct {
		name, signFailure, wantError string
		tamper, retain               bool
	}{
		{name: "verified"},
		{name: "staged signed metadata", retain: true},
		{name: "untrusted metadata not staged", retain: true, signFailure: "1", wantError: "signature verification failed"},
		{name: "signature rejected", signFailure: "1", wantError: "signature verification failed"},
		{name: "daemon content rejected", tamper: true, wantError: "failed checksum verification"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("VERIFY_FAILURE", test.signFailure)
			if test.signFailure == "" {
				t.Setenv("VERIFY_FAILURE", "0")
			}
			var latest atomic.Int32
			var downloads atomic.Int32
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/Doout/laneway/releases/latest":
					latest.Add(1)
					http.Redirect(response, request, server.URL+"/Doout/laneway/releases/tag/v1.2.3", http.StatusFound)
				case "/Doout/laneway/releases/tag/v1.2.3":
					response.WriteHeader(http.StatusOK)
				case "/Doout/laneway/releases/download/v1.2.3/checksums.txt":
					fmt.Fprintf(response, "%x  laneway_linux_arm64\n%x  lanewayd_linux_arm64\n", sha256.Sum256(cli), sha256.Sum256(node))
				case "/Doout/laneway/releases/download/v1.2.3/checksums.sigstore.json":
					_, _ = response.Write([]byte("detached-bundle"))
				case "/Doout/laneway/releases/download/v1.2.3/laneway_linux_arm64":
					downloads.Add(1)
					_, _ = response.Write(cli)
				case "/Doout/laneway/releases/download/v1.2.3/lanewayd_linux_arm64":
					downloads.Add(1)
					if test.tamper {
						_, _ = response.Write([]byte("unexpected content"))
					} else {
						_, _ = response.Write(node)
					}
				default:
					http.NotFound(response, request)
				}
			}))
			defer server.Close()
			client := &Client{baseURL: server.URL, repository: "Doout/laneway", httpClient: server.Client(),
				locateVerifier: func() (string, error) { return filepath.Join(bin, "cosign"), nil }}
			work := t.TempDir()
			assets := []Asset{
				{Name: "laneway_linux_arm64", Destination: filepath.Join(work, "laneway"), MaxBytes: 1024},
				{Name: "lanewayd_linux_arm64", Destination: filepath.Join(work, "lanewayd"), MaxBytes: 1024},
			}
			var tag string
			var err error
			if test.retain {
				tag, err = client.StageLatestSigned(context.Background(), work, assets...)
			} else {
				tag, err = client.DownloadLatestSigned(context.Background(), assets...)
			}
			if latest.Load() != 1 {
				t.Fatalf("resolved latest %d times", latest.Load())
			}
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("expected %q, got %v", test.wantError, err)
				}
				if _, statErr := os.Stat(assets[1].Destination); !os.IsNotExist(statErr) {
					t.Fatalf("unverified daemon was staged: %v", statErr)
				}
				if test.signFailure != "" {
					if downloads.Load() != 0 {
						t.Fatal("downloaded an asset before verifying its manifest")
					}
					if _, statErr := os.Stat(filepath.Join(work, "checksums.sigstore.json")); !os.IsNotExist(statErr) {
						t.Fatalf("staged an untrusted signature: %v", statErr)
					}
				}
				return
			}
			if err != nil || tag != "v1.2.3" || downloads.Load() != 2 {
				t.Fatalf("update downloads = %d, tag = %q, error = %v", downloads.Load(), tag, err)
			}
			if test.retain {
				bundle, err := os.ReadFile(filepath.Join(work, "checksums.sigstore.json"))
				if err != nil || string(bundle) != "detached-bundle" {
					t.Fatalf("staged bundle = %q, %v", bundle, err)
				}
				manifest, err := os.ReadFile(filepath.Join(work, "checksums.txt"))
				expected := fmt.Sprintf("%x  laneway_linux_arm64\n%x  lanewayd_linux_arm64\n", sha256.Sum256(cli), sha256.Sum256(node))
				if err != nil || string(manifest) != expected {
					t.Fatalf("staged manifest = %q, %v", manifest, err)
				}
			}
			for index, expected := range [][]byte{cli, node} {
				contents, err := os.ReadFile(assets[index].Destination)
				if err != nil || string(contents) != string(expected) {
					t.Fatalf("staged %s = %q, %v", assets[index].Name, contents, err)
				}
			}
		})
	}
}
