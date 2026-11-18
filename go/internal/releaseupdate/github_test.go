package releaseupdate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const macAsset = "laneway_darwin_arm64.tar.gz"

func TestDownloadLatest(t *testing.T) {
	binary := []byte("verified laneway binary")
	digest := sha256.Sum256(binary)
	var server *httptest.Server
	var downloads atomic.Int32
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
			fmt.Fprintf(response, "%x  %s\n", digest, macAsset)
		case "/Doout/laneway/releases/download/v1.2.3/checksums.sigstore.json":
			fmt.Fprint(response, `{"signature":"fixture"}`)
		case "/Doout/laneway/releases/download/v1.2.3/" + macAsset:
			downloads.Add(1)
			_, _ = response.Write(binary)
		default:
			http.NotFound(response, request)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	client := &Client{baseURL: server.URL, repository: "Doout/laneway", httpClient: server.Client()}
	destination := filepath.Join(t.TempDir(), "laneway")
	invalidSignature := errors.New("signature rejected")
	_, err := client.DownloadLatest(context.Background(), macAsset, destination, 1024,
		func(context.Context, string, []byte, []byte) error { return invalidSignature })
	if !errors.Is(err, invalidSignature) || downloads.Load() != 0 {
		t.Fatalf("bad signature did not block the download: %v", err)
	}
	release, err := client.DownloadLatest(context.Background(), macAsset, destination, 1024, func(_ context.Context, identity string, manifest, bundle []byte) error {
		if identity != "https://github.com/Doout/laneway/.github/workflows/release.yml@refs/tags/v1.2.3" ||
			string(manifest) != fmt.Sprintf("%x  %s\n", digest, macAsset) || string(bundle) != `{"signature":"fixture"}` {
			return errors.New("incorrect pinned identity or signature inputs")
		}
		return nil
	})
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
			fmt.Fprintf(response, "%064d  %s\n", 0, macAsset)
		case "/Doout/laneway/releases/download/v1.2.3/checksums.sigstore.json":
			fmt.Fprint(response, `{"signature":"fixture"}`)
		case "/Doout/laneway/releases/download/v1.2.3/" + macAsset:
			_, _ = response.Write([]byte("different"))
		default:
			http.NotFound(response, request)
		}
	})
	server = httptest.NewTLSServer(handler)
	defer server.Close()
	client := &Client{baseURL: server.URL, repository: "Doout/laneway", httpClient: server.Client()}
	destination := filepath.Join(t.TempDir(), "laneway")
	_, err := client.DownloadLatest(context.Background(), macAsset, destination, 1024,
		func(context.Context, string, []byte, []byte) error { return nil })
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
