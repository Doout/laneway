//go:build rustinterop

package controllerservice

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func rustConsoleDir(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("LANEWAY_RUST_CONSOLE_ASSETS"); path != "" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			t.Fatal(err)
		}
		return absolute
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"index.html":         `<!doctype html><title>Laneway</title><script type="module" src="/assets/app-abc.js"></script><link rel="stylesheet" href="/assets/app-abc.css"><div id="root"></div>`,
		"assets/app-abc.js":  `document.getElementById('root').textContent = 'Laneway';`,
		"assets/app-abc.css": `#root { color: black; }`,
		"laneway-mark.svg":   `<svg xmlns="http://www.w3.org/2000/svg"></svg>`,
		"site.webmanifest":   `{"name":"Laneway"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var consoleAssetLinks = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)

func testRustConsole(t *testing.T, client *http.Client, base, host string) {
	t.Helper()
	type result struct {
		header http.Header
		body   string
	}
	request := func(method, path, etag string, want int) result {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
		if err != nil || resp.StatusCode != want || len(data) > 8*1024*1024 {
			t.Fatalf("%s %s: console status %d, want %d: %v", method, path, resp.StatusCode, want, err)
		}
		return result{header: resp.Header, body: string(data)}
	}
	index := request("GET", "/overview", "", 200)
	deep := request("GET", "/networks/nodes/selected?show=info", "", 200)
	if index.body != deep.body || !strings.Contains(index.body, "<title>Laneway</title>") ||
		index.header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(index.header.Get("Content-Type"), "text/html") {
		t.Fatal("console navigation did not return the non-cacheable Laneway HTML shell")
	}
	for name, value := range consoleSecurityHeaders {
		if index.header.Get(name) != value {
			t.Fatalf("console lost %s", name)
		}
	}
	links := consoleAssetLinks.FindAllStringSubmatch(index.body, -1)
	seen := map[string]bool{}
	for _, link := range links {
		path := link[1]
		result := request("GET", path, "", 200)
		etag := result.header.Get("ETag")
		if len(result.body) == 0 || etag == "" ||
			result.header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatal("bundled console asset is not immutable")
		}
		if strings.HasSuffix(path, ".js") {
			seen["js"] = strings.HasPrefix(result.header.Get("Content-Type"), "text/javascript")
		} else if strings.HasSuffix(path, ".css") {
			seen["css"] = strings.HasPrefix(result.header.Get("Content-Type"), "text/css")
		}
		head := request("HEAD", path, "", 200)
		if head.body != "" || head.header.Get("Content-Length") != strconv.Itoa(len(result.body)) {
			t.Fatal("console asset HEAD lost the GET representation size")
		}
		revalidated := request("GET", path, "W/"+etag, 304)
		if revalidated.body != "" || revalidated.header.Get("ETag") != etag {
			t.Fatal("console asset did not revalidate without a body")
		}
	}
	if !seen["js"] || !seen["css"] {
		t.Fatal("console HTML did not link the actual JS and CSS bundles")
	}
	if icon := request("GET", "/laneway-mark.svg", "", 200); !strings.HasPrefix(icon.body, "<svg") ||
		icon.header.Get("Content-Type") != "image/svg+xml" || icon.header.Get("Cache-Control") != "no-cache" {
		t.Fatal("console did not serve a revalidatable Laneway favicon")
	}
	if manifest := request("GET", "/site.webmanifest", "", 200); manifest.header.Get("Content-Type") != "application/manifest+json" {
		t.Fatal("console web manifest is not installable")
	}
	request("GET", "/assets/obsolete.js", "", 404)
	request("GET", "/assets/%2e%2e/index.html", "", 404)
	if mutation := request("POST", "/overview", "", 405); mutation.header.Get("Allow") != "GET, HEAD" {
		t.Fatal("non-read console request did not report supported methods")
	}
	for _, path := range []string{"/v1/admin/unrecognized", "/oauth/unrecognized", "/.well-known/unrecognized"} {
		unknown := request("GET", path, "", 404)
		if strings.Contains(unknown.body, "<title>Laneway</title>") {
			t.Fatal("reserved API namespace served the console HTML shell")
		}
	}
}
