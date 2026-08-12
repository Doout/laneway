package controllerservice

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ConsoleHandler serves the administrator SPA beside the management API. API
// requests always remain owned by api; unknown browser routes fall back to the
// immutable index document so client-side routing works on reload.
func ConsoleHandler(api http.Handler, directory string) (http.Handler, error) {
	if api == nil {
		return nil, errors.New("console handler requires an API handler")
	}
	if !filepath.IsAbs(directory) {
		return nil, errors.New("console directory must be absolute")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open console directory: %w", err)
	}
	index, err := root.Open("index.html")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("open console index: %w", err)
	}
	info, err := index.Stat()
	index.Close()
	if err != nil || !info.Mode().IsRegular() {
		root.Close()
		return nil, errors.New("console index must be a regular file")
	}

	files := http.FileServerFS(root.FS())
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1" || strings.HasPrefix(request.URL.Path, "/v1/") || strings.HasPrefix(request.URL.Path, "/.well-known/") {
			api.ServeHTTP(writer, request)
			return
		}

		writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")

		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		name := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(request.URL.Path)), "/")
		if name != "." && name != "" && !strings.HasPrefix(name, ".") {
			if candidate, openErr := root.Open(name); openErr == nil {
				candidateInfo, statErr := candidate.Stat()
				candidate.Close()
				if statErr == nil && candidateInfo.Mode().IsRegular() {
					if strings.HasPrefix(name, "assets/") {
						writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					files.ServeHTTP(writer, request)
					return
				}
			}
		}

		writer.Header().Set("Cache-Control", "no-store")
		indexFile, openErr := root.Open("index.html")
		if openErr != nil {
			http.Error(writer, "console unavailable", http.StatusServiceUnavailable)
			return
		}
		defer indexFile.Close()
		http.ServeContent(writer, request, "index.html", info.ModTime(), indexFile)
	}), nil
}
