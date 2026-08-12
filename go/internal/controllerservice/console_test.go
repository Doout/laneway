package controllerservice

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var consoleSecurityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
	"Permissions-Policy":      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	"Referrer-Policy":         "no-referrer",
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
}

func newConsoleHandler(t *testing.T, api http.Handler) http.Handler {
	t.Helper()
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("<main>console</main>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "assets", "app.js"), []byte("console.log('ready')"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := ConsoleHandler(api, directory)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func assertConsoleSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for name, want := range consoleSecurityHeaders {
		if got := response.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestConsoleHandlerServesAssetsAndSPAFallback(t *testing.T) {
	handler := newConsoleHandler(t, http.NotFoundHandler())

	for _, test := range []struct {
		path, contains, cache string
	}{
		{"/nodes/atlas-gateway", "console", "no-store"},
		{"/assets/app.js", "ready", "public, max-age=31536000, immutable"},
		{"/v1ish/health", "console", "no-store"},
		{"/.well-knownish/metadata", "console", "no-store"},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != test.cache {
				t.Fatalf("Cache-Control = %q, want %q", got, test.cache)
			}
			assertConsoleSecurityHeaders(t, response)
		})
	}
}

func TestConsoleHandlerDelegatesReservedRoutesWithoutSPAFallback(t *testing.T) {
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Laneway-Handler", "api")
		writer.WriteHeader(http.StatusTeapot)
		_, _ = writer.Write([]byte(request.Method + " " + request.URL.Path))
	})
	handler := newConsoleHandler(t, api)

	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1"},
		{http.MethodPost, "/v1/networks"},
		{http.MethodGet, "/.well-known/laneway/bootstrap.json"},
		{http.MethodPost, "/.well-known/laneway/bootstrap/token"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusTeapot)
			}
			if got, want := response.Body.String(), test.method+" "+test.path; got != want {
				t.Fatalf("body = %q, want %q", got, want)
			}
			if got := response.Header().Get("X-Laneway-Handler"); got != "api" {
				t.Fatalf("X-Laneway-Handler = %q, want api", got)
			}
			if strings.Contains(response.Body.String(), "console") {
				t.Fatalf("reserved route fell back to the SPA: %q", response.Body.String())
			}
			for name := range consoleSecurityHeaders {
				if got := response.Header().Get(name); got != "" {
					t.Errorf("delegated response unexpectedly has %s = %q", name, got)
				}
			}
		})
	}
}

func TestConsoleHandlerRejectsUnsafeSetup(t *testing.T) {
	if _, err := ConsoleHandler(nil, t.TempDir()); err == nil {
		t.Fatal("nil API handler accepted")
	}
	if _, err := ConsoleHandler(http.NotFoundHandler(), "relative"); err == nil {
		t.Fatal("relative console directory accepted")
	}
	if _, err := ConsoleHandler(http.NotFoundHandler(), t.TempDir()); err == nil {
		t.Fatal("console directory without index accepted")
	}
}

func TestConsoleHandlerRejectsConsoleMutation(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("console"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := ConsoleHandler(http.NotFoundHandler(), directory)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/overview", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.Code)
	}
	if got := response.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want %q", got, "GET, HEAD")
	}
	if strings.Contains(response.Body.String(), "console") {
		t.Fatalf("mutation fell back to the SPA: %q", response.Body.String())
	}
	assertConsoleSecurityHeaders(t, response)
}
