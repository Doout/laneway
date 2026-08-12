package controllerservice

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleHandlerServesAssetsSPAFallbackAndAPI(t *testing.T) {
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
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	})
	handler, err := ConsoleHandler(api, directory)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		path, contains, cache string
	}{
		{"/nodes/atlas-gateway", "console", "no-store"},
		{"/assets/app.js", "ready", "immutable"},
		{"/v1/health", `"ok":true`, ""},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if test.cache != "" && !strings.Contains(response.Header().Get("Cache-Control"), test.cache) {
				t.Fatalf("cache=%q", response.Header().Get("Cache-Control"))
			}
			if !strings.HasPrefix(test.path, "/v1/") && response.Header().Get("Content-Security-Policy") == "" {
				t.Fatal("missing content security policy")
			}
		})
	}
}

func TestConsoleHandlerRejectsUnsafeSetupAndMutationRoutes(t *testing.T) {
	if _, err := ConsoleHandler(http.NotFoundHandler(), "relative"); err == nil {
		t.Fatal("relative console directory accepted")
	}
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
}
