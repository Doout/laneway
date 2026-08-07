package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneway.dev/laneway/internal/controllerservice"
)

func TestBearerAuthorizerFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorize, err := bearerAuthorizerFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://controller/v1/admin/enrollment-tokens", nil)
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("missing credential error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if err := authorize(request); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token+"x")
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestBearerAuthorizerRejectsWeakAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(weak); err == nil {
		t.Fatal("weak token accepted")
	}
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxAdminTokenFile+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(large); err == nil {
		t.Fatal("oversized token accepted")
	}
}
