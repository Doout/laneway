package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/bootstrap"
)

type bootstrapSourceFixture struct {
	bundleID string
	bundle   []byte
	err      error
	calls    int
}

func (f *bootstrapSourceFixture) BootstrapMetadata(context.Context) ([]byte, error) {
	return []byte(`{"schema_version":1}`), f.err
}

func (f *bootstrapSourceFixture) BootstrapBundle(_ context.Context, id string) ([]byte, error) {
	f.bundleID = id
	f.calls++
	return append([]byte(nil), f.bundle...), f.err
}

func TestPublicBootstrapHandlerProxiesOnlyExactBundleCapabilities(t *testing.T) {
	id := strings.Repeat("A", bootstrap.BundleIDLength)
	source := &bootstrapSourceFixture{bundle: []byte("#!/bin/bash\necho encrypted\n")}
	handler := publicBootstrapHandlerFromSource(source, newPublicRateLimiter())

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, bootstrap.BundlePathPrefix+id, nil))
	if response.Code != http.StatusOK || response.Body.String() != string(source.bundle) || source.bundleID != id {
		t.Fatalf("bundle proxy status=%d id=%q body=%q", response.Code, source.bundleID, response.Body.String())
	}
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "text/x-shellscript") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bundle headers = %v", response.Header())
	}

	for _, path := range []string{bootstrap.BundlePathPrefix + strings.Repeat("A", bootstrap.BundleIDLength-1), "/unrelated"} {
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, path, nil))
		if result.Code != http.StatusNotFound {
			t.Fatalf("invalid path %q status=%d", path, result.Code)
		}
	}
	source.err = errors.New("used or expired")
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, bootstrap.BundlePathPrefix+id, nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing bundle status=%d", missing.Code)
	}
}

func TestPublicBootstrapHandlerWithoutControllerFailsClosed(t *testing.T) {
	id := strings.Repeat("A", bootstrap.BundleIDLength)
	response := httptest.NewRecorder()
	publicBootstrapHandler(nil, newPublicRateLimiter()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, bootstrap.BundlePathPrefix+id, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("controller-less bootstrap status=%d", response.Code)
	}
}

func TestPublicBootstrapBundleUsesRateLimiterBeforeController(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := newPublicRateLimiter()
	limiter.now = func() time.Time { return now }
	id := strings.Repeat("A", bootstrap.BundleIDLength)
	source := &bootstrapSourceFixture{bundle: []byte("#!/bin/bash\necho encrypted\n")}
	handler := publicBootstrapHandlerFromSource(source, limiter)

	request := func() *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		httpRequest := httptest.NewRequest(http.MethodGet, bootstrap.BundlePathPrefix+id, nil)
		httpRequest.RemoteAddr = "203.0.113.7:50000"
		handler.ServeHTTP(response, httpRequest)
		return response
	}
	for index := 0; index < 10; index++ {
		if response := request(); response.Code != http.StatusOK {
			t.Fatalf("bootstrap request %d status=%d", index+1, response.Code)
		}
	}
	limited := request()
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "1" {
		t.Fatalf("rate-limited response status=%d headers=%v", limited.Code, limited.Header())
	}
	if source.calls != 10 {
		t.Fatalf("controller fetches=%d, want 10", source.calls)
	}
}
