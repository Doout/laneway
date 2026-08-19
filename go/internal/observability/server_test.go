package observability

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateListenAddress(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"127.0.0.1:0", "[::1]:6060", "localhost:6060"} {
		if err := ValidateListenAddress(valid); err != nil {
			t.Errorf("ValidateListenAddress(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.0.2.1:6060", "invalid"} {
		if err := ValidateListenAddress(invalid); err == nil {
			t.Errorf("ValidateListenAddress(%q) succeeded", invalid)
		}
	}
}

func TestMetricsAreSortedAndInvalidNamesAreExcluded(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	Handler(func() map[string]uint64 {
		return map[string]uint64{"packets_sent_total": 7, "connections": 2, "bad-name": 99}
	}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	want := "laneway_connections 2\nlaneway_packets_sent_total 7\n"
	if got := response.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("Content-Type = %q", contentType)
	}
}

func TestPprofUsesPrivateMux(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil)
	response := httptest.NewRecorder()
	Handler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "goroutine profile") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestStartDisabled(t *testing.T) {
	t.Parallel()
	done, err := Start(context.Background(), Config{})
	if err != nil || done != nil {
		t.Fatalf("Start disabled = (%v, %v)", done, err)
	}
}

func TestServeStopsWithContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	done, err := Start(ctx, Config{Listen: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("completion error = %v", err)
	}
}

func TestStartListenerUsesOnlyPreboundLoopbackSocket(t *testing.T) {
	t.Parallel()
	config := Config{Listen: "127.0.0.1:0"}
	listener, err := Listen(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, err := StartListener(ctx, listener, config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("completion error = %v", err)
	}

	wildcard, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wildcard.Close()
	if _, err := StartListener(context.Background(), wildcard, config); !errors.Is(err, ErrNonLoopbackAddress) {
		t.Fatalf("wildcard pre-bound listener error = %v", err)
	}
}
