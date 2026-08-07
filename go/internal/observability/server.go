// Package observability provides an opt-in, loopback-only diagnostics server
// for Laneway processes.
package observability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sort"
	"strings"
	"time"
)

const (
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultIdleTimeout       = 30 * time.Second
)

var ErrNonLoopbackAddress = errors.New("observability: listen address must be loopback-only")

// Snapshot returns monotonically increasing process counters. Metric names
// must contain only lower-case ASCII letters, digits, and underscores.
type Snapshot func() map[string]uint64

// Config controls the diagnostics listener. The listener deliberately has no
// remote mode: operators can use an authenticated local tunnel when needed.
type Config struct {
	Listen            string
	Snapshot          Snapshot
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
}

// Serve runs metrics and Go pprof handlers until ctx is cancelled.
func Serve(ctx context.Context, config Config) error {
	done, err := Start(ctx, config)
	if err != nil {
		return err
	}
	if done == nil {
		return nil
	}
	return <-done
}

// Start binds the diagnostics listener synchronously and returns its completion
// channel. A nil channel means diagnostics are disabled.
func Start(ctx context.Context, config Config) (<-chan error, error) {
	if config.Listen == "" {
		return nil, nil
	}
	if err := ValidateListenAddress(config.Listen); err != nil {
		return nil, err
	}
	if config.ReadHeaderTimeout == 0 {
		config.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = DefaultIdleTimeout
	}
	if config.ReadHeaderTimeout <= 0 || config.IdleTimeout <= 0 {
		return nil, errors.New("observability: HTTP timeouts must be positive")
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, fmt.Errorf("observability: listen: %w", err)
	}
	server := &http.Server{
		Handler:           Handler(config.Snapshot),
		ReadHeaderTimeout: config.ReadHeaderTimeout,
		IdleTimeout:       config.IdleTimeout,
		MaxHeaderBytes:    8 << 10,
	}
	serveDone := make(chan error, 1)
	done := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	go func() {
		defer close(done)
		select {
		case err := <-serveDone:
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			done <- err
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownContext); err != nil {
				done <- fmt.Errorf("observability: shutdown: %w", err)
				return
			}
			err := <-serveDone
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				done <- err
				return
			}
			done <- ctx.Err()
		}
	}()
	return done, nil
}

// ValidateListenAddress rejects wildcard, unspecified, and non-loopback binds.
func ValidateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonLoopbackAddress, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrNonLoopbackAddress
	}
	return nil
}

// Handler returns an isolated mux rather than mutating http.DefaultServeMux.
func Handler(snapshot Snapshot) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		metrics := map[string]uint64{}
		if snapshot != nil {
			metrics = snapshot()
		}
		names := make([]string, 0, len(metrics))
		for name := range metrics {
			if validMetricName(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			_, _ = fmt.Fprintf(writer, "laneway_%s %d\n", name, metrics[name])
		}
	})
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("POST /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	for _, name := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
		mux.Handle("GET /debug/pprof/"+name, pprof.Handler(name))
	}
	return mux
}

func validMetricName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
