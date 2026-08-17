// Command laneway-docker-plugin exposes a local-scope Docker remote network
// driver over the managed-plugin Unix socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/buildinfo"
	"github.com/Doout/laneway/go/internal/dockerplugin"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "laneway-docker-plugin:", err)
		os.Exit(1)
	}
}

func run() error {
	var socket, state, authorization, tunnel string
	flag.StringVar(&socket, "socket", "/run/docker/plugins/laneway.sock", "Docker remote-driver Unix socket")
	flag.StringVar(&state, "state", "/var/lib/laneway-docker-plugin/state-v1.json", "persistent ownership state")
	flag.StringVar(&authorization, "authorization", "/var/lib/laneway-docker-plugin/controller-authorization-v1.json", "controller authorization snapshot")
	flag.StringVar(&tunnel, "tunnel-interface", "lane0", "Laneway tunnel interface")
	flag.Parse()
	store, err := dockerplugin.OpenStore(state)
	if err != nil {
		return err
	}
	backend, err := dockerplugin.NewLinuxBackend(dockerplugin.LinuxBackendConfig{TunnelInterface: tunnel})
	if err != nil {
		return err
	}
	driver, err := dockerplugin.NewDriver(dockerplugin.DriverOptions{Store: store, Backend: backend, Authorizations: dockerplugin.FileAuthorizationSource{Path: authorization}, Version: buildinfo.Version})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := driver.Reconcile(ctx); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %s", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0660); err != nil {
		return err
	}
	server := &http.Server{Handler: driver.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		return server.Shutdown(shutdownCtx)
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
