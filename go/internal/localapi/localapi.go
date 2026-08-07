// Package localapi implements the bounded Unix-socket API shared by lanewayd
// and the user-facing laneway command.
package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const MaxResponseBytes = 1 << 20

var ErrAlreadyRunning = errors.New("lanewayd local API is already running")

type Metrics struct {
	Connections     uint64 `json:"connections"`
	Reconnects      uint64 `json:"reconnects"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
	PacketsDropped  uint64 `json:"packets_dropped"`
	TCPConnections  uint64 `json:"tcp_connections"`
	QUICFailures    uint64 `json:"quic_failures"`
	TCPFailures     uint64 `json:"tcp_failures"`
}

type Status struct {
	Running        bool             `json:"running"`
	ProductVersion string           `json:"product_version"`
	ControlVersion string           `json:"control_version"`
	PacketVersion  uint8            `json:"packet_version"`
	Capabilities   string           `json:"capabilities"`
	SelectedPath   string           `json:"selected_path"`
	NetworkID      string           `json:"network_id"`
	NodeID         string           `json:"node_id"`
	Name           string           `json:"name"`
	Interface      string           `json:"interface"`
	Relay          string           `json:"relay"`
	MTU            int              `json:"mtu"`
	Metrics        Metrics          `json:"metrics"`
	Exit           ExitStatus       `json:"exit"`
	Controller     ControllerStatus `json:"controller"`
}

type ControllerStatus struct {
	CandidateExchangeEnabled         bool   `json:"candidate_exchange_enabled"`
	CertificatePresentedSerial       string `json:"certificate_presented_serial"`
	CertificateRenewalNeeded         bool   `json:"certificate_renewal_needed"`
	CertificateRenewAfterUnixSeconds uint64 `json:"certificate_renew_after_unix_seconds"`
	CertificateNotAfterUnixSeconds   uint64 `json:"certificate_not_after_unix_seconds"`
}

type ExitStatus struct {
	Enabled        bool   `json:"enabled"`
	SelectedNodeID string `json:"selected_node_id,omitempty"`
	Authorized     bool   `json:"authorized"`
}

type ExitSelection struct {
	Enabled        bool   `json:"enabled"`
	SelectedNodeID string `json:"selected_node_id,omitempty"`
}

type Peer struct {
	NodeID   string   `json:"node_id"`
	Name     string   `json:"name,omitempty"`
	Prefixes []string `json:"prefixes"`
	Path     string   `json:"path"`
}

type Route struct {
	Prefix  string `json:"prefix"`
	ViaNode string `json:"via_node"`
	Kind    string `json:"kind"`
}

type Snapshot func() (Status, []Peer, []Route)

type Server struct {
	SocketPath string
	Snapshot   Snapshot
	SetExit    func(context.Context, ExitSelection) error
}

func (s Server) Serve(ctx context.Context) error {
	if s.SocketPath == "" || s.Snapshot == nil {
		return errors.New("local API requires a socket path and snapshot callback")
	}
	if err := prepareSocket(s.SocketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", s.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on local API socket: %w", err)
	}
	owned, err := os.Lstat(s.SocketPath)
	if err != nil {
		listener.Close()
		return err
	}
	defer func() {
		_ = listener.Close()
		if current, statErr := os.Lstat(s.SocketPath); statErr == nil && os.SameFile(owned, current) {
			_ = os.Remove(s.SocketPath)
		}
	}()
	if err := os.Chmod(s.SocketPath, 0o600); err != nil {
		return fmt.Errorf("secure local API socket: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		status, _, _ := s.Snapshot()
		writeJSON(w, status)
	})
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, _ *http.Request) {
		_, peers, _ := s.Snapshot()
		writeJSON(w, peers)
	})
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, _ *http.Request) {
		_, _, routes := s.Snapshot()
		writeJSON(w, routes)
	})
	mux.HandleFunc("POST /v1/exit", func(w http.ResponseWriter, r *http.Request) {
		if s.SetExit == nil {
			http.Error(w, "exit selection is not configured", http.StatusNotImplemented)
			return
		}
		body := http.MaxBytesReader(w, r.Body, 4096)
		decoder := json.NewDecoder(body)
		decoder.DisallowUnknownFields()
		var selection ExitSelection
		if err := decoder.Decode(&selection); err != nil {
			http.Error(w, "invalid exit selection", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "invalid exit selection", http.StatusBadRequest)
			return
		}
		if err := s.SetExit(r.Context(), selection); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{
		Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		<-done
		return ctx.Err()
	}
}

func prepareSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket local API path %q", path)
	}
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		connection.Close()
		return ErrAlreadyRunning
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale local API socket: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
	}
}

type Client struct {
	http *http.Client
}

func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, errors.New("local API socket path is empty")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true, MaxIdleConns: 2, IdleConnTimeout: 15 * time.Second,
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: 5 * time.Second}}, nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var value Status
	err := c.get(ctx, "/v1/status", &value)
	return value, err
}

func (c *Client) Peers(ctx context.Context) ([]Peer, error) {
	var value []Peer
	err := c.get(ctx, "/v1/peers", &value)
	return value, err
}

func (c *Client) Routes(ctx context.Context) ([]Route, error) {
	var value []Route
	err := c.get(ctx, "/v1/routes", &value)
	return value, err
}

func (c *Client) SetExit(ctx context.Context, selection ExitSelection) error {
	payload, err := json.Marshal(selection)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://lanewayd/v1/exit", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact lanewayd: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("lanewayd returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) get(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://lanewayd"+path, nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("contact lanewayd: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("lanewayd returned %s", response.Status)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(contents) > MaxResponseBytes {
		return errors.New("lanewayd response is oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode lanewayd response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("lanewayd response is oversized or contains trailing data")
	}
	return nil
}
