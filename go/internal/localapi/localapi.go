// Package localapi implements the bounded Unix-socket API shared by lanewayd
// and the user-facing laneway command.
package localapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	MaxResponseBytes    = 1 << 20
	maxRequestBodyBytes = 4 << 10
	maxErrorDetailBytes = 2 << 10
	maxErrorBodyBytes   = 4 << 10

	// APIRevision identifies the additive response schema served under /v1.
	// It is not a status generation or a product build number.
	APIRevision uint32 = 1

	RequestIDHeader = "X-Laneway-Request-ID"

	ErrorCodeInvalidRequest       = "invalid_request"
	ErrorCodeNotFound             = "not_found"
	ErrorCodeMethodNotAllowed     = "method_not_allowed"
	ErrorCodeConflict             = "conflict"
	ErrorCodeUnsupportedOperation = "unsupported_operation"
	ErrorCodeBusy                 = "busy"
	ErrorCodeInternal             = "internal"
)

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
	DaemonInstanceID string           `json:"daemon_instance_id"`
	APIRevision      uint32           `json:"api_revision"`
	Running          bool             `json:"running"`
	Actor            string           `json:"actor"`
	ProductVersion   string           `json:"product_version"`
	ControlVersion   string           `json:"control_version"`
	PacketVersion    uint8            `json:"packet_version"`
	Capabilities     string           `json:"capabilities"`
	SelectedPath     string           `json:"selected_path"`
	NetworkID        string           `json:"network_id"`
	NodeID           string           `json:"node_id"`
	Name             string           `json:"name"`
	OverlayAddresses []string         `json:"overlay_addresses"`
	SelectedRoutes   []string         `json:"selected_routes"`
	Interface        string           `json:"interface"`
	Relay            string           `json:"relay"`
	MTU              int              `json:"mtu"`
	Metrics          Metrics          `json:"metrics"`
	Exit             ExitStatus       `json:"exit"`
	Controller       ControllerStatus `json:"controller"`
}

type ControllerStatus struct {
	CandidateExchangeEnabled                bool   `json:"candidate_exchange_enabled"`
	CertificatePresentedSerial              string `json:"certificate_presented_serial"`
	CertificateRenewalNeeded                bool   `json:"certificate_renewal_needed"`
	CertificateRenewAfterUnixSeconds        uint64 `json:"certificate_renew_after_unix_seconds"`
	CertificateNotAfterUnixSeconds          uint64 `json:"certificate_not_after_unix_seconds"`
	IdentityLeaseExpiresAtUnixSeconds       uint64 `json:"identity_lease_expires_at_unix_seconds"`
	ConfigurationLeaseValidUntilUnixSeconds uint64 `json:"configuration_lease_valid_until_unix_seconds"`
	ConfigurationLeaseExpired               bool   `json:"configuration_lease_expired"`
}

type ExitStatus struct {
	Enabled                  bool   `json:"enabled"`
	SelectedNodeID           string `json:"selected_node_id,omitempty"`
	Authorized               bool   `json:"authorized"`
	Serving                  bool   `json:"serving"`
	ForwardingReady          bool   `json:"forwarding_ready"`
	NATReady                 bool   `json:"nat_ready"`
	ForwardedPackets         uint64 `json:"forwarded_packets"`
	NamespaceCleanupFailures uint64 `json:"namespace_cleanup_failures"`
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

// APIError is the stable machine-readable error returned by the local API.
// Callers may inspect Code and Retryable; Detail is intended for people and is
// not a compatibility boundary.
type APIError struct {
	StatusCode int    `json:"-"`
	RequestID  string `json:"request_id"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	Retryable  bool   `json:"retryable"`
}

func (e *APIError) Error() string {
	if e == nil {
		return "lanewayd returned an error"
	}
	status := http.StatusText(e.StatusCode)
	if status == "" {
		status = fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	if e.RequestID != "" {
		return fmt.Sprintf("lanewayd returned %s (%s, request %s): %s", status, e.Code, e.RequestID, e.Detail)
	}
	return fmt.Sprintf("lanewayd returned %s (%s): %s", status, e.Code, e.Detail)
}

type requestIDs struct {
	prefix string
	next   atomic.Uint64
}

func (g *requestIDs) New() string {
	return fmt.Sprintf("%s%016x", g.prefix, g.next.Add(1))
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
	instanceID, err := newOpaqueID()
	if err != nil {
		return fmt.Errorf("generate local API daemon instance ID: %w", err)
	}
	requestIDSource := &requestIDs{prefix: instanceID[:16]}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveRequest(w, r, instanceID)
	})
	server := &http.Server{
		Handler: localAPIContract(handler, requestIDSource), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
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

func (s Server) serveRequest(w http.ResponseWriter, r *http.Request, instanceID string) {
	path := r.RequestURI
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
		writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid local API request", false)
		return
	}
	if len(r.TransferEncoding) != 0 {
		writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid local API request", false)
		return
	}
	if r.ContentLength > maxRequestBodyBytes {
		writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid local API request", false)
		return
	}
	if r.Method == http.MethodGet && r.ContentLength != 0 {
		writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid local API request", false)
		return
	}
	switch path {
	case "/v1/status":
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, ErrorCodeMethodNotAllowed, "method not allowed", false)
			return
		}
		status, _, _ := s.Snapshot()
		status.DaemonInstanceID = instanceID
		status.APIRevision = APIRevision
		writeJSON(w, normalizeStatus(status))
	case "/v1/peers":
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, ErrorCodeMethodNotAllowed, "method not allowed", false)
			return
		}
		_, peers, _ := s.Snapshot()
		writeJSON(w, normalizePeers(peers))
	case "/v1/routes":
		if r.Method != http.MethodGet {
			writeAPIError(w, http.StatusMethodNotAllowed, ErrorCodeMethodNotAllowed, "method not allowed", false)
			return
		}
		_, _, routes := s.Snapshot()
		writeJSON(w, normalizeRoutes(routes))
	case "/v1/exit":
		if r.Method != http.MethodPost {
			writeAPIError(w, http.StatusMethodNotAllowed, ErrorCodeMethodNotAllowed, "method not allowed", false)
			return
		}
		if s.SetExit == nil {
			writeAPIError(w, http.StatusNotImplemented, ErrorCodeUnsupportedOperation, "exit selection is not configured", false)
			return
		}
		body := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		contents, err := io.ReadAll(body)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid exit selection", false)
			return
		}
		selection, err := decodeExitSelection(contents)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, "invalid exit selection", false)
			return
		}
		if err := s.SetExit(r.Context(), selection); err != nil {
			writeAPIError(w, http.StatusConflict, ErrorCodeConflict, err.Error(), false)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeAPIError(w, http.StatusNotFound, ErrorCodeNotFound, "local API route not found", false)
	}
}

func decodeExitSelection(contents []byte) (ExitSelection, error) {
	if !utf8.Valid(contents) {
		return ExitSelection{}, errors.New("exit selection must be UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return ExitSelection{}, errors.New("exit selection must be an object")
	}
	var selection ExitSelection
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		rawKey, err := decoder.Token()
		if err != nil {
			return ExitSelection{}, errors.New("invalid exit selection key")
		}
		key, ok := rawKey.(string)
		if !ok {
			return ExitSelection{}, errors.New("invalid exit selection key")
		}
		if _, duplicate := seen[key]; duplicate {
			return ExitSelection{}, fmt.Errorf("duplicate exit selection field %q", key)
		}
		seen[key] = struct{}{}
		value, err := decoder.Token()
		if err != nil {
			return ExitSelection{}, fmt.Errorf("invalid exit selection field %q", key)
		}
		switch key {
		case "enabled":
			enabled, ok := value.(bool)
			if !ok {
				return ExitSelection{}, errors.New("exit selection enabled must be a boolean")
			}
			selection.Enabled = enabled
		case "selected_node_id":
			nodeID, ok := value.(string)
			if !ok {
				return ExitSelection{}, errors.New("exit selection selected_node_id must be a string")
			}
			selection.SelectedNodeID = nodeID
		default:
			return ExitSelection{}, fmt.Errorf("unknown exit selection field %q", key)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return ExitSelection{}, errors.New("invalid exit selection object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ExitSelection{}, errors.New("exit selection contains trailing data")
	}
	if selection.Enabled {
		if !validLowerHexID(selection.SelectedNodeID) {
			return ExitSelection{}, errors.New("enabled exit selection requires a canonical nonzero node ID")
		}
	} else if selection.SelectedNodeID != "" {
		return ExitSelection{}, errors.New("disabled exit selection must not select a node")
	}
	return selection, nil
}

func newOpaqueID() (string, error) {
	for {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			return "", err
		}
		if !bytes.Equal(value, make([]byte, len(value))) {
			return fmt.Sprintf("%x", value), nil
		}
	}
}

func localAPIContract(next http.Handler, ids *requestIDs) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := ids.New()
		w.Header().Set(RequestIDHeader, requestID)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
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
	payload, err := json.Marshal(value)
	if err != nil || len(payload)+1 > MaxResponseBytes {
		writeAPIError(w, http.StatusInternalServerError, ErrorCodeInternal, "encode local API response", true)
		return
	}
	payload = append(payload, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	_, _ = w.Write(payload)
}

func writeAPIError(w http.ResponseWriter, status int, code, detail string, retryable bool) {
	requestID := w.Header().Get(RequestIDHeader)
	payload, err := json.Marshal(APIError{RequestID: requestID, Code: code, Detail: boundedDetail(detail), Retryable: retryable})
	if err != nil {
		payload = []byte(`{"request_id":"","code":"internal","detail":"encode local API error","retryable":true}`)
	}
	payload = append(payload, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func boundedDetail(detail string) string {
	if detail == "" {
		return "local API request failed"
	}
	if len(detail) <= maxErrorDetailBytes {
		return detail
	}
	detail = detail[:maxErrorDetailBytes]
	for !utf8.ValidString(detail) {
		detail = detail[:len(detail)-1]
	}
	return detail
}

func normalizeStatus(status Status) Status {
	if status.OverlayAddresses == nil {
		status.OverlayAddresses = []string{}
	}
	if status.SelectedRoutes == nil {
		status.SelectedRoutes = []string{}
	}
	return status
}

func normalizePeers(peers []Peer) []Peer {
	if len(peers) == 0 {
		return []Peer{}
	}
	result := append([]Peer(nil), peers...)
	for index := range result {
		if result[index].Prefixes == nil {
			result[index].Prefixes = []string{}
		}
	}
	return result
}

func normalizeRoutes(routes []Route) []Route {
	if routes == nil {
		return []Route{}
	}
	return routes
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
		return responseError(response)
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
		return responseError(response)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(contents) > MaxResponseBytes {
		return errors.New("lanewayd response is oversized")
	}
	return decodeJSONResponse(contents, destination)
}

func decodeJSONResponse(contents []byte, destination any) error {
	if !utf8.Valid(contents) {
		return errors.New("decode lanewayd response: response is not UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode lanewayd response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("lanewayd response is oversized or contains trailing data")
	}
	if err := validateKnownResponseFields(contents, destination); err != nil {
		return fmt.Errorf("decode lanewayd response: %w", err)
	}
	return nil
}

func responseError(response *http.Response) error {
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes+1))
	if readErr != nil || len(body) > maxErrorBodyBytes {
		return errors.New("invalid lanewayd error response")
	}
	var envelope APIError
	if err := decodeJSONResponse(body, &envelope); err == nil {
		if err := validateErrorContract(response.StatusCode, response.Header.Get(RequestIDHeader), envelope); err != nil {
			return fmt.Errorf("invalid lanewayd error response: %w", err)
		}
		envelope.StatusCode = response.StatusCode
		return &envelope
	}
	detail := strings.TrimSpace(string(body))
	if strings.HasPrefix(detail, "{") || response.Header.Get("Content-Type") == "application/json" {
		return errors.New("invalid lanewayd JSON error response")
	}
	if detail == "" {
		return fmt.Errorf("lanewayd returned %s", response.Status)
	}
	return fmt.Errorf("lanewayd returned %s: %s", response.Status, detail)
}

type rawValidator func(json.RawMessage) error

func validateKnownResponseFields(contents []byte, destination any) error {
	switch value := destination.(type) {
	case *Status:
		return validateStatusResponse(contents, value)
	case *[]Peer:
		return validatePeerResponse(contents, *value)
	case *[]Route:
		return validateRouteResponse(contents, *value)
	case *APIError:
		return validateErrorEnvelope(contents, value)
	default:
		return nil
	}
}

func validateStatusResponse(contents []byte, status *Status) error {
	metrics := map[string]rawValidator{
		"connections": validateNumber, "reconnects": validateNumber, "packets_sent": validateNumber,
		"packets_received": validateNumber, "packets_dropped": validateNumber, "tcp_connections": validateNumber,
		"quic_failures": validateNumber, "tcp_failures": validateNumber,
	}
	exit := map[string]rawValidator{
		"enabled": validateBool, "selected_node_id": validateString, "authorized": validateBool,
		"serving": validateBool, "forwarding_ready": validateBool, "nat_ready": validateBool,
		"forwarded_packets": validateNumber, "namespace_cleanup_failures": validateNumber,
	}
	controller := map[string]rawValidator{
		"candidate_exchange_enabled": validateBool, "certificate_presented_serial": validateString,
		"certificate_renewal_needed": validateBool, "certificate_renew_after_unix_seconds": validateNumber,
		"certificate_not_after_unix_seconds": validateNumber, "identity_lease_expires_at_unix_seconds": validateNumber,
		"configuration_lease_valid_until_unix_seconds": validateNumber, "configuration_lease_expired": validateBool,
	}
	fields := map[string]rawValidator{
		"daemon_instance_id": validateString, "api_revision": validateNumber, "running": validateBool,
		"actor": validateString, "product_version": validateString, "control_version": validateString,
		"packet_version": validateNumber, "capabilities": validateString, "selected_path": validateString,
		"network_id": validateString, "node_id": validateString, "name": validateString,
		"overlay_addresses": validateStringArray, "selected_routes": validateStringArray,
		"interface": validateString, "relay": validateString, "mtu": validateNumber,
		"metrics": validateObject(metrics), "exit": validateObject(exit), "controller": validateObject(controller),
	}
	object, err := validateJSONObject(contents, fields)
	if err != nil {
		return err
	}
	if _, present := object["daemon_instance_id"]; present && !validLowerHexID(status.DaemonInstanceID) {
		return errors.New("daemon_instance_id is not a nonzero lowercase 128-bit identifier")
	}
	if _, present := object["api_revision"]; present && status.APIRevision == 0 {
		return errors.New("api_revision must be positive")
	}
	if status.MTU < 0 {
		return errors.New("mtu must not be negative")
	}
	return nil
}

func validatePeerResponse(contents []byte, _ []Peer) error {
	fields := map[string]rawValidator{
		"node_id": validateString, "name": validateString, "prefixes": validateStringArray, "path": validateString,
	}
	_, err := validateJSONObjectArray(contents, fields)
	return err
}

func validateRouteResponse(contents []byte, _ []Route) error {
	fields := map[string]rawValidator{
		"prefix": validateString, "via_node": validateString, "kind": validateString,
	}
	_, err := validateJSONObjectArray(contents, fields)
	return err
}

func validateErrorEnvelope(contents []byte, envelope *APIError) error {
	fields := map[string]rawValidator{
		"request_id": validateString, "code": validateString, "detail": validateString, "retryable": validateBool,
	}
	object, err := validateJSONObject(contents, fields)
	if err != nil {
		return err
	}
	for _, required := range []string{"request_id", "code", "detail", "retryable"} {
		if _, present := object[required]; !present {
			return fmt.Errorf("error envelope omits %s", required)
		}
	}
	if !validLowerHexRequestID(envelope.RequestID) {
		return errors.New("error envelope request_id is invalid")
	}
	if envelope.Code == "" || envelope.Detail == "" || len(envelope.Detail) > maxErrorDetailBytes {
		return errors.New("error envelope code or detail is invalid")
	}
	return nil
}

func validateJSONObject(contents []byte, fields map[string]rawValidator) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("response must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("response must be a JSON object")
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		rawKey, err := decoder.Token()
		if err != nil {
			return nil, errors.New("response object key is invalid")
		}
		key, ok := rawKey.(string)
		if !ok {
			return nil, errors.New("response object key is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("response field %q is invalid", key)
		}
		validator, known := fields[key]
		if !known {
			for knownKey := range fields {
				if strings.EqualFold(key, knownKey) {
					return nil, fmt.Errorf("response field %q uses noncanonical casing", key)
				}
			}
			continue
		}
		if _, duplicate := object[key]; duplicate {
			return nil, fmt.Errorf("response contains duplicate field %q", key)
		}
		if err := validator(raw); err != nil {
			return nil, fmt.Errorf("response field %q: %w", key, err)
		}
		object[key] = raw
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("response object is invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("response object contains trailing data")
	}
	return object, nil
}

func validateJSONObjectArray(contents []byte, fields map[string]rawValidator) ([]map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("response must be a JSON array")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(trimmed, &values); err != nil || values == nil {
		return nil, errors.New("response must be a JSON array")
	}
	objects := make([]map[string]json.RawMessage, len(values))
	for index, raw := range values {
		object, err := validateJSONObject(raw, fields)
		if err != nil {
			return nil, fmt.Errorf("response element %d: %w", index, err)
		}
		objects[index] = object
	}
	return objects, nil
}

func validateObject(fields map[string]rawValidator) rawValidator {
	return func(raw json.RawMessage) error {
		_, err := validateJSONObject(raw, fields)
		return err
	}
}

func validateString(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("must be a string, not null")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("must be a string")
	}
	return nil
}

func validateBool(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("must be a boolean, not null")
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return errors.New("must be a boolean")
	}
	return nil
}

func validateNumber(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("must be a number, not null")
	}
	var value json.Number
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return errors.New("must be a number")
	}
	return nil
}

func validateStringArray(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return errors.New("must be an array")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(trimmed, &values); err != nil || values == nil {
		return errors.New("must be an array")
	}
	for index, value := range values {
		if err := validateString(value); err != nil {
			return fmt.Errorf("element %d: %w", index, err)
		}
	}
	return nil
}

func validLowerHexID(value string) bool {
	return value != strings.Repeat("0", 32) && validLowerHexRequestID(value)
}

func validLowerHexRequestID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validateErrorContract(status int, headerID string, envelope APIError) error {
	if !validLowerHexRequestID(headerID) || headerID != envelope.RequestID {
		return errors.New("request ID header and envelope do not match")
	}
	wantCode, wantRetryable, ok := errorContract(status)
	if !ok || envelope.Code != wantCode || envelope.Retryable != wantRetryable {
		return errors.New("status, code, and retryable fields do not match the v1 contract")
	}
	return nil
}

func errorContract(status int) (string, bool, bool) {
	switch status {
	case http.StatusBadRequest:
		return ErrorCodeInvalidRequest, false, true
	case http.StatusNotFound:
		return ErrorCodeNotFound, false, true
	case http.StatusMethodNotAllowed:
		return ErrorCodeMethodNotAllowed, false, true
	case http.StatusConflict:
		return ErrorCodeConflict, false, true
	case http.StatusInternalServerError:
		return ErrorCodeInternal, true, true
	case http.StatusNotImplemented:
		return ErrorCodeUnsupportedOperation, false, true
	case http.StatusServiceUnavailable:
		return ErrorCodeBusy, true, true
	default:
		return "", false, false
	}
}
