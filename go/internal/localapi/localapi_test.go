package localapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testPeerID     = "202122232425262728292a2b2c2d2e2f"
	testConflictID = "303132333435363738393a3b3c3d3e3f"
)

func TestServerClientLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanewayd.sock")
	var selected ExitSelection
	server := Server{SocketPath: path, Snapshot: func() (Status, []Peer, []Route) {
		return Status{Running: true, Actor: "exit-node", NodeID: "node", Name: strings.Repeat("n", 2300), OverlayAddresses: []string{"100.96.0.1/32"}, SelectedRoutes: []string{"0.0.0.0/0"}, MTU: 1200, ProductVersion: "1.0.0", ControlVersion: "1.0", PacketVersion: 1, Capabilities: "relay-v1", SelectedPath: "relay-quic", Controller: ControllerStatus{CandidateExchangeEnabled: true, CertificateRenewalNeeded: true, CertificateNotAfterUnixSeconds: 12345, IdentityLeaseExpiresAtUnixSeconds: 23456, ConfigurationLeaseValidUntilUnixSeconds: 34567, ConfigurationLeaseExpired: true}, Exit: ExitStatus{Serving: true, ForwardingReady: true, NATReady: true, ForwardedPackets: 12, NamespaceCleanupFailures: 1}},
			[]Peer{{NodeID: "peer", Name: "homelab-gateway", Prefixes: []string{"100.96.0.2/32"}, Path: "direct"}},
			[]Route{{Prefix: "100.96.0.2/32", ViaNode: "peer", Kind: "peer"}}
	}, SetExit: func(_ context.Context, selection ExitSelection) error {
		if selection.SelectedNodeID == testConflictID {
			return errors.New("selected exit is unavailable")
		}
		selected = selection
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(path)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		status, err = client.Status(context.Background())
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil || !validOpaqueID(status.DaemonInstanceID) || status.APIRevision != APIRevision || !status.Running || status.Actor != "exit-node" || len(status.OverlayAddresses) != 1 || len(status.SelectedRoutes) != 1 || status.MTU != 1200 || status.ProductVersion != "1.0.0" || status.ControlVersion != "1.0" || status.PacketVersion != 1 || status.Capabilities != "relay-v1" || status.SelectedPath != "relay-quic" || !status.Controller.CandidateExchangeEnabled || !status.Controller.CertificateRenewalNeeded || status.Controller.CertificateNotAfterUnixSeconds != 12345 || status.Controller.IdentityLeaseExpiresAtUnixSeconds != 23456 || status.Controller.ConfigurationLeaseValidUntilUnixSeconds != 34567 || !status.Controller.ConfigurationLeaseExpired || !status.Exit.Serving || !status.Exit.NATReady || status.Exit.ForwardedPackets != 12 || status.Exit.NamespaceCleanupFailures != 1 {
		t.Fatalf("status = %#v, %v", status, err)
	}
	secondStatus, err := client.Status(context.Background())
	if err != nil || secondStatus.DaemonInstanceID != status.DaemonInstanceID || secondStatus.APIRevision != status.APIRevision {
		t.Fatalf("second status = %#v, %v", secondStatus, err)
	}
	{
		request, requestErr := http.NewRequest(http.MethodGet, "http://lanewayd/v1/status", nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, requestErr := client.http.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil || len(body) <= 2048 || response.ContentLength != int64(len(body)) || response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || len(response.TransferEncoding) != 0 {
			t.Fatalf("large response length = header %q parsed %d body %d transfer %v, %v", response.Header.Get("Content-Length"), response.ContentLength, len(body), response.TransferEncoding, readErr)
		}
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v", info.Mode().Perm())
	}
	peers, err := client.Peers(context.Background())
	if err != nil || len(peers) != 1 || peers[0].NodeID != "peer" || peers[0].Name != "homelab-gateway" || peers[0].Path != "direct" {
		t.Fatalf("peers = %#v, %v", peers, err)
	}
	routes, err := client.Routes(context.Background())
	if err != nil || len(routes) != 1 || routes[0].Kind != "peer" {
		t.Fatalf("routes = %#v, %v", routes, err)
	}
	if err := client.SetExit(context.Background(), ExitSelection{Enabled: true, SelectedNodeID: testPeerID}); err != nil {
		t.Fatal(err)
	}
	if !selected.Enabled || selected.SelectedNodeID != testPeerID {
		t.Fatalf("exit selection = %#v", selected)
	}
	if err := client.SetExit(context.Background(), ExitSelection{Enabled: true, SelectedNodeID: testConflictID}); err == nil {
		t.Fatal("conflicting exit selection succeeded")
	} else {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != ErrorCodeConflict || apiErr.Retryable || !validOpaqueID(apiErr.RequestID) {
			t.Fatalf("conflict error = %#v, %v", apiErr, err)
		}
	}
	request, err := http.NewRequest(http.MethodPost, "http://lanewayd/v1/exit", strings.NewReader(`{"enabled":false,"unexpected":true}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	malformedBody, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	var malformed APIError
	decodeErr := json.Unmarshal(malformedBody, &malformed)
	if readErr != nil || decodeErr != nil || response.StatusCode != http.StatusBadRequest || response.ContentLength != int64(len(malformedBody)) || response.Header.Get("Content-Length") != strconv.Itoa(len(malformedBody)) || len(response.TransferEncoding) != 0 || malformed.Code != ErrorCodeInvalidRequest || malformed.Retryable || !validOpaqueID(malformed.RequestID) || response.Header.Get(RequestIDHeader) != malformed.RequestID {
		t.Fatalf("malformed response = %d %#v length %d/%d transfer %v, %v/%v", response.StatusCode, malformed, response.ContentLength, len(malformedBody), response.TransferEncoding, readErr, decodeErr)
	}
	if !selected.Enabled || selected.SelectedNodeID != testPeerID {
		t.Fatalf("invalid request reached exit callback: %#v", selected)
	}
	request, err = http.NewRequest(http.MethodGet, "http://lanewayd/missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var notFound APIError
	decodeErr = json.NewDecoder(response.Body).Decode(&notFound)
	response.Body.Close()
	if decodeErr != nil || response.StatusCode != http.StatusNotFound || notFound.Code != ErrorCodeNotFound || response.Header.Get(RequestIDHeader) != notFound.RequestID || notFound.RequestID == malformed.RequestID {
		t.Fatalf("not-found response = %d %#v, %v", response.StatusCode, notFound, decodeErr)
	}
	for _, test := range []struct {
		name   string
		method string
		url    string
		body   io.Reader
		status int
	}{
		{name: "head", method: http.MethodHead, url: "http://lanewayd/v1/status", status: http.StatusMethodNotAllowed},
		{name: "head body", method: http.MethodHead, url: "http://lanewayd/v1/status", body: strings.NewReader("{}"), status: http.StatusMethodNotAllowed},
		{name: "head query", method: http.MethodHead, url: "http://lanewayd/v1/status?fresh=1", status: http.StatusBadRequest},
		{name: "put body", method: http.MethodPut, url: "http://lanewayd/v1/status", body: strings.NewReader("{}"), status: http.StatusMethodNotAllowed},
		{name: "put oversized body", method: http.MethodPut, url: "http://lanewayd/v1/status", body: strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1)), status: http.StatusBadRequest},
		{name: "double slash", method: http.MethodGet, url: "http://lanewayd/v1//status", status: http.StatusNotFound},
		{name: "query", method: http.MethodGet, url: "http://lanewayd/v1/status?fresh=1", status: http.StatusBadRequest},
		{name: "get body", method: http.MethodGet, url: "http://lanewayd/v1/status", body: strings.NewReader("{}"), status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, test.url, test.body)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.http.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			wireBody, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != test.status || !validOpaqueID(response.Header.Get(RequestIDHeader)) {
				t.Fatalf("response = %d request ID %q", response.StatusCode, response.Header.Get(RequestIDHeader))
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if test.method == http.MethodHead && (len(wireBody) != 0 || response.Header.Get("Content-Length") == "0") {
				t.Fatalf("HEAD body = %q content length %q", wireBody, response.Header.Get("Content-Length"))
			}
		})
	}
	request, err = http.NewRequest(http.MethodPost, "http://lanewayd/v1/exit", strings.NewReader(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	response, err = client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("chunked request status = %d", response.StatusCode)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket was not removed: %v", err)
	}
}

func TestSharedV1FixturesAndAdditiveResponseDecoding(t *testing.T) {
	statusFixture, err := os.ReadFile(filepath.Join("..", "..", "..", "testvectors", "local-api", "status-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := decodeJSONResponse(statusFixture, &status); err != nil {
		t.Fatal(err)
	}
	if status.DaemonInstanceID != "0123456789abcdef0123456789abcdef" || status.APIRevision != APIRevision || status.NodeID != strings.Repeat("1", 32) || status.MTU != 1280 {
		t.Fatalf("status fixture = %#v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, statusFixture, encoded)

	var additive map[string]any
	if err := json.Unmarshal(statusFixture, &additive); err != nil {
		t.Fatal(err)
	}
	additive["future_status_member"] = map[string]any{"value": true}
	additive["metrics"].(map[string]any)["future_metric"] = 7
	additiveFixture, err := json.Marshal(additive)
	if err != nil {
		t.Fatal(err)
	}
	var tolerant Status
	if err := decodeJSONResponse(additiveFixture, &tolerant); err != nil {
		t.Fatalf("additive response was rejected: %v", err)
	}
	if tolerant.DaemonInstanceID != status.DaemonInstanceID || tolerant.Metrics.Connections != status.Metrics.Connections {
		t.Fatalf("additive response changed known fields: %#v", tolerant)
	}
	delete(additive, "daemon_instance_id")
	delete(additive, "api_revision")
	legacyFixture, err := json.Marshal(additive)
	if err != nil {
		t.Fatal(err)
	}
	var legacy Status
	if err := decodeJSONResponse(legacyFixture, &legacy); err != nil || legacy.DaemonInstanceID != "" || legacy.APIRevision != 0 {
		t.Fatalf("legacy response = %#v, %v", legacy, err)
	}

	errorFixture, err := os.ReadFile(filepath.Join("..", "..", "..", "testvectors", "local-api", "error-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var apiErr APIError
	if err := json.Unmarshal(errorFixture, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.RequestID != "0123456789abcdef0000000000000001" || apiErr.Code != ErrorCodeInvalidRequest || apiErr.Detail != "invalid exit selection" || apiErr.Retryable {
		t.Fatalf("error fixture = %#v", apiErr)
	}
	encoded, err = json.Marshal(apiErr)
	if err != nil {
		t.Fatal(err)
	}
	assertSameJSON(t, errorFixture, encoded)
	if detail := boundedDetail(strings.Repeat("é", maxErrorDetailBytes)); len(detail) > maxErrorDetailBytes || !validUTF8(detail) {
		t.Fatalf("bounded detail has %d bytes", len(detail))
	}
	if boundedDetail("") == "" {
		t.Fatal("empty error detail was not normalized")
	}
}

func TestSharedExitSelectionStrictness(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "testvectors", "local-api", "exit-selection-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Valid []struct {
			Name           string `json:"name"`
			JSON           string `json:"json"`
			Enabled        bool   `json:"enabled"`
			SelectedNodeID string `json:"selected_node_id"`
		} `json:"valid"`
		Invalid []struct {
			Name string `json:"name"`
			JSON string `json:"json"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(contents, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases.Valid {
		t.Run("valid "+test.Name, func(t *testing.T) {
			selection, err := decodeExitSelection([]byte(test.JSON))
			if err != nil || selection.Enabled != test.Enabled || selection.SelectedNodeID != test.SelectedNodeID {
				t.Fatalf("selection = %#v, %v", selection, err)
			}
		})
	}
	for _, test := range cases.Invalid {
		t.Run("invalid "+test.Name, func(t *testing.T) {
			if selection, err := decodeExitSelection([]byte(test.JSON)); err == nil {
				t.Fatalf("selection accepted: %#v", selection)
			}
		})
	}
	if selection, err := decodeExitSelection([]byte("{\"selected_node_id\":\"\xff\"}")); err == nil {
		t.Fatalf("non-UTF-8 selection accepted: %#v", selection)
	}
}

func TestTolerantResponsesRejectInvalidKnownFields(t *testing.T) {
	for _, test := range []struct {
		name     string
		contents string
	}{
		{name: "null document", contents: `null`},
		{name: "null boolean", contents: `{"running":null}`},
		{name: "wrong boolean", contents: `{"running":"yes"}`},
		{name: "case alias", contents: `{"Running":true}`},
		{name: "duplicate known", contents: `{"running":true,"running":false}`},
		{name: "null object", contents: `{"metrics":null}`},
		{name: "null array", contents: `{"overlay_addresses":null}`},
		{name: "null array element", contents: `{"overlay_addresses":[null]}`},
		{name: "zero API revision", contents: `{"api_revision":0}`},
		{name: "zero instance ID", contents: `{"daemon_instance_id":"00000000000000000000000000000000"}`},
		{name: "uppercase instance ID", contents: `{"daemon_instance_id":"0123456789ABCDEF0123456789ABCDEF"}`},
		{name: "negative MTU", contents: `{"mtu":-1}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var status Status
			if err := decodeJSONResponse([]byte(test.contents), &status); err == nil {
				t.Fatalf("invalid status accepted: %#v", status)
			}
		})
	}
	var additive Status
	if err := decodeJSONResponse([]byte(`{"future_status":{"nullable":null}}`), &additive); err != nil {
		t.Fatalf("additive response rejected: %v", err)
	}
	if err := decodeJSONResponse([]byte(`{"future_status":{"value":1,"value":2}}`), &additive); err != nil {
		t.Fatalf("opaque additive duplicate rejected: %v", err)
	}
	if err := decodeJSONResponse([]byte("{\"future_status\":\"\xff\"}"), &additive); err == nil {
		t.Fatal("non-UTF-8 additive response accepted")
	}
	var peers []Peer
	if err := decodeJSONResponse([]byte(`null`), &peers); err == nil {
		t.Fatal("null peer array accepted")
	}
	if err := decodeJSONResponse([]byte(`[{"node_id":null,"prefixes":[],"path":"direct"}]`), &peers); err == nil {
		t.Fatal("null known peer field accepted")
	}
	if err := decodeJSONResponse([]byte(`[{"node_id":"202122232425262728292a2b2c2d2e2f","prefixes":[],"path":""}]`), &peers); err != nil {
		t.Fatalf("legacy empty peer path rejected: %v", err)
	}
}

func TestResponseErrorRequiresV1Contract(t *testing.T) {
	requestID := "0123456789abcdef0000000000000001"
	validBody := `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","detail":"invalid request","retryable":false,"future":{"value":true}}`
	err := responseError(localErrorResponse(http.StatusBadRequest, requestID, validBody, "application/json"))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RequestID != requestID || apiErr.Code != ErrorCodeInvalidRequest {
		t.Fatalf("valid additive envelope = %#v, %v", apiErr, err)
	}

	longDetail, marshalErr := json.Marshal(map[string]any{
		"request_id": requestID, "code": ErrorCodeInvalidRequest,
		"detail": strings.Repeat("x", maxErrorDetailBytes+1), "retryable": false,
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, test := range []struct {
		name     string
		status   int
		headerID string
		body     string
	}{
		{name: "missing header", status: 400, body: validBody},
		{name: "header mismatch", status: 400, headerID: "1123456789abcdef0000000000000001", body: validBody},
		{name: "uppercase header", status: 400, headerID: "0123456789ABCDEF0000000000000001", body: validBody},
		{name: "missing request ID", status: 400, headerID: requestID, body: `{"code":"invalid_request","detail":"invalid request","retryable":false}`},
		{name: "invalid body request ID", status: 400, headerID: requestID, body: `{"request_id":"0123456789ABCDEF0000000000000001","code":"invalid_request","detail":"invalid request","retryable":false}`},
		{name: "null code", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":null,"detail":"invalid request","retryable":false}`},
		{name: "empty code", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"","detail":"invalid request","retryable":false}`},
		{name: "null detail", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","detail":null,"retryable":false}`},
		{name: "empty detail", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","detail":"","retryable":false}`},
		{name: "null retryable", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","detail":"invalid request","retryable":null}`},
		{name: "duplicate code", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","code":"conflict","detail":"invalid request","retryable":false}`},
		{name: "wrong status code", status: 409, headerID: requestID, body: validBody},
		{name: "wrong retryable", status: 400, headerID: requestID, body: `{"request_id":"0123456789abcdef0000000000000001","code":"invalid_request","detail":"invalid request","retryable":true}`},
		{name: "oversized detail", status: 400, headerID: requestID, body: string(longDetail)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := responseError(localErrorResponse(test.status, test.headerID, test.body, "application/json"))
			var typed *APIError
			if err == nil || errors.As(err, &typed) {
				t.Fatalf("invalid envelope accepted: %#v, %v", typed, err)
			}
		})
	}
	oversized := localErrorResponse(http.StatusBadRequest, requestID, validBody+strings.Repeat(" ", maxErrorBodyBytes), "application/json")
	if err := responseError(oversized); err == nil || errors.As(err, &apiErr) {
		t.Fatalf("oversized envelope accepted: %#v, %v", apiErr, err)
	}
	interrupted := localErrorResponse(http.StatusBadRequest, requestID, validBody, "application/json")
	interrupted.Body = io.NopCloser(&readThenError{contents: []byte(validBody)})
	if err := responseError(interrupted); err == nil || errors.As(err, &apiErr) {
		t.Fatalf("interrupted envelope accepted: %#v, %v", apiErr, err)
	}
	legacy := responseError(localErrorResponse(http.StatusConflict, "", "old daemon failure\n", "text/plain; charset=utf-8"))
	if legacy == nil || !strings.Contains(legacy.Error(), "old daemon failure") {
		t.Fatalf("legacy error = %v", legacy)
	}
}

func TestWireNormalizationUsesArrays(t *testing.T) {
	status := normalizeStatus(Status{
		DaemonInstanceID: "0123456789abcdef0123456789abcdef",
		APIRevision:      APIRevision,
	})
	statusPayload, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var decodedStatus Status
	if err := decodeJSONResponse(statusPayload, &decodedStatus); err != nil {
		t.Fatalf("normalized status rejected: %v", err)
	}
	for name, peers := range map[string][]Peer{
		"nil":        nil,
		"empty":      make([]Peer, 0),
		"nil prefix": {{NodeID: testPeerID, Path: "direct"}},
	} {
		peersPayload, err := json.Marshal(normalizePeers(peers))
		if err != nil {
			t.Fatal(err)
		}
		var decodedPeers []Peer
		if err := decodeJSONResponse(peersPayload, &decodedPeers); err != nil {
			t.Fatalf("normalized %s peers rejected: %v", name, err)
		}
	}
	routesPayload, err := json.Marshal(normalizeRoutes(nil))
	if err != nil {
		t.Fatal(err)
	}
	var decodedRoutes []Route
	if err := decodeJSONResponse(routesPayload, &decodedRoutes); err != nil {
		t.Fatalf("normalized routes rejected: %v", err)
	}
}

type readThenError struct {
	contents []byte
}

func (r *readThenError) Read(buffer []byte) (int, error) {
	if len(r.contents) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	count := copy(buffer, r.contents)
	r.contents = r.contents[count:]
	return count, nil
}

func localErrorResponse(status int, requestID, body, contentType string) *http.Response {
	header := make(http.Header)
	if requestID != "" {
		header.Set(RequestIDHeader, requestID)
	}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Status:     strconv.Itoa(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func validOpaqueID(value string) bool {
	if len(value) != 32 || value == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func assertSameJSON(t *testing.T, left, right []byte) {
	t.Helper()
	var leftValue, rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftValue, rightValue) {
		t.Fatalf("JSON differs:\nleft: %s\nright: %s", left, right)
	}
}

func validUTF8(value string) bool {
	return strings.ToValidUTF8(value, "") == value
}

func TestRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanewayd.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := (Server{SocketPath: path, Snapshot: func() (Status, []Peer, []Route) { return Status{}, nil, nil }}).Serve(context.Background())
	if err == nil {
		t.Fatal("non-socket path was accepted")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil || string(contents) != "do not replace" {
		t.Fatalf("foreign file changed: %q, %v", contents, readErr)
	}
}
