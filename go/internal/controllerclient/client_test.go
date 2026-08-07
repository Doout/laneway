package controllerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

func TestNormalizeEndpoint(t *testing.T) {
	for _, value := range []string{"http://controller", "https://controller/path", "https://user@controller", "controller"} {
		if _, err := normalizeEndpoint(value); err == nil {
			t.Errorf("accepted invalid endpoint %q", value)
		}
	}
	if got, err := normalizeEndpoint("https://controller.example/"); err != nil || got != "https://controller.example" {
		t.Fatalf("normalize endpoint = %q, %v", got, err)
	}
}

func TestClientAcceptsOnlyOneAuthenticatedCASource(t *testing.T) {
	now := time.Now().UTC()
	material, _, err := pki.NewAuthority("bootstrap CA", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pki.CertificatePEM(material.CertificateDER)
	networkID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	serviceID, _ := identity.ParseID("101112131415161718191a1b1c1d1e1f")
	options := Options{Endpoint: "https://controller.example.test:8443", CAPEM: caPEM, ExpectedNetworkID: networkID, ExpectedServiceID: serviceID}
	if _, err := New(options); err != nil {
		t.Fatal(err)
	}
	without := options
	without.CAPEM = nil
	if _, err := New(without); err == nil {
		t.Fatal("missing CA source accepted")
	}
	both := options
	both.CAFile = filepath.Join(t.TempDir(), "ca.crt")
	if _, err := New(both); err == nil {
		t.Fatal("ambiguous CA sources accepted")
	}
}

func TestReadAdminToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("top-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := readAdminToken(path); err != nil || token != "top-secret" {
		t.Fatalf("readAdminToken = %q, %v", token, err)
	}
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminToken(path); err == nil {
		t.Fatal("multiline token accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxAdminTokenBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdminToken(path); err == nil {
		t.Fatal("oversized token accepted")
	}
}

func TestEnrollAndConfiguration(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Error("missing protobuf content type")
		}
		switch r.URL.Path {
		case "/v1/enroll":
			body, _ := io.ReadAll(r.Body)
			request := new(lanewayv1.EnrollmentRequest)
			if err := proto.Unmarshal(body, request); err != nil || request.GetEnrollmentToken() != "secret" {
				t.Errorf("bad enrollment request: %#v, %v", request, err)
			}
			if request.GetRequestedName() == "network-bound" && len(request.GetExpectedNetworkId()) != identity.IDSize {
				t.Errorf("network-bound enrollment omitted expected NetworkID: %#v", request)
			}
			if request.GetRequestedName() == "class-bound" && request.GetExpectedEnrollmentClass() != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER {
				t.Errorf("class-bound enrollment omitted expected class: %#v", request)
			}
			payload, _ := proto.Marshal(&lanewayv1.EnrollmentResponse{NetworkId: make([]byte, 16), NodeId: make([]byte, 16)})
			_, _ = w.Write(payload)
		case "/v1/configuration":
			w.Header().Set(snapshotValidityHeader, "2000000000")
			w.WriteHeader(http.StatusNotModified)
		case "/v1/relay/configuration":
			payload, _ := proto.Marshal(&lanewayv1.RelayConfiguration{NetworkId: make([]byte, 16), ConfigurationEpoch: 2})
			_, _ = w.Write(payload)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client()}
	response, err := client.Enroll(context.Background(), "secret", "node", []byte{1})
	if err != nil || len(response.GetNodeId()) != 16 {
		t.Fatalf("Enroll = %#v, %v", response, err)
	}
	networkID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	if _, err := client.EnrollForNetwork(context.Background(), "secret", "network-bound", []byte{1}, networkID); err != nil {
		t.Fatalf("EnrollForNetwork = %v", err)
	}
	if _, err := client.EnrollForNetworkAndClass(context.Background(), "secret", "class-bound", []byte{1}, networkID,
		lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER); err != nil {
		t.Fatalf("EnrollForNetworkAndClass = %v", err)
	}
	configuration, unchanged, err := client.Configuration(context.Background(), 4)
	if err != nil || !unchanged || configuration.GetValidUntilUnixSeconds() != 2_000_000_000 {
		t.Fatalf("Configuration unchanged = %t, %v", unchanged, err)
	}
	relay, unchanged, err := client.RelayConfiguration(context.Background(), 0)
	if err != nil || unchanged || relay.GetConfigurationEpoch() != 2 {
		t.Fatalf("RelayConfiguration = %#v, %t, %v", relay, unchanged, err)
	}
}

func TestConfigurationRejectsNotModifiedWithoutLeaseDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client()}
	if _, _, err := client.Configuration(context.Background(), 1); err == nil {
		t.Fatal("not-modified response without a snapshot deadline was accepted")
	}
}

func TestProtocolErrorAndResponseLimit(t *testing.T) {
	t.Run("protocol error", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			payload, _ := proto.Marshal(&lanewayv1.ProtocolError{Code: lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, Detail: "denied"})
			_, _ = w.Write(payload)
		}))
		defer server.Close()
		client := &Client{endpoint: server.URL, http: server.Client()}
		if _, err := client.Enroll(context.Background(), "x", "n", []byte{1}); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, strings.Repeat("x", MaxResponseBytes+1))
		}))
		defer server.Close()
		client := &Client{endpoint: server.URL, http: server.Client()}
		if _, err := client.Enroll(context.Background(), "x", "n", []byte{1}); err == nil {
			t.Fatal("oversized response accepted")
		}
	})
}

func TestManagementMethodsAndAuthentication(t *testing.T) {
	networkID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	nodeID, _ := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	objectID, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	adminPaths := map[string]bool{
		"POST /v1/admin/networks":                                                     true,
		"GET /v1/admin/networks/" + networkID.String():                                true,
		"POST /v1/admin/enrollment-tokens":                                            true,
		"POST /v1/admin/routes/" + objectID.String() + "/approve":                     true,
		"GET /v1/admin/networks/" + networkID.String() + "/routes?limit=7":            true,
		"POST /v1/admin/networks/" + networkID.String() + "/acl-rules":                true,
		"DELETE /v1/admin/acl-rules/" + objectID.String():                             true,
		"POST /v1/admin/nodes/" + nodeID.String() + "/revoke":                         true,
		"POST /v1/admin/networks/" + networkID.String() + "/certificates/0123/revoke": true,
		"POST /v1/admin/networks/" + networkID.String() + "/relays":                   true,
		"POST /v1/admin/relays/" + objectID.String() + "/disable":                     true,
		"GET /v1/admin/networks/" + networkID.String() + "/audit?limit=9":             true,
	}
	var lastTokenBody []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.RequestURI()
		if adminPaths[key] {
			if got := r.Header.Get("Authorization"); got != "Bearer admin-secret" {
				t.Errorf("%s Authorization = %q", key, got)
			}
		} else if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("node request leaked admin credential: %s", key)
		}
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) != 0 && !json.Valid(body) {
				t.Errorf("%s invalid request JSON %q", key, body)
			}
			if key == "POST /v1/admin/networks" && bytes.Contains(body, []byte(`"name":"preidentified"`)) &&
				!bytes.Contains(body, []byte(`"network_id":"`+networkID.String()+`"`)) {
				t.Errorf("preidentified network request omitted network_id: %s", body)
			}
			if key == "POST /v1/admin/enrollment-tokens" {
				lastTokenBody = append(lastTokenBody[:0], body...)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case key == "POST /v1/admin/networks", key == "GET /v1/admin/networks/"+networkID.String():
			_, _ = io.WriteString(w, `{"network_id":"`+networkID.String()+`","name":"test","ipv4_pool":"10.0.0.0/24","configuration_epoch":1,"created_at_unix_seconds":1}`)
		case key == "POST /v1/admin/enrollment-tokens":
			_, _ = io.WriteString(w, `{"token_id":"`+objectID.String()+`","enrollment_token":"issued-secret","expires_at_unix_seconds":100}`)
		case key == "POST /v1/routes":
			_, _ = io.WriteString(w, `{"route_id":"`+objectID.String()+`","network_id":"`+networkID.String()+`","node_id":"`+nodeID.String()+`","prefix":"192.0.2.0/24","kind":"subnet","mode":"nat","metric":5,"state":"advertised","created_at_unix_seconds":1}`)
		case key == "GET /v1/admin/networks/"+networkID.String()+"/routes?limit=7":
			_, _ = io.WriteString(w, `{"routes":[]}`)
		case key == "POST /v1/admin/networks/"+networkID.String()+"/acl-rules":
			_, _ = io.WriteString(w, `{"rule_id":"`+objectID.String()+`","network_id":"`+networkID.String()+`","priority":1,"action":"deny","selector":{},"description":"test","configuration_epoch":2}`)
		case key == "GET /v1/admin/networks/"+networkID.String()+"/audit?limit=9":
			_, _ = io.WriteString(w, `{"events":[]}`)
		case key == "POST /v1/admin/networks/"+networkID.String()+"/relays":
			_, _ = io.WriteString(w, `{"relay_id":"`+objectID.String()+`","network_id":"`+networkID.String()+`","service_id":"`+objectID.String()+`","name":"relay","endpoint":"relay.example:443","enabled":true,"created_at_unix_seconds":1,"configuration_epoch":2}`)
		default:
			_, _ = io.WriteString(w, `{"configuration_epoch":2}`)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer admin-secret"}
	ctx := context.Background()
	if _, err := client.CreateNetwork(ctx, "test", netip.MustParsePrefix("10.0.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateNetworkDualStackWithID(ctx, networkID, "preidentified", netip.MustParsePrefix("10.1.0.0/24"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Network(ctx, networkID); err != nil {
		t.Fatal(err)
	}
	if token, err := client.IssueEnrollmentToken(ctx, networkID, "label", time.Unix(100, 0)); err != nil || token.EnrollmentToken != "issued-secret" {
		t.Fatalf("token=%+v err=%v", token, err)
	}
	if _, err := client.IssueEnrollmentTokenWithOptions(ctx, networkID, "temporary", time.Unix(200, 0), EnrollmentTokenOptions{Class: "ephemeral", SessionLifetime: 8 * time.Hour, RequestedName: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(lastTokenBody, []byte(`"enrollment_class":"ephemeral"`)) || !bytes.Contains(lastTokenBody, []byte(`"session_lifetime_seconds":28800`)) {
		t.Fatalf("ephemeral token request=%s", lastTokenBody)
	}
	if !bytes.Contains(lastTokenBody, []byte(`"requested_name":"laptop"`)) {
		t.Fatalf("name-bound token request=%s", lastTokenBody)
	}
	if _, err := client.AdvertiseRoute(ctx, netip.MustParsePrefix("192.0.2.0/24"), "subnet", "nat", 5, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WithdrawRoute(ctx, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ApproveRoute(ctx, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Routes(ctx, networkID, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddACLRule(ctx, networkID, 1, "deny", json.RawMessage(`{}`), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteACLRule(ctx, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RevokeNode(ctx, nodeID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.RevokeCertificate(ctx, networkID, []byte{0x01, 0x23}, "test"); err != nil {
		t.Fatal(err)
	}
	if relay, err := client.RegisterRelay(ctx, networkID, objectID, &nodeID, "relay", "relay.example:443"); err != nil || relay.ServiceID != objectID.String() {
		t.Fatalf("relay=%+v err=%v", relay, err)
	}
	if _, err := client.DisableRelay(ctx, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Audit(ctx, networkID, 9); err != nil {
		t.Fatal(err)
	}
}

func TestJSONAdminRequiredErrorsAndLimits(t *testing.T) {
	client := &Client{endpoint: "https://unused.invalid", http: http.DefaultClient}
	if _, err := client.Network(context.Background(), identity.NetworkID{}); err == nil || !strings.Contains(err.Error(), "admin token") {
		t.Fatalf("missing admin token error = %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oversize" {
			_, _ = io.WriteString(w, strings.Repeat("x", MaxResponseBytes+1))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"code":"ERROR_CODE_MALFORMED","detail":"bad input","retryable":false}`)
	}))
	defer server.Close()
	client = &Client{endpoint: server.URL, http: server.Client()}
	if err := client.json(context.Background(), http.MethodGet, "/error", nil, new(Epoch), false); err == nil || !strings.Contains(err.Error(), "bad input") {
		t.Fatalf("JSON API error = %v", err)
	}
	if err := client.json(context.Background(), http.MethodGet, "/oversize", nil, new(Epoch), false); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	if err := client.json(context.Background(), http.MethodPost, "/unused", struct {
		Value string `json:"value"`
	}{strings.Repeat("x", MaxJSONRequestBytes)}, new(Epoch), false); err == nil || !strings.Contains(err.Error(), "request exceeds") {
		t.Fatalf("request limit error = %v", err)
	}
}

func TestPinnedDialContextNeverUsesRotatedHostnameTarget(t *testing.T) {
	sentinel := errors.New("dial stopped")
	var gotNetwork, gotAddress string
	dial := pinnedDialContext("203.0.113.20:443", func(_ context.Context, network, address string) (net.Conn, error) {
		gotNetwork, gotAddress = network, address
		return nil, sentinel
	})
	_, err := dial(context.Background(), "tcp", "controller.example:443")
	if !errors.Is(err, sentinel) {
		t.Fatalf("dial error = %v, want sentinel", err)
	}
	if gotNetwork != "tcp" || gotAddress != "203.0.113.20:443" {
		t.Fatalf("dial target = %s %s, want tcp 203.0.113.20:443", gotNetwork, gotAddress)
	}
}

func TestValidatePinnedDialAddress(t *testing.T) {
	for _, valid := range []string{"203.0.113.20:443", "[2001:db8::20]:8443"} {
		if err := validatePinnedDialAddress(valid); err != nil {
			t.Fatalf("validatePinnedDialAddress(%q): %v", valid, err)
		}
	}
	for _, invalid := range []string{"controller.example:443", "203.0.113.20", "0.0.0.0:443", "[::]:443"} {
		if err := validatePinnedDialAddress(invalid); err == nil {
			t.Fatalf("validatePinnedDialAddress(%q) succeeded", invalid)
		}
	}
}
