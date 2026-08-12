package controllerclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

type controllerClientRoundTripFunc func(*http.Request) (*http.Response, error)

func (f controllerClientRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

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
			if request.GetRequestedName() == "durable-bound" && request.GetExpectedEnrollmentClass() != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE {
				t.Errorf("durable enrollment omitted expected class: %#v", request)
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
	if _, err := client.EnrollForNetwork(context.Background(), "secret", "network-bound", []byte{1}, make([]byte, 32), networkID); err != nil {
		t.Fatalf("EnrollForNetwork = %v", err)
	}
	if _, err := client.EnrollForNetworkAndClass(context.Background(), "secret", "class-bound", []byte{1}, make([]byte, 32), networkID,
		lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER); err != nil {
		t.Fatalf("EnrollForNetworkAndClass = %v", err)
	}
	if _, err := client.EnrollForNetworkAndClass(context.Background(), "secret", "durable-bound", []byte{1}, make([]byte, 32), networkID,
		lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE); err != nil {
		t.Fatalf("durable EnrollForNetworkAndClass = %v", err)
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
		"POST /v1/admin/routes/" + objectID.String() + "/withdraw":                    true,
		"GET /v1/admin/networks/" + networkID.String() + "/routes?limit=7":            true,
		"POST /v1/admin/networks/" + networkID.String() + "/acl-rules":                true,
		"PUT /v1/admin/acl-rules/" + objectID.String():                                true,
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
	if _, err := client.IssueEnrollmentTokenWithOptions(ctx, networkID, "temporary", time.Unix(200, 0), EnrollmentTokenOptions{Class: "ephemeral", SessionLifetime: 8 * time.Hour, RequestedName: "laptop", EnabledCapabilities: 16}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(lastTokenBody, []byte(`"enrollment_class":"ephemeral"`)) || !bytes.Contains(lastTokenBody, []byte(`"session_lifetime_seconds":28800`)) {
		t.Fatalf("ephemeral token request=%s", lastTokenBody)
	}
	if !bytes.Contains(lastTokenBody, []byte(`"requested_name":"laptop"`)) {
		t.Fatalf("name-bound token request=%s", lastTokenBody)
	}
	if !bytes.Contains(lastTokenBody, []byte(`"enabled_capabilities":16`)) {
		t.Fatalf("capability-bound token request=%s", lastTokenBody)
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
	if _, err := client.AdminWithdrawRoute(ctx, objectID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Routes(ctx, networkID, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AddACLRule(ctx, networkID, 1, "deny", json.RawMessage(`{}`), "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.UpdateACLRule(ctx, objectID, 2, "accept", json.RawMessage(`{}`), "updated", false); err != nil {
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

func TestAuditDecodesDurableActorFieldsWithStrictJSON(t *testing.T) {
	networkID, _ := identity.ParseNetworkID("000102030405060708090a0b0c0d0e0f")
	actorID, _ := identity.ParseID("101112131415161718191a1b1c1d1e1f")
	targetID, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	eventID, _ := identity.ParseID("303132333435363738393a3b3c3d3e3f")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.RequestURI() != "/v1/admin/networks/"+networkID.String()+"/audit?limit=1" {
			t.Errorf("unexpected audit request %s %s", r.Method, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"events":[{"event_id":"`+eventID.String()+`","network_id":"`+networkID.String()+`","actor_kind":"administrator","actor_id":"`+actorID.String()+`","action":"route.assign","target_type":"route","target_id":"`+targetID.String()+`","details":{"created":true},"created_at_unix_seconds":1700000000}]}`)
	}))
	defer server.Close()

	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer test-admin-token"}
	events, err := client.Audit(context.Background(), networkID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ActorKind != "administrator" || events[0].ActorID == nil || *events[0].ActorID != actorID.String() {
		t.Fatalf("audit events=%+v", events)
	}
	if events[0].TargetID == nil || *events[0].TargetID != targetID.String() || string(events[0].Details) != `{"created":true}` {
		t.Fatalf("audit target/details=%+v", events[0])
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

func TestRootTokenLifecycleUsesExactStatusesAndNeverFollowsRedirects(t *testing.T) {
	rotationID, _ := identity.ParseID("202122232425262728292a2b2c2d2e2f")
	redirected := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		redirected++
		if request.Header.Get("Authorization") != "" {
			t.Error("redirect target received root Authorization")
		}
	}))
	defer redirectTarget.Close()

	var rootStatus = http.StatusNoContent
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request.Header.Get("Authorization") != "Bearer root-secret" {
			t.Errorf("%s %s authorization=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/admin/auth/root":
			writer.WriteHeader(rootStatus)
			if rootStatus == http.StatusUnauthorized {
				_, _ = io.WriteString(writer, `{"code":"ERROR_CODE_UNAUTHENTICATED","detail":"authentication failed"}`)
			}
		case "POST /v1/admin/auth/root-token-rotations/" + rotationID.String() + "/begin",
			"POST /v1/admin/auth/root-token-rotations/" + rotationID.String() + "/complete":
			writer.WriteHeader(http.StatusNoContent)
		case "GET /redirect":
			http.Redirect(writer, request, redirectTarget.URL, http.StatusTemporaryRedirect)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer root-secret"}

	accepted, err := client.RootAuthenticationAccepted(context.Background())
	if err != nil || !accepted {
		t.Fatalf("accepted root probe=%t error=%v", accepted, err)
	}
	rootStatus = http.StatusUnauthorized
	accepted, err = client.RootAuthenticationAccepted(context.Background())
	if err != nil || accepted {
		t.Fatalf("rejected root probe=%t error=%v", accepted, err)
	}
	rootStatus = http.StatusForbidden
	if _, err := client.RootAuthenticationAccepted(context.Background()); err == nil {
		t.Fatal("403 was accepted as root-token rejection")
	}
	if err := client.BeginRootTokenRotation(context.Background(), rotationID); err != nil {
		t.Fatal(err)
	}
	if err := client.CompleteRootTokenRotation(context.Background(), rotationID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.rootLifecycleRequest(context.Background(), http.MethodGet, "/redirect"); err != nil {
		t.Fatal(err)
	}
	if redirected != 0 {
		t.Fatalf("lifecycle redirect target requests=%d", redirected)
	}
}

func TestRootTokenLifecycleRejectsMissingAuthOversizeAndInvalidRotation(t *testing.T) {
	client := &Client{endpoint: "https://unused.invalid", http: http.DefaultClient}
	if _, err := client.RootAuthenticationAccepted(context.Background()); err == nil {
		t.Fatal("root probe accepted missing administrator credential")
	}
	if err := client.BeginRootTokenRotation(context.Background(), identity.ID{}); err == nil {
		t.Fatal("root rotation accepted zero ID")
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, strings.Repeat("x", maxLifecycleReplyBytes+1))
	}))
	defer server.Close()
	client = &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer root-secret"}
	if _, err := client.RootAuthenticationAccepted(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized lifecycle response error=%v", err)
	}
}

func TestDecodeLifecycleAdministratorsRequiresExactJSONShape(t *testing.T) {
	const principalID = "202122232425262728292a2b2c2d2e2f"
	principal := `{"principal_id":"` + principalID + `","username":"owner.name","role":"owner","enabled":false,"all_networks":true,"network_ids":[],"created_at_unix_seconds":1,"updated_at_unix_seconds":2,"password_updated_at_unix_seconds":1}`
	valid := `{"administrators":[` + principal + `]}`

	administrators, err := decodeLifecycleAdministrators([]byte(valid))
	if err != nil || len(administrators) != 1 {
		t.Fatalf("valid administrator lookup=%+v error=%v", administrators, err)
	}
	parsed, err := validateLifecycleAdministrator(administrators[0])
	if err != nil || parsed.String() != principalID {
		t.Fatalf("valid lifecycle administrator ID=%s error=%v", parsed, err)
	}

	duplicatePrincipalID := strings.Replace(principal, `"principal_id":"`+principalID+`"`,
		`"principal_id":"`+principalID+`","principal_id":"`+principalID+`"`, 1)
	missingEnabled := strings.Replace(principal, `,"enabled":false`, "", 1)
	nullEnabled := strings.Replace(principal, `"enabled":false`, `"enabled":null`, 1)
	missingNetworks := strings.Replace(principal, `,"network_ids":[]`, "", 1)
	nullNetworks := strings.Replace(principal, `"network_ids":[]`, `"network_ids":null`, 1)
	unknownPrincipalField := strings.TrimSuffix(principal, "}") + `,"unexpected":true}`
	wrongPrincipalIDType := strings.Replace(principal, `"principal_id":"`+principalID+`"`, `"principal_id":7`, 1)
	wrongTimestampType := strings.Replace(principal, `"created_at_unix_seconds":1`, `"created_at_unix_seconds":"1"`, 1)

	invalid := map[string]string{
		"duplicate wrapper field":   `{"administrators":[],"administrators":[]}`,
		"missing wrapper field":     `{}`,
		"null wrapper field":        `{"administrators":null}`,
		"unknown wrapper field":     `{"administrators":[],"unexpected":true}`,
		"wrong wrapper type":        `{"administrators":{}}`,
		"trailing JSON":             valid + `{}`,
		"multiple results":          `{"administrators":[` + principal + `,` + principal + `]}`,
		"duplicate principal field": `{"administrators":[` + duplicatePrincipalID + `]}`,
		"missing boolean field":     `{"administrators":[` + missingEnabled + `]}`,
		"null boolean field":        `{"administrators":[` + nullEnabled + `]}`,
		"missing array field":       `{"administrators":[` + missingNetworks + `]}`,
		"null array field":          `{"administrators":[` + nullNetworks + `]}`,
		"unknown principal field":   `{"administrators":[` + unknownPrincipalField + `]}`,
		"wrong string type":         `{"administrators":[` + wrongPrincipalIDType + `]}`,
		"wrong integer type":        `{"administrators":[` + wrongTimestampType + `]}`,
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if decoded, err := decodeLifecycleAdministrators([]byte(input)); err == nil {
				t.Fatalf("unsafe administrator lookup JSON was accepted: %+v", decoded)
			}
		})
	}
}

func TestDecodeAdministratorLifecycleGrantRequiresCanonicalJSON(t *testing.T) {
	grantText := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x35}, 32))
	const expiresAtUnix = int64(2_000_000_000)
	valid := map[string]string{
		"contract order": fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d}`, grantText, expiresAtUnix),
		"reordered with whitespace": fmt.Sprintf("\n { \n \"expires_at_unix_seconds\" : %d, \n \"grant\" : %q \n } \r\n",
			expiresAtUnix, grantText),
	}
	for name, input := range valid {
		t.Run(name, func(t *testing.T) {
			mutable := []byte(input)
			grant, expiresAt, err := decodeAdministratorLifecycleGrant(mutable)
			clear(mutable)
			defer clear(grant)
			if err != nil || string(grant) != grantText || expiresAt.Unix() != expiresAtUnix {
				t.Fatalf("grant=%q expiry=%d error=%v", grant, expiresAt.Unix(), err)
			}
		})
	}

	escapedGrant := fmt.Sprintf(`{"grant":"\u%04x%s","expires_at_unix_seconds":%d}`,
		grantText[0], grantText[1:], expiresAtUnix)
	invalid := map[string]string{
		"duplicate grant": fmt.Sprintf(`{"grant":%q,"grant":%q,"expires_at_unix_seconds":%d}`,
			grantText, grantText, expiresAtUnix),
		"duplicate expiry": fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d,"expires_at_unix_seconds":%d}`,
			grantText, expiresAtUnix, expiresAtUnix),
		"unknown field": fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d,"unexpected":true}`,
			grantText, expiresAtUnix),
		"trailing JSON":    fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d}{}`, grantText, expiresAtUnix),
		"escaped grant":    escapedGrant,
		"missing grant":    fmt.Sprintf(`{"expires_at_unix_seconds":%d}`, expiresAtUnix),
		"missing expiry":   fmt.Sprintf(`{"grant":%q}`, grantText),
		"wrong grant type": fmt.Sprintf(`{"grant":7,"expires_at_unix_seconds":%d}`, expiresAtUnix),
		"wrong expiry type": fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%q}`, grantText,
			strconv.FormatInt(expiresAtUnix, 10)),
		"trailing comma": fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d,}`, grantText, expiresAtUnix),
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			mutable := []byte(input)
			grant, _, err := decodeAdministratorLifecycleGrant(mutable)
			clear(mutable)
			clear(grant)
			if err == nil {
				t.Fatal("unsafe administrator grant JSON was accepted")
			}
		})
	}
}

func TestAdministratorLifecycleConsumeRejectsUnsafeResponsesAndNeverReplaysSecrets(t *testing.T) {
	const endpoint = "https://controller.example"
	const requestCanary = "request-password-secret-canary"
	const responseCanary = "response-body-secret-canary"
	tests := []struct {
		name          string
		status        int
		body          string
		contentLength int64
		response      func(http.Header)
		wantErr       bool
	}{
		{name: "success", status: http.StatusNoContent, contentLength: 0, wantErr: false},
		{name: "wrong status", status: http.StatusOK, body: responseCanary,
			contentLength: int64(len(responseCanary)), wantErr: true},
		{name: "no-content body", status: http.StatusNoContent, body: responseCanary,
			contentLength: -1, wantErr: true},
		{name: "no-content declared body", status: http.StatusNoContent,
			contentLength: 1, wantErr: true},
		{name: "missing no-store", status: http.StatusNoContent, contentLength: 0,
			response: func(header http.Header) { header.Del("Cache-Control") }, wantErr: true},
		{name: "sets cookie", status: http.StatusNoContent, contentLength: 0,
			response: func(header http.Header) { header.Set("Set-Cookie", "server-secret-canary=forbidden; Secure") }, wantErr: true},
		{name: "redirect", status: http.StatusFound, body: responseCanary,
			contentLength: int64(len(responseCanary)), response: func(header http.Header) {
				header.Set("Location", "https://redirect.example/secret-target")
			}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpointURL, err := url.Parse(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(endpointURL, []*http.Cookie{{Name: "browser", Value: "forbidden", Secure: true, Path: "/"}})

			payload := []byte(`{"grant":"grant-secret-canary","password":"` + requestCanary + `"}`)
			roundTrips := 0
			transport := controllerClientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				roundTrips++
				if request.Method != http.MethodPost || request.URL.String() != endpoint+"/v1/admin/auth/recover" {
					t.Errorf("consume request=%s %s", request.Method, request.URL)
				}
				if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" ||
					request.Header.Get("Origin") != endpoint || request.Header.Get("Cache-Control") != "no-store" ||
					request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" ||
					request.Header.Get("Sec-Fetch-Site") != "" {
					t.Errorf("consume credential headers=%v", request.Header)
				}
				if request.GetBody != nil {
					t.Error("secret-bearing consume request retained a replay body")
				}
				if request.ContentLength != int64(len(payload)) {
					t.Errorf("consume ContentLength=%d want=%d", request.ContentLength, len(payload))
				}
				body, readErr := io.ReadAll(request.Body)
				_ = request.Body.Close()
				if readErr != nil || !bytes.Equal(body, payload) {
					t.Errorf("consume request body mismatch: %v", readErr)
				}
				clear(body)

				header := make(http.Header)
				header.Set("Cache-Control", "no-store")
				if test.response != nil {
					test.response(header)
				}
				return &http.Response{
					StatusCode:    test.status,
					Status:        fmt.Sprintf("%d %s", test.status, http.StatusText(test.status)),
					Header:        header,
					Body:          io.NopCloser(strings.NewReader(test.body)),
					ContentLength: test.contentLength,
					Request:       request,
				}, nil
			})
			client := &Client{endpoint: endpoint, http: &http.Client{Transport: transport, Jar: jar},
				adminBearer: "Bearer root-secret-canary"}
			err = client.consumeAdministratorLifecycleGrant(context.Background(), "/v1/admin/auth/recover", payload)
			clear(payload)
			if (err != nil) != test.wantErr {
				t.Fatalf("consume error=%v wantErr=%t", err, test.wantErr)
			}
			if err != nil && (strings.Contains(err.Error(), requestCanary) || strings.Contains(err.Error(), responseCanary) ||
				strings.Contains(err.Error(), "root-secret-canary") || strings.Contains(err.Error(), "grant-secret-canary")) {
				t.Fatalf("consume error leaked a credential: %v", err)
			}
			if roundTrips != 1 {
				t.Fatalf("consume round trips=%d, want 1", roundTrips)
			}
			for _, cookie := range jar.Cookies(endpointURL) {
				if cookie.Name != "browser" {
					t.Fatalf("lifecycle response updated the caller cookie jar: %s", cookie.Name)
				}
			}
		})
	}
}

func TestAdministratorLifecycleIssuesAndConsumesGrantWithoutLeakingCredentials(t *testing.T) {
	principalID := "202122232425262728292a2b2c2d2e2f"
	grant := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Cache-Control", "no-store")
		if request.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s request omitted cache protection", request.URL.RequestURI())
		}
		if request.Header.Get("Cookie") != "" {
			t.Errorf("%s sent a browser cookie", request.URL.RequestURI())
		}
		key := request.Method + " " + request.URL.RequestURI()
		switch key {
		case "POST /v1/admin/auth/bootstrap-grants",
			"POST /v1/admin/administrators/" + principalID + "/recovery-grants":
			if request.Header.Get("Authorization") != "Bearer root-secret" || request.Header.Get("Origin") != "" {
				t.Errorf("%s used the wrong credential boundary", key)
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(writer, `{"grant":%q,"expires_at_unix_seconds":%d}`, grant, expiresAt)
		case "GET /v1/admin/administrators?username=owner.name":
			if request.Header.Get("Authorization") != "Bearer root-secret" || request.Header.Get("Origin") != "" {
				t.Errorf("%s used the wrong credential boundary", key)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"administrators":[{"principal_id":%q,"username":"owner.name","role":"owner","enabled":false,"all_networks":true,"network_ids":[],"created_at_unix_seconds":1,"updated_at_unix_seconds":2,"disabled_at_unix_seconds":2,"password_updated_at_unix_seconds":1}]}`, principalID)
		case "POST /v1/admin/auth/bootstrap", "POST /v1/admin/auth/recover":
			if request.Header.Get("Authorization") != "" || request.Header.Get("Origin") != server.URL ||
				request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Sec-Fetch-Site") != "" {
				t.Errorf("%s used the wrong unauthenticated request boundary", key)
			}
			body, _ := io.ReadAll(request.Body)
			var decoded map[string]string
			if err := json.Unmarshal(body, &decoded); err != nil || decoded["grant"] != grant ||
				decoded["password"] != "a private administrator password" {
				t.Errorf("%s lifecycle body was invalid", key)
			}
			if key == "POST /v1/admin/auth/bootstrap" && decoded["username"] != "owner.name" {
				t.Error("bootstrap omitted the canonical username")
			}
			if key == "POST /v1/admin/auth/recover" {
				if _, exists := decoded["username"]; exists {
					t.Error("recovery sent an uncontracted username in the grant consumption body")
				}
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer root-secret"}
	bootstrapPassword := []byte("a private administrator password")
	if err := client.BootstrapFirstAdministrator(context.Background(), "owner.name", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bootstrapPassword, make([]byte, len(bootstrapPassword))) {
		t.Fatal("bootstrap did not clear its caller-owned password")
	}
	recoveryPassword := []byte("a private administrator password")
	if err := client.RecoverAdministratorOwner(context.Background(), "owner.name", recoveryPassword); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recoveryPassword, make([]byte, len(recoveryPassword))) {
		t.Fatal("recovery did not clear its caller-owned password")
	}
	if requests != 5 {
		t.Fatalf("administrator lifecycle requests=%d, want 5", requests)
	}
}

func TestAdministratorLifecycleFailsClosedBeforeGrantConsumption(t *testing.T) {
	grant := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
	redirected := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer target.Close()
	tests := []struct {
		name   string
		header func(http.Header)
		status int
		body   string
	}{
		{"missing no-store", func(header http.Header) { header.Set("Content-Type", "application/json") }, http.StatusCreated,
			fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d}`, grant, time.Now().Add(time.Minute).Unix())},
		{"sets cookie", func(header http.Header) {
			header.Set("Cache-Control", "no-store")
			header.Set("Content-Type", "application/json")
			header.Set("Set-Cookie", "browser=forbidden; Secure")
		}, http.StatusCreated, fmt.Sprintf(`{"grant":%q,"expires_at_unix_seconds":%d}`, grant, time.Now().Add(time.Minute).Unix())},
		{"wrong status", func(header http.Header) { header.Set("Cache-Control", "no-store") }, http.StatusNoContent, ""},
		{"malformed grant", func(header http.Header) {
			header.Set("Cache-Control", "no-store")
			header.Set("Content-Type", "application/json")
		}, http.StatusCreated, `{"grant":"not-canonical","expires_at_unix_seconds":1}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				test.header(writer.Header())
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer root-secret"}
			password := []byte("a private administrator password")
			if err := client.BootstrapFirstAdministrator(context.Background(), "owner.name", password); err == nil {
				t.Fatal("unsafe lifecycle response was accepted")
			}
			if !bytes.Equal(password, make([]byte, len(password))) {
				t.Fatal("failed lifecycle request did not clear the password")
			}
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer root-secret"}
	password := []byte("a private administrator password")
	if err := client.BootstrapFirstAdministrator(context.Background(), "owner.name", password); err == nil || redirected != 0 {
		t.Fatalf("lifecycle redirect error=%v redirected=%d", err, redirected)
	}
	invalid := []byte("short")
	if err := client.BootstrapFirstAdministrator(context.Background(), "owner.name", invalid); err == nil ||
		!bytes.Equal(invalid, make([]byte, len(invalid))) {
		t.Fatal("invalid password reached the lifecycle transport or was not cleared")
	}
}

func TestBootstrapBundleClientKeepsDecryptionKeyOutOfControllerRequests(t *testing.T) {
	id := strings.Repeat("A", bootstrap.BundleIDLength)
	expiresAt := time.Unix(2_000_000_600, 0).UTC()
	wrapper := []byte("#!/bin/bash\necho encrypted-envelope\n")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/admin/bootstrap-bundles":
			if r.Header.Get("Authorization") != "Bearer admin-secret" {
				t.Errorf("admin request authorization = %q", r.Header.Get("Authorization"))
			}
			body, _ := io.ReadAll(r.Body)
			if !bytes.Contains(body, []byte("encrypted-envelope")) || bytes.Contains(body, []byte("decryption-key")) {
				t.Errorf("bootstrap request body = %s", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"bundle_id":"`+id+`","public_path":"`+bootstrap.BundlePathPrefix+id+`","expires_at_unix_seconds":`+strconv.FormatInt(expiresAt.Unix(), 10)+`}`)
		case "GET /v1/bootstrap-bundles/" + id:
			if r.Header.Get("Authorization") != "" {
				t.Errorf("capability request leaked admin authorization")
			}
			w.Header().Set("Content-Type", "text/x-shellscript")
			_, _ = w.Write(wrapper)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &Client{endpoint: server.URL, http: server.Client(), adminBearer: "Bearer admin-secret"}
	bundle, err := client.CreateBootstrapBundle(context.Background(), wrapper, expiresAt)
	if err != nil || bundle.BundleID != id {
		t.Fatalf("create bundle=%+v err=%v", bundle, err)
	}
	downloaded, err := client.BootstrapBundle(context.Background(), id)
	if err != nil || !bytes.Equal(downloaded, wrapper) {
		t.Fatalf("downloaded=%q err=%v", downloaded, err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d, want 2", requests)
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
