package controllerservice

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodelocation"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

type testLocationResolver struct {
	calls int
	fail  bool
}

type locationTestStream struct {
	*bytes.Reader
	output bytes.Buffer
}

func (s *locationTestStream) Write(p []byte) (int, error) { return s.output.Write(p) }

func TestQUICConfigurationPreservesObservedAddress(t *testing.T) {
	var caller identity.NodeIdentity
	f := newFixture(t, 0, func(*http.Request) (identity.NodeIdentity, error) { return caller, nil })
	enrollment, response := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "quic-map-node")
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	caller.NetworkID = f.network.ID
	copy(caller.NodeID[:], enrollment.GetNodeId())
	resolver := &testLocationResolver{}
	f.service.locationResolver = resolver
	envelope := &lanewayv1.ControllerEnvelope{SchemaVersion: controllerSchemaVersion, RequestId: 1, Body: &lanewayv1.ControllerEnvelope_ConfigurationRequest{ConfigurationRequest: &lanewayv1.ConfigurationRequest{}}}
	encoded, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	if err := protocol.WriteControlFrame(&input, encoded, protocol.DefaultMaxControlFrame); err != nil {
		t.Fatal(err)
	}
	stream := &locationTestStream{Reader: bytes.NewReader(input.Bytes())}
	server := &QUICServer{service: f.service, handler: f.service.Handler()}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}}
	peer := identity.AuthenticatedIdentity{Role: identity.IdentityRoleNode, NetworkID: caller.NetworkID, SubjectID: identity.ID(caller.NodeID)}
	if err := server.handleStream(t.Context(), stream, state, peer, "8.8.8.8:54321"); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("QUIC peer address lost: lookups=%d", resolver.calls)
	}
}

func (r *testLocationResolver) Lookup(ip netip.Addr) (*nodelocation.Location, error) {
	r.calls++
	if r.fail {
		return nil, errors.New("lookup failed")
	}
	return &nodelocation.Location{Label: "Toronto, CA", Latitude: 43.65, Longitude: -79.38, AccuracyKM: 50}, nil
}

func TestNodeLocationSourceIgnoresForwardedHeaders(t *testing.T) {
	var caller identity.NodeIdentity
	f := newFixture(t, 0, func(*http.Request) (identity.NodeIdentity, error) { return caller, nil })
	enrollment, response := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "map-node")
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	caller.NetworkID = f.network.ID
	copy(caller.NodeID[:], enrollment.GetNodeId())
	resolver := &testLocationResolver{}
	f.service.locationResolver = resolver
	for _, remote := range []string{"127.0.0.1:1234", "10.1.1.1:1234", "100.96.0.2:1234", "[2001:db8::1]:1234", "malformed"} {
		r := httptest.NewRequest(http.MethodPut, "/v1/status", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "8.8.8.8")
		f.service.observeNodeLocation(r, caller)
	}
	if resolver.calls != 0 {
		t.Fatal("looked up private or forwarded address")
	}
	r := httptest.NewRequest(http.MethodPut, "/v1/status", nil)
	r.RemoteAddr = "8.8.8.8:1234"
	f.service.observeNodeLocation(r, caller)
	if resolver.calls != 1 {
		t.Fatal("public source not resolved")
	}
	path := "/v1/admin/networks/" + f.network.ID.String() + "/node-locations"
	read := jsonRequest(t, f.service.Handler(), http.MethodGet, path, nil)
	if read.Code != http.StatusOK {
		t.Fatal(read.Body.String())
	}
	locationPath := "/v1/admin/nodes/" + caller.NodeID.String() + "/location"
	bad := jsonRequest(t, f.service.Handler(), http.MethodPut, locationPath, map[string]any{"label": "Office"})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("missing coordinates: %d %s", bad.Code, bad.Body.String())
	}
	good := jsonRequest(t, f.service.Handler(), http.MethodPut, locationPath, map[string]any{"label": "Office", "latitude": 0, "longitude": 0})
	if good.Code != http.StatusNoContent {
		t.Fatal(good.Body.String())
	}
	deleted := jsonRequest(t, f.service.Handler(), http.MethodDelete, locationPath, nil)
	if deleted.Code != http.StatusNoContent {
		t.Fatal(deleted.Body.String())
	}
	// Exercise the authenticated handler with a resolver failure: health reporting
	// still succeeds, and an old inferred position must not remain current.
	network, err := f.store.Network(t.Context(), f.network.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(validEndpointStatusRequest(network.ConfigurationEpoch))
	if err != nil {
		t.Fatal(err)
	}
	status := httptest.NewRequest(http.MethodPut, "/v1/status", bytes.NewReader(body))
	status.Header.Set("Content-Type", "application/json")
	status.RemoteAddr = "8.8.8.8:1234"
	resolver.fail = true
	recorder := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(recorder, status)
	if recorder.Code != http.StatusNoContent || resolver.calls != 2 {
		t.Fatalf("failed enrichment broke status: %d calls=%d %s", recorder.Code, resolver.calls, recorder.Body.String())
	}
	read = jsonRequest(t, f.service.Handler(), http.MethodGet, path, nil)
	var decoded struct {
		Locations []struct {
			Source string `json:"source"`
		} `json:"node_locations"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Locations) != 1 || decoded.Locations[0].Source != "unknown" {
		t.Fatalf("failed lookup retained old location: %s", read.Body.String())
	}
}
