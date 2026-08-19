package controllerservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

func validEndpointStatusRequest(epoch uint64) endpointStatusRequest {
	cleanupFailures := uint32(0)
	return endpointStatusRequest{
		ValidForSeconds: 30, ProductVersion: "1.2.3", Platform: "linux",
		CertificateState: "healthy", ConfigurationState: "current", CarrierState: "relay_quic",
		RouteState: "ready", SelectedExitState: "not_selected", CleanupFailures: &cleanupFailures,
		ConfigurationEpoch: &epoch,
	}
}

func TestEndpointStatusRequiresNodeAuthenticationBeforeParsing(t *testing.T) {
	f := newFixture(t, 0, nil)
	request := httptest.NewRequest(http.MethodPut, "/v1/status", bytes.NewBufferString(`{"unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEndpointStatusRejectsExpiredCustomAuthorizedLeaseBeforeParsing(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, 0, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	token, err := f.store.IssueEnrollmentTokenWithOptions(t.Context(), f.network.ID, "expired-status-node",
		time.Now().Add(time.Hour), controller.EnrollmentTokenOptions{
			Class: controller.EnrollmentClassEphemeral, SessionLifetime: controller.MinEphemeralLifetime,
		})
	if err != nil {
		t.Fatal(err)
	}
	node, err := f.store.EnrollNode(t.Context(), token.Secret, "expired-status-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	authenticated = identity.NodeIdentity{NetworkID: f.network.ID, NodeID: node.ID}
	f.service.now = func() time.Time { return *node.LeaseExpiresAt }

	request := httptest.NewRequest(http.MethodPut, "/v1/status", bytes.NewBufferString(`{"unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired lease status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEndpointStatusLifecycleAndAdminProjection(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, 0, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	enrollment, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "status-node")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
	}
	authenticated.NetworkID = f.network.ID
	copy(authenticated.NodeID[:], enrollment.GetNodeId())
	network, err := f.store.Network(t.Context(), f.network.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	f.service.now = func() time.Time { return now }

	recorded := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/status",
		validEndpointStatusRequest(network.ConfigurationEpoch))
	if recorded.Code != http.StatusNoContent || recorded.Body.Len() != 0 {
		t.Fatalf("record status=%d body=%s", recorded.Code, recorded.Body.String())
	}
	path := "/v1/admin/networks/" + f.network.ID.String() + "/endpoint-statuses?limit=10"
	current := jsonRequest(t, f.service.Handler(), http.MethodGet, path, nil)
	if current.Code != http.StatusOK {
		t.Fatalf("read current status=%d body=%s", current.Code, current.Body.String())
	}
	var currentBody struct {
		Statuses []endpointStatusResponse `json:"endpoint_statuses"`
	}
	decodeJSONResponse(t, current, &currentBody)
	if len(currentBody.Statuses) != 1 || currentBody.Statuses[0].Freshness != "current" ||
		currentBody.Statuses[0].Report == nil || currentBody.Statuses[0].Report.CarrierState != "relay_quic" ||
		currentBody.Statuses[0].AuthoritativeConfigurationEpoch != network.ConfigurationEpoch {
		t.Fatalf("current status body=%+v", currentBody)
	}

	now = now.Add(30 * time.Second)
	expired := jsonRequest(t, f.service.Handler(), http.MethodGet, path, nil)
	var expiredBody struct {
		Statuses []endpointStatusResponse `json:"endpoint_statuses"`
	}
	decodeJSONResponse(t, expired, &expiredBody)
	if len(expiredBody.Statuses) != 1 || expiredBody.Statuses[0].Freshness != "expired" ||
		expiredBody.Statuses[0].Report != nil || expiredBody.Statuses[0].LastReportedAtUnixSeconds == nil ||
		expiredBody.Statuses[0].ExpiresAtUnixSeconds == nil {
		t.Fatalf("expired status body=%+v", expiredBody)
	}
}

func TestEndpointStatusRejectsUnknownFieldsStatesAndFutureEpoch(t *testing.T) {
	var authenticated identity.NodeIdentity
	f := newFixture(t, 0, func(*http.Request) (identity.NodeIdentity, error) { return authenticated, nil })
	enrollment, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "strict-status-node")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", result.Code, result.Body.String())
	}
	authenticated.NetworkID = f.network.ID
	copy(authenticated.NodeID[:], enrollment.GetNodeId())
	network, err := f.store.Network(t.Context(), f.network.ID)
	if err != nil {
		t.Fatal(err)
	}

	unknown := httptest.NewRequest(http.MethodPut, "/v1/status",
		bytes.NewBufferString(`{"valid_for_seconds":30,"unexpected":"private endpoint"}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResult := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(unknownResult, unknown)
	if unknownResult.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d body=%s", unknownResult.Code, unknownResult.Body.String())
	}
	missingRequired := validEndpointStatusRequest(network.ConfigurationEpoch)
	missingRequired.CleanupFailures = nil
	if response := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/status", missingRequired); response.Code != http.StatusBadRequest {
		t.Fatalf("missing cleanup failure count status=%d body=%s", response.Code, response.Body.String())
	}
	invalid := validEndpointStatusRequest(network.ConfigurationEpoch)
	invalid.CarrierState = "healthy"
	if response := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/status", invalid); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown carrier status=%d body=%s", response.Code, response.Body.String())
	}
	future := validEndpointStatusRequest(network.ConfigurationEpoch + 1)
	if response := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/status", future); response.Code != http.StatusConflict {
		t.Fatalf("future epoch status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := f.store.RevokeNode(t.Context(), authenticated.NodeID, "status authentication test"); err != nil {
		t.Fatal(err)
	}
	if response := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/status",
		validEndpointStatusRequest(network.ConfigurationEpoch)); response.Code != http.StatusForbidden {
		t.Fatalf("revoked node status=%d body=%s", response.Code, response.Body.String())
	}

	// The strict request surface never accepts private endpoint or peer data.
	encoded, err := json.Marshal(validEndpointStatusRequest(network.ConfigurationEpoch))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("endpoint")) || bytes.Contains(encoded, []byte("peer")) {
		t.Fatalf("status request unexpectedly exposes high-cardinality data: %s", encoded)
	}
}
