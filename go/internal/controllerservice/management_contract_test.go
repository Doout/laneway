package controllerservice

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

var administratorRequestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func administratorErrorEnvelope(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	result := response.Result()
	defer result.Body.Close()
	var envelope map[string]any
	if err := json.NewDecoder(result.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode administrator error: %v", err)
	}
	requestID := result.Header.Get(AdministratorRequestIDHeader)
	if !administratorRequestIDPattern.MatchString(requestID) {
		t.Fatalf("invalid response request ID %q", requestID)
	}
	if envelope["request_id"] != requestID {
		t.Fatalf("header request ID %q != envelope request ID %#v", requestID, envelope["request_id"])
	}
	return envelope
}

func TestAdministratorHTTPContractCorrelatesSuccessAndErrors(t *testing.T) {
	fixture := newFixture(t, 0, nil)

	successRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/networks?limit=1", nil)
	spoofed := "f" + "0000000000000000000000000000000"
	successRequest.Header.Set(AdministratorRequestIDHeader, spoofed)
	success := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(success, successRequest)
	if success.Code != http.StatusOK {
		t.Fatalf("success status=%d body=%s", success.Code, success.Body.String())
	}
	firstID := success.Result().Header.Get(AdministratorRequestIDHeader)
	if !administratorRequestIDPattern.MatchString(firstID) || firstID == spoofed {
		t.Fatalf("success request ID=%q spoofed=%q", firstID, spoofed)
	}

	fixture.service.access = accessControllerErrorStub{err: ErrUnauthenticated}
	unauthorized := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/admin/networks", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}
	envelope := administratorErrorEnvelope(t, unauthorized)
	if envelope["code"] != "ERROR_CODE_UNAUTHENTICATED" || envelope["retryable"] != false {
		t.Fatalf("unauthorized envelope=%#v", envelope)
	}
	if envelope["request_id"] == firstID {
		t.Fatal("separate requests reused a request ID")
	}
}

func TestAdministratorHTTPContractNormalizesMuxAndCanonicalPathErrors(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantAllow  string
	}{
		{name: "unknown route", method: http.MethodGet, path: "/v1/admin/not-a-route", wantStatus: http.StatusNotFound},
		{name: "wrong method", method: http.MethodDelete, path: "/v1/admin/auth/state", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD"},
		{name: "duplicate slash", method: http.MethodGet, path: "/v1/admin//auth/state", wantStatus: http.StatusBadRequest},
		{name: "dot segment", method: http.MethodGet, path: "/v1/admin/./auth/state", wantStatus: http.StatusBadRequest},
		{name: "encoded dot segment", method: http.MethodGet, path: "/v1/admin/%2e%2e/health", wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			fixture.service.Handler().ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			result := response.Result()
			if location := result.Header.Get("Location"); location != "" {
				t.Fatalf("administrator error redirected to %q", location)
			}
			if test.wantAllow != "" && result.Header.Get("Allow") != test.wantAllow {
				t.Fatalf("Allow=%q want %q", result.Header.Get("Allow"), test.wantAllow)
			}
			administratorErrorEnvelope(t, response)
		})
	}

	nonAdministrator := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(nonAdministrator, httptest.NewRequest(http.MethodGet, "/v1/not-a-route", nil))
	if nonAdministrator.Header().Get(AdministratorRequestIDHeader) != "" {
		t.Fatal("non-administrator route received an administrator request ID")
	}
}

func TestAdministratorHTTPContractFailsClosedWithUniqueFallbackIDs(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	fixture.service.requestIDGenerator = func() (string, error) { return "", errors.New("random unavailable") }
	seen := make(map[string]struct{})
	for range 2 {
		response := httptest.NewRecorder()
		fixture.service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/auth/state", nil))
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		envelope := administratorErrorEnvelope(t, response)
		requestID := envelope["request_id"].(string)
		if _, duplicate := seen[requestID]; duplicate {
			t.Fatalf("fallback request ID %q was reused", requestID)
		}
		seen[requestID] = struct{}{}
	}
}

func TestAdministratorHTTPContractContextAndJSONGuard(t *testing.T) {
	const requestID = "0123456789abcdef0123456789abcdef"
	service := &Service{requestIDGenerator: func() (string, error) { return requestID, nil }}
	handler := service.administratorHTTPContract(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := administratorRequestID(r.Context()); got != requestID {
			t.Errorf("context request ID=%q", got)
		}
		service.writeJSON(w, http.StatusTeapot, map[string]any{
			"code": "ERROR_CODE_INTERNAL", "detail": "failure", "retryable": false,
		})
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/example", nil))
	if response.Code != http.StatusTeapot {
		t.Fatalf("status=%d", response.Code)
	}
	administratorErrorEnvelope(t, response)
}
