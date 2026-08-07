package controllerservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
)

func TestEnrollmentRateLimiterIsPerSourceBoundedAndRefills(t *testing.T) {
	limiter := newEnrollmentRateLimiter()
	now := time.Unix(2_000_000_000, 0).UTC()
	for i := 0; i < int(enrollmentRateBurst); i++ {
		if !limiter.allow("192.0.2.10:1234", now) {
			t.Fatalf("request %d unexpectedly limited", i)
		}
	}
	if limiter.allow("192.0.2.10:1234", now) {
		t.Fatal("burst limit was not enforced")
	}
	if !limiter.allow("192.0.2.11:1234", now) {
		t.Fatal("one source consumed another source's budget")
	}
	if !limiter.allow("192.0.2.10:1234", now.Add(time.Second)) {
		t.Fatal("rate budget did not refill")
	}
	if limiter.allow("not-a-remote-address", now) {
		t.Fatal("malformed remote address bypassed limiter")
	}
}

func TestEnrollmentRateLimitReturnsBoundedProtocolError(t *testing.T) {
	fixture := newFixture(t, DefaultMaxBodyBytes, nil)
	fixedNow := time.Unix(2_000_000_000, 0).UTC()
	fixture.service.now = func() time.Time { return fixedNow }
	for i := 0; i < int(enrollmentRateBurst); i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader([]byte{0xff}))
		request.Header.Set("Content-Type", "application/x-protobuf")
		response := httptest.NewRecorder()
		fixture.service.Handler().ServeHTTP(response, request)
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was limited before the burst was consumed", i)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader([]byte{0xff}))
	request.Header.Set("Content-Type", "application/x-protobuf")
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("limited response status=%d headers=%v", response.Code, response.Header())
	}
	problem := new(lanewayv1.ProtocolError)
	if err := proto.Unmarshal(response.Body.Bytes(), problem); err != nil || problem.GetCode() != lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED || !strings.Contains(problem.GetDetail(), "retry") {
		t.Fatalf("limited problem=%+v err=%v", problem, err)
	}
}
