package controllerservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

func TestBootstrapBundleIsBoundedSingleUseAndExpires(t *testing.T) {
	f := newFixture(t, 0, nil)
	now := time.Unix(2_000_000_000, 0).UTC()
	f.service.now = func() time.Time { return now }
	f.service.bootstrapBundles.now = f.service.now
	payload := "#!/bin/bash\nprintf 'encrypted wrapper'\n"

	create := func(expiry time.Time) bootstrapBundleResponse {
		t.Helper()
		body, err := json.Marshal(bootstrapBundleRequest{Payload: payload, ExpiresAtUnix: expiry.Unix()})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/bootstrap-bundles", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusCreated {
			t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
		}
		var result bootstrapBundleResponse
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.BundleID) != bootstrap.BundleIDLength || result.PublicPath != bootstrap.BundlePathPrefix+result.BundleID {
			t.Fatalf("bundle response = %+v", result)
		}
		return result
	}

	first := create(now.Add(bootstrap.MaxBundleLifetime))
	authState, err := f.store.AdministratorAuthState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	events, err := f.store.GlobalAuditEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	foundCreateAudit := false
	for _, event := range events {
		if event.Action == "bootstrap_bundle.create" && event.Actor.Kind == adminauth.ActorServicePrincipal &&
			event.Actor.ID != nil && *event.Actor.ID == authState.RootServicePrincipalID {
			foundCreateAudit = true
		}
	}
	if !foundCreateAudit {
		t.Fatal("bootstrap bundle creation omitted stable root service-principal audit")
	}
	privateRequest := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(privateRequest, httptest.NewRequest(http.MethodGet, "/v1/bootstrap-bundles/"+first.BundleID, nil))
	if privateRequest.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated private fetch status = %d", privateRequest.Code)
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	uri, err := (pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: serviceID, Role: pki.RoleRelay}).URI()
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{URIs: []*url.URL{uri}}
	relayRequest := func(bundleID string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/v1/bootstrap-bundles/"+bundleID, nil)
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
		return request
	}
	download := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(download, relayRequest(first.BundleID))
	if download.Code != http.StatusOK || download.Body.String() != payload || !strings.HasPrefix(download.Header().Get("Content-Type"), "text/x-shellscript") {
		t.Fatalf("download status=%d type=%q body=%q", download.Code, download.Header().Get("Content-Type"), download.Body.String())
	}
	replay := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(replay, relayRequest(first.BundleID))
	if replay.Code != http.StatusNotFound {
		t.Fatalf("replay status = %d", replay.Code)
	}

	concurrent := create(now.Add(time.Minute))
	const requestCount = 32
	codes := make(chan int, requestCount)
	var requests sync.WaitGroup
	for index := 0; index < requestCount; index++ {
		requests.Add(1)
		go func() {
			defer requests.Done()
			response := httptest.NewRecorder()
			f.service.Handler().ServeHTTP(response, relayRequest(concurrent.BundleID))
			codes <- response.Code
		}()
	}
	requests.Wait()
	close(codes)
	ok, missing := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusNotFound:
			missing++
		default:
			t.Fatalf("concurrent download status = %d", code)
		}
	}
	if ok != 1 || missing != requestCount-1 {
		t.Fatalf("concurrent downloads: ok=%d not-found=%d", ok, missing)
	}

	private := create(now.Add(time.Minute))
	privateResponse := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(privateResponse, relayRequest(private.BundleID))
	if privateResponse.Code != http.StatusOK || privateResponse.Body.String() != payload {
		t.Fatalf("relay fetch status=%d body=%q", privateResponse.Code, privateResponse.Body.String())
	}

	expired := create(now.Add(time.Minute))
	now = now.Add(time.Minute)
	expiredResponse := httptest.NewRecorder()
	f.service.Handler().ServeHTTP(expiredResponse, relayRequest(expired.BundleID))
	if expiredResponse.Code != http.StatusNotFound {
		t.Fatalf("expired status = %d", expiredResponse.Code)
	}
}

func TestBootstrapBundleRejectsUnsafePayloadAndLifetime(t *testing.T) {
	f := newFixture(t, 0, nil)
	now := time.Unix(2_000_000_000, 0).UTC()
	f.service.now = func() time.Time { return now }
	f.service.bootstrapBundles.now = f.service.now
	for _, requestBody := range []bootstrapBundleRequest{
		{Payload: "not a script", ExpiresAtUnix: now.Add(time.Minute).Unix()},
		{Payload: "#!/bin/bash\necho ok\n", ExpiresAtUnix: now.Add(bootstrap.MaxBundleLifetime + time.Second).Unix()},
	} {
		body, _ := json.Marshal(requestBody)
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/bootstrap-bundles", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsafe request status=%d body=%s", response.Code, response.Body.String())
		}
	}
}
