package controllerservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func applicationHTTPPKCE(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestApplicationRegistrationStartIsStrictAndRedirectsToConsent(t *testing.T) {
	fixture := newFixture(t, DefaultMaxBodyBytes, nil)
	manifest, err := json.Marshal(map[string]any{
		"name":                       "Example deployment controller",
		"homepage_uri":               "https://client.example.com",
		"setup_uri":                  "https://client.example.com/setup",
		"redirect_uris":              []string{"https://client.example.com/callback"},
		"scopes":                     []string{"network.read", "node.read"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{
		"manifest":              {string(manifest)},
		"state":                 {"opaque-state"},
		"code_challenge":        {applicationHTTPPKCE(strings.Repeat("v", 48))},
		"code_challenge_method": {"S256"},
	}
	request := httptest.NewRequest(http.MethodPost, "/applications/new", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || !strings.HasPrefix(response.Header().Get("Location"), "/applications/consent?request=") {
		t.Fatalf("registration status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if strings.TrimPrefix(response.Header().Get("Location"), "/applications/consent?request=") == "" {
		t.Fatal("registration omitted request identifier")
	}

	duplicate := url.Values(values)
	duplicate["state"] = []string{"one", "two"}
	request = httptest.NewRequest(http.MethodPost, "/applications/new", strings.NewReader(duplicate.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response = httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("duplicate status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestApplicationPublicErrorsAndUnsupportedInstallerMode(t *testing.T) {
	fixture := newFixture(t, DefaultMaxBodyBytes, nil)
	token := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"}, "code_verifier": {strings.Repeat("v", 48)}, "redirect_uri": {"https://client.example.com/callback"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(token.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("unknown:secret")))
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("token error status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}

	body := bytes.NewBufferString(`{"name":"private-services","kind":"connector","install_mode":"docker_compose"}`)
	request = httptest.NewRequest(http.MethodPost, "/v1/admin/networks/"+fixture.network.ID.String()+"/node-installers", body)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), `"code":"unsupported_mode"`) ||
		!strings.Contains(response.Body.String(), `"request_id":`) {
		t.Fatalf("installer error status=%d body=%s", response.Code, response.Body.String())
	}
}
