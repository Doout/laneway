package controllerservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

func TestDetectAdminCredential(t *testing.T) {
	newRequest := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/networks", nil)
	}
	tests := []struct {
		name string
		edit func(*http.Request)
		want CredentialKind
		err  error
	}{
		{name: "none", want: CredentialNone},
		{name: "bearer", edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer root-secret") }, want: CredentialRootBearer},
		{name: "case-insensitive bearer scheme", edit: func(r *http.Request) { r.Header.Set("Authorization", "bearer root-secret") }, want: CredentialRootBearer},
		{name: "session", edit: func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "session-secret"})
		}, want: CredentialAdministratorSession},
		{name: "mixed bearer and session", edit: func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer root-secret")
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "session-secret"})
		}, err: ErrMixedAdminCredentials},
		{name: "mixed unsupported authorization and session", edit: func(r *http.Request) {
			r.Header.Set("Authorization", "Basic credential")
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "session-secret"})
		}, err: ErrMixedAdminCredentials},
		{name: "duplicate authorization", edit: func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer first")
			r.Header.Add("Authorization", "Bearer second")
		}, err: ErrMalformedAdminCredentials},
		{name: "duplicate session", edit: func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "first"})
			r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "second"})
		}, err: ErrMalformedAdminCredentials},
		{name: "empty authorization", edit: func(r *http.Request) { r.Header["Authorization"] = []string{""} }, err: ErrMalformedAdminCredentials},
		{name: "unsupported scheme", edit: func(r *http.Request) { r.Header.Set("Authorization", "Basic credential") }, err: ErrMalformedAdminCredentials},
		{name: "missing bearer value", edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer") }, err: ErrMalformedAdminCredentials},
		{name: "extra bearer whitespace", edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer  credential") }, err: ErrMalformedAdminCredentials},
		{name: "embedded bearer whitespace", edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer cred\tential") }, err: ErrMalformedAdminCredentials},
		{name: "combined bearer values", edit: func(r *http.Request) { r.Header.Set("Authorization", "Bearer first,Bearer second") }, err: ErrMalformedAdminCredentials},
		{name: "empty session", edit: func(r *http.Request) { r.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName}) }, err: ErrMalformedAdminCredentials},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest()
			if test.edit != nil {
				test.edit(request)
			}
			got, err := DetectAdminCredential(request)
			if got != test.want || !errors.Is(err, test.err) {
				t.Fatalf("DetectAdminCredential()=(%q,%v), want (%q,%v)", got, err, test.want, test.err)
			}
		})
	}
	if got, err := DetectAdminCredential(nil); got != CredentialNone || !errors.Is(err, ErrMalformedAdminCredentials) {
		t.Fatalf("nil request=(%q,%v)", got, err)
	}
}

func TestRequestActorValidationAndAccessControllerContract(t *testing.T) {
	now := time.Now().UTC()
	servicePrincipalID := identity.ID{1}
	root := RequestActor{
		Credential: CredentialRootBearer,
		Subject:    adminauth.RootSubject(servicePrincipalID),
	}
	if !root.Valid() {
		t.Fatal("valid root actor rejected")
	}
	principalID, sessionID := identity.ID{2}, identity.ID{3}
	principal := adminauth.Principal{ID: principalID, Username: "owner", Role: adminauth.RoleOwner, Enabled: true, AllNetworks: true}
	csrf := [sha256.Size]byte{4}
	session := RequestActor{
		Credential:   CredentialAdministratorSession,
		Subject:      adminauth.SessionSubject(principalID, sessionID),
		Principal:    &principal,
		CSRFHash:     csrf,
		IdleLifetime: time.Minute, IdleExpiresAt: now.Add(time.Minute), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if !session.Valid() {
		t.Fatal("valid session actor rejected")
	}

	wrongID := identity.ID{9}
	invalid := []RequestActor{
		{},
		{Credential: CredentialRootBearer},
		{Credential: CredentialRootBearer, Subject: root.Subject, Principal: &principal},
		{Credential: CredentialRootBearer, Subject: root.Subject, CSRFHash: csrf},
		{Credential: CredentialAdministratorSession, Subject: session.Subject, Principal: &principal},
		{Credential: CredentialAdministratorSession, Subject: adminauth.SessionSubject(wrongID, sessionID), Principal: &principal, CSRFHash: csrf},
		{Credential: CredentialAdministratorSession, Subject: adminauth.SessionSubject(principalID, identity.ID{}), Principal: &principal, CSRFHash: csrf},
	}
	for index, actor := range invalid {
		if actor.Valid() {
			t.Errorf("invalid actor %d accepted: %+v", index, actor)
		}
	}

	var _ AccessController = accessControllerStub{}
	actor, err := (accessControllerStub{}).Authenticate(context.Background(), httptest.NewRequest(http.MethodGet, "https://controller.example/", nil))
	if err != nil || !actor.Valid() {
		t.Fatalf("stub authentication actor=%+v err=%v", actor, err)
	}
}

type accessControllerStub struct{ rootID identity.ID }

func (s accessControllerStub) Authenticate(context.Context, *http.Request) (RequestActor, error) {
	id := s.rootID
	if id.IsZero() {
		id = identity.ID{1}
	}
	return RequestActor{Credential: CredentialRootBearer, Subject: adminauth.RootSubject(id)}, nil
}

type accessControllerErrorStub struct{ err error }

func (s accessControllerErrorStub) Authenticate(context.Context, *http.Request) (RequestActor, error) {
	return RequestActor{}, s.err
}

func (s accessControllerErrorStub) Authorize(context.Context, RequestActor, adminauth.RoutePolicy,
	adminauth.DecisionTarget) (adminauth.Decision, error) {
	return adminauth.Decision{}, s.err
}

func (accessControllerStub) Authorize(_ context.Context, actor RequestActor, policy adminauth.RoutePolicy, target adminauth.DecisionTarget) (adminauth.Decision, error) {
	return adminauth.NewDecision(actor.Subject, policy, target)
}

func TestValidateSameOrigin(t *testing.T) {
	newRequest := func(host, origin string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "https://"+host+"/v1/admin/networks", nil)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		return request
	}
	tests := []struct {
		name    string
		host    string
		origin  string
		edit    func(*http.Request)
		wantErr bool
	}{
		{name: "same origin", host: "controller.example", origin: "https://controller.example"},
		{name: "default port", host: "controller.example:443", origin: "https://controller.example"},
		{name: "case insensitive host", host: "CONTROLLER.EXAMPLE", origin: "https://controller.example"},
		{name: "same IPv6 origin", host: "[2001:db8::1]:8443", origin: "https://[2001:0db8::1]:8443"},
		{name: "mapped IPv6 is not IPv4 origin", host: "[::ffff:192.0.2.1]", origin: "https://192.0.2.1", wantErr: true},
		{name: "same origin fetch metadata", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-origin") }},
		{name: "missing origin", host: "controller.example", wantErr: true},
		{name: "insecure origin", host: "controller.example", origin: "http://controller.example", wantErr: true},
		{name: "different host", host: "controller.example", origin: "https://other.example", wantErr: true},
		{name: "different port", host: "controller.example:8443", origin: "https://controller.example:9443", wantErr: true},
		{name: "null origin", host: "controller.example", origin: "null", wantErr: true},
		{name: "origin user info", host: "controller.example", origin: "https://user@controller.example", wantErr: true},
		{name: "origin path", host: "controller.example", origin: "https://controller.example/path", wantErr: true},
		{name: "origin slash", host: "controller.example", origin: "https://controller.example/", wantErr: true},
		{name: "origin query", host: "controller.example", origin: "https://controller.example?query", wantErr: true},
		{name: "origin fragment", host: "controller.example", origin: "https://controller.example#fragment", wantErr: true},
		{name: "cross site fetch metadata", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, wantErr: true},
		{name: "same site fetch metadata", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, wantErr: true},
		{name: "duplicate fetch metadata", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) {
			r.Header.Add("Sec-Fetch-Site", "same-origin")
			r.Header.Add("Sec-Fetch-Site", "same-origin")
		}, wantErr: true},
		{name: "duplicate origin", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.Header.Add("Origin", "https://controller.example") }, wantErr: true},
		{name: "invalid request host", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.Host = "controller.example/path" }, wantErr: true},
		{name: "IPv6 zone", host: "[fe80::1%25en0]:8443", origin: "https://[fe80::1%25en0]:8443", wantErr: true},
		{name: "no TLS", host: "controller.example", origin: "https://controller.example", edit: func(r *http.Request) { r.TLS = nil }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest(test.host, test.origin)
			if test.edit != nil {
				test.edit(request)
			}
			err := ValidateSameOrigin(request)
			if (err != nil) != test.wantErr || err != nil && !errors.Is(err, ErrBrowserOrigin) {
				t.Fatalf("ValidateSameOrigin()=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
	if err := ValidateSameOrigin(nil); !errors.Is(err, ErrBrowserOrigin) {
		t.Fatalf("nil request error=%v", err)
	}
}

func TestValidateCSRF(t *testing.T) {
	token, digest, err := adminauth.NewSecret(adminauth.SecretCSRF, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	otherToken, otherDigest, err := adminauth.NewSecret(adminauth.SecretCSRF, bytes.NewReader(bytes.Repeat([]byte{8}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "https://controller.example/v1/admin/networks", nil)
		request.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: token})
		request.Header.Set(adminauth.CSRFHeaderName, token)
		return request
	}
	tests := []struct {
		name    string
		digest  [sha256.Size]byte
		edit    func(*http.Request)
		wantErr bool
	}{
		{name: "valid", digest: digest},
		{name: "zero stored hash", wantErr: true},
		{name: "wrong stored hash", digest: otherDigest, wantErr: true},
		{name: "missing cookie", digest: digest, edit: func(r *http.Request) { r.Header.Del("Cookie") }, wantErr: true},
		{name: "missing header", digest: digest, edit: func(r *http.Request) { r.Header.Del(adminauth.CSRFHeaderName) }, wantErr: true},
		{name: "mismatched header", digest: digest, edit: func(r *http.Request) { r.Header.Set(adminauth.CSRFHeaderName, otherToken) }, wantErr: true},
		{name: "mismatched cookie", digest: digest, edit: func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: otherToken})
		}, wantErr: true},
		{name: "malformed token", digest: digest, edit: func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: "malformed"})
			r.Header.Set(adminauth.CSRFHeaderName, "malformed")
		}, wantErr: true},
		{name: "duplicate cookie", digest: digest, edit: func(r *http.Request) { r.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: token}) }, wantErr: true},
		{name: "duplicate header", digest: digest, edit: func(r *http.Request) { r.Header.Add(adminauth.CSRFHeaderName, token) }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := newRequest()
			if test.edit != nil {
				test.edit(request)
			}
			err := ValidateCSRF(request, test.digest)
			if (err != nil) != test.wantErr || err != nil && !errors.Is(err, ErrCSRF) {
				t.Fatalf("ValidateCSRF()=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
	if err := ValidateCSRF(nil, digest); !errors.Is(err, ErrCSRF) {
		t.Fatalf("nil request error=%v", err)
	}
}

func TestMutationProtectionCredentialBoundary(t *testing.T) {
	token, digest, err := adminauth.NewSecret(adminauth.SecretCSRF, bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	principalID, sessionID, serviceID := identity.ID{1}, identity.ID{2}, identity.ID{3}
	principal := adminauth.Principal{ID: principalID, Username: "operator", Role: adminauth.RoleOperator, Enabled: true, AllNetworks: true}
	session := RequestActor{
		Credential:   CredentialAdministratorSession,
		Subject:      adminauth.SessionSubject(principalID, sessionID),
		Principal:    &principal,
		CSRFHash:     digest,
		IdleLifetime: time.Minute, IdleExpiresAt: time.Now().Add(time.Minute), AbsoluteExpiresAt: time.Now().Add(time.Hour),
	}
	root := RequestActor{Credential: CredentialRootBearer, Subject: adminauth.RootSubject(serviceID)}

	validBrowser := httptest.NewRequest(http.MethodPost, "https://controller.example/v1/admin/networks", nil)
	validBrowser.Header.Set("Origin", "https://controller.example")
	validBrowser.Header.Set("Sec-Fetch-Site", "same-origin")
	validBrowser.Header.Set(adminauth.CSRFHeaderName, token)
	validBrowser.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: token})
	if err := ValidateMutationProtection(validBrowser, session); err != nil {
		t.Fatalf("valid browser mutation: %v", err)
	}

	crossOrigin := validBrowser.Clone(validBrowser.Context())
	crossOrigin.Header.Set("Origin", "https://other.example")
	if err := ValidateMutationProtection(crossOrigin, session); !errors.Is(err, ErrBrowserOrigin) {
		t.Fatalf("cross-origin mutation error=%v", err)
	}

	missingBrowserProof := httptest.NewRequest(http.MethodPost, "https://controller.example/v1/admin/networks", nil)
	if err := ValidateMutationProtection(missingBrowserProof, root); err != nil {
		t.Fatalf("root bearer incorrectly required browser protection: %v", err)
	}

	safe := httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/networks", nil)
	if err := ValidateMutationProtection(safe, session); err != nil {
		t.Fatalf("safe session request incorrectly protected: %v", err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if BrowserMutationRequiresProtection(method) {
			t.Errorf("safe method %s requires mutation protection", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodTrace, ""} {
		if !BrowserMutationRequiresProtection(method) {
			t.Errorf("unsafe method %q bypasses mutation protection", method)
		}
	}
	if err := ValidateMutationProtection(validBrowser, RequestActor{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("invalid actor error=%v", err)
	}
	if err := ValidateMutationProtection(nil, session); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("nil mutation error=%v", err)
	}
}
