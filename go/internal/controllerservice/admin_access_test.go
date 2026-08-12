package controllerservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
	servicePrincipalID := identity.ID{1}
	root := RequestActor{
		Credential: CredentialRootBearer,
		Actor:      adminauth.IDActor(adminauth.ActorServicePrincipal, servicePrincipalID),
	}
	if !root.Valid() {
		t.Fatal("valid root actor rejected")
	}
	principalID, sessionID := identity.ID{2}, identity.ID{3}
	principal := adminauth.Principal{ID: principalID, Username: "owner", Role: adminauth.RoleOwner, Enabled: true, AllNetworks: true}
	csrf := [sha256.Size]byte{4}
	session := RequestActor{
		Credential: CredentialAdministratorSession,
		Actor:      adminauth.IDActor(adminauth.ActorAdministrator, principalID),
		Principal:  &principal,
		SessionID:  &sessionID,
		CSRFHash:   csrf,
	}
	if !session.Valid() {
		t.Fatal("valid session actor rejected")
	}

	wrongID := identity.ID{9}
	invalid := []RequestActor{
		{},
		{Credential: CredentialRootBearer, Actor: adminauth.SystemActor()},
		{Credential: CredentialRootBearer, Actor: root.Actor, Principal: &principal},
		{Credential: CredentialRootBearer, Actor: root.Actor, SessionID: &sessionID},
		{Credential: CredentialRootBearer, Actor: root.Actor, CSRFHash: csrf},
		{Credential: CredentialAdministratorSession, Actor: session.Actor, Principal: &principal, SessionID: &sessionID},
		{Credential: CredentialAdministratorSession, Actor: adminauth.IDActor(adminauth.ActorAdministrator, wrongID), Principal: &principal, SessionID: &sessionID, CSRFHash: csrf},
		{Credential: CredentialAdministratorSession, Actor: session.Actor, Principal: &principal, CSRFHash: csrf},
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

type accessControllerStub struct{}

func (accessControllerStub) Authenticate(context.Context, *http.Request) (RequestActor, error) {
	id := identity.ID{1}
	return RequestActor{Credential: CredentialRootBearer, Actor: adminauth.IDActor(adminauth.ActorServicePrincipal, id)}, nil
}

func (accessControllerStub) Authorize(_ context.Context, actor RequestActor, operation adminauth.Operation, networkID *identity.NetworkID) (Decision, error) {
	return NewDecision(actor, operation, networkID)
}

func TestDecisionValidationAndDefensiveCopies(t *testing.T) {
	actorID := identity.ID{1}
	sessionID := identity.ID{4}
	networkID := identity.NetworkID{2}
	actor := adminauth.IDActor(adminauth.ActorAdministrator, actorID)
	principal := adminauth.Principal{ID: actorID, Username: "operator", Role: adminauth.RoleOperator, Enabled: true, AllNetworks: true}
	requestActor := RequestActor{
		Credential: CredentialAdministratorSession, Actor: actor, Principal: &principal,
		SessionID: &sessionID, CSRFHash: [sha256.Size]byte{1},
	}
	decision, err := NewDecision(requestActor, adminauth.OperationRouteManage, &networkID)
	if err != nil || !decision.Valid() {
		t.Fatalf("valid scoped decision=%+v err=%v", decision, err)
	}
	if !decision.Matches(requestActor, adminauth.OperationRouteManage, &networkID) {
		t.Fatal("valid decision did not match its authorization input")
	}
	otherNetwork := identity.NetworkID{5}
	otherPrincipalID := identity.ID{6}
	otherPrincipal := principal
	otherPrincipal.ID = otherPrincipalID
	otherActor := requestActor
	otherActor.Actor = adminauth.IDActor(adminauth.ActorAdministrator, otherPrincipalID)
	otherActor.Principal = &otherPrincipal
	otherSession := requestActor
	otherSessionID := identity.ID{7}
	otherSession.SessionID = &otherSessionID
	for name, matches := range map[string]bool{
		"operation": decision.Matches(requestActor, adminauth.OperationACLManage, &networkID),
		"network":   decision.Matches(requestActor, adminauth.OperationRouteManage, &otherNetwork),
		"nil scope": decision.Matches(requestActor, adminauth.OperationRouteManage, nil),
		"actor":     decision.Matches(otherActor, adminauth.OperationRouteManage, &networkID),
		"session":   decision.Matches(otherSession, adminauth.OperationRouteManage, &networkID),
		"invalid":   decision.Matches(RequestActor{}, adminauth.OperationRouteManage, &networkID),
	} {
		if matches {
			t.Errorf("decision matched mismatched %s", name)
		}
	}
	actor.ID[0] = 9
	sessionID[0] = 9
	networkID[0] = 9
	if decision.Actor().ID == nil || *decision.Actor().ID != (identity.ID{1}) || decision.Operation() != adminauth.OperationRouteManage ||
		decision.Credential() != CredentialAdministratorSession || decision.SessionID() == nil || *decision.SessionID() != (identity.ID{4}) ||
		decision.NetworkID() == nil || *decision.NetworkID() != (identity.NetworkID{2}) {
		t.Fatalf("decision retained caller-owned storage: %+v scope=%v", decision, decision.NetworkID())
	}
	returnedActor := decision.Actor()
	returnedActor.ID[0] = 8
	if *decision.Actor().ID != (identity.ID{1}) {
		t.Fatalf("decision exposed mutable actor: %+v", decision.Actor())
	}
	returned := decision.NetworkID()
	returned[0] = 7
	if *decision.NetworkID() != (identity.NetworkID{2}) {
		t.Fatalf("decision exposed mutable scope: %v", decision.NetworkID())
	}
	returnedSession := decision.SessionID()
	returnedSession[0] = 7
	if *decision.SessionID() != (identity.ID{4}) {
		t.Fatalf("decision exposed mutable session: %v", decision.SessionID())
	}

	serviceID := identity.ID{3}
	root := RequestActor{Credential: CredentialRootBearer, Actor: adminauth.IDActor(adminauth.ActorServicePrincipal, serviceID)}
	global, err := NewDecision(root, adminauth.OperationNetworkList, nil)
	if err != nil || !global.Valid() || global.NetworkID() != nil {
		t.Fatalf("valid global decision=%+v err=%v", global, err)
	}
	for name, test := range map[string]struct {
		actor     RequestActor
		operation adminauth.Operation
		network   *identity.NetworkID
	}{
		"invalid actor":     {actor: RequestActor{}, operation: adminauth.OperationNetworkList},
		"system actor":      {actor: RequestActor{Credential: CredentialRootBearer, Actor: adminauth.SystemActor()}, operation: adminauth.OperationNetworkList},
		"invalid operation": {actor: root, operation: "unknown"},
		"missing scope":     {actor: root, operation: adminauth.OperationRouteManage},
		"unexpected scope":  {actor: root, operation: adminauth.OperationNetworkList, network: &networkID},
		"zero scope":        {actor: root, operation: adminauth.OperationRouteManage, network: new(identity.NetworkID)},
	} {
		t.Run(name, func(t *testing.T) {
			if decision, err := NewDecision(test.actor, test.operation, test.network); err == nil || decision.Valid() {
				t.Fatalf("invalid decision accepted: %+v err=%v", decision, err)
			}
		})
	}
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
		Credential: CredentialAdministratorSession,
		Actor:      adminauth.IDActor(adminauth.ActorAdministrator, principalID),
		Principal:  &principal,
		SessionID:  &sessionID,
		CSRFHash:   digest,
	}
	root := RequestActor{Credential: CredentialRootBearer, Actor: adminauth.IDActor(adminauth.ActorServicePrincipal, serviceID)}

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
