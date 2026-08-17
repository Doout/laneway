package controllerservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

const testRootBearer = "root-automation-secret"

func useProductionRootAccess(t *testing.T, fixture fixture) {
	t.Helper()
	fixture.service.authorizeAdm = func(request *http.Request) (adminauth.Actor, error) {
		if request.Header.Get("Authorization") != "Bearer "+testRootBearer {
			return adminauth.Actor{}, ErrUnauthenticated
		}
		state, err := fixture.store.AdministratorAuthState(request.Context())
		if err != nil {
			return adminauth.Actor{}, err
		}
		return adminauth.IDActor(adminauth.ActorServicePrincipal, state.RootServicePrincipalID), nil
	}
	fixture.service.access = &storeAccessController{store: fixture.store, rootBearer: func(request *http.Request) (adminauth.Actor, error) {
		return fixture.service.authorizeAdm(request)
	}}
}

func rootHTTPRequest(method, target string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testRootBearer)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func browserJSONRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Host = "controller.example"
	request.Header.Set("Origin", "https://controller.example")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Content-Type", "application/json")
	return request
}

func bootstrapAdministratorSessionForHTTPTest(t *testing.T, fixture fixture, username, password string) (
	controller.AdministratorSession, string, string, string,
) {
	t.Helper()
	useProductionRootAccess(t, fixture)
	grantResponse := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(grantResponse, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/bootstrap-grants", nil))
	var grant struct {
		Grant string `json:"grant"`
	}
	if grantResponse.Code != http.StatusCreated || json.Unmarshal(grantResponse.Body.Bytes(), &grant) != nil || grant.Grant == "" {
		t.Fatalf("bootstrap grant status=%d body=%s", grantResponse.Code, grantResponse.Body.String())
	}
	passwordHash, err := adminauth.HashPassword([]byte(password), bytes.NewReader(bytes.Repeat([]byte{9}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.BootstrapFirstAdministrator(context.Background(), grant.Grant, username, passwordHash); err != nil {
		t.Fatal(err)
	}
	candidate, err := fixture.store.AdministratorPasswordCandidate(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	session, token, csrf, err := fixture.store.CreateAdministratorSessionAfterPassword(context.Background(), candidate,
		controller.AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return session, token, csrf, passwordHash
}

func TestAdministratorRootProbeAndRotationHTTPContract(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	useProductionRootAccess(t, fixture)
	handler := fixture.service.Handler()

	assertResponse := func(t *testing.T, request *http.Request, status int) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control=%q", response.Header().Get("Cache-Control"))
		}
		return response
	}

	validProbe := assertResponse(t, rootHTTPRequest(http.MethodGet, "https://controller.example/v1/admin/auth/root", nil), http.StatusNoContent)
	if validProbe.Body.Len() != 0 || len(validProbe.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("root probe returned body/cookie: body=%q cookies=%v", validProbe.Body.String(), validProbe.Header().Values("Set-Cookie"))
	}
	assertResponse(t, httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/auth/root", nil), http.StatusUnauthorized)
	invalid := rootHTTPRequest(http.MethodGet, "https://controller.example/v1/admin/auth/root", nil)
	invalid.Header.Set("Authorization", "Bearer wrong")
	assertResponse(t, invalid, http.StatusUnauthorized)
	mixed := rootHTTPRequest(http.MethodGet, "https://controller.example/v1/admin/auth/root", nil)
	mixed.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "session"})
	assertResponse(t, mixed, http.StatusUnauthorized)
	browserBearer := rootHTTPRequest(http.MethodGet, "https://controller.example/v1/admin/auth/root", nil)
	browserBearer.Header.Set("Origin", "https://controller.example")
	assertResponse(t, browserBearer, http.StatusUnauthorized)

	rotationID := "01000000000000000000000000000000"
	beginPath := "https://controller.example/v1/admin/auth/root-token-rotations/" + rotationID + "/begin"
	completePath := "https://controller.example/v1/admin/auth/root-token-rotations/" + rotationID + "/complete"
	otherComplete := "https://controller.example/v1/admin/auth/root-token-rotations/02000000000000000000000000000000/complete"
	assertResponse(t, rootHTTPRequest(http.MethodPost, otherComplete, nil), http.StatusConflict)
	for _, path := range []string{beginPath, beginPath, completePath, completePath} {
		response := assertResponse(t, rootHTTPRequest(http.MethodPost, path, nil), http.StatusNoContent)
		if response.Body.Len() != 0 || len(response.Header().Values("Set-Cookie")) != 0 {
			t.Fatalf("rotation returned body/cookie: body=%q cookies=%v", response.Body.String(), response.Header().Values("Set-Cookie"))
		}
	}
	assertResponse(t, httptest.NewRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/root-token-rotations/not-an-id/begin", nil), http.StatusUnauthorized)
	assertResponse(t, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/root-token-rotations/not-an-id/begin", nil), http.StatusBadRequest)
}

func TestAdministratorBrowserSessionLifecycleAndFamilyLogout(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	useProductionRootAccess(t, fixture)
	handler := fixture.service.Handler()

	state := httptest.NewRecorder()
	handler.ServeHTTP(state, httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/auth/state", nil))
	if state.Code != http.StatusOK || !strings.Contains(state.Body.String(), `"bootstrap_required"`) {
		t.Fatalf("initial state status=%d body=%s", state.Code, state.Body.String())
	}

	grantResponse := httptest.NewRecorder()
	handler.ServeHTTP(grantResponse, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/bootstrap-grants", nil))
	if grantResponse.Code != http.StatusCreated {
		t.Fatalf("grant status=%d body=%s", grantResponse.Code, grantResponse.Body.String())
	}
	var grant struct {
		Grant string `json:"grant"`
	}
	if err := json.Unmarshal(grantResponse.Body.Bytes(), &grant); err != nil || grant.Grant == "" {
		t.Fatalf("decode grant: %v body=%s", err, grantResponse.Body.String())
	}
	password := "correct horse battery staple"
	bootstrapBody, _ := json.Marshal(map[string]string{"grant": grant.Grant, "username": "initial-owner", "password": password})
	bootstrap := httptest.NewRecorder()
	handler.ServeHTTP(bootstrap, browserJSONRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/bootstrap", string(bootstrapBody)))
	if bootstrap.Code != http.StatusNoContent || len(bootstrap.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("bootstrap status=%d body=%s cookies=%v", bootstrap.Code, bootstrap.Body.String(), bootstrap.Header().Values("Set-Cookie"))
	}

	badOrigin := httptest.NewRequest(http.MethodPost, "http://controller.example/v1/admin/auth/login", strings.NewReader("not-json"))
	badOrigin.Header.Set("Content-Type", "application/json")
	badOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(badOriginResponse, badOrigin)
	if badOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("login validated body before origin: status=%d body=%s", badOriginResponse.Code, badOriginResponse.Body.String())
	}

	loginBody, _ := json.Marshal(map[string]string{"username": "initial-owner", "password": password})
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, browserJSONRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/login", string(loginBody)))
	if login.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", login.Code, login.Body.String())
	}
	var view administratorSessionView
	if err := json.Unmarshal(login.Body.Bytes(), &view); err != nil || view.SessionID == "" || view.CSRFToken == "" ||
		view.IdleLifetimeSeconds < 60 || view.IdleExpiresAtUnixSeconds >= view.AbsoluteExpiresAtUnixSeconds {
		t.Fatalf("invalid login view=%+v err=%v", view, err)
	}
	loginCookies := login.Result().Cookies()
	if len(loginCookies) != 2 {
		t.Fatalf("login cookies=%v", login.Header().Values("Set-Cookie"))
	}
	for _, cookie := range loginCookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("unsafe cookie: %+v", cookie)
		}
	}
	oldSession, oldCSRF := cookieValue(loginCookies, adminauth.SessionCookieName), cookieValue(loginCookies, adminauth.CSRFCookieName)
	beforeFailure, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), oldSession)
	if err != nil {
		t.Fatal(err)
	}
	badCSRF := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/networks", `{}`)
	badCSRF.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: oldSession})
	badCSRF.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: oldCSRF})
	badCSRF.Header.Set(adminauth.CSRFHeaderName, "wrong")
	badCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(badCSRFResponse, badCSRF)
	if badCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status=%d body=%s", badCSRFResponse.Code, badCSRFResponse.Body.String())
	}
	afterFailure, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), oldSession)
	if err != nil || afterFailure.LastSeenAt != beforeFailure.LastSeenAt || afterFailure.IdleExpiresAt != beforeFailure.IdleExpiresAt {
		t.Fatalf("failed request refreshed session: before=%+v after=%+v err=%v", beforeFailure, afterFailure, err)
	}

	rootOnly := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/bootstrap-grants", "")
	rootOnly.Header.Del("Content-Type")
	rootOnly.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: oldSession})
	rootOnly.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: oldCSRF})
	rootOnly.Header.Set(adminauth.CSRFHeaderName, oldCSRF)
	rootOnlyResponse := httptest.NewRecorder()
	handler.ServeHTTP(rootOnlyResponse, rootOnly)
	if rootOnlyResponse.Code != http.StatusForbidden {
		t.Fatalf("session reached root-only grant route: status=%d body=%s", rootOnlyResponse.Code, rootOnlyResponse.Body.String())
	}
	afterForbidden, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), oldSession)
	if err != nil || afterForbidden.LastSeenAt != beforeFailure.LastSeenAt {
		t.Fatalf("forbidden request refreshed session: before=%s after=%s err=%v", beforeFailure.LastSeenAt, afterForbidden.LastSeenAt, err)
	}

	// Cross a whole Store timestamp second, then prove a successful authorized
	// read slides the deadline while the failed requests above did not.
	time.Sleep(1100 * time.Millisecond)
	readRequest := httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/networks", nil)
	readRequest.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: oldSession})
	readRequest.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: oldCSRF})
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, readRequest)
	if readResponse.Code != http.StatusOK {
		t.Fatalf("authorized read status=%d body=%s", readResponse.Code, readResponse.Body.String())
	}
	afterSuccess, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), oldSession)
	if err != nil || !afterSuccess.LastSeenAt.After(beforeFailure.LastSeenAt) {
		t.Fatalf("successful request did not refresh session: before=%s after=%s err=%v", beforeFailure.LastSeenAt, afterSuccess.LastSeenAt, err)
	}
	if readResponse.Header().Get(administratorSessionIDHeader) != afterSuccess.ID.String() ||
		readResponse.Header().Get(administratorSessionIdleHeader) != strconv.FormatInt(afterSuccess.IdleExpiresAt.Unix(), 10) {
		t.Fatalf("response session metadata=%v want id=%s idle=%d", readResponse.Header(), afterSuccess.ID, afterSuccess.IdleExpiresAt.Unix())
	}

	rotateRequest := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/session/rotate", "")
	rotateRequest.Header.Del("Content-Type")
	rotateRequest.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: oldSession})
	rotateRequest.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: oldCSRF})
	rotateRequest.Header.Set(adminauth.CSRFHeaderName, oldCSRF)
	rotate := httptest.NewRecorder()
	handler.ServeHTTP(rotate, rotateRequest)
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotate.Code, rotate.Body.String())
	}
	newCookies := rotate.Result().Cookies()
	newSession := cookieValue(newCookies, adminauth.SessionCookieName)
	newCSRF := cookieValue(newCookies, adminauth.CSRFCookieName)
	if newSession == "" || newSession == oldSession || newCSRF == "" || newCSRF == oldCSRF {
		t.Fatalf("rotation did not replace both secrets")
	}

	// A logout carrying the rotated predecessor revokes its whole family. A
	// delayed browser application of the rotation cookies cannot resurrect it.
	logoutRequest := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/logout", "")
	logoutRequest.Header.Del("Content-Type")
	logoutRequest.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: oldSession})
	logoutRequest.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: oldCSRF})
	logoutRequest.Header.Set(adminauth.CSRFHeaderName, oldCSRF)
	logout := httptest.NewRecorder()
	handler.ServeHTTP(logout, logoutRequest)
	logoutResult := logout.Result()
	if logoutResult.StatusCode != http.StatusNoContent || len(logoutResult.Cookies()) != 2 {
		t.Fatalf("logout status=%d body=%s cookies=%v", logoutResult.StatusCode, logout.Body.String(), logoutResult.Cookies())
	}

	restored := httptest.NewRequest(http.MethodGet, "https://controller.example/v1/admin/auth/session", nil)
	restored.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: newSession})
	restored.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: newCSRF})
	restoreResponse := httptest.NewRecorder()
	handler.ServeHTTP(restoreResponse, restored)
	if restoreResponse.Code != http.StatusUnauthorized || len(restoreResponse.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("family resurrected or stale 401 cleared newer cookies: status=%d cookies=%v body=%s",
			restoreResponse.Code, restoreResponse.Header().Values("Set-Cookie"), restoreResponse.Body.String())
	}
}

func TestAdministratorLoginReplacesOnlyStaleSessionCookie(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	const username = "stale-cookie-owner"
	const password = "correct horse battery staple"
	session, sessionToken, csrfToken, passwordHash := bootstrapAdministratorSessionForHTTPTest(t, fixture, username, password)

	var verificationCalls atomic.Int32
	verifier, err := adminauth.NewPasswordVerifier(adminauth.PasswordVerifierOptions{
		DummyHash: passwordHash,
		Verify: func(string, []byte) (bool, error) {
			verificationCalls.Add(1)
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.passwordVerifier = verifier
	loginBody := `{"username":"` + username + `","password":"` + password + `"}`
	newLogin := func() *http.Request {
		return browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/login", loginBody)
	}
	assertRejectedWithoutVerification := func(t *testing.T, request *http.Request) {
		t.Helper()
		before := verificationCalls.Load()
		response := httptest.NewRecorder()
		fixture.service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || len(response.Header().Values("Set-Cookie")) != 0 {
			t.Fatalf("status=%d cookies=%v body=%s", response.Code, response.Header().Values("Set-Cookie"), response.Body.String())
		}
		if got := verificationCalls.Load(); got != before {
			t.Fatalf("rejected transport performed password verification: before=%d after=%d", before, got)
		}
	}

	valid := newLogin()
	valid.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionToken})
	valid.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrfToken})
	assertRejectedWithoutVerification(t, valid)

	mixed := newLogin()
	mixed.Header.Set("Authorization", "Bearer "+testRootBearer)
	mixed.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionToken})
	assertRejectedWithoutVerification(t, mixed)

	duplicate := newLogin()
	duplicate.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionToken})
	duplicate.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "another-session"})
	assertRejectedWithoutVerification(t, duplicate)

	malformed := newLogin()
	malformed.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName})
	assertRejectedWithoutVerification(t, malformed)

	if err := fixture.store.LogoutAdministratorSession(context.Background(),
		adminauth.SessionSubject(session.PrincipalID, session.ID)); err != nil {
		t.Fatal(err)
	}
	stale := newLogin()
	stale.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionToken})
	stale.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrfToken})
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, stale)
	if response.Code != http.StatusOK {
		t.Fatalf("stale-cookie login status=%d body=%s", response.Code, response.Body.String())
	}
	if got := verificationCalls.Load(); got != 1 {
		t.Fatalf("stale-cookie login verifications=%d want=1", got)
	}
	newToken := cookieValue(response.Result().Cookies(), adminauth.SessionCookieName)
	if newToken == "" || newToken == sessionToken {
		t.Fatalf("stale cookie was not overwritten: cookies=%v", response.Header().Values("Set-Cookie"))
	}
	if _, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), newToken); err != nil {
		t.Fatalf("replacement session is invalid: %v", err)
	}
}

func TestAdministratorLoginSessionReplacementErrorClasses(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "revoked or invalid", err: controller.ErrSessionInvalid, want: true},
		{name: "expired", err: controller.ErrSessionExpired, want: true},
		{name: "valid", err: nil},
		{name: "credential state", err: controller.ErrCredentialInvalid},
		{name: "store failure", err: errors.New("store unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := administratorLoginMayReplaceSession(test.err); got != test.want {
				t.Fatalf("replace=%t want=%t", got, test.want)
			}
		})
	}
}

func TestAdministratorLogoutDoesNotClearCookiesBeforeOriginAndCredentialValidation(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	const username = "logout-boundary-owner"
	const password = "correct horse battery staple"
	_, sessionToken, csrfToken, _ := bootstrapAdministratorSessionForHTTPTest(t, fixture, username, password)

	newLogout := func() *http.Request {
		request := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/logout", "")
		request.Header.Del("Content-Type")
		request.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: sessionToken})
		request.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrfToken})
		request.Header.Set(adminauth.CSRFHeaderName, csrfToken)
		return request
	}
	for name, edit := range map[string]func(*http.Request){
		"cross origin":   func(request *http.Request) { request.Header.Set("Origin", "https://attacker.example") },
		"mixed bearer":   func(request *http.Request) { request.Header.Set("Authorization", "Bearer "+testRootBearer) },
		"malformed csrf": func(request *http.Request) { request.Header.Set(adminauth.CSRFHeaderName, "wrong") },
	} {
		t.Run(name, func(t *testing.T) {
			request := newLogout()
			edit(request)
			response := httptest.NewRecorder()
			fixture.service.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden && response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if cookies := response.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("rejected logout altered cookies: %v", cookies)
			}
		})
	}
	if _, _, err := fixture.store.AuthenticateAdministratorSession(context.Background(), sessionToken); err != nil {
		t.Fatalf("rejected logout revoked session: %v", err)
	}

	stale := newLogout()
	staleCookies := stale.Cookies()
	for _, cookie := range staleCookies {
		if cookie.Name == adminauth.SessionCookieName {
			cookie.Value = "stale-session-secret"
		}
	}
	stale.Header.Del("Cookie")
	for _, cookie := range staleCookies {
		stale.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, stale)
	result := response.Result()
	if result.StatusCode != http.StatusUnauthorized || len(result.Cookies()) != 2 {
		t.Fatalf("origin-valid stale logout status=%d cookies=%v body=%s", response.Code,
			result.Cookies(), response.Body.String())
	}
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func TestRootBearerBrowserContextRejectedOnManagementRoutes(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	useProductionRootAccess(t, fixture)
	request := rootHTTPRequest(http.MethodGet, "https://controller.example/v1/admin/networks", nil)
	request.Header.Set("Origin", "https://controller.example")
	response := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("browser-context root bearer status=%d body=%s", response.Code, response.Body.String())
	}
}

type fixedActorAccessController struct{ actor RequestActor }

func (a fixedActorAccessController) Authenticate(context.Context, *http.Request) (RequestActor, error) {
	return a.actor, nil
}

func (a fixedActorAccessController) Authorize(_ context.Context, actor RequestActor, policy adminauth.RoutePolicy,
	target adminauth.DecisionTarget) (adminauth.Decision, error) {
	if !adminauth.AuthorizeEarly(actor.Subject, actor.Principal, policy, target) {
		return adminauth.Decision{}, ErrPermissionDenied
	}
	return adminauth.NewDecision(actor.Subject, policy, target)
}

func TestDeniedAdministratorPasswordRoutesDoNotAdmitHashWork(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	principalID, sessionID := identity.ID{31}, identity.ID{32}
	principal := adminauth.Principal{ID: principalID, Username: "audit-user", Role: adminauth.RoleAuditor,
		Enabled: true, AllNetworks: true}
	csrf, csrfHash, err := adminauth.NewSecret(adminauth.SecretCSRF, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.access = fixedActorAccessController{actor: RequestActor{
		Credential: CredentialAdministratorSession, Subject: adminauth.SessionSubject(principalID, sessionID),
		Principal: &principal, CSRFHash: csrfHash, IdleLifetime: time.Minute,
		IdleExpiresAt: time.Now().UTC().Add(time.Hour), AbsoluteExpiresAt: time.Now().UTC().Add(2 * time.Hour),
	}}
	var calls atomic.Int32
	fixture.service.passwordHasher = func([]byte) (string, error) {
		calls.Add(1)
		return "", errors.New("must not be called")
	}
	for _, target := range []string{
		"https://controller.example/v1/admin/administrators",
		"https://controller.example/v1/admin/administrators/01000000000000000000000000000000/password",
	} {
		request := browserJSONRequest(http.MethodPost, target,
			`{"username":"new-user","password":"correct horse battery staple","role":"auditor","all_networks":true,"network_ids":[]}`)
		if strings.HasSuffix(target, "/password") {
			request = browserJSONRequest(http.MethodPost, target, `{"password":"correct horse battery staple"}`)
		}
		request.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "opaque-session"})
		request.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrf})
		request.Header.Set(adminauth.CSRFHeaderName, csrf)
		response := httptest.NewRecorder()
		fixture.service.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("denied routes admitted %d password hashes", calls.Load())
	}
}

func TestPasswordWorkAdmissionIsSharedAcrossVerifyAndHash(t *testing.T) {
	service := &Service{passwordWorkSlots: make(chan struct{}, 2)}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	service.passwordHasher = func([]byte) (string, error) {
		started <- struct{}{}
		<-release
		return "hash", nil
	}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := service.hashAdministratorPassword([]byte("correct horse battery staple"))
			done <- err
		}()
	}
	<-started
	<-started
	// Login verification uses this same admission before invoking the bounded
	// verifier, so the two in-flight recovery/create hashes exhaust its cap.
	if service.acquirePasswordWork() {
		service.releasePasswordWork()
		t.Fatal("mixed password work exceeded the global admission cap")
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRateLimitedRecoveryFloodDoesNotAmplifyAuditWrites(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	limiter, err := adminauth.NewLoginLimiter(adminauth.LoginLimiterOptions{
		GlobalLimit: 1, SourceLimit: 1, UsernameLimit: 1,
		Key: bytes.Repeat([]byte{7}, 32), Now: fixture.service.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.recoveryLimiter = limiter
	for attempt := range 20 {
		request := browserJSONRequest(http.MethodPost, "https://controller.example/v1/admin/auth/recover",
			`{"grant":"invalid","password":"correct horse battery staple"}`)
		response := httptest.NewRecorder()
		fixture.service.Handler().ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if attempt > 0 {
			want = http.StatusTooManyRequests
		}
		if response.Code != want {
			t.Fatalf("attempt %d status=%d want=%d body=%s", attempt, response.Code, want, response.Body.String())
		}
	}
	events, err := fixture.store.GlobalAuditEvents(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, event := range events {
		if event.Action == "administrator.recovery.failure" {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("recovery flood wrote %d failure audits, want one admitted-attempt audit", failures)
	}
}

func TestAdministratorAuthStateIsDirectPeerRateLimited(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	limiter, err := adminauth.NewLoginLimiter(adminauth.LoginLimiterOptions{
		GlobalLimit: 2, SourceLimit: 1, UsernameLimit: 2,
		Key: bytes.Repeat([]byte{8}, 32), Now: fixture.service.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.service.authStateLimiter = limiter
	first := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodGet,
		"https://controller.example/v1/admin/auth/state", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first auth state status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodGet,
		"https://controller.example/v1/admin/auth/state", nil))
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("second auth state status=%d Retry-After=%q body=%s", second.Code,
			second.Header().Get("Retry-After"), second.Body.String())
	}
}

func TestAdministratorExactUsernameLookupIsRootOnlyAndUnboundedByList(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	useProductionRootAccess(t, fixture)
	grantResponse := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(grantResponse, rootHTTPRequest(http.MethodPost,
		"https://controller.example/v1/admin/auth/bootstrap-grants", nil))
	var grant struct {
		Grant string `json:"grant"`
	}
	if grantResponse.Code != http.StatusCreated || json.Unmarshal(grantResponse.Body.Bytes(), &grant) != nil {
		t.Fatalf("bootstrap grant status=%d body=%s", grantResponse.Code, grantResponse.Body.String())
	}
	hash, err := adminauth.HashPassword([]byte("correct horse battery staple"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.BootstrapFirstAdministrator(context.Background(), grant.Grant, "exact-owner", hash); err != nil {
		t.Fatal(err)
	}

	lookup := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(lookup, rootHTTPRequest(http.MethodGet,
		"https://controller.example/v1/admin/administrators?username=exact-owner", nil))
	if lookup.Code != http.StatusOK || !strings.Contains(lookup.Body.String(), `"username":"exact-owner"`) {
		t.Fatalf("lookup status=%d body=%s", lookup.Code, lookup.Body.String())
	}
	invalid := httptest.NewRecorder()
	fixture.service.Handler().ServeHTTP(invalid, rootHTTPRequest(http.MethodGet,
		"https://controller.example/v1/admin/administrators?username=exact-owner&limit=1", nil))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("mixed lookup query status=%d body=%s", invalid.Code, invalid.Body.String())
	}
}

func TestAdministratorPatchRejectsEmptyAndPartialAuthorityChanges(t *testing.T) {
	fixture := newFixture(t, 0, nil)
	target := "https://controller.example/v1/admin/administrators/01000000000000000000000000000000"
	for name, body := range map[string]string{
		"empty":          `{}`,
		"null enabled":   `{"enabled":null}`,
		"empty access":   `{"access":{}}`,
		"partial access": `{"access":{"role":"operator"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPatch, target, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			fixture.service.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}
