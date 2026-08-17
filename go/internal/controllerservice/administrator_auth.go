package controllerservice

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	administratorSessionIDHeader       = "X-Laneway-Session-ID"
	administratorSessionIdleHeader     = "X-Laneway-Session-Idle-Expires-At"
	administratorSessionAbsoluteHeader = "X-Laneway-Session-Absolute-Expires-At"
)

type storeAccessController struct {
	store      *controller.Store
	rootBearer AdminAuthorizer
}

func (a *storeAccessController) Authenticate(ctx context.Context, request *http.Request) (RequestActor, error) {
	if a == nil || a.store == nil || a.rootBearer == nil {
		return RequestActor{}, ErrUnauthenticated
	}
	kind, err := DetectAdminCredential(request)
	if err != nil {
		return RequestActor{}, err
	}
	switch kind {
	case CredentialRootBearer:
		if browserContextBearer(request) {
			return RequestActor{}, ErrUnauthenticated
		}
		actor, err := a.rootBearer(request)
		if err != nil {
			return RequestActor{}, err
		}
		if !actor.Valid() || actor.Kind != adminauth.ActorServicePrincipal || actor.ID == nil {
			return RequestActor{}, ErrPermissionDenied
		}
		result := RequestActor{Credential: CredentialRootBearer, Subject: adminauth.RootSubject(*actor.ID)}
		if !result.Valid() {
			return RequestActor{}, ErrUnauthenticated
		}
		return result, nil
	case CredentialAdministratorSession:
		cookies := request.CookiesNamed(adminauth.SessionCookieName)
		if len(cookies) != 1 || cookies[0].Value == "" {
			return RequestActor{}, ErrUnauthenticated
		}
		session, principal, err := a.store.AuthenticateAdministratorSession(ctx, cookies[0].Value)
		if err != nil {
			return RequestActor{}, err
		}
		principalCopy := principal
		result := RequestActor{
			Credential: CredentialAdministratorSession,
			Subject:    adminauth.SessionSubject(session.PrincipalID, session.ID), Principal: &principalCopy,
			CSRFHash: session.CSRFHash, IdleLifetime: session.IdleTimeout,
			IdleExpiresAt: session.IdleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
		}
		if !result.Valid() {
			return RequestActor{}, ErrUnauthenticated
		}
		return result, nil
	default:
		return RequestActor{}, ErrUnauthenticated
	}
}

func (a *storeAccessController) Authorize(_ context.Context, actor RequestActor, policy adminauth.RoutePolicy,
	target adminauth.DecisionTarget) (adminauth.Decision, error) {
	if !actor.Valid() {
		return adminauth.Decision{}, ErrUnauthenticated
	}
	if !adminauth.AuthorizeEarly(actor.Subject, actor.Principal, policy, target) {
		return adminauth.Decision{}, ErrPermissionDenied
	}
	decision, err := adminauth.NewDecision(actor.Subject, policy, target)
	if err != nil {
		return adminauth.Decision{}, ErrPermissionDenied
	}
	return decision, nil
}

type administratorRequestContext struct {
	actor  RequestActor
	policy adminauth.RoutePolicy
}

type administratorRequestContextKey struct{}
type administratorDecisionContextKey struct{}

func (s *Service) managementHandler(policy adminauth.RoutePolicy, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, err := s.access.Authenticate(r.Context(), r)
		if err != nil {
			s.writeError(w, err, false)
			return
		}
		if policy.Mutation {
			if err := ValidateMutationProtection(r, actor); err != nil {
				s.writeError(w, err, false)
				return
			}
		}
		if actor.Credential == CredentialAdministratorSession &&
			(actor.Principal == nil || !adminauth.RoleAllows(actor.Principal.Role, policy.Operation)) {
			s.writeError(w, ErrPermissionDenied, false)
			return
		}
		if actor.Credential == CredentialAdministratorSession {
			w = &administratorSessionMetadataWriter{ResponseWriter: w, service: s, request: r, actor: actor}
		}
		ctx := context.WithValue(r.Context(), administratorRequestContextKey{}, administratorRequestContext{actor: actor, policy: policy})
		next(w, r.WithContext(ctx))
	}
}

type administratorSessionMetadataWriter struct {
	http.ResponseWriter
	service     *Service
	request     *http.Request
	actor       RequestActor
	wroteHeader bool
}

func (w *administratorSessionMetadataWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *administratorSessionMetadataWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if status >= 200 && status < 400 {
		actor := w.actor
		validActor := true
		if w.service != nil && w.request != nil {
			cookies := w.request.CookiesNamed(adminauth.SessionCookieName)
			validActor = len(cookies) == 1
			if validActor {
				if session, principal, err := w.service.store.AuthenticateAdministratorSession(w.request.Context(), cookies[0].Value); err == nil {
					refreshed := sessionRequestActor(session, principal)
					if refreshed.Subject == actor.Subject {
						actor = refreshed
					} else {
						validActor = false
					}
				} else {
					validActor = false
				}
			}
		}
		if validActor {
			setAdministratorSessionHeaders(w.ResponseWriter, actor)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *administratorSessionMetadataWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(payload)
}

func (s *Service) registerManagementRoute(mux *http.ServeMux, method, pattern string, handler http.HandlerFunc) {
	policy, ok := ManagementRoutePolicy(method, pattern)
	if !ok {
		panic("controller management route missing policy: " + method + " " + pattern)
	}
	mux.Handle(method+" "+pattern, s.managementHandler(policy, handler))
}

func (s *Service) administratorDecision(request *http.Request, target adminauth.DecisionTarget) (adminauth.Decision, error) {
	if request == nil {
		return adminauth.Decision{}, ErrUnauthenticated
	}
	requestContext, ok := request.Context().Value(administratorRequestContextKey{}).(administratorRequestContext)
	if !ok || !requestContext.actor.Valid() || !requestContext.policy.Valid() {
		return adminauth.Decision{}, ErrUnauthenticated
	}
	decision, err := s.access.Authorize(request.Context(), requestContext.actor, requestContext.policy, target)
	if err != nil {
		return adminauth.Decision{}, err
	}
	if !decision.Matches(requestContext.actor.Subject, requestContext.policy, target) {
		return adminauth.Decision{}, ErrPermissionDenied
	}
	// Preserve the exact decision in the handler context for diagnostics and
	// for tests that prove it cannot be substituted across handlers.
	*request = *request.WithContext(context.WithValue(request.Context(), administratorDecisionContextKey{}, decision))
	return decision, nil
}

type administratorSessionView struct {
	PrincipalID                  string                `json:"principal_id"`
	Username                     string                `json:"username"`
	Role                         adminauth.Role        `json:"role"`
	Permissions                  []adminauth.Operation `json:"permissions"`
	AllNetworks                  bool                  `json:"all_networks"`
	NetworkIDs                   []string              `json:"network_ids"`
	SessionID                    string                `json:"session_id"`
	IdleLifetimeSeconds          int64                 `json:"idle_lifetime_seconds"`
	IdleExpiresAtUnixSeconds     int64                 `json:"idle_expires_at_unix_seconds"`
	AbsoluteExpiresAtUnixSeconds int64                 `json:"absolute_expires_at_unix_seconds"`
	CSRFToken                    string                `json:"csrf_token"`
}

func administratorSessionJSON(session controller.AdministratorSession, principal adminauth.Principal, csrf string) administratorSessionView {
	networkIDs := make([]string, 0, len(principal.NetworkIDs))
	for _, networkID := range principal.NetworkIDs {
		networkIDs = append(networkIDs, networkID.String())
	}
	return administratorSessionView{
		PrincipalID: principal.ID.String(), Username: principal.Username, Role: principal.Role,
		Permissions: adminauth.Permissions(principal.Role), AllNetworks: principal.AllNetworks,
		NetworkIDs: networkIDs, SessionID: session.ID.String(), IdleLifetimeSeconds: int64(session.IdleTimeout / time.Second),
		IdleExpiresAtUnixSeconds: session.IdleExpiresAt.Unix(), AbsoluteExpiresAtUnixSeconds: session.AbsoluteExpiresAt.Unix(),
		CSRFToken: csrf,
	}
}

func setAdministratorSessionHeaders(w http.ResponseWriter, actor RequestActor) {
	if w == nil || actor.Credential != CredentialAdministratorSession || !actor.Valid() {
		return
	}
	sessionID, ok := actor.Subject.SessionID()
	if !ok {
		return
	}
	w.Header().Set(administratorSessionIDHeader, sessionID.String())
	w.Header().Set(administratorSessionIdleHeader, strconv.FormatInt(actor.IdleExpiresAt.Unix(), 10))
	w.Header().Set(administratorSessionAbsoluteHeader, strconv.FormatInt(actor.AbsoluteExpiresAt.Unix(), 10))
}

func (s *Service) setAdministratorSessionCookies(w http.ResponseWriter, session controller.AdministratorSession, token, csrf string) {
	maxAge := int(session.AbsoluteExpiresAt.Sub(s.now().UTC()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: adminauth.SessionCookieName, Value: token, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.AbsoluteExpiresAt, MaxAge: maxAge})
	http.SetCookie(w, &http.Cookie{Name: adminauth.CSRFCookieName, Value: csrf, Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: session.AbsoluteExpiresAt, MaxAge: maxAge})
}

func clearAdministratorSessionCookies(w http.ResponseWriter) {
	expires := time.Unix(1, 0).UTC()
	for _, name := range []string{adminauth.SessionCookieName, adminauth.CSRFCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: -1})
	}
}

func (s *Service) administratorAuthState(w http.ResponseWriter, r *http.Request) {
	remote, err := administratorRemoteAddress(r)
	if err != nil {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	limit, err := s.authStateLimiter.Allow(remote, "auth-state")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !limit.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(limit.RetryAfter.Seconds())))))
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	state, err := s.store.AdministratorAuthState(r.Context())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value := "bootstrap_required"
	if state.InitialOwnerPrincipalID != nil && state.BootstrapCompletedAt != nil {
		value = "sign_in"
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"state": value})
}

type administratorLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Service) administratorLogin(w http.ResponseWriter, r *http.Request) {
	kind, err := DetectAdminCredential(r)
	if err != nil || kind == CredentialRootBearer {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	if err := ValidateSameOrigin(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	var request administratorLoginRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	remote, err := administratorRemoteAddress(r)
	if err != nil {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	limit, err := s.loginLimiter.Allow(remote, request.Username)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !limit.Allowed {
		// The limiter itself is the durable bound. Emitting one SQLite audit row
		// per rejected packet would turn a cheap unauthenticated flood into
		// serialized writes and unbounded audit growth.
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(limit.RetryAfter.Seconds())))))
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err := s.validateAdministratorLoginSession(r.Context(), r, kind); err != nil {
		s.writeError(w, err, false)
		return
	}
	candidate, err := s.store.AdministratorPasswordCandidate(r.Context(), request.Username)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !s.acquirePasswordWork() {
		s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureBusy)
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	matched, err := s.passwordVerifier.Verify(adminauth.PasswordCandidate{Hash: candidate.PasswordHash, Usable: candidate.Usable}, password)
	s.releasePasswordWork()
	if errors.Is(err, adminauth.ErrPasswordVerificationBusy) {
		s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureBusy)
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !matched {
		s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureCredential)
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	session, token, csrf, err := s.store.CreateAdministratorSessionAfterPassword(r.Context(), candidate, controller.AdministratorSessionOptions{})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	authenticatedSession, principal, err := s.store.AuthenticateAdministratorSession(r.Context(), token)
	if err != nil {
		_ = s.store.LogoutAdministratorSession(r.Context(), adminauth.SessionSubject(session.PrincipalID, session.ID))
		s.writeError(w, err, false)
		return
	}
	session = authenticatedSession
	s.setAdministratorSessionCookies(w, session, token, csrf)
	setAdministratorSessionHeaders(w, sessionRequestActor(session, principal))
	s.writeJSON(w, http.StatusOK, administratorSessionJSON(session, principal, csrf))
}

// validateAdministratorLoginSession permits a login request to replace one
// stale session cookie, but never a currently valid browser session. The
// request has already passed the direct-peer login limiter before this Store
// lookup, so arbitrary invalid cookies cannot create an unbounded read path.
func (s *Service) validateAdministratorLoginSession(ctx context.Context, request *http.Request, kind CredentialKind) error {
	switch kind {
	case CredentialNone:
		return nil
	case CredentialAdministratorSession:
		cookies := request.CookiesNamed(adminauth.SessionCookieName)
		if len(cookies) != 1 || cookies[0].Value == "" {
			return ErrUnauthenticated
		}
		_, _, err := s.store.AuthenticateAdministratorSession(ctx, cookies[0].Value)
		if err == nil {
			return ErrUnauthenticated
		}
		if administratorLoginMayReplaceSession(err) {
			return nil
		}
		return err
	default:
		return ErrUnauthenticated
	}
}

func administratorLoginMayReplaceSession(err error) bool {
	return errors.Is(err, controller.ErrSessionInvalid) || errors.Is(err, controller.ErrSessionExpired)
}

func (s *Service) administratorSession(w http.ResponseWriter, r *http.Request) {
	actor, err := s.access.Authenticate(r.Context(), r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if actor.Credential != CredentialAdministratorSession || actor.Principal == nil {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	csrf, err := csrfCookieToken(r, actor.CSRFHash)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	sessionCookies := r.CookiesNamed(adminauth.SessionCookieName)
	if len(sessionCookies) != 1 {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	session, principal, err := s.store.AuthenticateAndTouchAdministratorSession(r.Context(), sessionCookies[0].Value)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	actor = sessionRequestActor(session, principal)
	setAdministratorSessionHeaders(w, actor)
	s.writeJSON(w, http.StatusOK, administratorSessionJSON(session, principal, csrf))
}

func (s *Service) administratorSessionRotate(w http.ResponseWriter, r *http.Request) {
	actor, err := s.access.Authenticate(r.Context(), r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if actor.Credential != CredentialAdministratorSession || actor.Principal == nil {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	if err := ValidateMutationProtection(r, actor); err != nil {
		s.writeError(w, err, false)
		return
	}
	session, token, csrf, err := s.store.RotateAdministratorSession(r.Context(), actor.Subject)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	authenticatedSession, principal, err := s.store.AuthenticateAdministratorSession(r.Context(), token)
	if err != nil {
		_ = s.store.LogoutAdministratorSession(r.Context(), adminauth.SessionSubject(session.PrincipalID, session.ID))
		s.writeError(w, err, false)
		return
	}
	session = authenticatedSession
	s.setAdministratorSessionCookies(w, session, token, csrf)
	setAdministratorSessionHeaders(w, sessionRequestActor(session, principal))
	s.writeJSON(w, http.StatusOK, administratorSessionJSON(session, principal, csrf))
}

func (s *Service) administratorLogout(w http.ResponseWriter, r *http.Request) {
	kind, err := DetectAdminCredential(r)
	if err != nil || kind != CredentialAdministratorSession {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	if err := ValidateSameOrigin(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	sessions := r.CookiesNamed(adminauth.SessionCookieName)
	csrfCookies := r.CookiesNamed(adminauth.CSRFCookieName)
	csrfHeaders := r.Header.Values(adminauth.CSRFHeaderName)
	if len(sessions) != 1 || len(csrfCookies) != 1 || len(csrfHeaders) != 1 ||
		!constantStringEqual(csrfCookies[0].Value, csrfHeaders[0]) {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	// Only an origin-valid, structurally authenticated logout request may alter
	// cookie state. Once that boundary is crossed, clear with the exact creation
	// attributes even when the Store reports a stale or revoked session family.
	clearAdministratorSessionCookies(w)
	if err := s.store.LogoutAdministratorSessionBySecrets(r.Context(), sessions[0].Value, csrfHeaders[0]); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) administratorRootProbe(w http.ResponseWriter, r *http.Request) {
	kind, err := DetectAdminCredential(r)
	if err != nil || kind != CredentialRootBearer || browserContextBearer(r) {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	actor, err := s.access.Authenticate(r.Context(), r)
	if err != nil || actor.Credential != CredentialRootBearer {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	state, err := s.store.AdministratorAuthState(r.Context())
	if err != nil || actor.Subject.ActorID() != state.RootServicePrincipalID {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func sessionRequestActor(session controller.AdministratorSession, principal adminauth.Principal) RequestActor {
	principalCopy := principal
	return RequestActor{Credential: CredentialAdministratorSession,
		Subject: adminauth.SessionSubject(session.PrincipalID, session.ID), Principal: &principalCopy,
		CSRFHash: session.CSRFHash, IdleLifetime: session.IdleTimeout,
		IdleExpiresAt: session.IdleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt}
}

func csrfCookieToken(r *http.Request, expected [sha256.Size]byte) (string, error) {
	cookies := r.CookiesNamed(adminauth.CSRFCookieName)
	if len(cookies) != 1 || cookies[0].Value == "" || !adminauth.SecretMatches(adminauth.SecretCSRF, expected, cookies[0].Value) {
		return "", ErrUnauthenticated
	}
	return cookies[0].Value, nil
}

func constantStringEqual(left, right string) bool {
	return left != "" && len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func browserContextBearer(request *http.Request) bool {
	if request == nil || len(request.Header.Values("Origin")) != 0 {
		return true
	}
	for name := range request.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Sec-Fetch-") {
			return true
		}
	}
	return false
}

func directRemoteAddress(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}

func administratorRemoteAddress(request *http.Request) (netip.Addr, error) {
	if request == nil {
		return netip.Addr{}, errors.New("administrator request is required")
	}
	values := request.Header.Values(adminauth.PublicClientAddressHeader)
	if len(values) == 0 {
		return directRemoteAddress(request.RemoteAddr)
	}
	if len(values) != 1 || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return netip.Addr{}, errors.New("administrator public client address is not authenticated")
	}
	authenticated, err := identity.AuthenticatedIdentityFromCertificate(request.TLS.VerifiedChains[0][0])
	if err != nil || authenticated.RequireRole(identity.IdentityRoleRelay) != nil {
		return netip.Addr{}, errors.New("administrator public client address requires an authenticated relay")
	}
	return netip.ParseAddr(values[0])
}

func tooManyAdministratorAttempts() error {
	return &requestError{status: http.StatusTooManyRequests, code: lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED,
		detail: "authentication temporarily unavailable", retryable: true}
}

func (s *Service) auditAdministratorAuthenticationFailure(ctx context.Context, kind controller.AdministratorAuthFailure) {
	// Failure auditing must not make authentication responses distinguishable.
	_ = s.store.AuditAdministratorAuthenticationFailure(ctx, kind)
}

type administratorBootstrapRequest struct {
	Grant    string `json:"grant"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type administratorRecoveryRequest struct {
	Grant    string `json:"grant"`
	Password string `json:"password"`
}

func (s *Service) bootstrapAdministrator(w http.ResponseWriter, r *http.Request) {
	if kind, err := DetectAdminCredential(r); err != nil || kind != CredentialNone {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	if err := ValidateSameOrigin(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	var request administratorBootstrapRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	if !s.allowRecoveryAttempt(w, r, "bootstrap") {
		return
	}
	candidate, err := s.store.AdministratorRecoveryCandidate(r.Context(), request.Grant,
		controller.AdministratorRecoveryBootstrapOwner)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !candidate.Usable {
		s.rejectRecovery(w, r)
		return
	}
	if !adminauth.ValidateUsername(request.Username) {
		s.writeError(w, malformed("invalid username"), false)
		return
	}
	hash, err := s.hashAdministratorPassword(password)
	if errors.Is(err, adminauth.ErrPasswordVerificationBusy) {
		s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureBusy)
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err != nil {
		s.writeError(w, malformed("invalid password"), false)
		return
	}
	if _, err := s.store.BootstrapFirstAdministrator(r.Context(), request.Grant, request.Username, hash); err != nil {
		if administratorRecoveryFailure(err) {
			s.rejectRecovery(w, r)
			return
		}
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) recoverAdministrator(w http.ResponseWriter, r *http.Request) {
	if kind, err := DetectAdminCredential(r); err != nil || kind != CredentialNone {
		s.writeError(w, ErrUnauthenticated, false)
		return
	}
	if err := ValidateSameOrigin(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	var request administratorRecoveryRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	if !s.allowRecoveryAttempt(w, r, "recovery") {
		return
	}
	candidate, err := s.store.AdministratorRecoveryCandidate(r.Context(), request.Grant,
		controller.AdministratorRecoveryOwner)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if !candidate.Usable {
		s.rejectRecovery(w, r)
		return
	}
	hash, err := s.hashAdministratorPassword(password)
	if errors.Is(err, adminauth.ErrPasswordVerificationBusy) {
		s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureBusy)
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err != nil {
		s.writeError(w, malformed("invalid password"), false)
		return
	}
	if _, err := s.store.RecoverAdministratorOwner(r.Context(), request.Grant, hash); err != nil {
		if administratorRecoveryFailure(err) {
			s.rejectRecovery(w, r)
			return
		}
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) allowRecoveryAttempt(w http.ResponseWriter, r *http.Request, bucket string) bool {
	remote, err := administratorRemoteAddress(r)
	if err != nil {
		s.writeError(w, ErrUnauthenticated, false)
		return false
	}
	decision, err := s.recoveryLimiter.Allow(remote, bucket)
	if err != nil {
		s.writeError(w, err, false)
		return false
	}
	if decision.Allowed {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(decision.RetryAfter.Seconds())))))
	s.writeError(w, tooManyAdministratorAttempts(), false)
	return false
}

func (s *Service) hashAdministratorPassword(password []byte) (string, error) {
	if err := adminauth.ValidatePassword(password); err != nil {
		return "", err
	}
	if !s.acquirePasswordWork() {
		return "", adminauth.ErrPasswordVerificationBusy
	}
	defer s.releasePasswordWork()
	if s.passwordHasher == nil {
		return "", errors.New("administrator password hasher is not initialized")
	}
	return s.passwordHasher(password)
}

func (s *Service) acquirePasswordWork() bool {
	select {
	case s.passwordWorkSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Service) releasePasswordWork() { <-s.passwordWorkSlots }

func (s *Service) rejectRecovery(w http.ResponseWriter, r *http.Request) {
	s.auditAdministratorAuthenticationFailure(r.Context(), controller.AdministratorAuthFailureRecovery)
	s.writeError(w, ErrUnauthenticated, false)
}

func administratorRecoveryFailure(err error) bool {
	return errors.Is(err, controller.ErrRecoveryInvalid) || errors.Is(err, controller.ErrRecoveryExpired) ||
		errors.Is(err, controller.ErrRecoveryConsumed) || errors.Is(err, controller.ErrBootstrapComplete)
}
