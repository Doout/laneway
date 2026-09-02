package controllerservice

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/applicationauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/protocol"
)

type applicationResponse struct {
	ApplicationID           string   `json:"application_id"`
	ClientID                string   `json:"client_id"`
	Name                    string   `json:"name"`
	HomepageURI             string   `json:"homepage_uri"`
	SetupURI                string   `json:"setup_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Enabled                 bool     `json:"enabled"`
	CreatedAtUnixSeconds    int64    `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds    int64    `json:"updated_at_unix_seconds"`
}

func applicationJSON(value controller.RegisteredApplication) applicationResponse {
	return applicationResponse{ApplicationID: value.ID.String(), ClientID: value.ClientID, Name: value.Manifest.Name,
		HomepageURI: value.Manifest.HomepageURI, SetupURI: value.Manifest.SetupURI,
		RedirectURIs: slices.Clone(value.Manifest.RedirectURIs), Scopes: slices.Clone(value.Manifest.Scopes),
		TokenEndpointAuthMethod: value.Manifest.TokenEndpointAuthMethod, Enabled: value.Enabled,
		CreatedAtUnixSeconds: value.CreatedAt.Unix(), UpdatedAtUnixSeconds: value.UpdatedAt.Unix()}
}

func (s *Service) allowApplicationRequest(w http.ResponseWriter, r *http.Request) bool {
	if !s.applicationLimiter.allow(r.RemoteAddr, s.now()) {
		w.Header().Set("Retry-After", "1")
		s.writeApplicationError(w, http.StatusTooManyRequests, "temporarily_unavailable", "request rate limit exceeded")
		return false
	}
	_, _ = s.store.CleanupApplicationCredentials(r.Context(), controller.ApplicationCleanupLimit)
	return true
}

func (s *Service) writeApplicationError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

func strictForm(w http.ResponseWriter, r *http.Request, maxBytes int64, allowed ...string) (url.Values, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" || len(r.Header.Values("Content-Type")) != 1 || r.URL.RawQuery != "" {
		return nil, errors.New("invalid form content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name, values := range r.PostForm {
		if _, ok := allowedSet[name]; !ok || len(values) != 1 {
			return nil, errors.New("unknown or duplicate form field")
		}
	}
	return r.PostForm, nil
}

func exactQuery(values url.Values, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name, entries := range values {
		if _, ok := allowedSet[name]; !ok || len(entries) != 1 {
			return errors.New("unknown or duplicate query field")
		}
	}
	return nil
}

func decodeManifest(raw string) (applicationauth.Manifest, error) {
	var manifest applicationauth.Manifest
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return manifest, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return manifest, errors.New("manifest must contain one JSON object")
	}
	return manifest, nil
}

func (s *Service) startApplicationRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.allowApplicationRequest(w, r) {
		return
	}
	form, err := strictForm(w, r, s.maxBody, "manifest", "state", "code_challenge", "code_challenge_method")
	if err != nil || form.Get("manifest") == "" || form.Get("state") == "" || form.Get("code_challenge") == "" || form.Get("code_challenge_method") != "S256" {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid registration request")
		return
	}
	manifest, err := decodeManifest(form.Get("manifest"))
	if err == nil {
		manifest, err = applicationauth.ValidateManifest(manifest, s.allowInsecureApplicationCallbacks)
	}
	if err != nil {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid application manifest")
		return
	}
	request, err := s.store.CreateApplicationRegistrationRequest(r.Context(), manifest, form.Get("state"), form.Get("code_challenge"))
	if err != nil {
		s.writeApplicationError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration unavailable")
		return
	}
	http.Redirect(w, r, "/applications/consent?request="+url.QueryEscape(request.ID.String()), http.StatusSeeOther)
}

type registrationExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

func (s *Service) exchangeApplicationRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.allowApplicationRequest(w, r) {
		return
	}
	var request registrationExchangeRequest
	if err := s.decodeJSON(w, r, &request); err != nil || request.Code == "" || request.CodeVerifier == "" {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid registration exchange")
		return
	}
	value, err := s.store.ExchangeApplicationRegistration(r.Context(), request.Code, request.CodeVerifier)
	if err != nil {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_grant", "registration exchange failed")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	s.writeJSON(w, http.StatusOK, map[string]any{"application_id": value.Application.ID.String(),
		"client_id": value.Application.ClientID, "client_secret": value.ClientSecret, "name": value.Application.Manifest.Name})
}

func (s *Service) startApplicationAuthorization(w http.ResponseWriter, r *http.Request) {
	if !s.allowApplicationRequest(w, r) {
		return
	}
	query := r.URL.Query()
	if exactQuery(query, "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method") != nil ||
		query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("state") == "" {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
		return
	}
	request, err := s.store.CreateApplicationAuthorizationRequest(r.Context(), query.Get("client_id"), query.Get("redirect_uri"),
		strings.Fields(query.Get("scope")), query.Get("state"), query.Get("code_challenge"))
	if err != nil {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid authorization request")
		return
	}
	http.Redirect(w, r, "/applications/install?request="+url.QueryEscape(request.ID.String()), http.StatusSeeOther)
}

func (s *Service) readApplicationAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeApplicationError(w, http.StatusNotFound, "invalid_request", "authorization request not found")
		return
	}
	request, err := s.store.ApplicationAuthorizationRequest(r.Context(), id)
	if err != nil {
		s.writeApplicationError(w, http.StatusNotFound, "invalid_request", "authorization request not found")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"request_id": request.ID.String(), "application": applicationJSON(request.Application),
		"redirect_uri": request.RedirectURI, "scopes": request.Scopes, "expires_at_unix_seconds": request.ExpiresAt.Unix()})
}

func basicApplicationClient(r *http.Request) (string, string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Basic ") {
		return "", "", errors.New("missing client authentication")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(values[0], "Basic "))
	if err != nil {
		return "", "", err
	}
	clientID, secret, ok := strings.Cut(string(raw), ":")
	clear(raw)
	if !ok || clientID == "" || secret == "" || strings.Contains(secret, ":") {
		return "", "", errors.New("invalid client authentication")
	}
	return clientID, secret, nil
}

func applicationInstallationJSON(value controller.ApplicationInstallation) map[string]any {
	return map[string]any{"installation_id": value.ID.String(), "application_id": value.ApplicationID.String(),
		"network_id": value.NetworkID.String(), "service_principal_id": value.ServicePrincipalID.String(),
		"scopes": value.Scopes, "enabled": value.Enabled, "created_at_unix_seconds": value.CreatedAt.Unix(),
		"updated_at_unix_seconds": value.UpdatedAt.Unix()}
}

func applicationTokenJSON(grant controller.ApplicationTokenGrant) map[string]any {
	network := networkJSON(grant.Network)
	return map[string]any{"access_token": grant.AccessToken, "token_type": "Bearer", "expires_in": grant.ExpiresIn,
		"refresh_token": grant.RefreshToken, "scope": strings.Join(grant.Installation.Scopes, " "),
		"installation": map[string]any{"installation_id": grant.Installation.ID.String(),
			"application_id": grant.Application.ID.String(), "network": network}}
}

func (s *Service) applicationToken(w http.ResponseWriter, r *http.Request) {
	if !s.allowApplicationRequest(w, r) {
		return
	}
	clientID, clientSecret, err := basicApplicationClient(r)
	if err == nil {
		err = s.store.AuthenticateApplicationClient(r.Context(), clientID, clientSecret)
	}
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Laneway OAuth"`)
		s.writeApplicationError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	form, err := strictForm(w, r, s.maxBody, "grant_type", "code", "code_verifier", "redirect_uri", "refresh_token")
	if err != nil {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	var grant controller.ApplicationTokenGrant
	switch form.Get("grant_type") {
	case "authorization_code":
		if form.Get("code") == "" || form.Get("code_verifier") == "" || form.Get("redirect_uri") == "" || form.Get("refresh_token") != "" {
			err = errors.New("invalid code grant")
		} else {
			grant, err = s.store.ExchangeApplicationAuthorizationCode(r.Context(), clientID, clientSecret, form.Get("code"), form.Get("code_verifier"), form.Get("redirect_uri"))
		}
	case "refresh_token":
		if form.Get("refresh_token") == "" || form.Get("code") != "" || form.Get("code_verifier") != "" || form.Get("redirect_uri") != "" {
			err = errors.New("invalid refresh grant")
		} else {
			grant, err = s.store.RefreshApplicationToken(r.Context(), clientID, clientSecret, form.Get("refresh_token"))
		}
	default:
		s.writeApplicationError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant type")
		return
	}
	if err != nil {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_grant", "token grant failed")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	s.writeJSON(w, http.StatusOK, applicationTokenJSON(grant))
}

func (s *Service) revokeApplicationToken(w http.ResponseWriter, r *http.Request) {
	if !s.allowApplicationRequest(w, r) {
		return
	}
	clientID, clientSecret, err := basicApplicationClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Laneway OAuth"`)
		s.writeApplicationError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	form, err := strictForm(w, r, s.maxBody, "token", "token_type_hint")
	if err != nil || form.Get("token") == "" || form.Get("token_type_hint") != "refresh_token" {
		s.writeApplicationError(w, http.StatusBadRequest, "invalid_request", "invalid revocation request")
		return
	}
	if err := s.store.RevokeApplicationRefreshToken(r.Context(), clientID, clientSecret, form.Get("token")); err != nil {
		s.writeApplicationError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

func appendCallback(baseURI string, values map[string]string) (string, error) {
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	for key, value := range values {
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (s *Service) readApplications(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, controller.MaxRegisteredApplications)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorApplications(r.Context(), decision, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]applicationResponse, 0, len(values))
	for _, value := range values {
		response = append(response, applicationJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"applications": response})
}

func (s *Service) readApplication(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "application_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorApplication(r.Context(), decision, id)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, applicationJSON(value))
}

func (s *Service) rotateApplicationClientSecret(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "application_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if r.ContentLength > 0 {
		var request struct{}
		if err := s.decodeJSON(w, r, &request); err != nil {
			s.writeError(w, err, false)
			return
		}
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	secret, err := s.store.AdministratorRotateApplicationClientSecret(r.Context(), decision, id)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	s.writeJSON(w, http.StatusCreated, map[string]string{"application_id": id.String(), "client_secret": secret})
}

func (s *Service) disableApplication(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "application_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := s.store.AdministratorDisableApplication(r.Context(), decision, id); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) readApplicationRegistrationRequest(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorApplicationRegistrationRequest(r.Context(), decision, id)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"request_id": id.String(), "manifest": value.Manifest, "expires_at_unix_seconds": value.ExpiresAt.Unix()})
}

func (s *Service) approveApplicationRegistration(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorApproveApplicationRegistration(r.Context(), decision, id)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	redirect, err := appendCallback(value.SetupURI, map[string]string{"code": value.Code, "state": value.State})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect_uri": redirect})
}

func (s *Service) cancelApplicationRegistration(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorCancelApplicationRegistration(r.Context(), decision, id)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	redirect, _ := appendCallback(value.Manifest.SetupURI, map[string]string{"error": "access_denied", "state": value.State})
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect_uri": redirect})
}

type applicationAuthorizationApprovalRequest struct {
	Scopes []string `json:"scopes"`
}

func (s *Service) approveApplicationAuthorization(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	requestID, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request applicationAuthorizationApprovalRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorApproveApplicationAuthorization(r.Context(), decision, requestID, networkID, request.Scopes)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	redirect, _ := appendCallback(value.RedirectURI, map[string]string{"code": value.Code, "state": value.State})
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect_uri": redirect})
}

func (s *Service) cancelApplicationAuthorization(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	requestID, err := parseIDPath(r, "request_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorCancelApplicationAuthorization(r.Context(), decision, requestID, networkID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	redirect, _ := appendCallback(value.RedirectURI, map[string]string{"error": "access_denied", "state": value.State})
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect_uri": redirect})
}

func (s *Service) readApplicationInstallations(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorApplicationInstallations(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]map[string]any, 0, len(values))
	for _, value := range values {
		response = append(response, applicationInstallationJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"application_installations": response})
}

func (s *Service) deleteApplicationInstallation(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDPath(r, "installation_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(id))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := s.store.AdministratorRevokeApplicationInstallation(r.Context(), decision, id); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type nodeInstallerRequest struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	InstallMode string `json:"install_mode"`
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func (s *Service) createNodeInstaller(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request nodeInstallerRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	if request.InstallMode != "systemd" {
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"code": "unsupported_mode", "detail": "installer mode is not supported", "retryable": false,
		})
		return
	}
	var capabilities protocol.Capability
	switch request.Kind {
	case "node":
	case "connector":
		capabilities = protocol.CapabilitySubnetRouterV1
	case "exit":
		capabilities = protocol.CapabilityExitNodeV1
	default:
		s.writeError(w, malformed("kind must be node, connector, or exit"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	expires := s.now().Add(10 * time.Minute)
	token, err := s.store.AdministratorIssueNodeInstallerToken(r.Context(), decision, networkID, request.Name, expires, uint64(capabilities))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	authority := "https://" + r.Host
	command := fmt.Sprintf(`token_file=$(mktemp); trap 'rm -f "$token_file"' EXIT; umask 077; printf %%s %s > "$token_file"; sudo laneway node install %s --token-file "$token_file" --name %s`, shellQuote(token.Secret), shellQuote(authority), shellQuote(request.Name))
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", "/v1/admin/node-installers/"+token.ID.String())
	s.writeJSON(w, http.StatusCreated, map[string]any{"installation_id": token.ID.String(), "command": command, "expires_at_unix_seconds": token.ExpiresAt.Unix()})
}
