package controllerservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

const administratorRecoveryGrantLifetime = 10 * time.Minute

type administratorAccessPatchRequest struct {
	Role        *adminauth.Role `json:"role"`
	AllNetworks *bool           `json:"all_networks"`
	NetworkIDs  *[]string       `json:"network_ids"`
}

type administratorUpdateRequest struct {
	Access  *administratorAccessPatchRequest `json:"access,omitempty"`
	Enabled *bool                            `json:"enabled,omitempty"`
}

type createAdministratorRequest struct {
	Username    string         `json:"username"`
	Password    string         `json:"password"`
	Role        adminauth.Role `json:"role"`
	AllNetworks bool           `json:"all_networks"`
	NetworkIDs  []string       `json:"network_ids"`
}

type replaceAdministratorPasswordRequest struct {
	Password string `json:"password"`
}

type revokeAdministratorSessionRequest struct {
	Reason string `json:"reason"`
}

type administratorResponse struct {
	PrincipalID                  string         `json:"principal_id"`
	Username                     string         `json:"username"`
	Role                         adminauth.Role `json:"role"`
	Enabled                      bool           `json:"enabled"`
	AllNetworks                  bool           `json:"all_networks"`
	NetworkIDs                   []string       `json:"network_ids"`
	CreatedAtUnixSeconds         int64          `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds         int64          `json:"updated_at_unix_seconds"`
	DisabledAtUnixSeconds        *int64         `json:"disabled_at_unix_seconds,omitempty"`
	PasswordUpdatedAtUnixSeconds int64          `json:"password_updated_at_unix_seconds"`
}

type administratorSessionResponse struct {
	SessionID                    string                               `json:"session_id"`
	PrincipalID                  string                               `json:"principal_id"`
	State                        controller.AdministratorSessionState `json:"state"`
	Current                      bool                                 `json:"current"`
	CreatedAtUnixSeconds         int64                                `json:"created_at_unix_seconds"`
	LastSeenAtUnixSeconds        int64                                `json:"last_seen_at_unix_seconds"`
	IdleLifetimeSeconds          int64                                `json:"idle_lifetime_seconds"`
	MaximumSessions              int                                  `json:"maximum_sessions"`
	IdleExpiresAtUnixSeconds     int64                                `json:"idle_expires_at_unix_seconds"`
	AbsoluteExpiresAtUnixSeconds int64                                `json:"absolute_expires_at_unix_seconds"`
	RevokedAtUnixSeconds         *int64                               `json:"revoked_at_unix_seconds,omitempty"`
	RevocationReason             string                               `json:"revocation_reason,omitempty"`
}

func administratorJSON(value controller.AdministratorSummary) administratorResponse {
	networkIDs := make([]string, 0, len(value.NetworkIDs))
	for _, networkID := range value.NetworkIDs {
		networkIDs = append(networkIDs, networkID.String())
	}
	return administratorResponse{PrincipalID: value.ID.String(), Username: value.Username, Role: value.Role,
		Enabled: value.Enabled, AllNetworks: value.AllNetworks, NetworkIDs: networkIDs,
		CreatedAtUnixSeconds: value.CreatedAt.Unix(), UpdatedAtUnixSeconds: value.UpdatedAt.Unix(),
		DisabledAtUnixSeconds: unixPointer(value.DisabledAt), PasswordUpdatedAtUnixSeconds: value.PasswordUpdatedAt.Unix()}
}

func administratorSessionSummaryJSON(value controller.AdministratorSessionSummary) administratorSessionResponse {
	return administratorSessionResponse{SessionID: value.ID.String(), PrincipalID: value.PrincipalID.String(),
		State: value.State, Current: value.Current, CreatedAtUnixSeconds: value.CreatedAt.Unix(),
		LastSeenAtUnixSeconds: value.LastSeenAt.Unix(), IdleLifetimeSeconds: int64(value.IdleTimeout / time.Second),
		MaximumSessions: value.MaximumSessions, IdleExpiresAtUnixSeconds: value.IdleExpiresAt.Unix(),
		AbsoluteExpiresAtUnixSeconds: value.AbsoluteExpiresAt.Unix(), RevokedAtUnixSeconds: unixPointer(value.RevokedAt),
		RevocationReason: value.RevocationReason}
}

func (s *Service) createAdministrator(w http.ResponseWriter, r *http.Request) {
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAdministratorRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	networkIDs, err := parseAdministratorNetworkIDs(request.NetworkIDs)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	hash, err := s.hashAdministratorPassword(password)
	if errors.Is(err, adminauth.ErrPasswordVerificationBusy) {
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err != nil {
		s.writeError(w, malformed("invalid password"), false)
		return
	}
	value, err := s.store.CreateAdministrator(r.Context(), decision, controller.CreateAdministratorSpec{
		Username: request.Username, PasswordHash: hash, Access: controller.AdministratorAccessSpec{
			Role: request.Role, Enabled: true, AllNetworks: request.AllNetworks, NetworkIDs: networkIDs,
		},
	})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	w.Header().Set("Location", "/v1/admin/administrators/"+value.ID.String())
	s.writeJSON(w, http.StatusCreated, administratorJSON(value))
}

func (s *Service) readAdministrators(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if _, filtered := query["username"]; filtered {
		requestContext, ok := r.Context().Value(administratorRequestContextKey{}).(administratorRequestContext)
		if !ok || requestContext.actor.Credential != CredentialRootBearer {
			s.writeError(w, ErrPermissionDenied, false)
			return
		}
		if len(query) != 1 || len(query["username"]) != 1 || !adminauth.ValidateUsername(query["username"][0]) {
			s.writeError(w, malformed("username must be one canonical administrator username"), false)
			return
		}
		decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
		if err != nil {
			s.writeError(w, err, false)
			return
		}
		value, err := s.store.AdministratorPrincipalByUsername(r.Context(), decision, query["username"][0])
		if errors.Is(err, controller.ErrNotFound) {
			s.writeJSON(w, http.StatusOK, map[string]any{"administrators": []administratorResponse{}})
			return
		}
		if err != nil {
			s.writeError(w, err, false)
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"administrators": []administratorResponse{administratorJSON(value)}})
		return
	}
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorPrincipals(r.Context(), decision, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]administratorResponse, 0, len(values))
	for _, value := range values {
		response = append(response, administratorJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"administrators": response})
}

func (s *Service) readAdministrator(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.AdministratorPrincipalAuthorized(r.Context(), decision, principalID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, administratorJSON(value))
}

func (s *Service) updateAdministrator(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request administratorUpdateRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	if request.Access == nil && request.Enabled == nil {
		s.writeError(w, malformed("access or enabled is required"), false)
		return
	}
	var access *controller.AdministratorAccessSpec
	if request.Access != nil {
		if request.Access.Role == nil || request.Access.AllNetworks == nil || request.Access.NetworkIDs == nil {
			s.writeError(w, malformed("access requires role, all_networks, and network_ids"), false)
			return
		}
		networkIDs, err := parseAdministratorNetworkIDs(*request.Access.NetworkIDs)
		if err != nil {
			s.writeError(w, err, false)
			return
		}
		access = &controller.AdministratorAccessSpec{Role: *request.Access.Role,
			AllNetworks: *request.Access.AllNetworks, NetworkIDs: networkIDs}
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.UpdateAdministrator(r.Context(), decision, principalID,
		controller.AdministratorUpdateSpec{Access: access, Enabled: request.Enabled})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, administratorJSON(value))
}

func (s *Service) replaceAdministratorPassword(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request replaceAdministratorPasswordRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	password := []byte(request.Password)
	request.Password = ""
	defer clear(password)
	hash, err := s.hashAdministratorPassword(password)
	if errors.Is(err, adminauth.ErrPasswordVerificationBusy) {
		w.Header().Set("Retry-After", "1")
		s.writeError(w, tooManyAdministratorAttempts(), false)
		return
	}
	if err != nil {
		s.writeError(w, malformed("invalid password"), false)
		return
	}
	_, err = s.store.ReplaceAdministratorPassword(r.Context(), decision, principalID, hash)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	// Replacing the current caller's credential revokes its session atomically.
	if decision.Subject().Kind() == adminauth.SubjectAdministratorSession && decision.Subject().ActorID() == principalID {
		clearAdministratorSessionCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) readAdministratorSessions(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorSessions(r.Context(), decision, principalID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]administratorSessionResponse, 0, len(values))
	for _, value := range values {
		response = append(response, administratorSessionSummaryJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"sessions": response})
}

func (s *Service) revokeAdministratorSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := parseIDPath(r, "session_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request revokeAdministratorSessionRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(sessionID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := s.store.RevokeAdministratorSessionByDecision(r.Context(), decision, sessionID, request.Reason); err != nil {
		s.writeError(w, err, false)
		return
	}
	if current, ok := decision.Subject().SessionID(); ok && current == sessionID {
		clearAdministratorSessionCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) issueBootstrapGrant(w http.ResponseWriter, r *http.Request) {
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.issueRecoveryGrant(w, r, decision, controller.AdministratorRecoveryBootstrapOwner, nil)
}

func (s *Service) issueAdministratorRecoveryGrant(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	target := identity.ID(principalID)
	s.issueRecoveryGrant(w, r, decision, controller.AdministratorRecoveryOwner, &target)
}

func (s *Service) issueRecoveryGrant(w http.ResponseWriter, r *http.Request, decision adminauth.Decision,
	purpose controller.AdministratorRecoveryPurpose, target *identity.ID) {
	expiresAt := s.now().UTC().Truncate(time.Second).Add(administratorRecoveryGrantLifetime)
	grant, secret, err := s.store.IssueAdministratorRecoveryGrant(r.Context(), decision, purpose, target, expiresAt)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"grant": secret, "expires_at_unix_seconds": grant.ExpiresAt.Unix()})
}

func (s *Service) beginRootTokenRotation(w http.ResponseWriter, r *http.Request) {
	s.auditRootTokenRotation(w, r, s.store.AuditRootAdministratorTokenRotationBegin)
}

func (s *Service) completeRootTokenRotation(w http.ResponseWriter, r *http.Request) {
	s.auditRootTokenRotation(w, r, s.store.AuditRootAdministratorTokenRotationComplete)
}

func (s *Service) auditRootTokenRotation(w http.ResponseWriter, r *http.Request,
	audit func(context.Context, adminauth.Decision, identity.ID) error) {
	rotationID, err := parseIDPath(r, "rotation_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(rotationID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := audit(r.Context(), decision, rotationID); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) readGlobalAudit(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	events, err := s.store.AdministratorGlobalAuditEvents(r.Context(), decision, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]auditResponse, 0, len(events))
	for _, event := range events {
		item := auditResponse{EventID: event.ID.String(), ActorKind: string(event.Actor.Kind), Action: event.Action,
			TargetType: event.TargetType, Details: json.RawMessage(event.Details), CreatedAtUnixSeconds: event.CreatedAt.Unix()}
		if event.NetworkScope != nil {
			item.NetworkID = event.NetworkScope.String()
		}
		if event.Actor.ID != nil {
			value := event.Actor.ID.String()
			item.ActorID = &value
		}
		if event.ActorNodeID != nil {
			value := event.ActorNodeID.String()
			item.ActorNodeID = &value
		}
		if event.TargetID != nil {
			value := event.TargetID.String()
			item.TargetID = &value
		}
		response = append(response, item)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"events": response})
}

func parseAdministratorNetworkIDs(raw []string) ([]identity.NetworkID, error) {
	if raw == nil {
		raw = []string{}
	}
	result := make([]identity.NetworkID, 0, len(raw))
	seen := make(map[identity.NetworkID]struct{}, len(raw))
	for _, value := range raw {
		networkID, err := identity.ParseNetworkID(value)
		if err != nil {
			return nil, malformed("invalid network_ids")
		}
		if _, exists := seen[networkID]; exists {
			return nil, malformed("duplicate network_ids")
		}
		seen[networkID] = struct{}{}
		result = append(result, networkID)
	}
	return result, nil
}
