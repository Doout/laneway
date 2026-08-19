package controllerservice

import (
	"net/http"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

type servicePrincipalResponse struct {
	PrincipalID          string                `json:"principal_id"`
	Name                 string                `json:"name"`
	Enabled              bool                  `json:"enabled"`
	AllNetworks          bool                  `json:"all_networks"`
	NetworkIDs           []string              `json:"network_ids"`
	Permissions          []adminauth.Operation `json:"permissions"`
	CreatedAtUnixSeconds int64                 `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds int64                 `json:"updated_at_unix_seconds"`
}

func servicePrincipalJSON(value controller.ServicePrincipalSummary) servicePrincipalResponse {
	networkIDs := make([]string, 0, len(value.Principal.NetworkIDs))
	for _, networkID := range value.Principal.NetworkIDs {
		networkIDs = append(networkIDs, networkID.String())
	}
	return servicePrincipalResponse{PrincipalID: value.Principal.ID.String(), Name: value.Principal.Name,
		Enabled: value.Principal.Enabled, AllNetworks: value.Principal.AllNetworks,
		NetworkIDs: networkIDs, Permissions: value.Principal.Permissions,
		CreatedAtUnixSeconds: value.CreatedAt.Unix(), UpdatedAtUnixSeconds: value.UpdatedAt.Unix()}
}

type createServicePrincipalRequest struct {
	Name        string                `json:"name"`
	AllNetworks bool                  `json:"all_networks"`
	NetworkIDs  []string              `json:"network_ids"`
	Permissions []adminauth.Operation `json:"permissions"`
}

func parseServicePrincipalNetworkIDs(values []string) ([]identity.NetworkID, error) {
	result := make([]identity.NetworkID, 0, len(values))
	for _, value := range values {
		networkID, err := identity.ParseNetworkID(value)
		if err != nil {
			return nil, malformed("invalid network_ids")
		}
		result = append(result, networkID)
	}
	return result, nil
}

func (s *Service) createServicePrincipal(w http.ResponseWriter, r *http.Request) {
	var request createServicePrincipalRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	networkIDs, err := parseServicePrincipalNetworkIDs(request.NetworkIDs)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, err := s.store.CreateServicePrincipal(r.Context(), decision, controller.ServicePrincipalSpec{
		Name: request.Name, AllNetworks: request.AllNetworks, NetworkIDs: networkIDs,
		Permissions: request.Permissions,
	})
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	w.Header().Set("Location", "/v1/admin/service-principals/"+value.Principal.ID.String())
	s.writeJSON(w, http.StatusCreated, servicePrincipalJSON(value))
}

func (s *Service) readServicePrincipals(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, controller.MaxEnabledServicePrincipals)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.ServicePrincipals(r.Context(), decision, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]servicePrincipalResponse, 0, len(values))
	for _, value := range values {
		response = append(response, servicePrincipalJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"service_principals": response})
}

func (s *Service) disableServicePrincipal(w http.ResponseWriter, r *http.Request) {
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
	if err := s.store.DisableServicePrincipal(r.Context(), decision, principalID); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type issueServiceAccessTokenRequest struct {
	Label                string `json:"label"`
	ExpiresAtUnixSeconds int64  `json:"expires_at_unix_seconds"`
}

type serviceAccessTokenResponse struct {
	TokenID              string `json:"token_id"`
	PrincipalID          string `json:"principal_id"`
	Label                string `json:"label"`
	State                string `json:"state"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	ExpiresAtUnixSeconds int64  `json:"expires_at_unix_seconds"`
	RevokedAtUnixSeconds *int64 `json:"revoked_at_unix_seconds,omitempty"`
	RevocationReason     string `json:"revocation_reason,omitempty"`
}

func serviceAccessTokenJSON(value controller.ServiceAccessTokenSummary, now time.Time) serviceAccessTokenResponse {
	state := "active"
	if value.RevokedAt != nil {
		state = "revoked"
	} else if !now.Before(value.ExpiresAt) {
		state = "expired"
	}
	result := serviceAccessTokenResponse{TokenID: value.ID.String(), PrincipalID: value.PrincipalID.String(),
		Label: value.Label, State: state, CreatedAtUnixSeconds: value.CreatedAt.Unix(),
		ExpiresAtUnixSeconds: value.ExpiresAt.Unix(), RevocationReason: value.RevocationReason}
	if value.RevokedAt != nil {
		at := value.RevokedAt.Unix()
		result.RevokedAtUnixSeconds = &at
	}
	return result
}

func (s *Service) issueServiceAccessToken(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request issueServiceAccessTokenRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, bearer, err := s.store.IssueServiceAccessToken(r.Context(), decision, principalID,
		request.Label, time.Unix(request.ExpiresAtUnixSeconds, 0).UTC())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", "/v1/admin/service-access-tokens/"+value.ID.String())
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"access_token": bearer, "token": serviceAccessTokenJSON(value, s.now()),
	})
}

func (s *Service) readServiceAccessTokens(w http.ResponseWriter, r *http.Request) {
	principalID, err := parseIDPath(r, "principal_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	limit, err := queryLimit(r, controller.MaxUnrevokedServiceAccessTokensPerPrincipal)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(principalID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.ServiceAccessTokens(r.Context(), decision, principalID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]serviceAccessTokenResponse, 0, len(values))
	for _, value := range values {
		response = append(response, serviceAccessTokenJSON(value, s.now()))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tokens": response})
}

type revokeServiceAccessTokenRequest struct {
	Reason string `json:"reason"`
}

func (s *Service) revokeServiceAccessToken(w http.ResponseWriter, r *http.Request) {
	tokenID, err := parseIDPath(r, "token_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request revokeServiceAccessTokenRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(tokenID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	if err := s.store.RevokeServiceAccessToken(r.Context(), decision, tokenID, request.Reason); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
