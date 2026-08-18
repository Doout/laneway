package controllerservice

import (
	"net/http"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

type accessUserResponse struct {
	UserID               string `json:"user_id"`
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds int64  `json:"updated_at_unix_seconds"`
}

type accessTeamResponse struct {
	TeamID               string `json:"team_id"`
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds int64  `json:"updated_at_unix_seconds"`
}

type accessTeamMemberResponse struct {
	NetworkID            string `json:"network_id"`
	TeamID               string `json:"team_id"`
	UserID               string `json:"user_id"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
}

type accessGrantResponse struct {
	GrantID              string `json:"grant_id"`
	NetworkID            string `json:"network_id"`
	SubjectKind          string `json:"subject_kind"`
	SubjectID            string `json:"subject_id"`
	TargetKind           string `json:"target_kind"`
	NodeID               string `json:"node_id,omitempty"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
}

type accessInventoryResponse struct {
	Users       []accessUserResponse       `json:"users"`
	Teams       []accessTeamResponse       `json:"teams"`
	Memberships []accessTeamMemberResponse `json:"memberships"`
	Grants      []accessGrantResponse      `json:"grants"`
}

func accessInventoryJSON(inventory controller.AccessInventory) accessInventoryResponse {
	response := accessInventoryResponse{
		Users:       make([]accessUserResponse, 0, len(inventory.Users)),
		Teams:       make([]accessTeamResponse, 0, len(inventory.Teams)),
		Memberships: make([]accessTeamMemberResponse, 0, len(inventory.Memberships)),
		Grants:      make([]accessGrantResponse, 0, len(inventory.Grants)),
	}
	for _, user := range inventory.Users {
		response.Users = append(response.Users, accessUserJSON(user))
	}
	for _, team := range inventory.Teams {
		response.Teams = append(response.Teams, accessTeamJSON(team))
	}
	for _, membership := range inventory.Memberships {
		response.Memberships = append(response.Memberships, accessTeamMemberResponse{
			NetworkID: membership.NetworkID.String(), TeamID: membership.TeamID.String(), UserID: membership.UserID.String(), CreatedAtUnixSeconds: membership.CreatedAt.Unix(),
		})
	}
	for _, grant := range inventory.Grants {
		response.Grants = append(response.Grants, accessGrantJSON(grant))
	}
	return response
}

func accessUserJSON(user controller.AccessUser) accessUserResponse {
	return accessUserResponse{UserID: user.ID.String(), NetworkID: user.NetworkID.String(), Name: user.Name, Enabled: user.Enabled, CreatedAtUnixSeconds: user.CreatedAt.Unix(), UpdatedAtUnixSeconds: user.UpdatedAt.Unix()}
}

func accessTeamJSON(team controller.AccessTeam) accessTeamResponse {
	return accessTeamResponse{TeamID: team.ID.String(), NetworkID: team.NetworkID.String(), Name: team.Name, CreatedAtUnixSeconds: team.CreatedAt.Unix(), UpdatedAtUnixSeconds: team.UpdatedAt.Unix()}
}

func accessGrantJSON(grant controller.AccessGrant) accessGrantResponse {
	response := accessGrantResponse{GrantID: grant.ID.String(), NetworkID: grant.NetworkID.String(), SubjectKind: string(grant.SubjectKind), SubjectID: grant.SubjectID.String(), TargetKind: string(grant.TargetKind), CreatedAtUnixSeconds: grant.CreatedAt.Unix()}
	if grant.NodeID != nil {
		response.NodeID = grant.NodeID.String()
	}
	return response
}

func (s *Service) readAccessInventory(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	inventory, err := s.store.AdministratorAccessInventory(r.Context(), decision, networkID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, accessInventoryJSON(inventory))
}

type createAccessSubjectRequest struct {
	Name string `json:"name"`
}

func (s *Service) createAccessUser(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessSubjectRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	user, _, err := s.store.AdministratorCreateAccessUser(r.Context(), decision, networkID, request.Name)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessUserJSON(user))
}

type updateAccessUserRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Service) updateAccessUser(w http.ResponseWriter, r *http.Request) {
	userID, err := parseIDPath(r, "user_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request updateAccessUserRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	if request.Enabled == nil {
		s.writeError(w, malformed("enabled is required"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(userID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	user, _, err := s.store.AdministratorSetAccessUserEnabled(r.Context(), decision, userID, *request.Enabled)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, accessUserJSON(user))
}

func (s *Service) createAccessTeam(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessSubjectRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	team, _, err := s.store.AdministratorCreateAccessTeam(r.Context(), decision, networkID, request.Name)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessTeamJSON(team))
}

func (s *Service) addAccessTeamMember(w http.ResponseWriter, r *http.Request) {
	teamID, userID, err := accessTeamMemberIDs(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(teamID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorSetAccessTeamMember(r.Context(), decision, teamID, userID, true)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) removeAccessTeamMember(w http.ResponseWriter, r *http.Request) {
	teamID, userID, err := accessTeamMemberIDs(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(teamID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorSetAccessTeamMember(r.Context(), decision, teamID, userID, false)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func accessTeamMemberIDs(r *http.Request) (identity.ID, identity.ID, error) {
	teamID, err := parseIDPath(r, "team_id")
	if err != nil {
		return identity.ID{}, identity.ID{}, err
	}
	userID, err := parseIDPath(r, "user_id")
	if err != nil {
		return identity.ID{}, identity.ID{}, err
	}
	return teamID, userID, nil
}

type createAccessGrantRequest struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	TargetKind  string `json:"target_kind"`
	NodeID      string `json:"node_id,omitempty"`
}

func (s *Service) createAccessGrant(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessGrantRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	subjectID, err := identity.ParseID(request.SubjectID)
	if err != nil {
		s.writeError(w, malformed("invalid subject_id"), false)
		return
	}
	var nodeID *identity.NodeID
	if request.NodeID != "" {
		value, err := identity.ParseNodeID(request.NodeID)
		if err != nil {
			s.writeError(w, malformed("invalid node_id"), false)
			return
		}
		nodeID = &value
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	grant, _, err := s.store.AdministratorCreateAccessGrant(r.Context(), decision, networkID, controller.AccessSubjectKind(request.SubjectKind), subjectID, controller.AccessTargetKind(request.TargetKind), nodeID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessGrantJSON(grant))
}

func (s *Service) deleteAccessGrant(w http.ResponseWriter, r *http.Request) {
	grantID, err := parseIDPath(r, "grant_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(grantID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorDeleteAccessGrant(r.Context(), decision, grantID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}
