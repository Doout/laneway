package controllerservice

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"

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

type accessResourceResponse struct {
	ResourceID           string `json:"resource_id"`
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	TargetKind           string `json:"target_kind"`
	NodeID               string `json:"node_id,omitempty"`
	RouteID              string `json:"route_id,omitempty"`
	Prefix               string `json:"prefix,omitempty"`
	Enabled              bool   `json:"enabled"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds int64  `json:"updated_at_unix_seconds"`
}

type accessPortRangeResponse struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}

type accessServiceResponse struct {
	ServiceID            string                    `json:"service_id"`
	NetworkID            string                    `json:"network_id"`
	Name                 string                    `json:"name"`
	Protocol             string                    `json:"protocol"`
	Ports                []accessPortRangeResponse `json:"ports"`
	Enabled              bool                      `json:"enabled"`
	CreatedAtUnixSeconds int64                     `json:"created_at_unix_seconds"`
	UpdatedAtUnixSeconds int64                     `json:"updated_at_unix_seconds"`
}

type accessResourceGrantResponse struct {
	GrantID              string `json:"grant_id"`
	NetworkID            string `json:"network_id"`
	SubjectKind          string `json:"subject_kind"`
	SubjectID            string `json:"subject_id"`
	ResourceID           string `json:"resource_id"`
	ServiceID            string `json:"service_id"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
}

type accessInventoryResponse struct {
	Users          []accessUserResponse          `json:"users"`
	Teams          []accessTeamResponse          `json:"teams"`
	Memberships    []accessTeamMemberResponse    `json:"memberships"`
	Grants         []accessGrantResponse         `json:"grants"`
	Resources      []accessResourceResponse      `json:"resources"`
	Services       []accessServiceResponse       `json:"services"`
	ResourceGrants []accessResourceGrantResponse `json:"resource_grants"`
}

func accessInventoryJSON(inventory controller.AccessInventory) accessInventoryResponse {
	response := accessInventoryResponse{
		Users:          make([]accessUserResponse, 0, len(inventory.Users)),
		Teams:          make([]accessTeamResponse, 0, len(inventory.Teams)),
		Memberships:    make([]accessTeamMemberResponse, 0, len(inventory.Memberships)),
		Grants:         make([]accessGrantResponse, 0, len(inventory.Grants)),
		Resources:      make([]accessResourceResponse, 0, len(inventory.Resources)),
		Services:       make([]accessServiceResponse, 0, len(inventory.Services)),
		ResourceGrants: make([]accessResourceGrantResponse, 0, len(inventory.ResourceGrants)),
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
	for _, resource := range inventory.Resources {
		response.Resources = append(response.Resources, accessResourceJSON(resource))
	}
	for _, service := range inventory.Services {
		response.Services = append(response.Services, accessServiceJSON(service))
	}
	for _, grant := range inventory.ResourceGrants {
		response.ResourceGrants = append(response.ResourceGrants, accessResourceGrantJSON(grant))
	}
	return response
}

func accessResourceJSON(resource controller.AccessResource) accessResourceResponse {
	response := accessResourceResponse{ResourceID: resource.ID.String(), NetworkID: resource.NetworkID.String(), Name: resource.Name,
		TargetKind: string(resource.TargetKind), Enabled: resource.Enabled, CreatedAtUnixSeconds: resource.CreatedAt.Unix(), UpdatedAtUnixSeconds: resource.UpdatedAt.Unix()}
	if resource.NodeID != nil {
		response.NodeID = resource.NodeID.String()
	}
	if resource.RouteID != nil {
		response.RouteID = resource.RouteID.String()
	}
	if resource.Prefix.IsValid() {
		response.Prefix = resource.Prefix.String()
	}
	return response
}

func accessServiceJSON(service controller.AccessService) accessServiceResponse {
	response := accessServiceResponse{ServiceID: service.ID.String(), NetworkID: service.NetworkID.String(), Name: service.Name,
		Protocol: string(service.Protocol), Ports: make([]accessPortRangeResponse, 0, len(service.Ports)), Enabled: service.Enabled,
		CreatedAtUnixSeconds: service.CreatedAt.Unix(), UpdatedAtUnixSeconds: service.UpdatedAt.Unix()}
	for _, portRange := range service.Ports {
		response.Ports = append(response.Ports, accessPortRangeResponse{First: portRange.First, Last: portRange.Last})
	}
	return response
}

func accessResourceGrantJSON(grant controller.AccessResourceGrant) accessResourceGrantResponse {
	return accessResourceGrantResponse{GrantID: grant.ID.String(), NetworkID: grant.NetworkID.String(), SubjectKind: string(grant.SubjectKind),
		SubjectID: grant.SubjectID.String(), ResourceID: grant.ResourceID.String(), ServiceID: grant.ServiceID.String(), CreatedAtUnixSeconds: grant.CreatedAt.Unix()}
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

type createAccessResourceRequest struct {
	Name       string `json:"name"`
	TargetKind string `json:"target_kind"`
	NodeID     string `json:"node_id,omitempty"`
	RouteID    string `json:"route_id,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
}

func (s *Service) createAccessResource(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessResourceRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
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
	var routeID *identity.ID
	if request.RouteID != "" {
		value, err := identity.ParseID(request.RouteID)
		if err != nil {
			s.writeError(w, malformed("invalid route_id"), false)
			return
		}
		routeID = &value
	}
	var prefix netip.Prefix
	if request.Prefix != "" {
		value, err := netip.ParsePrefix(request.Prefix)
		if err != nil || value != value.Masked() || value.Addr().Is4In6() {
			s.writeError(w, malformed("invalid prefix"), false)
			return
		}
		prefix = value
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	resource, _, err := s.store.AdministratorCreateAccessResource(r.Context(), decision, networkID, request.Name,
		controller.AccessResourceTargetKind(request.TargetKind), nodeID, routeID, prefix)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessResourceJSON(resource))
}

type updateAccessSelectorRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Service) updateAccessResource(w http.ResponseWriter, r *http.Request) {
	resourceID, err := parseIDPath(r, "resource_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request updateAccessSelectorRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	if request.Enabled == nil {
		s.writeError(w, malformed("enabled is required"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(resourceID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	resource, _, err := s.store.AdministratorSetAccessResourceEnabled(r.Context(), decision, resourceID, *request.Enabled)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, accessResourceJSON(resource))
}

type accessPortRangeRequest struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
}

type createAccessServiceRequest struct {
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Ports    json.RawMessage `json:"ports,omitempty"`
}

func (s *Service) createAccessService(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessServiceRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	protocol := controller.AccessServiceProtocol(request.Protocol)
	hasPorts := len(request.Ports) != 0
	if hasPorts && bytes.Equal(bytes.TrimSpace(request.Ports), []byte("null")) {
		s.writeError(w, malformed("ports must be an array, not null"), false)
		return
	}
	if protocol.SupportsPorts() && !hasPorts {
		s.writeError(w, malformed("TCP and UDP services require at least one port range"), false)
		return
	}
	if !protocol.SupportsPorts() && hasPorts {
		s.writeError(w, malformed("only TCP and UDP services may select ports"), false)
		return
	}
	var requestedPorts []accessPortRangeRequest
	if hasPorts {
		decoder := json.NewDecoder(bytes.NewReader(request.Ports))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&requestedPorts); err != nil || decoder.Decode(new(any)) != io.EOF {
			s.writeError(w, malformed("ports must be an array of port ranges"), false)
			return
		}
		if len(requestedPorts) == 0 {
			s.writeError(w, malformed("TCP and UDP services require at least one port range"), false)
			return
		}
	}
	ports := make([]controller.AccessPortRange, 0, len(requestedPorts))
	for _, portRange := range requestedPorts {
		if portRange.First == 0 || portRange.First > 65535 || portRange.Last < portRange.First || portRange.Last > 65535 {
			s.writeError(w, malformed("invalid service port range"), false)
			return
		}
		ports = append(ports, controller.AccessPortRange{First: uint16(portRange.First), Last: uint16(portRange.Last)})
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	service, _, err := s.store.AdministratorCreateAccessService(r.Context(), decision, networkID, request.Name,
		protocol, ports)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessServiceJSON(service))
}

func (s *Service) updateAccessService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := parseIDPath(r, "service_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request updateAccessSelectorRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	if request.Enabled == nil {
		s.writeError(w, malformed("enabled is required"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(serviceID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	service, _, err := s.store.AdministratorSetAccessServiceEnabled(r.Context(), decision, serviceID, *request.Enabled)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, accessServiceJSON(service))
}

type createAccessResourceGrantRequest struct {
	SubjectKind string `json:"subject_kind"`
	SubjectID   string `json:"subject_id"`
	ResourceID  string `json:"resource_id"`
	ServiceID   string `json:"service_id"`
}

func (s *Service) createAccessResourceGrant(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request createAccessResourceGrantRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	subjectID, err := identity.ParseID(request.SubjectID)
	if err != nil {
		s.writeError(w, malformed("invalid subject_id"), false)
		return
	}
	resourceID, err := identity.ParseID(request.ResourceID)
	if err != nil {
		s.writeError(w, malformed("invalid resource_id"), false)
		return
	}
	serviceID, err := identity.ParseID(request.ServiceID)
	if err != nil {
		s.writeError(w, malformed("invalid service_id"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	grant, _, err := s.store.AdministratorCreateAccessResourceGrant(r.Context(), decision, networkID,
		controller.AccessSubjectKind(request.SubjectKind), subjectID, resourceID, serviceID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, accessResourceGrantJSON(grant))
}

func (s *Service) deleteAccessResourceGrant(w http.ResponseWriter, r *http.Request) {
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
	epoch, err := s.store.AdministratorDeleteAccessResourceGrant(r.Context(), decision, grantID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}
