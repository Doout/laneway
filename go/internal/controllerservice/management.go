package controllerservice

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

type networkRequest struct {
	NetworkID string `json:"network_id,omitempty"`
	Name      string `json:"name"`
	IPv4Pool  string `json:"ipv4_pool"`
	IPv6Pool  string `json:"ipv6_pool,omitempty"`
}

type networkResponse struct {
	NetworkID          string `json:"network_id"`
	Name               string `json:"name"`
	IPv4Pool           string `json:"ipv4_pool"`
	IPv6Pool           string `json:"ipv6_pool,omitempty"`
	ConfigurationEpoch uint64 `json:"configuration_epoch"`
	CreatedAtUnix      int64  `json:"created_at_unix_seconds"`
}

func networkJSON(network controller.Network) networkResponse {
	response := networkResponse{
		NetworkID: network.ID.String(), Name: network.Name, IPv4Pool: network.IPv4Pool.String(),
		ConfigurationEpoch: network.ConfigurationEpoch, CreatedAtUnix: network.CreatedAt.Unix(),
	}
	if network.IPv6Pool.IsValid() {
		response.IPv6Pool = network.IPv6Pool.String()
	}
	return response
}

func (s *Service) createNetwork(w http.ResponseWriter, r *http.Request) {
	var req networkRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	pool, err := netip.ParsePrefix(req.IPv4Pool)
	if err != nil || pool.String() != req.IPv4Pool {
		s.writeError(w, malformed("ipv4_pool must be a canonical CIDR prefix"), false)
		return
	}
	var pool6 netip.Prefix
	if req.IPv6Pool != "" {
		pool6, err = netip.ParsePrefix(req.IPv6Pool)
		if err != nil || pool6.String() != req.IPv6Pool {
			s.writeError(w, malformed("ipv6_pool must be a canonical CIDR prefix"), false)
			return
		}
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var network controller.Network
	if req.NetworkID == "" {
		network, err = s.store.AdministratorCreateNetworkDualStack(r.Context(), decision, req.Name, pool, pool6)
	} else {
		var networkID identity.NetworkID
		networkID, err = identity.ParseNetworkID(req.NetworkID)
		if err != nil {
			s.writeError(w, malformed("network_id must be a canonical non-zero ID"), false)
			return
		}
		network, err = s.store.AdministratorCreateNetworkDualStackWithID(r.Context(), decision, networkID, req.Name, pool, pool6)
	}
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, networkJSON(network))
}

func (s *Service) readNetwork(w http.ResponseWriter, r *http.Request) {
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
	network, err := s.store.AdministratorNetwork(r.Context(), decision, networkID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, networkJSON(network))
}

func (s *Service) readNetworks(w http.ResponseWriter, r *http.Request) {
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.FilteredTarget())
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorNetworks(r.Context(), decision, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]networkResponse, 0, len(values))
	for _, value := range values {
		response = append(response, networkJSON(value))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"networks": response})
}

type nodeResponse struct {
	NodeID                    string `json:"node_id"`
	NetworkID                 string `json:"network_id"`
	Name                      string `json:"name"`
	EnabledCapabilities       uint64 `json:"enabled_capabilities"`
	IPv4Address               string `json:"ipv4_address,omitempty"`
	IPv6Address               string `json:"ipv6_address,omitempty"`
	CreatedAtUnixSeconds      int64  `json:"created_at_unix_seconds"`
	RevokedAtUnixSeconds      *int64 `json:"revoked_at_unix_seconds,omitempty"`
	EnrollmentClass           string `json:"enrollment_class"`
	LeaseExpiresAtUnixSeconds *int64 `json:"lease_expires_at_unix_seconds,omitempty"`
}

func (s *Service) readNodes(w http.ResponseWriter, r *http.Request) {
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
	values, err := s.store.AdministratorNetworkNodes(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]nodeResponse, 0, len(values))
	for _, value := range values {
		item := nodeResponse{NodeID: value.ID.String(), NetworkID: networkID.String(), Name: value.Name,
			EnabledCapabilities: value.EnabledCapabilities, CreatedAtUnixSeconds: value.CreatedAt.Unix(), RevokedAtUnixSeconds: unixPointer(value.RevokedAt),
			EnrollmentClass: string(value.EnrollmentClass), LeaseExpiresAtUnixSeconds: unixPointer(value.LeaseExpiresAt)}
		if value.IPv4Address.IsValid() {
			item.IPv4Address = value.IPv4Address.String()
		}
		if value.IPv6Address.IsValid() {
			item.IPv6Address = value.IPv6Address.String()
		}
		response = append(response, item)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"nodes": response})
}

type registerRelayRequest struct {
	ServiceID string `json:"service_id"`
	NodeID    string `json:"node_id,omitempty"`
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
}

type updateRelayRequest struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Enabled  bool   `json:"enabled"`
}

type relayResponse struct {
	RelayID            string  `json:"relay_id"`
	NetworkID          string  `json:"network_id"`
	ServiceID          string  `json:"service_id"`
	NodeID             *string `json:"node_id,omitempty"`
	Name               string  `json:"name"`
	Endpoint           string  `json:"endpoint"`
	Enabled            bool    `json:"enabled"`
	CreatedAtUnix      int64   `json:"created_at_unix_seconds"`
	ConfigurationEpoch uint64  `json:"configuration_epoch"`
}

func relayJSON(relay controller.Relay, epoch uint64) relayResponse {
	response := relayResponse{
		RelayID: relay.ID.String(), NetworkID: relay.NetworkID.String(), ServiceID: relay.ServiceID.String(),
		Name: relay.Name, Endpoint: relay.Endpoint, Enabled: relay.Enabled,
		CreatedAtUnix: relay.CreatedAt.Unix(), ConfigurationEpoch: epoch,
	}
	if relay.NodeID != nil {
		value := relay.NodeID.String()
		response.NodeID = &value
	}
	return response
}

func (s *Service) registerRelay(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req registerRelayRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	serviceID, err := identity.ParseID(req.ServiceID)
	if err != nil {
		s.writeError(w, malformed("invalid service_id"), false)
		return
	}
	var nodeID *identity.NodeID
	if req.NodeID != "" {
		parsed, err := identity.ParseNodeID(req.NodeID)
		if err != nil {
			s.writeError(w, malformed("invalid node_id"), false)
			return
		}
		nodeID = &parsed
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	relay, epoch, err := s.store.AdministratorRegisterRelay(r.Context(), decision, networkID, serviceID, nodeID, req.Name, req.Endpoint)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, relayJSON(relay, epoch))
}

func (s *Service) disableRelay(w http.ResponseWriter, r *http.Request) {
	relayID, err := parseIDPath(r, "relay_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(relayID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorDisableRelay(r.Context(), decision, relayID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) updateRelay(w http.ResponseWriter, r *http.Request) {
	relayID, err := parseIDPath(r, "relay_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var request updateRelayRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(relayID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	value, epoch, err := s.store.AdministratorUpdateRelay(r.Context(), decision, relayID, request.Name, request.Endpoint, request.Enabled)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, relayJSON(value, epoch))
}

func (s *Service) readRelays(w http.ResponseWriter, r *http.Request) {
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
	values, epoch, err := s.store.AdministratorNetworkRelays(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]relayResponse, 0, len(values))
	for _, value := range values {
		response = append(response, relayJSON(value, epoch))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"relays": response})
}

type certificateResponse struct {
	CertificateID        string `json:"certificate_id"`
	NetworkID            string `json:"network_id"`
	NodeID               string `json:"node_id"`
	Serial               string `json:"serial"`
	NotBeforeUnixSeconds int64  `json:"not_before_unix_seconds"`
	NotAfterUnixSeconds  int64  `json:"not_after_unix_seconds"`
	CreatedAtUnixSeconds int64  `json:"created_at_unix_seconds"`
	RevokedAtUnixSeconds *int64 `json:"revoked_at_unix_seconds,omitempty"`
	RevocationReason     string `json:"revocation_reason,omitempty"`
}

func (s *Service) readCertificates(w http.ResponseWriter, r *http.Request) {
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
	values, err := s.store.AdministratorNetworkCertificates(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]certificateResponse, 0, len(values))
	for _, value := range values {
		response = append(response, certificateResponse{CertificateID: value.ID.String(), NetworkID: networkID.String(), NodeID: value.NodeID.String(),
			Serial: hex.EncodeToString(value.Serial), NotBeforeUnixSeconds: value.NotBefore.Unix(), NotAfterUnixSeconds: value.NotAfter.Unix(),
			CreatedAtUnixSeconds: value.CreatedAt.Unix(), RevokedAtUnixSeconds: unixPointer(value.RevokedAt), RevocationReason: value.RevocationReason})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"certificates": response})
}

type advertiseRouteRequest struct {
	Prefix                string `json:"prefix"`
	Kind                  string `json:"kind"`
	Mode                  string `json:"mode"`
	Metric                uint32 `json:"metric"`
	ValidUntilUnixSeconds int64  `json:"valid_until_unix_seconds,omitempty"`
}

type routeResponse struct {
	RouteID                string `json:"route_id"`
	NetworkID              string `json:"network_id"`
	NodeID                 string `json:"node_id"`
	Prefix                 string `json:"prefix"`
	Kind                   string `json:"kind"`
	Mode                   string `json:"mode"`
	Metric                 uint32 `json:"metric"`
	State                  string `json:"state"`
	ValidUntilUnixSeconds  *int64 `json:"valid_until_unix_seconds,omitempty"`
	CreatedAtUnixSeconds   int64  `json:"created_at_unix_seconds"`
	ApprovedAtUnixSeconds  *int64 `json:"approved_at_unix_seconds,omitempty"`
	WithdrawnAtUnixSeconds *int64 `json:"withdrawn_at_unix_seconds,omitempty"`
}

func routeJSON(route controller.Route) routeResponse {
	return routeResponse{
		RouteID: route.ID.String(), NetworkID: route.NetworkID.String(), NodeID: route.NodeID.String(),
		Prefix: route.Prefix.String(), Kind: string(route.Kind), Mode: string(route.Mode), Metric: route.Metric,
		State: string(route.State), ValidUntilUnixSeconds: unixPointer(route.ValidUntil),
		CreatedAtUnixSeconds: route.CreatedAt.Unix(), ApprovedAtUnixSeconds: unixPointer(route.ApprovedAt),
		WithdrawnAtUnixSeconds: unixPointer(route.WithdrawnAt),
	}
}

func unixPointer(value *time.Time) *int64 {
	if value == nil {
		return nil
	}
	unix := value.Unix()
	return &unix
}

func (s *Service) advertiseRoute(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req advertiseRouteRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	prefix, err := netip.ParsePrefix(req.Prefix)
	if err != nil || prefix.String() != req.Prefix {
		s.writeError(w, malformed("prefix must be a canonical CIDR prefix"), false)
		return
	}
	kind := controller.RouteKind(req.Kind)
	if kind != controller.RouteKindSubnet && kind != controller.RouteKindExit {
		s.writeError(w, malformed("kind must be subnet or exit"), false)
		return
	}
	mode := controller.RouteMode(req.Mode)
	if mode != controller.RouteModeNAT && mode != controller.RouteModeRouted {
		s.writeError(w, malformed("mode must be nat or routed"), false)
		return
	}
	var validUntil *time.Time
	if req.ValidUntilUnixSeconds != 0 {
		value := time.Unix(req.ValidUntilUnixSeconds, 0).UTC()
		validUntil = &value
	}
	route, err := s.store.AdvertiseRoute(r.Context(), caller.NodeID, prefix, kind, mode, req.Metric, validUntil)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, routeJSON(route))
}

type assignRouteRequest struct {
	NetworkID string `json:"network_id"`
	NodeID    string `json:"node_id"`
	Prefix    string `json:"prefix"`
	Mode      string `json:"mode"`
	Metric    uint32 `json:"metric"`
}

func (s *Service) assignRoute(w http.ResponseWriter, r *http.Request) {
	var req assignRouteRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	networkID, err := identity.ParseNetworkID(req.NetworkID)
	if err != nil {
		s.writeError(w, malformed("network_id is invalid"), false)
		return
	}
	nodeID, err := identity.ParseNodeID(req.NodeID)
	if err != nil {
		s.writeError(w, malformed("node_id is invalid"), false)
		return
	}
	prefix, err := netip.ParsePrefix(req.Prefix)
	if err != nil || prefix != prefix.Masked() || prefix.Bits() == 0 {
		s.writeError(w, malformed("prefix must be a canonical non-default CIDR prefix"), false)
		return
	}
	mode := controller.RouteMode(req.Mode)
	if mode != controller.RouteModeNAT && mode != controller.RouteModeRouted {
		s.writeError(w, malformed("mode must be nat or routed"), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	route, _, created, err := s.store.AdministratorAssignRoute(r.Context(), decision, networkID, nodeID, prefix, mode, req.Metric)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	s.writeJSON(w, status, routeJSON(route))
}

type epochResponse struct {
	ConfigurationEpoch uint64 `json:"configuration_epoch"`
}

type nodeCapabilitiesRequest struct {
	EnabledCapabilities uint64 `json:"enabled_capabilities"`
}

func (s *Service) setNodeCapabilities(w http.ResponseWriter, r *http.Request) {
	nodeRaw, err := parseIDPath(r, "node_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req nodeCapabilitiesRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(nodeRaw))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorSetNodeCapabilities(r.Context(), decision, identity.NodeID(nodeRaw), protocol.Capability(req.EnabledCapabilities))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) withdrawRoute(w http.ResponseWriter, r *http.Request) {
	caller, err := s.authenticatedNode(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	routeID, err := parseIDPath(r, "route_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.WithdrawRoute(r.Context(), routeID, &caller.NodeID)
	if errors.Is(err, controller.ErrInvalid) {
		err = ErrPermissionDenied
	}
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) approveRoute(w http.ResponseWriter, r *http.Request) {
	routeID, err := parseIDPath(r, "route_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(routeID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorApproveRoute(r.Context(), decision, routeID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) adminWithdrawRoute(w http.ResponseWriter, r *http.Request) {
	routeID, err := parseIDPath(r, "route_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(routeID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorWithdrawRoute(r.Context(), decision, routeID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

type aclRuleRequest struct {
	Priority    uint32          `json:"priority"`
	Action      string          `json:"action"`
	Selector    json.RawMessage `json:"selector"`
	Description string          `json:"description"`
}

type updateACLRuleRequest struct {
	Priority    uint32          `json:"priority"`
	Action      string          `json:"action"`
	Selector    json.RawMessage `json:"selector"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
}

type aclRuleResponse struct {
	RuleID             string          `json:"rule_id"`
	NetworkID          string          `json:"network_id"`
	Priority           uint32          `json:"priority"`
	Action             string          `json:"action"`
	Selector           json.RawMessage `json:"selector"`
	Description        string          `json:"description"`
	Enabled            bool            `json:"enabled"`
	ConfigurationEpoch uint64          `json:"configuration_epoch"`
}

func (s *Service) addACLRule(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req aclRuleRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	action := controller.ACLAction(req.Action)
	if action != controller.ACLActionAccept && action != controller.ACLActionDeny {
		s.writeError(w, malformed("action must be accept or deny"), false)
		return
	}
	selector, selectorJSON, err := parseTrafficSelector(req.Selector)
	if err != nil {
		s.writeError(w, malformed(err.Error()), false)
		return
	}
	if err := validateTrafficSelector(selector); err != nil {
		s.writeError(w, malformed(err.Error()), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	rule, epoch, err := s.store.AdministratorAddACLRule(r.Context(), decision, networkID, req.Priority, action, string(selectorJSON), req.Description)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, aclRuleResponse{
		RuleID: rule.ID.String(), NetworkID: networkID.String(), Priority: rule.Priority, Action: string(rule.Action),
		Selector: selectorJSON, Description: rule.Description, Enabled: true, ConfigurationEpoch: epoch,
	})
}

func (s *Service) readACLRules(w http.ResponseWriter, r *http.Request) {
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
	values, epoch, err := s.store.AdministratorNetworkACLRules(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]aclRuleResponse, 0, len(values))
	for _, value := range values {
		response = append(response, aclRuleResponse{RuleID: value.ID.String(), NetworkID: networkID.String(), Priority: value.Priority,
			Action: string(value.Action), Selector: json.RawMessage(value.SelectorJSON), Description: value.Description, Enabled: value.Enabled,
			ConfigurationEpoch: epoch})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"acl_rules": response})
}

func (s *Service) updateACLRule(w http.ResponseWriter, r *http.Request) {
	ruleID, err := parseIDPath(r, "rule_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req updateACLRuleRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	action := controller.ACLAction(req.Action)
	if action != controller.ACLActionAccept && action != controller.ACLActionDeny {
		s.writeError(w, malformed("action must be accept or deny"), false)
		return
	}
	selector, selectorJSON, err := parseTrafficSelector(req.Selector)
	if err != nil {
		s.writeError(w, malformed(err.Error()), false)
		return
	}
	if err := validateTrafficSelector(selector); err != nil {
		s.writeError(w, malformed(err.Error()), false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(ruleID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	rule, epoch, err := s.store.AdministratorUpdateACLRule(r.Context(), decision, ruleID, req.Priority, action, string(selectorJSON), req.Description, req.Enabled)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, aclRuleResponse{
		RuleID: rule.ID.String(), NetworkID: rule.NetworkID.String(), Priority: rule.Priority, Action: string(rule.Action),
		Selector: selectorJSON, Description: rule.Description, Enabled: rule.Enabled, ConfigurationEpoch: epoch,
	})
}

func parseTrafficSelector(raw json.RawMessage) (*lanewayv1.TrafficSelector, []byte, error) {
	if len(raw) == 0 {
		return nil, nil, errors.New("selector is required")
	}
	selector := new(lanewayv1.TrafficSelector)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, selector); err != nil {
		return nil, nil, errors.New("selector must be strict TrafficSelector protojson")
	}
	canonical, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(selector)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal selector: %w", err)
	}
	return selector, canonical, nil
}

func validateTrafficSelector(selector *lanewayv1.TrafficSelector) error {
	for _, ids := range [][][]byte{selector.GetSourceNodeIds(), selector.GetDestinationNodeIds()} {
		for _, raw := range ids {
			if len(raw) != identity.IDSize {
				return errors.New("selector node IDs must be exactly 16 bytes")
			}
			var id identity.ID
			copy(id[:], raw)
			if id.IsZero() {
				return errors.New("selector node IDs must be nonzero")
			}
		}
	}
	for _, prefixes := range [][]*lanewayv1.IpPrefix{selector.GetSourcePrefixes(), selector.GetDestinationPrefixes()} {
		for _, prefix := range prefixes {
			if prefix == nil {
				return errors.New("selector prefix must not be null")
			}
			addr, ok := netip.AddrFromSlice(prefix.GetAddress())
			if !ok || int(prefix.GetPrefixLength()) > addr.BitLen() {
				return errors.New("selector contains an invalid IP prefix")
			}
			parsed := netip.PrefixFrom(addr, int(prefix.GetPrefixLength()))
			if parsed != parsed.Masked() {
				return errors.New("selector IP prefixes must be canonical")
			}
		}
	}
	protocol := selector.GetIpProtocol()
	switch protocol {
	case lanewayv1.IpProtocol_IP_PROTOCOL_ICMP, lanewayv1.IpProtocol_IP_PROTOCOL_TCP,
		lanewayv1.IpProtocol_IP_PROTOCOL_UDP, lanewayv1.IpProtocol_IP_PROTOCOL_ICMPV6,
		lanewayv1.IpProtocol_IP_PROTOCOL_ANY:
	default:
		return errors.New("selector ip_protocol must be explicit")
	}
	for _, portRange := range selector.GetDestinationPorts() {
		if portRange == nil || portRange.GetFirst() == 0 || portRange.GetFirst() > portRange.GetLast() || portRange.GetLast() > 65535 {
			return errors.New("selector contains an invalid destination port range")
		}
		if protocol != lanewayv1.IpProtocol_IP_PROTOCOL_TCP && protocol != lanewayv1.IpProtocol_IP_PROTOCOL_UDP {
			return errors.New("selector destination ports require TCP or UDP")
		}
	}
	return nil
}

func (s *Service) deleteACLRule(w http.ResponseWriter, r *http.Request) {
	ruleID, err := parseIDPath(r, "rule_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(ruleID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorDeleteACLRule(r.Context(), decision, ruleID)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

type revocationRequest struct {
	Reason string `json:"reason"`
}

func (s *Service) revokeNode(w http.ResponseWriter, r *http.Request) {
	nodeRaw, err := parseIDPath(r, "node_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var req revocationRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(nodeRaw))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorRevokeNode(r.Context(), decision, identity.NodeID(nodeRaw), req.Reason)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	serialText := r.PathValue("serial")
	if serialText == "" || len(serialText) > 64 || len(serialText)%2 != 0 || strings.ToLower(serialText) != serialText || (len(serialText) > 2 && strings.HasPrefix(serialText, "00")) {
		s.writeError(w, malformed("serial must be canonical lowercase even-length hexadecimal"), false)
		return
	}
	serial, err := hex.DecodeString(serialText)
	if err != nil || len(serial) == 0 || serial[0] == 0 {
		s.writeError(w, malformed("serial must be canonical lowercase even-length hexadecimal"), false)
		return
	}
	var req revocationRequest
	if err := s.decodeJSON(w, r, &req); err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	epoch, err := s.store.AdministratorRevokeCertificateBySerial(r.Context(), decision, networkID, serial, req.Reason)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusOK, epochResponse{ConfigurationEpoch: epoch})
}

func (s *Service) readRoutes(w http.ResponseWriter, r *http.Request) {
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
	routes, err := s.store.AdministratorNetworkRoutes(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]routeResponse, 0, len(routes))
	for _, route := range routes {
		response = append(response, routeJSON(route))
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"routes": response})
}

type auditResponse struct {
	EventID   string  `json:"event_id"`
	NetworkID string  `json:"network_id,omitempty"`
	ActorKind string  `json:"actor_kind"`
	ActorID   *string `json:"actor_id,omitempty"`
	// ActorNodeID is retained for existing clients while actor_kind/actor_id
	// carries every durable actor class.
	ActorNodeID          *string         `json:"actor_node_id,omitempty"`
	Action               string          `json:"action"`
	TargetType           string          `json:"target_type"`
	TargetID             *string         `json:"target_id,omitempty"`
	Details              json.RawMessage `json:"details"`
	CreatedAtUnixSeconds int64           `json:"created_at_unix_seconds"`
}

func (s *Service) readAudit(w http.ResponseWriter, r *http.Request) {
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
	events, err := s.store.AdministratorAuditEvents(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	response := make([]auditResponse, 0, len(events))
	for _, event := range events {
		item := auditResponse{
			EventID: event.ID.String(), NetworkID: networkID.String(), ActorKind: string(event.Actor.Kind), Action: event.Action,
			TargetType: event.TargetType, Details: json.RawMessage(event.Details), CreatedAtUnixSeconds: event.CreatedAt.Unix(),
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

func parseNetworkPath(r *http.Request) (identity.NetworkID, error) {
	networkID, err := identity.ParseNetworkID(r.PathValue("network_id"))
	if err != nil {
		return identity.NetworkID{}, malformed("invalid network_id")
	}
	return networkID, nil
}

func parseIDPath(r *http.Request, name string) (identity.ID, error) {
	id, err := identity.ParseID(r.PathValue(name))
	if err != nil {
		return identity.ID{}, malformed("invalid " + name)
	}
	return id, nil
}

func queryLimit(r *http.Request, defaultValue int) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultValue, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 1000 {
		return 0, malformed("limit must be an integer from 1 through 1000")
	}
	return limit, nil
}
