package adminauth

import "net/http"

type ScopeSource string

const (
	ScopeGlobal   ScopeSource = "global"
	ScopePath     ScopeSource = "path"
	ScopeBody     ScopeSource = "body"
	ScopeObject   ScopeSource = "object"
	ScopeFiltered ScopeSource = "filtered"
)

type RoutePolicy struct {
	Method      string
	Pattern     string
	Operation   Operation
	ScopeSource ScopeSource
	Mutation    bool
}

var managementRoutes = []RoutePolicy{
	{http.MethodPost, "/v1/admin/auth/bootstrap-grants", OperationRecoveryManage, ScopeGlobal, true},
	{http.MethodPost, "/v1/admin/auth/root-token-rotations/{rotation_id}/begin", OperationRootTokenRotate, ScopeObject, true},
	{http.MethodPost, "/v1/admin/auth/root-token-rotations/{rotation_id}/complete", OperationRootTokenRotate, ScopeObject, true},
	{http.MethodPost, "/v1/admin/administrators", OperationPrincipalManage, ScopeGlobal, true},
	{http.MethodGet, "/v1/admin/administrators", OperationPrincipalManage, ScopeGlobal, false},
	{http.MethodGet, "/v1/admin/administrators/{principal_id}", OperationPrincipalManage, ScopeObject, false},
	{http.MethodPatch, "/v1/admin/administrators/{principal_id}", OperationPrincipalManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/administrators/{principal_id}/password", OperationPrincipalManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/administrators/{principal_id}/recovery-grants", OperationRecoveryManage, ScopeObject, true},
	{http.MethodGet, "/v1/admin/administrators/{principal_id}/sessions", OperationSessionManage, ScopeObject, false},
	{http.MethodPost, "/v1/admin/sessions/{session_id}/revoke", OperationSessionManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/service-principals", OperationServicePrincipalManage, ScopeGlobal, true},
	{http.MethodGet, "/v1/admin/service-principals", OperationServicePrincipalManage, ScopeGlobal, false},
	{http.MethodPost, "/v1/admin/service-principals/{principal_id}/disable", OperationServicePrincipalManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/service-principals/{principal_id}/tokens", OperationServicePrincipalManage, ScopeObject, true},
	{http.MethodGet, "/v1/admin/service-principals/{principal_id}/tokens", OperationServicePrincipalManage, ScopeObject, false},
	{http.MethodPost, "/v1/admin/service-access-tokens/{token_id}/revoke", OperationServicePrincipalManage, ScopeObject, true},
	{http.MethodGet, "/v1/admin/audit", OperationAuditReadGlobal, ScopeGlobal, false},
	{http.MethodGet, "/v1/admin/audit/page", OperationAuditReadGlobal, ScopeGlobal, false},
	{http.MethodPost, "/v1/admin/enrollment-tokens", OperationEnrollmentIssue, ScopeBody, true},
	{http.MethodPost, "/v1/admin/bootstrap-bundles", OperationBootstrapCreate, ScopeGlobal, true},
	{http.MethodPost, "/v1/admin/networks", OperationNetworkCreate, ScopeGlobal, true},
	{http.MethodGet, "/v1/admin/networks", OperationNetworkList, ScopeFiltered, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}", OperationNetworkRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/nodes", OperationNodeRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/endpoint-statuses", OperationNodeRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/relays", OperationRelayRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/acl-rules", OperationACLRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/access-subjects", OperationACLRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/certificates", OperationCertificateRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/routes", OperationRouteRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/audit", OperationAuditRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/audit/page", OperationAuditRead, ScopePath, false},
	{http.MethodPost, "/v1/admin/routes/assign", OperationRouteManage, ScopeBody, true},
	{http.MethodPost, "/v1/admin/routes/{route_id}/approve", OperationRouteManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/routes/{route_id}/withdraw", OperationRouteManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/acl-rules", OperationACLManage, ScopePath, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/users", OperationACLManage, ScopePath, true},
	{http.MethodPatch, "/v1/admin/users/{user_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/teams", OperationACLManage, ScopePath, true},
	{http.MethodPut, "/v1/admin/teams/{team_id}/members/{user_id}", OperationACLManage, ScopeObject, true},
	{http.MethodDelete, "/v1/admin/teams/{team_id}/members/{user_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/access-grants", OperationACLManage, ScopePath, true},
	{http.MethodDelete, "/v1/admin/access-grants/{grant_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/resources", OperationACLManage, ScopePath, true},
	{http.MethodPatch, "/v1/admin/resources/{resource_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/services", OperationACLManage, ScopePath, true},
	{http.MethodPatch, "/v1/admin/services/{service_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/resource-access-grants", OperationACLManage, ScopePath, true},
	{http.MethodDelete, "/v1/admin/resource-access-grants/{grant_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPut, "/v1/admin/acl-rules/{rule_id}", OperationACLManage, ScopeObject, true},
	{http.MethodDelete, "/v1/admin/acl-rules/{rule_id}", OperationACLManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/nodes/{node_id}/revoke", OperationNodeManage, ScopeObject, true},
	{http.MethodPut, "/v1/admin/nodes/{node_id}/capabilities", OperationNodeManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/certificates/{serial}/revoke", OperationCertificateManage, ScopePath, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/relays", OperationRelayManage, ScopePath, true},
	{http.MethodPost, "/v1/admin/relays/{relay_id}/disable", OperationRelayManage, ScopeObject, true},
	{http.MethodPut, "/v1/admin/relays/{relay_id}", OperationRelayManage, ScopeObject, true},
}

func ManagementRoutes() []RoutePolicy {
	return append([]RoutePolicy(nil), managementRoutes...)
}

func (p RoutePolicy) Valid() bool {
	if p.Method == "" || p.Pattern == "" || !p.Operation.Valid() {
		return false
	}
	switch p.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		if p.Mutation {
			return false
		}
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if !p.Mutation {
			return false
		}
	default:
		return false
	}
	switch p.ScopeSource {
	case ScopeGlobal, ScopeFiltered:
		return !p.Operation.NetworkScoped()
	case ScopePath, ScopeBody:
		return p.Operation.NetworkScoped()
	case ScopeObject:
		return p.Operation.NetworkScoped() || p.Operation == OperationPrincipalManage ||
			p.Operation == OperationSessionManage || p.Operation == OperationServicePrincipalManage ||
			p.Operation == OperationRecoveryManage ||
			p.Operation == OperationRootTokenRotate
	default:
		return false
	}
}
