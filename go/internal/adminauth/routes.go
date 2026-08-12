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
	{http.MethodPost, "/v1/admin/enrollment-tokens", OperationEnrollmentIssue, ScopeBody, true},
	{http.MethodPost, "/v1/admin/bootstrap-bundles", OperationBootstrapCreate, ScopeGlobal, true},
	{http.MethodPost, "/v1/admin/networks", OperationNetworkCreate, ScopeGlobal, true},
	{http.MethodGet, "/v1/admin/networks", OperationNetworkList, ScopeFiltered, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}", OperationNetworkRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/nodes", OperationNodeRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/relays", OperationRelayRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/acl-rules", OperationACLRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/certificates", OperationCertificateRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/routes", OperationRouteRead, ScopePath, false},
	{http.MethodGet, "/v1/admin/networks/{network_id}/audit", OperationAuditRead, ScopePath, false},
	{http.MethodPost, "/v1/admin/routes/assign", OperationRouteManage, ScopeBody, true},
	{http.MethodPost, "/v1/admin/routes/{route_id}/approve", OperationRouteManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/routes/{route_id}/withdraw", OperationRouteManage, ScopeObject, true},
	{http.MethodPost, "/v1/admin/networks/{network_id}/acl-rules", OperationACLManage, ScopePath, true},
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
	case ScopePath, ScopeBody, ScopeObject:
		return p.Operation.NetworkScoped()
	default:
		return false
	}
}
