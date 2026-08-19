package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

var (
	administratorEnrollmentIssuePolicy     = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/enrollment-tokens")
	administratorBootstrapCreatePolicy     = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/bootstrap-bundles")
	administratorNetworkCreatePolicy       = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks")
	administratorNetworkListPolicy         = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks")
	administratorNetworkReadPolicy         = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}")
	administratorNodeListPolicy            = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/nodes")
	administratorRelayListPolicy           = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/relays")
	administratorACLListPolicy             = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/acl-rules")
	administratorAccessInventoryPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/access-subjects")
	administratorCertificateListPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/certificates")
	administratorRouteListPolicy           = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/routes")
	administratorAuditListPolicy           = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/audit")
	administratorAuditPageListPolicy       = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/audit/page")
	administratorGlobalAuditListPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/audit")
	administratorGlobalAuditPageListPolicy = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/audit/page")
	administratorRouteAssignPolicy         = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/routes/assign")
	administratorRouteApprovePolicy        = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/routes/{route_id}/approve")
	administratorRouteWithdrawPolicy       = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/routes/{route_id}/withdraw")
	administratorACLCreatePolicy           = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/acl-rules")
	administratorAccessUserCreatePolicy    = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/users")
	administratorAccessUserUpdatePolicy    = mustAdministratorResourcePolicy(http.MethodPatch, "/v1/admin/users/{user_id}")
	administratorAccessTeamCreatePolicy    = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/teams")
	administratorAccessMemberAddPolicy     = mustAdministratorResourcePolicy(http.MethodPut, "/v1/admin/teams/{team_id}/members/{user_id}")
	administratorAccessMemberDeletePolicy  = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/teams/{team_id}/members/{user_id}")
	administratorAccessGrantCreatePolicy   = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/access-grants")
	administratorAccessGrantDeletePolicy   = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/access-grants/{grant_id}")
	administratorACLUpdatePolicy           = mustAdministratorResourcePolicy(http.MethodPut, "/v1/admin/acl-rules/{rule_id}")
	administratorACLDeletePolicy           = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/acl-rules/{rule_id}")
	administratorNodeRevokePolicy          = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/nodes/{node_id}/revoke")
	administratorNodeCapabilitiesPolicy    = mustAdministratorResourcePolicy(http.MethodPut, "/v1/admin/nodes/{node_id}/capabilities")
	administratorCertificateRevokePolicy   = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/certificates/{serial}/revoke")
	administratorRelayCreatePolicy         = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/relays")
	administratorRelayDisablePolicy        = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/relays/{relay_id}/disable")
	administratorRelayUpdatePolicy         = mustAdministratorResourcePolicy(http.MethodPut, "/v1/admin/relays/{relay_id}")
)

func mustAdministratorResourcePolicy(method, pattern string) adminauth.RoutePolicy {
	for _, policy := range adminauth.ManagementRoutes() {
		if policy.Method == method && policy.Pattern == pattern {
			return policy
		}
	}
	panic("controller administrator resource policy is not registered: " + method + " " + pattern)
}

func validateAdministratorResourceDecision(decision adminauth.Decision, policy adminauth.RoutePolicy, target adminauth.DecisionTarget) error {
	if !decision.Matches(decision.Subject(), policy, target) {
		return fmt.Errorf("%w: administrator decision does not match resource operation", ErrInvalid)
	}
	return nil
}

func (s *Store) authorizeAdministratorGlobalResourceTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision,
	policy adminauth.RoutePolicy, target adminauth.DecisionTarget) (adminauth.Actor, error) {
	if err := validateAdministratorResourceDecision(decision, policy, target); err != nil {
		return adminauth.Actor{}, err
	}
	return s.authorizeAdministratorDecisionTx(ctx, tx, decision, nil)
}

func (s *Store) authorizeAdministratorNetworkResourceTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision,
	policy adminauth.RoutePolicy, networkID identity.NetworkID) (adminauth.Actor, error) {
	if err := validateAdministratorResourceDecision(decision, policy, adminauth.NetworkTarget(networkID)); err != nil {
		return adminauth.Actor{}, err
	}
	return s.authorizeAdministratorDecisionTx(ctx, tx, decision, &networkID)
}

func administratorNetworkExistsTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID) error {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM networks WHERE id=?`, idBytes(networkID)).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("read administrator network parent: %w", err)
	}
	return nil
}

// authorizeAdministratorObjectResourceTx checks exact route/object binding
// before querying, resolves the canonical network in this transaction, then
// revalidates durable authorization. Missing objects use the same generic
// denial as out-of-scope objects so callers cannot probe record existence.
func (s *Store) authorizeAdministratorObjectResourceTx(ctx context.Context, tx *sql.Tx, decision adminauth.Decision,
	policy adminauth.RoutePolicy, objectID identity.ID, networkQuery string, queryArguments ...any) (adminauth.Actor, identity.NetworkID, error) {
	if err := validateAdministratorResourceDecision(decision, policy, adminauth.ObjectTarget(objectID)); err != nil {
		return adminauth.Actor{}, identity.NetworkID{}, err
	}
	authorization, err := s.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return adminauth.Actor{}, identity.NetworkID{}, err
	}
	var networkRaw []byte
	if err := tx.QueryRowContext(ctx, networkQuery, queryArguments...).Scan(&networkRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return adminauth.Actor{}, identity.NetworkID{}, ErrNotFound
		}
		return adminauth.Actor{}, identity.NetworkID{}, err
	}
	networkValue, err := scanID(networkRaw)
	if err != nil {
		return adminauth.Actor{}, identity.NetworkID{}, err
	}
	networkID := identity.NetworkID(networkValue)
	err = authorizeAdministratorDecisionScope(authorization, decision, &networkID)
	if errors.Is(err, ErrPermissionDenied) {
		return adminauth.Actor{}, identity.NetworkID{}, ErrNotFound
	}
	return authorization.actor, networkID, err
}
