// Package adminauth defines controller administrator identities and the
// authoritative management-operation permission matrix.
package adminauth

import (
	"slices"
	"strings"

	"github.com/Doout/laneway/go/internal/identity"
)

const (
	MinUsernameLength = 3
	MaxUsernameLength = 64
	MaxSessionReason  = 256
)

type Role string

const (
	RoleOwner    Role = "owner"
	RoleOperator Role = "operator"
	RoleAuditor  Role = "auditor"
)

func (r Role) Valid() bool {
	return r == RoleOwner || r == RoleOperator || r == RoleAuditor
}

func ValidateUsername(username string) bool {
	if len(username) < MinUsernameLength || len(username) > MaxUsernameLength || username != strings.TrimSpace(username) {
		return false
	}
	for index := range len(username) {
		character := username[index]
		if character >= 'A' && character <= 'Z' || character >= 0x80 {
			return false
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && index < len(username)-1 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

type ActorKind string

const (
	ActorSystem           ActorKind = "system"
	ActorNode             ActorKind = "node"
	ActorAdministrator    ActorKind = "administrator"
	ActorServicePrincipal ActorKind = "service_principal"
	ActorRecoveryGrant    ActorKind = "recovery_grant"
	ActorUnauthenticated  ActorKind = "unauthenticated"
	ActorLegacyUnknown    ActorKind = "legacy_unknown"
)

type Actor struct {
	Kind ActorKind
	ID   *identity.ID
}

func (a Actor) Valid() bool {
	switch a.Kind {
	case ActorSystem, ActorUnauthenticated, ActorLegacyUnknown:
		return a.ID == nil
	case ActorNode, ActorAdministrator, ActorServicePrincipal, ActorRecoveryGrant:
		return a.ID != nil && !a.ID.IsZero()
	default:
		return false
	}
}

func SystemActor() Actor { return Actor{Kind: ActorSystem} }

func IDActor(kind ActorKind, id identity.ID) Actor {
	copyID := id
	return Actor{Kind: kind, ID: &copyID}
}

type Principal struct {
	ID          identity.ID
	Username    string
	Role        Role
	Enabled     bool
	AllNetworks bool
	NetworkIDs  []identity.NetworkID
}

func (p Principal) Valid() bool {
	if p.ID.IsZero() || !ValidateUsername(p.Username) || !p.Role.Valid() || p.Role == RoleOwner && !p.AllNetworks ||
		p.AllNetworks && len(p.NetworkIDs) != 0 {
		return false
	}
	seen := make(map[identity.NetworkID]struct{}, len(p.NetworkIDs))
	for _, networkID := range p.NetworkIDs {
		if networkID.IsZero() {
			return false
		}
		if _, exists := seen[networkID]; exists {
			return false
		}
		seen[networkID] = struct{}{}
	}
	return true
}

type Operation string

const (
	OperationNetworkList       Operation = "network.list"
	OperationNetworkRead       Operation = "network.read"
	OperationNetworkCreate     Operation = "network.create"
	OperationEnrollmentIssue   Operation = "enrollment.issue"
	OperationBootstrapCreate   Operation = "bootstrap_bundle.create"
	OperationNodeRead          Operation = "node.read"
	OperationNodeManage        Operation = "node.manage"
	OperationRouteRead         Operation = "route.read"
	OperationRouteManage       Operation = "route.manage"
	OperationACLRead           Operation = "acl.read"
	OperationACLManage         Operation = "acl.manage"
	OperationRelayRead         Operation = "relay.read"
	OperationRelayManage       Operation = "relay.manage"
	OperationCertificateRead   Operation = "certificate.read"
	OperationCertificateManage Operation = "certificate.revoke"
	OperationAuditRead         Operation = "audit.read"
	OperationAuditReadGlobal   Operation = "audit.read_global"
	OperationPrincipalManage   Operation = "principal.manage"
	OperationSessionManage     Operation = "session.manage_others"
	OperationRecoveryManage    Operation = "recovery.manage"
	OperationRootTokenRotate   Operation = "root_token.rotate"
)

type operationPolicy struct {
	owner, operator, auditor bool
	networkScoped            bool
}

var operationPolicies = map[Operation]operationPolicy{
	OperationNetworkList:     {owner: true, operator: true, auditor: true},
	OperationNetworkRead:     {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationNetworkCreate:   {owner: true},
	OperationEnrollmentIssue: {owner: true, operator: true, networkScoped: true},
	// Bootstrap bundles have no network identifier in their current wire
	// contract. Keep issuance global and owner-only until the request and the
	// resulting bundle are durably bound to a canonical network.
	OperationBootstrapCreate:   {owner: true},
	OperationNodeRead:          {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationNodeManage:        {owner: true, operator: true, networkScoped: true},
	OperationRouteRead:         {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationRouteManage:       {owner: true, operator: true, networkScoped: true},
	OperationACLRead:           {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationACLManage:         {owner: true, operator: true, networkScoped: true},
	OperationRelayRead:         {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationRelayManage:       {owner: true, operator: true, networkScoped: true},
	OperationCertificateRead:   {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationCertificateManage: {owner: true, operator: true, networkScoped: true},
	OperationAuditRead:         {owner: true, operator: true, auditor: true, networkScoped: true},
	OperationAuditReadGlobal:   {owner: true},
	OperationPrincipalManage:   {owner: true},
	OperationSessionManage:     {owner: true},
	// Recovery-grant issuance and root-token rotation are stable root service-
	// principal capabilities, not human-role permissions. Root subjects bypass
	// this role matrix and are revalidated against the durable singleton.
	OperationRecoveryManage:  {},
	OperationRootTokenRotate: {},
}

// permissionOrder is the stable wire order used by session views. Keep it
// exhaustive with operationPolicies so clients never need to duplicate the
// controller's permission matrix.
var permissionOrder = []Operation{
	OperationNetworkList, OperationNetworkRead, OperationNetworkCreate,
	OperationEnrollmentIssue, OperationBootstrapCreate, OperationNodeRead,
	OperationNodeManage, OperationRouteRead, OperationRouteManage,
	OperationACLRead, OperationACLManage, OperationRelayRead,
	OperationRelayManage, OperationCertificateRead, OperationCertificateManage,
	OperationAuditRead, OperationAuditReadGlobal, OperationPrincipalManage,
	OperationSessionManage, OperationRecoveryManage, OperationRootTokenRotate,
}

// Permissions returns a deterministic, defensive list of every operation
// granted to role by the authoritative matrix.
func Permissions(role Role) []Operation {
	permissions := make([]Operation, 0, len(permissionOrder))
	for _, operation := range permissionOrder {
		if RoleAllows(role, operation) {
			permissions = append(permissions, operation)
		}
	}
	return permissions
}

func (o Operation) Valid() bool {
	_, ok := operationPolicies[o]
	return ok
}

func (o Operation) NetworkScoped() bool {
	policy, ok := operationPolicies[o]
	return ok && policy.networkScoped
}

// RoleAllows reports whether the authoritative permission matrix grants an
// operation to a role. It deliberately ignores principal state and network
// scope; callers that have a canonical network must use Authorize instead.
func RoleAllows(role Role, operation Operation) bool {
	policy, ok := operationPolicies[operation]
	if !ok {
		return false
	}
	switch role {
	case RoleOwner:
		return policy.owner
	case RoleOperator:
		return policy.operator
	case RoleAuditor:
		return policy.auditor
	default:
		return false
	}
}

func Authorize(principal Principal, operation Operation, networkID *identity.NetworkID) bool {
	if !principal.Enabled || !principal.Valid() {
		return false
	}
	policy, ok := operationPolicies[operation]
	if !ok || (policy.networkScoped != (networkID != nil)) {
		return false
	}
	if !RoleAllows(principal.Role, operation) {
		return false
	}
	if networkID == nil || principal.Role == RoleOwner || principal.AllNetworks {
		return true
	}
	return slices.Contains(principal.NetworkIDs, *networkID)
}

// VisibleNetworkIDs returns the networks a principal may discover from a
// controller-provided list. Callers must use this for filtered network-list
// operations rather than authorizing the request and returning every record.
func VisibleNetworkIDs(principal Principal, available []identity.NetworkID) []identity.NetworkID {
	if !principal.Enabled || !principal.Valid() {
		return nil
	}
	visible := make([]identity.NetworkID, 0, len(available))
	for _, networkID := range available {
		if networkID.IsZero() {
			continue
		}
		if principal.Role == RoleOwner || principal.AllNetworks || slices.Contains(principal.NetworkIDs, networkID) {
			visible = append(visible, networkID)
		}
	}
	return visible
}
