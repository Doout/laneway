package adminauth

import (
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/Doout/laneway/go/internal/identity"
)

// SubjectKind identifies the durable credential class that authenticated a
// management request. It is transport-neutral: HTTP bearer headers and
// cookies are interpreted before a Subject is constructed.
type SubjectKind string

const (
	SubjectRootServicePrincipal  SubjectKind = "root_service_principal"
	SubjectServicePrincipalToken SubjectKind = "service_principal_token"
	SubjectAdministratorSession  SubjectKind = "administrator_session"
)

func (k SubjectKind) Valid() bool {
	return k == SubjectRootServicePrincipal || k == SubjectServicePrincipalToken ||
		k == SubjectAdministratorSession
}

// Subject is the immutable durable identity binding for an authenticated
// management request. It never contains a role, network grant, username,
// display label, or other state that can change after authentication.
type Subject struct {
	kind      SubjectKind
	actorID   identity.ID
	sessionID identity.ID
	tokenHash [sha256.Size]byte
}

func RootSubject(servicePrincipalID identity.ID) Subject {
	return Subject{kind: SubjectRootServicePrincipal, actorID: servicePrincipalID}
}

func SessionSubject(principalID, sessionID identity.ID) Subject {
	return Subject{kind: SubjectAdministratorSession, actorID: principalID, sessionID: sessionID}
}

func ServicePrincipalTokenSubject(principalID, tokenID identity.ID, tokenHash [sha256.Size]byte) Subject {
	return Subject{kind: SubjectServicePrincipalToken, actorID: principalID, sessionID: tokenID, tokenHash: tokenHash}
}

func (s Subject) Valid() bool {
	if s.actorID.IsZero() {
		return false
	}
	switch s.kind {
	case SubjectRootServicePrincipal:
		return s.sessionID.IsZero() && s.tokenHash == [sha256.Size]byte{}
	case SubjectAdministratorSession:
		return !s.sessionID.IsZero() && s.tokenHash == [sha256.Size]byte{}
	case SubjectServicePrincipalToken:
		return !s.sessionID.IsZero() && s.tokenHash != [sha256.Size]byte{}
	default:
		return false
	}
}

func (s Subject) Kind() SubjectKind { return s.kind }

// Actor derives the audit identity from the durable subject. An invalid
// subject yields an invalid zero Actor.
func (s Subject) Actor() Actor {
	if !s.Valid() {
		return Actor{}
	}
	switch s.kind {
	case SubjectRootServicePrincipal, SubjectServicePrincipalToken:
		return IDActor(ActorServicePrincipal, s.actorID)
	case SubjectAdministratorSession:
		return IDActor(ActorAdministrator, s.actorID)
	default:
		return Actor{}
	}
}

func (s Subject) ActorID() identity.ID { return s.actorID }

func (s Subject) SessionID() (identity.ID, bool) {
	if !s.Valid() || s.kind != SubjectAdministratorSession {
		return identity.ID{}, false
	}
	return s.sessionID, true
}

func (s Subject) TokenID() (identity.ID, bool) {
	if !s.Valid() || s.kind != SubjectServicePrincipalToken {
		return identity.ID{}, false
	}
	return s.sessionID, true
}

func (s Subject) TokenHash() ([sha256.Size]byte, bool) {
	if !s.Valid() || s.kind != SubjectServicePrincipalToken {
		return [sha256.Size]byte{}, false
	}
	return s.tokenHash, true
}

// DecisionTargetKind distinguishes global authorization, a filtered global
// list, a caller-supplied canonical network, and an exact object. For
// network-scoped object operations, the Store resolves the object's network
// inside the protected transaction.
type DecisionTargetKind string

const (
	DecisionTargetGlobal   DecisionTargetKind = "global"
	DecisionTargetFiltered DecisionTargetKind = "filtered"
	DecisionTargetNetwork  DecisionTargetKind = "network"
	DecisionTargetObject   DecisionTargetKind = "object"
)

func (k DecisionTargetKind) Valid() bool {
	return k == DecisionTargetGlobal || k == DecisionTargetFiltered ||
		k == DecisionTargetNetwork || k == DecisionTargetObject
}

// DecisionTarget binds an early decision to exactly one route-policy target.
// Value-typed IDs prevent callers from mutating a decision through aliases.
type DecisionTarget struct {
	kind      DecisionTargetKind
	networkID identity.NetworkID
	objectID  identity.ID
}

func GlobalTarget() DecisionTarget {
	return DecisionTarget{kind: DecisionTargetGlobal}
}

func FilteredTarget() DecisionTarget {
	return DecisionTarget{kind: DecisionTargetFiltered}
}

func NetworkTarget(networkID identity.NetworkID) DecisionTarget {
	return DecisionTarget{kind: DecisionTargetNetwork, networkID: networkID}
}

func ObjectTarget(objectID identity.ID) DecisionTarget {
	return DecisionTarget{kind: DecisionTargetObject, objectID: objectID}
}

func (t DecisionTarget) Valid() bool {
	switch t.kind {
	case DecisionTargetGlobal, DecisionTargetFiltered:
		return t.networkID.IsZero() && t.objectID.IsZero()
	case DecisionTargetNetwork:
		return !t.networkID.IsZero() && t.objectID.IsZero()
	case DecisionTargetObject:
		return t.networkID.IsZero() && !t.objectID.IsZero()
	default:
		return false
	}
}

func (t DecisionTarget) Kind() DecisionTargetKind { return t.kind }

func (t DecisionTarget) NetworkID() (identity.NetworkID, bool) {
	if !t.Valid() || t.kind != DecisionTargetNetwork {
		return identity.NetworkID{}, false
	}
	return t.networkID, true
}

func (t DecisionTarget) ObjectID() (identity.ID, bool) {
	if !t.Valid() || t.kind != DecisionTargetObject {
		return identity.ID{}, false
	}
	return t.objectID, true
}

// Decision is an immutable early authorization result. It is bound to the
// exact route policy and target, but it is never durable write authority: the
// Store must revalidate the Subject and current permissions in its transaction.
type Decision struct {
	subject Subject
	policy  RoutePolicy
	target  DecisionTarget
}

func NewDecision(subject Subject, policy RoutePolicy, target DecisionTarget) (Decision, error) {
	decision := Decision{subject: subject, policy: policy, target: target}
	if !decision.Valid() {
		return Decision{}, errors.New("invalid administrator authorization decision")
	}
	return decision, nil
}

func (d Decision) Valid() bool {
	return d.subject.Valid() && d.policy.Valid() && d.target.Valid() && targetMatchesPolicy(d.target, d.policy)
}

func (d Decision) Subject() Subject       { return d.subject }
func (d Decision) Policy() RoutePolicy    { return d.policy }
func (d Decision) Operation() Operation   { return d.policy.Operation }
func (d Decision) Target() DecisionTarget { return d.target }

// Matches ensures middleware cannot substitute a decision made for another
// credential, route, or target, even when both routes share one operation.
func (d Decision) Matches(subject Subject, policy RoutePolicy, target DecisionTarget) bool {
	return d.Valid() && subject.Valid() && policy.Valid() && target.Valid() &&
		d.subject == subject && d.policy == policy && d.target == target
}

func targetMatchesPolicy(target DecisionTarget, policy RoutePolicy) bool {
	switch policy.ScopeSource {
	case ScopeGlobal:
		return target.kind == DecisionTargetGlobal
	case ScopeFiltered:
		return target.kind == DecisionTargetFiltered
	case ScopePath, ScopeBody:
		return target.kind == DecisionTargetNetwork
	case ScopeObject:
		return target.kind == DecisionTargetObject
	default:
		return false
	}
}

// AuthorizeEarly applies the current transport-layer principal snapshot
// without turning that snapshot into durable authority. Object targets
// intentionally stop at the role check: the Store must revalidate global
// objects or resolve a network-scoped object's canonical network inside the
// operation transaction.
func AuthorizeEarly(subject Subject, principal *Principal, policy RoutePolicy, target DecisionTarget) bool {
	if !subject.Valid() || !policy.Valid() || !target.Valid() || !targetMatchesPolicy(target, policy) {
		return false
	}
	switch subject.kind {
	case SubjectRootServicePrincipal:
		return principal == nil
	case SubjectAdministratorSession:
		if principal == nil || !principal.Enabled || !principal.Valid() || principal.ID != subject.actorID {
			return false
		}
		switch target.kind {
		case DecisionTargetGlobal, DecisionTargetFiltered:
			return Authorize(*principal, policy.Operation, nil)
		case DecisionTargetNetwork:
			networkID := target.networkID
			return Authorize(*principal, policy.Operation, &networkID)
		case DecisionTargetObject:
			return RoleAllows(principal.Role, policy.Operation)
		default:
			return false
		}
	default:
		return false
	}
}

// AuthorizeServicePrincipalEarly applies an authenticated automation
// principal snapshot for routing only. Durable state is always reloaded inside
// the Store transaction before a read or mutation is committed.
func AuthorizeServicePrincipalEarly(subject Subject, principal *ServicePrincipal, policy RoutePolicy,
	target DecisionTarget) bool {
	if !subject.Valid() || subject.kind != SubjectServicePrincipalToken || principal == nil ||
		!principal.Enabled || !principal.Valid() || principal.ID != subject.actorID ||
		!policy.Valid() || !target.Valid() || !targetMatchesPolicy(target, policy) ||
		!slices.Contains(principal.Permissions, policy.Operation) {
		return false
	}
	switch target.kind {
	case DecisionTargetGlobal, DecisionTargetFiltered:
		return AuthorizeServicePrincipal(*principal, policy.Operation, nil)
	case DecisionTargetNetwork:
		networkID := target.networkID
		return AuthorizeServicePrincipal(*principal, policy.Operation, &networkID)
	case DecisionTargetObject:
		// The Store resolves and rechecks the object's canonical network.
		return true
	default:
		return false
	}
}
