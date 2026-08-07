// Package controller implements the durable Laneway control-plane store.
//
// The store deliberately exposes control-plane operations rather than its SQL
// handle.  This keeps invariants such as single-use enrollment, unique overlay
// addresses, and configuration epoch changes inside database transactions.
package controller

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"laneway.dev/laneway/internal/identity"
)

const (
	MaxNameLength        = 253
	MaxTokenLabelLength  = 256
	MaxAuditDetailLength = 16 << 10
	MaxRouteMetric       = 1_000_000
	MaxTokenLifetime     = 30 * 24 * time.Hour
)

var (
	ErrNotFound        = errors.New("controller record not found")
	ErrConflict        = errors.New("controller record conflicts with existing state")
	ErrInvalid         = errors.New("invalid controller input")
	ErrTokenInvalid    = errors.New("invalid enrollment token")
	ErrTokenExpired    = errors.New("enrollment token expired")
	ErrTokenConsumed   = errors.New("enrollment token already consumed")
	ErrPoolExhausted   = errors.New("overlay address pool exhausted")
	ErrAlreadyApproved = errors.New("route already approved")
	ErrUnsupportedDB   = errors.New("database schema is newer than this controller")
)

type Network struct {
	ID                 identity.NetworkID
	Name               string
	IPv4Pool           netip.Prefix
	IPv6Pool           netip.Prefix
	ConfigurationEpoch uint64
	CreatedAt          time.Time
}

type Node struct {
	ID                  identity.NodeID
	NetworkID           identity.NetworkID
	Name                string
	EnabledCapabilities uint64
	IPv4Address         netip.Addr
	IPv6Address         netip.Addr
	CreatedAt           time.Time
	RevokedAt           *time.Time
}

// EnrollmentToken contains the immutable token record and, only when returned
// by IssueEnrollmentToken, its bearer Secret. The secret is never persisted.
type EnrollmentToken struct {
	ID         identity.ID
	NetworkID  identity.NetworkID
	Label      string
	Secret     string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	ConsumedAt *time.Time
	ConsumedBy *identity.NodeID
}

type RouteKind string

const (
	RouteKindOverlay RouteKind = "overlay"
	RouteKindSubnet  RouteKind = "subnet"
	RouteKindExit    RouteKind = "exit"
)

type RouteMode string

const (
	RouteModeNone   RouteMode = "none"
	RouteModeNAT    RouteMode = "nat"
	RouteModeRouted RouteMode = "routed"
)

type RouteState string

const (
	RouteStateAdvertised RouteState = "advertised"
	RouteStateApproved   RouteState = "approved"
	RouteStateWithdrawn  RouteState = "withdrawn"
	RouteStateRejected   RouteState = "rejected"
)

type Route struct {
	ID          identity.ID
	NetworkID   identity.NetworkID
	NodeID      identity.NodeID
	Prefix      netip.Prefix
	Kind        RouteKind
	Mode        RouteMode
	Metric      uint32
	State       RouteState
	ValidUntil  *time.Time
	CreatedAt   time.Time
	ApprovedAt  *time.Time
	WithdrawnAt *time.Time
}

type Certificate struct {
	ID               identity.ID
	NetworkID        identity.NetworkID
	NodeID           identity.NodeID
	Serial           []byte
	DER              []byte
	NotBefore        time.Time
	NotAfter         time.Time
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

// CertificateMaterial is the bounded immutable certificate payload produced
// while enrolling a node. The store validates and copies every field before
// persisting it in the enrollment transaction.
type CertificateMaterial struct {
	Serial    []byte
	DER       []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// Enrollment contains every durable record created by one atomic enrollment.
type Enrollment struct {
	Node        Node
	Certificate Certificate
}

// EnrollmentCertificateIssuer is called exactly once after the prospective
// node and its overlay addresses have been allocated, but before enrollment is
// committed. Returning an error rolls back token consumption and all records.
// Implementations must honor ctx, do bounded local work, and not call Store.
type EnrollmentCertificateIssuer func(ctx context.Context, node Node) (CertificateMaterial, error)

type AuditEvent struct {
	ID          identity.ID
	NetworkID   identity.NetworkID
	ActorNodeID *identity.NodeID
	Action      string
	TargetType  string
	TargetID    *identity.ID
	Details     string
	CreatedAt   time.Time
}

type ACLAction string

const (
	ACLActionAccept ACLAction = "accept"
	ACLActionDeny   ACLAction = "deny"
)

type ACLRule struct {
	ID           identity.ID
	NetworkID    identity.NetworkID
	Priority     uint32
	Action       ACLAction
	SelectorJSON string
	Description  string
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Relay struct {
	ID        identity.ID
	NetworkID identity.NetworkID
	ServiceID identity.ID
	NodeID    *identity.NodeID
	Name      string
	Endpoint  string
	Enabled   bool
	CreatedAt time.Time
}
