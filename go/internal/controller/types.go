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

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	MaxNameLength                       = 253
	MaxTokenLabelLength                 = 256
	MaxAuditDetailLength                = 16 << 10
	MaxRouteMetric                      = 1_000_000
	MaxTokenLifetime                    = 30 * 24 * time.Hour
	MinEphemeralLifetime                = 5 * time.Minute
	MaxEphemeralLifetime                = 24 * time.Hour
	MaxActiveEphemeral                  = 4096
	DefaultAdministratorIdleTimeout     = adminauth.DefaultSessionIdleLifetime
	DefaultAdministratorAbsoluteTimeout = adminauth.DefaultSessionAbsoluteLifetime
	DefaultMaxAdministratorSessions     = adminauth.DefaultMaximumSessions
)

type EnrollmentClass string

const (
	EnrollmentClassDurable    EnrollmentClass = "durable"
	EnrollmentClassEphemeral  EnrollmentClass = "ephemeral"
	EnrollmentClassRemembered EnrollmentClass = "remembered"
)

func (c EnrollmentClass) Valid() bool {
	return c == EnrollmentClassDurable || c == EnrollmentClassEphemeral || c == EnrollmentClassRemembered
}

var (
	ErrNotFound          = errors.New("controller record not found")
	ErrConflict          = errors.New("controller record conflicts with existing state")
	ErrInvalid           = errors.New("invalid controller input")
	ErrTokenInvalid      = errors.New("invalid enrollment token")
	ErrTokenExpired      = errors.New("enrollment token expired")
	ErrTokenConsumed     = errors.New("enrollment token already consumed")
	ErrTokenNetwork      = errors.New("enrollment token belongs to a different network")
	ErrTokenName         = errors.New("enrollment token is bound to a different name")
	ErrTokenClass        = errors.New("enrollment token has a different enrollment class")
	ErrPoolExhausted     = errors.New("overlay address pool exhausted")
	ErrAlreadyApproved   = errors.New("route already approved")
	ErrUnsupportedDB     = errors.New("database schema is newer than this controller")
	ErrBootstrapComplete = errors.New("administrator bootstrap is already complete")
	ErrCredentialInvalid = errors.New("administrator credential is invalid")
	ErrPermissionDenied  = errors.New("administrator permission denied")
	ErrSessionInvalid    = errors.New("administrator session is invalid")
	ErrSessionExpired    = errors.New("administrator session has expired")
	ErrRecoveryInvalid   = errors.New("administrator recovery grant is invalid")
	ErrRecoveryExpired   = errors.New("administrator recovery grant has expired")
	ErrRecoveryConsumed  = errors.New("administrator recovery grant is already consumed")
)

type Network struct {
	ID                 identity.NetworkID
	Name               string
	IPv4Pool           netip.Prefix
	IPv6Pool           netip.Prefix
	ConfigurationEpoch uint64
	CreatedAt          time.Time
}

// ControllerInitialNetwork is the exact immutable network topology a
// controller may establish before it begins serving requests.
type ControllerInitialNetwork struct {
	NetworkID identity.NetworkID
	Name      string
	IPv4Pool  netip.Prefix
	IPv6Pool  netip.Prefix
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
	EnrollmentClass     EnrollmentClass
	LeaseExpiresAt      *time.Time
	WireGuardPublicKey  WireGuardPublicKey
	UserID              *identity.ID
}

// EndpointStatusReport is one bounded endpoint-produced runtime observation.
// It deliberately excludes endpoints, peers, credentials, packet data, and
// free-form diagnostic text. The controller retains only the latest report.
type EndpointStatusReport struct {
	ValidForSeconds    uint32
	ProductVersion     string
	Platform           EndpointPlatform
	CertificateState   CertificateStatusState
	ConfigurationState ConfigurationStatusState
	CarrierState       CarrierStatusState
	RouteState         RouteStatusState
	SelectedExitState  SelectedExitStatusState
	CleanupFailures    uint32
	ConfigurationEpoch uint64
}

type EndpointPlatform string

const (
	EndpointPlatformLinux   EndpointPlatform = "linux"
	EndpointPlatformDarwin  EndpointPlatform = "darwin"
	EndpointPlatformWindows EndpointPlatform = "windows"
	EndpointPlatformOther   EndpointPlatform = "other"
	EndpointPlatformUnknown EndpointPlatform = "unknown"
)

func (value EndpointPlatform) Valid() bool {
	switch value {
	case EndpointPlatformLinux, EndpointPlatformDarwin, EndpointPlatformWindows,
		EndpointPlatformOther, EndpointPlatformUnknown:
		return true
	default:
		return false
	}
}

type CertificateStatusState string

const (
	CertificateStatusHealthy    CertificateStatusState = "healthy"
	CertificateStatusRenewalDue CertificateStatusState = "renewal_due"
	CertificateStatusExpired    CertificateStatusState = "expired"
	CertificateStatusRevoked    CertificateStatusState = "revoked"
	CertificateStatusUnknown    CertificateStatusState = "unknown"
)

func (value CertificateStatusState) Valid() bool {
	switch value {
	case CertificateStatusHealthy, CertificateStatusRenewalDue, CertificateStatusExpired,
		CertificateStatusRevoked, CertificateStatusUnknown:
		return true
	default:
		return false
	}
}

type ConfigurationStatusState string

const (
	ConfigurationStatusCurrent ConfigurationStatusState = "current"
	ConfigurationStatusStale   ConfigurationStatusState = "stale"
	ConfigurationStatusExpired ConfigurationStatusState = "expired"
	ConfigurationStatusUnknown ConfigurationStatusState = "unknown"
)

func (value ConfigurationStatusState) Valid() bool {
	switch value {
	case ConfigurationStatusCurrent, ConfigurationStatusStale, ConfigurationStatusExpired,
		ConfigurationStatusUnknown:
		return true
	default:
		return false
	}
}

type CarrierStatusState string

const (
	CarrierStatusDirect       CarrierStatusState = "direct"
	CarrierStatusRelayQUIC    CarrierStatusState = "relay_quic"
	CarrierStatusRelayTCP     CarrierStatusState = "relay_tcp"
	CarrierStatusNegotiating  CarrierStatusState = "negotiating"
	CarrierStatusDegraded     CarrierStatusState = "degraded"
	CarrierStatusDisconnected CarrierStatusState = "disconnected"
	CarrierStatusUnknown      CarrierStatusState = "unknown"
)

func (value CarrierStatusState) Valid() bool {
	switch value {
	case CarrierStatusDirect, CarrierStatusRelayQUIC, CarrierStatusRelayTCP,
		CarrierStatusNegotiating, CarrierStatusDegraded, CarrierStatusDisconnected,
		CarrierStatusUnknown:
		return true
	default:
		return false
	}
}

type RouteStatusState string

const (
	RouteStatusReady       RouteStatusState = "ready"
	RouteStatusDegraded    RouteStatusState = "degraded"
	RouteStatusUnavailable RouteStatusState = "unavailable"
	RouteStatusUnknown     RouteStatusState = "unknown"
)

func (value RouteStatusState) Valid() bool {
	switch value {
	case RouteStatusReady, RouteStatusDegraded, RouteStatusUnavailable, RouteStatusUnknown:
		return true
	default:
		return false
	}
}

type SelectedExitStatusState string

const (
	SelectedExitStatusNotSelected SelectedExitStatusState = "not_selected"
	SelectedExitStatusReady       SelectedExitStatusState = "ready"
	SelectedExitStatusDegraded    SelectedExitStatusState = "degraded"
	SelectedExitStatusUnavailable SelectedExitStatusState = "unavailable"
	SelectedExitStatusUnknown     SelectedExitStatusState = "unknown"
)

func (value SelectedExitStatusState) Valid() bool {
	switch value {
	case SelectedExitStatusNotSelected, SelectedExitStatusReady, SelectedExitStatusDegraded,
		SelectedExitStatusUnavailable, SelectedExitStatusUnknown:
		return true
	default:
		return false
	}
}

type EndpointStatusFreshness string

const (
	EndpointStatusCurrent       EndpointStatusFreshness = "current"
	EndpointStatusExpired       EndpointStatusFreshness = "expired"
	EndpointStatusNeverReported EndpointStatusFreshness = "never_reported"
	EndpointStatusNodeInactive  EndpointStatusFreshness = "node_inactive"
)

// EndpointStatus is the administrator-facing latest-state projection. Report
// is nil unless Freshness is current, preventing stale health from surviving
// its TTL. LastReportedAt remains available as evidence without implying
// current reachability.
type EndpointStatus struct {
	NodeID                          identity.NodeID
	NetworkID                       identity.NetworkID
	NodeName                        string
	AuthoritativeConfigurationEpoch uint64
	Freshness                       EndpointStatusFreshness
	LastReportedAt                  *time.Time
	ExpiresAt                       *time.Time
	Report                          *EndpointStatusReport
}

// EnrollmentToken contains the immutable token record and, only when returned
// by IssueEnrollmentToken, its bearer Secret. The secret is never persisted.
type EnrollmentToken struct {
	ID                  identity.ID
	NetworkID           identity.NetworkID
	Label               string
	Secret              string
	ExpiresAt           time.Time
	CreatedAt           time.Time
	ConsumedAt          *time.Time
	ConsumedBy          *identity.NodeID
	EnrollmentClass     EnrollmentClass
	SessionLifetime     time.Duration
	RequestedName       string
	EnabledCapabilities uint64
	UserID              *identity.ID
}

type EnrollmentTokenOptions struct {
	Class               EnrollmentClass
	SessionLifetime     time.Duration
	RequestedName       string
	EnabledCapabilities uint64
	UserID              *identity.ID
}

type AccessSubjectKind string

const (
	AccessSubjectUser AccessSubjectKind = "user"
	AccessSubjectTeam AccessSubjectKind = "team"
)

func (kind AccessSubjectKind) Valid() bool {
	return kind == AccessSubjectUser || kind == AccessSubjectTeam
}

type AccessTargetKind string

const (
	AccessTargetNetwork AccessTargetKind = "network"
	AccessTargetNode    AccessTargetKind = "node"
	AccessTargetExit    AccessTargetKind = "exit"
)

func (kind AccessTargetKind) Valid() bool {
	return kind == AccessTargetNetwork || kind == AccessTargetNode || kind == AccessTargetExit
}

type AccessUser struct {
	ID        identity.ID
	NetworkID identity.NetworkID
	Name      string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type AccessTeam struct {
	ID        identity.ID
	NetworkID identity.NetworkID
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type AccessTeamMember struct {
	NetworkID identity.NetworkID
	TeamID    identity.ID
	UserID    identity.ID
	CreatedAt time.Time
}

type AccessGrant struct {
	ID          identity.ID
	NetworkID   identity.NetworkID
	SubjectKind AccessSubjectKind
	SubjectID   identity.ID
	TargetKind  AccessTargetKind
	NodeID      *identity.NodeID
	CreatedAt   time.Time
}

type AccessInventory struct {
	Users       []AccessUser
	Teams       []AccessTeam
	Memberships []AccessTeamMember
	Grants      []AccessGrant
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
	Node                 Node
	Certificate          Certificate
	EphemeralExitSession *EphemeralExitSession
}

// EphemeralExitSession is controller-authoritative live lease state for an
// ephemeral identity granted exactly the Exit capability. Its generation is
// bound to the in-memory runtime; certificate possession is still proved by
// mTLS on every heartbeat.
type EphemeralExitSession struct {
	NodeID          identity.NodeID
	NetworkID       identity.NetworkID
	Generation      uint64
	LastHeartbeatAt time.Time
	SuspectAt       time.Time
	RevokeAt        time.Time
	CreatedAt       time.Time
	TerminatedAt    *time.Time
}

// EnrollmentCertificateIssuer is called exactly once after the prospective
// node and its overlay addresses have been allocated, but before enrollment is
// committed. Returning an error rolls back token consumption and all records.
// Implementations must honor ctx, do bounded local work, and not call Store.
type EnrollmentCertificateIssuer func(ctx context.Context, node Node) (CertificateMaterial, error)

// NodeRenewal contains the certificate and authoritative WireGuard binding
// committed by one authenticated renewal transaction.
type NodeRenewal struct {
	Node        Node
	Certificate Certificate
	Epoch       uint64
}

type AuditEvent struct {
	ID           identity.ID
	NetworkID    identity.NetworkID
	NetworkScope *identity.NetworkID
	Actor        adminauth.Actor
	ActorNodeID  *identity.NodeID
	Action       string
	TargetType   string
	TargetID     *identity.ID
	Details      string
	CreatedAt    time.Time
}

type AdministratorAuthState struct {
	RootServicePrincipalID  identity.ID
	InitialOwnerPrincipalID *identity.ID
	BootstrapCompletedAt    *time.Time
	RecoveryGeneration      uint64
	LastRecoveredAt         *time.Time
}

type AdministratorCredential struct {
	ID               identity.ID
	PrincipalID      identity.ID
	Type             string
	SecretHash       string
	CreatedAt        time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

// AdministratorPasswordCandidate is the exact immutable credential snapshot
// subjected to bounded password verification. Unknown, disabled, or otherwise
// unusable accounts return Usable=false so the caller takes the dummy-hash path.
// A successful verifier result is not durable authority: session creation must
// revalidate all three IDs and the active credential inside its transaction.
type AdministratorPasswordCandidate struct {
	PrincipalID  identity.ID
	CredentialID identity.ID
	PasswordHash string
	Usable       bool
}

type AdministratorRecord struct {
	Principal  adminauth.Principal
	Credential AdministratorCredential
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

type AdministratorSession struct {
	ID                identity.ID
	PrincipalID       identity.ID
	CredentialID      identity.ID
	TokenHash         [32]byte
	CSRFHash          [32]byte
	PreviousSessionID *identity.ID
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleTimeout       time.Duration
	MaximumSessions   int
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevocationReason  string
}

type AdministratorSessionOptions struct {
	IdleTimeout       time.Duration
	AbsoluteTimeout   time.Duration
	MaxActive         int
	PreviousSessionID *identity.ID
}

type AdministratorRecoveryPurpose string

const (
	AdministratorRecoveryBootstrapOwner AdministratorRecoveryPurpose = "bootstrap_owner"
	AdministratorRecoveryOwner          AdministratorRecoveryPurpose = "owner_recovery"
)

func (p AdministratorRecoveryPurpose) Valid() bool {
	return p == AdministratorRecoveryBootstrapOwner || p == AdministratorRecoveryOwner
}

type AdministratorRecoveryGrant struct {
	ID                 identity.ID
	SecretHash         [32]byte
	Purpose            AdministratorRecoveryPurpose
	TargetPrincipalID  *identity.ID
	RecoveryGeneration uint64
	CreatedAt          time.Time
	ExpiresAt          time.Time
	ConsumedAt         *time.Time
	RevokedAt          *time.Time
	RevocationReason   string
}

// AdministratorRecoveryCandidate is the opaque preflight result used before
// hashing a replacement password. It contains no recovery secret or hash and
// is never sufficient to consume the grant; final bootstrap/recovery rechecks
// the secret and all durable state in its transaction.
type AdministratorRecoveryCandidate struct {
	GrantID            identity.ID
	Purpose            AdministratorRecoveryPurpose
	TargetPrincipalID  *identity.ID
	RecoveryGeneration uint64
	Usable             bool
}

type AdministratorAccessSpec struct {
	Role        adminauth.Role
	Enabled     bool
	AllNetworks bool
	NetworkIDs  []identity.NetworkID
}

// AdministratorUpdateSpec models the atomic PATCH contract. Access, when
// present, is the complete role/scope tuple; Enabled is independent. Omitted
// fields are reloaded and preserved inside the authorized write transaction.
type AdministratorUpdateSpec struct {
	Access  *AdministratorAccessSpec
	Enabled *bool
}

type CreateAdministratorSpec struct {
	Username     string
	PasswordHash string
	Access       AdministratorAccessSpec
}

type AdministratorAuthFailure string

const (
	AdministratorAuthFailureCredential AdministratorAuthFailure = "credential_rejected"
	AdministratorAuthFailureLimited    AdministratorAuthFailure = "rate_limited"
	AdministratorAuthFailureBusy       AdministratorAuthFailure = "verification_busy"
	AdministratorAuthFailureRecovery   AdministratorAuthFailure = "recovery_rejected"
)

func (f AdministratorAuthFailure) Valid() bool {
	return f == AdministratorAuthFailureCredential || f == AdministratorAuthFailureLimited ||
		f == AdministratorAuthFailureBusy || f == AdministratorAuthFailureRecovery
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
