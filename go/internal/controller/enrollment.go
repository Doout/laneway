package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

const enrollmentSecretBytes = 32

func validateEphemeralExitCapabilities(class EnrollmentClass, capabilities uint64) error {
	if class == EnrollmentClassEphemeral && protocol.Capability(capabilities).Has(protocol.CapabilityExitNodeV1) &&
		capabilities != uint64(protocol.CapabilityExitNodeV1) {
		return fmt.Errorf("%w: ephemeral Exit enrollment grants only exit-node-v1", ErrInvalid)
	}
	return nil
}

func newEphemeralExitGeneration() (uint64, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, fmt.Errorf("generate ephemeral Exit lease generation: %w", err)
	}
	value := binary.BigEndian.Uint64(raw[:]) & uint64(math.MaxInt64)
	if value == 0 {
		value = 1
	}
	return value, nil
}

func insertInvitedExitRouteTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, nodeID identity.NodeID, validUntil *time.Time, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT metric FROM routes
		WHERE network_id=? AND state='approved' AND prefix_address=? AND prefix_length=0 AND metric>=100
		ORDER BY metric`, idBytes(networkID), netip.IPv4Unspecified().AsSlice())
	if err != nil {
		return fmt.Errorf("read existing default route metrics: %w", err)
	}
	metric := uint32(100)
	for rows.Next() {
		var used uint32
		if err := rows.Scan(&used); err != nil {
			rows.Close()
			return fmt.Errorf("scan existing default route metric: %w", err)
		}
		if used == metric {
			metric++
		} else if used > metric {
			break
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close existing default route metrics: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate existing default route metrics: %w", err)
	}
	if metric > MaxRouteMetric {
		return fmt.Errorf("%w: too many active exit routes", ErrConflict)
	}
	routeID, err := newID()
	if err != nil {
		return err
	}
	prefix := netip.MustParsePrefix("0.0.0.0/0")
	var valid any
	if validUntil != nil {
		valid = unix(*validUntil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO routes
        (id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at,approved_at)
        VALUES(?,?,?,?,0,'exit','nat',?,'approved',?,?,?)`, idBytes(routeID), idBytes(networkID), idBytes(nodeID), prefix.Addr().AsSlice(), metric, valid, unix(now), unix(now)); err != nil {
		return fmt.Errorf("create invited exit route: %w", err)
	}
	target := routeID
	return auditActorTx(ctx, tx, &networkID, adminauth.SystemActor(), "route.invited_exit.approve", "route", &target, fmt.Sprintf(`{"prefix":%q,"metric":%d}`, prefix.String(), metric), now)
}

func tokenDigest(secret string) ([32]byte, error) {
	var zero [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != enrollmentSecretBytes || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return zero, ErrTokenInvalid
	}
	return sha256.Sum256(decoded), nil
}

func nullableIdentityID(value *identity.ID) any {
	if value == nil {
		return nil
	}
	return idBytes(*value)
}

func (s *Store) IssueEnrollmentToken(ctx context.Context, networkID identity.NetworkID, label string, expiresAt time.Time) (EnrollmentToken, error) {
	return s.IssueEnrollmentTokenWithOptions(ctx, networkID, label, expiresAt, EnrollmentTokenOptions{Class: EnrollmentClassDurable})
}

func (s *Store) IssueEnrollmentTokenWithOptions(ctx context.Context, networkID identity.NetworkID, label string, expiresAt time.Time, options EnrollmentTokenOptions) (EnrollmentToken, error) {
	if label != strings.TrimSpace(label) || len(label) > MaxTokenLabelLength || strings.IndexByte(label, 0) >= 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: invalid enrollment token label", ErrInvalid)
	}
	now := s.now()
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.Sub(now) > MaxTokenLifetime {
		return EnrollmentToken{}, fmt.Errorf("%w: token expiry must be in the next %s", ErrInvalid, MaxTokenLifetime)
	}
	if options.Class == "" {
		options.Class = EnrollmentClassDurable
	}
	if !options.Class.Valid() {
		return EnrollmentToken{}, fmt.Errorf("%w: invalid enrollment class %q", ErrInvalid, options.Class)
	}
	if options.RequestedName != "" {
		if err := validateName("requested enrollment", options.RequestedName); err != nil {
			return EnrollmentToken{}, err
		}
	}
	if options.EnabledCapabilities > math.MaxInt64 || protocol.Capability(options.EnabledCapabilities)&^NodePolicyCapabilities != 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: enrollment token contains unsupported policy capabilities", ErrInvalid)
	}
	if err := validateEphemeralExitCapabilities(options.Class, options.EnabledCapabilities); err != nil {
		return EnrollmentToken{}, err
	}
	if options.Class == EnrollmentClassEphemeral {
		options.SessionLifetime = options.SessionLifetime.Truncate(time.Second)
		if options.SessionLifetime < MinEphemeralLifetime || options.SessionLifetime > MaxEphemeralLifetime {
			return EnrollmentToken{}, fmt.Errorf("%w: ephemeral lifetime must be in [%s,%s]", ErrInvalid, MinEphemeralLifetime, MaxEphemeralLifetime)
		}
	} else if options.SessionLifetime != 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: session lifetime is valid only for ephemeral enrollment", ErrInvalid)
	}
	raw := make([]byte, enrollmentSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256(raw)
	id, err := newID()
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token ID: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("begin issue enrollment token: %w", err)
	}
	defer tx.Rollback()
	var sessionLifetime any
	if options.Class == EnrollmentClassEphemeral {
		sessionLifetime = int64(options.SessionLifetime / time.Second)
	}
	var requestedName any
	if options.RequestedName != "" {
		requestedName = options.RequestedName
	}
	var userValue any
	if options.UserID != nil {
		if options.UserID.IsZero() {
			return EnrollmentToken{}, fmt.Errorf("%w: access user ID is zero", ErrInvalid)
		}
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT enabled FROM access_users WHERE id=? AND network_id=?`, idBytes(*options.UserID), idBytes(networkID)).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
			return EnrollmentToken{}, ErrNotFound
		} else if err != nil {
			return EnrollmentToken{}, fmt.Errorf("read enrollment access user: %w", err)
		} else if enabled != 1 {
			return EnrollmentToken{}, fmt.Errorf("%w: access user is disabled", ErrConflict)
		}
		userValue = idBytes(*options.UserID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens
		(id,network_id,token_hash,label,expires_at,created_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), digest[:], label, unix(expiresAt), unix(now), string(options.Class), sessionLifetime, requestedName, int64(options.EnabledCapabilities), userValue); err != nil {
		if isConstraint(err) {
			return EnrollmentToken{}, fmt.Errorf("%w: network does not exist", ErrNotFound)
		}
		return EnrollmentToken{}, fmt.Errorf("insert enrollment token: %w", err)
	}
	target := id
	details := fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q,"enabled_capabilities":%d}`, options.Class, options.RequestedName, options.EnabledCapabilities)
	if options.Class == EnrollmentClassEphemeral {
		details = fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q,"session_lifetime_seconds":%d,"enabled_capabilities":%d}`, options.Class, options.RequestedName, int64(options.SessionLifetime/time.Second), options.EnabledCapabilities)
	}
	if err := auditTx(ctx, tx, networkID, nil, "enrollment_token.issue", "enrollment_token", &target, details, now); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, fmt.Errorf("commit enrollment token: %w", err)
	}
	return EnrollmentToken{ID: id, NetworkID: networkID, Label: label, Secret: secret, ExpiresAt: expiresAt, CreatedAt: now,
		EnrollmentClass: options.Class, SessionLifetime: options.SessionLifetime, RequestedName: options.RequestedName, EnabledCapabilities: options.EnabledCapabilities, UserID: options.UserID}, nil
}

// AdministratorIssueEnrollmentTokenWithOptions revalidates the decision's
// current durable authority before observing network existence or inserting
// the one-time credential. Issuance and actor-aware audit are one transaction.
func (s *Store) AdministratorIssueEnrollmentTokenWithOptions(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, label string, expiresAt time.Time, options EnrollmentTokenOptions) (EnrollmentToken, error) {
	if label != strings.TrimSpace(label) || len(label) > MaxTokenLabelLength || strings.IndexByte(label, 0) >= 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: invalid enrollment token label", ErrInvalid)
	}
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if options.Class == "" {
		options.Class = EnrollmentClassDurable
	}
	if !options.Class.Valid() {
		return EnrollmentToken{}, fmt.Errorf("%w: invalid enrollment class %q", ErrInvalid, options.Class)
	}
	if options.RequestedName != "" {
		if err := validateName("requested enrollment", options.RequestedName); err != nil {
			return EnrollmentToken{}, err
		}
	}
	if options.EnabledCapabilities > math.MaxInt64 || protocol.Capability(options.EnabledCapabilities)&^NodePolicyCapabilities != 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: enrollment token contains unsupported policy capabilities", ErrInvalid)
	}
	if err := validateEphemeralExitCapabilities(options.Class, options.EnabledCapabilities); err != nil {
		return EnrollmentToken{}, err
	}
	if options.Class == EnrollmentClassEphemeral {
		options.SessionLifetime = options.SessionLifetime.Truncate(time.Second)
		if options.SessionLifetime < MinEphemeralLifetime || options.SessionLifetime > MaxEphemeralLifetime {
			return EnrollmentToken{}, fmt.Errorf("%w: ephemeral lifetime must be in [%s,%s]", ErrInvalid, MinEphemeralLifetime, MaxEphemeralLifetime)
		}
	} else if options.SessionLifetime != 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: session lifetime is valid only for ephemeral enrollment", ErrInvalid)
	}
	raw := make([]byte, enrollmentSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256(raw)
	id, err := newID()
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("generate enrollment token ID: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnrollmentToken{}, fmt.Errorf("begin authorized enrollment token issue: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorEnrollmentIssuePolicy, networkID)
	if err != nil {
		return EnrollmentToken{}, err
	}
	now := s.now()
	if !expiresAt.After(now) || expiresAt.Sub(now) > MaxTokenLifetime {
		return EnrollmentToken{}, fmt.Errorf("%w: token expiry must be in the next %s", ErrInvalid, MaxTokenLifetime)
	}
	var sessionLifetime any
	if options.Class == EnrollmentClassEphemeral {
		sessionLifetime = int64(options.SessionLifetime / time.Second)
	}
	var requestedName any
	if options.RequestedName != "" {
		requestedName = options.RequestedName
	}
	var userValue any
	if options.UserID != nil {
		if options.UserID.IsZero() {
			return EnrollmentToken{}, fmt.Errorf("%w: access user ID is zero", ErrInvalid)
		}
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT enabled FROM access_users WHERE id=? AND network_id=?`, idBytes(*options.UserID), idBytes(networkID)).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
			return EnrollmentToken{}, ErrNotFound
		} else if err != nil {
			return EnrollmentToken{}, fmt.Errorf("read authorized enrollment access user: %w", err)
		} else if enabled != 1 {
			return EnrollmentToken{}, fmt.Errorf("%w: access user is disabled", ErrConflict)
		}
		userValue = idBytes(*options.UserID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens
		(id,network_id,token_hash,label,expires_at,created_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities,user_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), digest[:], label, unix(expiresAt), unix(now), string(options.Class), sessionLifetime, requestedName, int64(options.EnabledCapabilities), userValue); err != nil {
		if isConstraint(err) {
			return EnrollmentToken{}, fmt.Errorf("%w: network does not exist", ErrNotFound)
		}
		return EnrollmentToken{}, fmt.Errorf("insert enrollment token: %w", err)
	}
	target := id
	details := fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q,"enabled_capabilities":%d}`, options.Class, options.RequestedName, options.EnabledCapabilities)
	if options.Class == EnrollmentClassEphemeral {
		details = fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q,"session_lifetime_seconds":%d,"enabled_capabilities":%d}`, options.Class, options.RequestedName, int64(options.SessionLifetime/time.Second), options.EnabledCapabilities)
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, "enrollment_token.issue", "enrollment_token", &target, details, now); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, fmt.Errorf("commit authorized enrollment token: %w", err)
	}
	return EnrollmentToken{ID: id, NetworkID: networkID, Label: label, Secret: secret, ExpiresAt: expiresAt, CreatedAt: now,
		EnrollmentClass: options.Class, SessionLifetime: options.SessionLifetime, RequestedName: options.RequestedName, EnabledCapabilities: options.EnabledCapabilities, UserID: options.UserID}, nil
}

// EnrollNode atomically consumes a single-use bearer token, creates a node and
// assigns its IPv4 and optional IPv6 overlay addresses. Any failure rolls back
// all changes.
func (s *Store) EnrollNode(ctx context.Context, secret, name string, enabledCapabilities uint64) (Node, error) {
	enrollment, err := s.enrollNode(ctx, secret, name, enabledCapabilities, identity.NetworkID{}, "", WireGuardPublicKey{}, nil)
	return enrollment.Node, err
}

// EnrollNodeWithCertificate atomically consumes a token and persists the node,
// overlay addresses, and issuer-produced certificate. Issuance or persistence
// failure leaves the token reusable and no partial enrollment records.
func (s *Store) EnrollNodeWithCertificate(ctx context.Context, secret, name string, enabledCapabilities uint64, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if issuer == nil {
		return Enrollment{}, fmt.Errorf("%w: enrollment certificate issuer is required", ErrInvalid)
	}
	return s.enrollNode(ctx, secret, name, enabledCapabilities, identity.NetworkID{}, "", WireGuardPublicKey{}, issuer)
}

// EnrollNodeWithCertificateForNetwork additionally binds enrollment to the
// NetworkID authenticated by bootstrap discovery. A mismatch is checked before
// token consumption and leaves the code reusable on its intended network.
func (s *Store) EnrollNodeWithCertificateForNetwork(ctx context.Context, secret, name string, enabledCapabilities uint64, expectedNetwork identity.NetworkID, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if expectedNetwork.IsZero() {
		return Enrollment{}, fmt.Errorf("%w: expected enrollment network is required", ErrInvalid)
	}
	if issuer == nil {
		return Enrollment{}, fmt.Errorf("%w: enrollment certificate issuer is required", ErrInvalid)
	}
	return s.enrollNode(ctx, secret, name, enabledCapabilities, expectedNetwork, "", WireGuardPublicKey{}, issuer)
}

// EnrollNodeWithCertificateForNetworkAndClass additionally binds the client's
// expected enrollment class. The class is checked before token consumption so
// an accidental remembered/ephemeral mismatch does not destroy the invite.
func (s *Store) EnrollNodeWithCertificateForNetworkAndClass(ctx context.Context, secret, name string, enabledCapabilities uint64, expectedNetwork identity.NetworkID, expectedClass EnrollmentClass, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if expectedNetwork.IsZero() || !expectedClass.Valid() {
		return Enrollment{}, fmt.Errorf("%w: expected enrollment network and class are required", ErrInvalid)
	}
	if issuer == nil {
		return Enrollment{}, fmt.Errorf("%w: enrollment certificate issuer is required", ErrInvalid)
	}
	return s.enrollNode(ctx, secret, name, enabledCapabilities, expectedNetwork, expectedClass, WireGuardPublicKey{}, issuer)
}

// EnrollNodeBound atomically binds a validated WireGuard key, the authenticated
// bootstrap NetworkID/class, overlay addresses, and certificate before consuming
// the invite. This is the protocol enrollment entry point; the older helpers
// remain only for migration and store-level administration.
func (s *Store) EnrollNodeBound(ctx context.Context, secret, name string, enabledCapabilities uint64, expectedNetwork identity.NetworkID, expectedClass EnrollmentClass, wireGuardPublicKey WireGuardPublicKey, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if expectedNetwork.IsZero() || !expectedClass.Valid() || wireGuardPublicKey.IsZero() || issuer == nil {
		return Enrollment{}, fmt.Errorf("%w: authenticated network, class, WireGuard key, and issuer are required", ErrInvalid)
	}
	return s.enrollNode(ctx, secret, name, enabledCapabilities, expectedNetwork, expectedClass, wireGuardPublicKey, issuer)
}

func (s *Store) enrollNode(ctx context.Context, secret, name string, enabledCapabilities uint64, expectedNetwork identity.NetworkID, expectedClass EnrollmentClass, wireGuardPublicKey WireGuardPublicKey, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if enabledCapabilities > math.MaxInt64 {
		return Enrollment{}, fmt.Errorf("%w: capability mask exceeds SQLite integer range", ErrInvalid)
	}
	if protocol.Capability(enabledCapabilities)&^NodePolicyCapabilities != 0 {
		return Enrollment{}, fmt.Errorf("%w: enrollment contains non-policy capabilities", ErrInvalid)
	}
	digest, err := tokenDigest(secret)
	if err != nil {
		return Enrollment{}, err
	}
	if _, err := s.ExpireEphemeral(ctx, MaxExpireBatch); err != nil {
		return Enrollment{}, fmt.Errorf("maintain ephemeral identities before enrollment: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	var tokenIDBytes, networkIDBytes []byte
	var expires int64
	var consumed sql.NullInt64
	var class string
	var sessionLifetime sql.NullInt64
	var requestedName sql.NullString
	var tokenCapabilities int64
	var userRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT id,network_id,expires_at,consumed_at,enrollment_class,session_lifetime_seconds,requested_name,enabled_capabilities,user_id FROM enrollment_tokens WHERE token_hash=?`, digest[:]).Scan(&tokenIDBytes, &networkIDBytes, &expires, &consumed, &class, &sessionLifetime, &requestedName, &tokenCapabilities, &userRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, ErrTokenInvalid
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("read enrollment token: %w", err)
	}
	if consumed.Valid {
		return Enrollment{}, ErrTokenConsumed
	}
	if unix(now) >= expires {
		return Enrollment{}, ErrTokenExpired
	}
	tokenID, err := scanID(tokenIDBytes)
	if err != nil {
		return Enrollment{}, err
	}
	networkRaw, err := scanID(networkIDBytes)
	if err != nil {
		return Enrollment{}, err
	}
	networkID := identity.NetworkID(networkRaw)
	if !expectedNetwork.IsZero() && networkID != expectedNetwork {
		return Enrollment{}, ErrTokenNetwork
	}
	if requestedName.Valid {
		if name == "" {
			name = requestedName.String
		} else if name != requestedName.String {
			return Enrollment{}, ErrTokenName
		}
	}
	if err := validateName("node", name); err != nil {
		return Enrollment{}, err
	}
	enrollmentClass := EnrollmentClass(class)
	if !enrollmentClass.Valid() || (enrollmentClass == EnrollmentClassEphemeral) != sessionLifetime.Valid {
		return Enrollment{}, errors.New("corrupt enrollment token class")
	}
	if expectedClass != "" && enrollmentClass != expectedClass {
		return Enrollment{}, ErrTokenClass
	}
	if tokenCapabilities < 0 || protocol.Capability(tokenCapabilities)&^NodePolicyCapabilities != 0 {
		return Enrollment{}, errors.New("corrupt enrollment token capabilities")
	}
	enabledCapabilities |= uint64(tokenCapabilities)
	var leaseExpiresAt *time.Time
	var accessUserID *identity.ID
	if len(userRaw) != 0 {
		userID, err := scanID(userRaw)
		if err != nil {
			return Enrollment{}, err
		}
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT enabled FROM access_users WHERE id=? AND network_id=?`, idBytes(userID), idBytes(networkID)).Scan(&enabled); err != nil || enabled != 1 {
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return Enrollment{}, fmt.Errorf("revalidate enrollment access user: %w", err)
			}
			return Enrollment{}, fmt.Errorf("%w: access user is unavailable", ErrTokenInvalid)
		}
		accessUserID = &userID
	}
	if enrollmentClass == EnrollmentClassEphemeral {
		lifetime := time.Duration(sessionLifetime.Int64) * time.Second
		if lifetime < MinEphemeralLifetime || lifetime > MaxEphemeralLifetime {
			return Enrollment{}, errors.New("corrupt ephemeral enrollment lifetime")
		}
		lease := now.Add(lifetime).UTC().Truncate(time.Second)
		leaseExpiresAt = &lease
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE network_id=? AND enrollment_class='ephemeral' AND revoked_at IS NULL AND lease_expires_at>?`, idBytes(networkID), unix(now)).Scan(&active); err != nil {
			return Enrollment{}, fmt.Errorf("count active ephemeral identities: %w", err)
		}
		if active >= MaxActiveEphemeral {
			return Enrollment{}, fmt.Errorf("%w: active ephemeral identity limit reached", ErrConflict)
		}
	}
	nodeID, err := identity.NewNodeID()
	if err != nil {
		return Enrollment{}, fmt.Errorf("generate node ID: %w", err)
	}
	var leaseUnix any
	if leaseExpiresAt != nil {
		leaseUnix = unix(*leaseExpiresAt)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes
		(id,network_id,name,enabled_capabilities,created_at,enrollment_class,lease_expires_at,wireguard_public_key,user_id) VALUES(?,?,?,?,?,?,?,?,?)`,
		idBytes(nodeID), idBytes(networkID), name, int64(enabledCapabilities), unix(now), string(enrollmentClass), leaseUnix, nullableWireGuardKey(wireGuardPublicKey), nullableIdentityID(accessUserID)); err != nil {
		if isConstraint(err) {
			return Enrollment{}, fmt.Errorf("%w: node name or WireGuard public key already exists", ErrConflict)
		}
		return Enrollment{}, fmt.Errorf("insert enrolled node: %w", err)
	}
	address, err := allocateIPv4Tx(ctx, tx, networkID, nodeID, now)
	if err != nil {
		return Enrollment{}, err
	}
	address6, err := allocateIPv6Tx(ctx, tx, networkID, nodeID, now)
	if err != nil {
		return Enrollment{}, err
	}
	if protocol.Capability(enabledCapabilities).Has(protocol.CapabilityExitNodeV1) {
		if err := insertInvitedExitRouteTx(ctx, tx, networkID, nodeID, leaseExpiresAt, now); err != nil {
			return Enrollment{}, err
		}
	}
	var ephemeralExitSession *EphemeralExitSession
	if enrollmentClass == EnrollmentClassEphemeral && protocol.Capability(enabledCapabilities).Has(protocol.CapabilityExitNodeV1) {
		if err := validateEphemeralExitCapabilities(enrollmentClass, enabledCapabilities); err != nil {
			return Enrollment{}, err
		}
		generation, err := newEphemeralExitGeneration()
		if err != nil {
			return Enrollment{}, err
		}
		suspectAt, revokeAt := now.Add(20*time.Second), now.Add(60*time.Second)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ephemeral_exit_sessions
			(node_id,network_id,generation,last_heartbeat_at,suspect_at,revoke_at,created_at)
			VALUES(?,?,?,?,?,?,?)`, idBytes(nodeID), idBytes(networkID), int64(generation), unix(now), unix(suspectAt), unix(revokeAt), unix(now)); err != nil {
			return Enrollment{}, fmt.Errorf("create ephemeral Exit session: %w", err)
		}
		ephemeralExitSession = &EphemeralExitSession{NodeID: nodeID, NetworkID: networkID, Generation: generation,
			LastHeartbeatAt: now, SuspectAt: suspectAt, RevokeAt: revokeAt, CreatedAt: now}
	}
	result, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET consumed_at=?,consumed_by=?
        WHERE id=? AND consumed_at IS NULL AND expires_at>?`, unix(now), idBytes(nodeID), idBytes(tokenID), unix(now))
	if err != nil {
		return Enrollment{}, fmt.Errorf("consume enrollment token: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Enrollment{}, fmt.Errorf("check enrollment token consumption: %w", err)
	}
	if changed != 1 {
		return Enrollment{}, ErrTokenConsumed
	}
	// Adding an overlay identity changes both node and relay route snapshots.
	// Bump the network epoch in the same transaction so connected peers cannot
	// retain a configuration that omits the newly enrolled node.
	if _, err := incrementEpochTx(ctx, tx, networkID); err != nil {
		return Enrollment{}, err
	}
	target := identity.ID(nodeID)
	details := fmt.Sprintf(`{"enrollment_class":%q,"ipv4_address":%q}`, enrollmentClass, address.String())
	if address6.IsValid() {
		details = fmt.Sprintf(`{"enrollment_class":%q,"ipv4_address":%q,"ipv6_address":%q}`, enrollmentClass, address.String(), address6.String())
	}
	if leaseExpiresAt != nil {
		details = strings.TrimSuffix(details, "}") + fmt.Sprintf(`,"lease_expires_at":%d}`, leaseExpiresAt.Unix())
	}
	if err := auditTx(ctx, tx, networkID, &nodeID, "node.enroll", "node", &target, details, now); err != nil {
		return Enrollment{}, err
	}
	if ephemeralExitSession != nil {
		if err := auditActorTx(ctx, tx, &networkID, adminauth.SystemActor(), "ephemeral_exit.session.start", "node", &target,
			fmt.Sprintf(`{"generation":%d,"suspect_at":%d,"revoke_at":%d}`, ephemeralExitSession.Generation,
				ephemeralExitSession.SuspectAt.Unix(), ephemeralExitSession.RevokeAt.Unix()), now); err != nil {
			return Enrollment{}, err
		}
	}
	node := Node{ID: nodeID, NetworkID: networkID, Name: name, EnabledCapabilities: enabledCapabilities, IPv4Address: address, IPv6Address: address6, CreatedAt: now,
		EnrollmentClass: enrollmentClass, LeaseExpiresAt: leaseExpiresAt, WireGuardPublicKey: wireGuardPublicKey, UserID: accessUserID}
	var certificate Certificate
	if issuer != nil {
		material, err := issuer(ctx, node)
		if err != nil {
			return Enrollment{}, fmt.Errorf("issue enrollment certificate: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return Enrollment{}, fmt.Errorf("issue enrollment certificate: %w", err)
		}
		material, err = normalizeCertificateMaterial(material)
		if err != nil {
			return Enrollment{}, fmt.Errorf("persist enrollment certificate: %w", err)
		}
		if leaseExpiresAt != nil && material.NotAfter.After(*leaseExpiresAt) {
			return Enrollment{}, fmt.Errorf("persist enrollment certificate: %w: certificate exceeds ephemeral lease", ErrInvalid)
		}
		certificate, err = addCertificateTx(ctx, tx, networkID, nodeID, material, now)
		if err != nil {
			return Enrollment{}, fmt.Errorf("persist enrollment certificate: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit enrollment: %w", err)
	}
	return Enrollment{Node: node, Certificate: certificate, EphemeralExitSession: ephemeralExitSession}, nil
}
