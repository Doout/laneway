package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

const enrollmentSecretBytes = 32

func tokenDigest(secret string) ([32]byte, error) {
	var zero [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != enrollmentSecretBytes || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return zero, ErrTokenInvalid
	}
	return sha256.Sum256(decoded), nil
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens
		(id,network_id,token_hash,label,expires_at,created_at,enrollment_class,session_lifetime_seconds,requested_name) VALUES(?,?,?,?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), digest[:], label, unix(expiresAt), unix(now), string(options.Class), sessionLifetime, requestedName); err != nil {
		if isConstraint(err) {
			return EnrollmentToken{}, fmt.Errorf("%w: network does not exist", ErrNotFound)
		}
		return EnrollmentToken{}, fmt.Errorf("insert enrollment token: %w", err)
	}
	target := id
	details := fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q}`, options.Class, options.RequestedName)
	if options.Class == EnrollmentClassEphemeral {
		details = fmt.Sprintf(`{"enrollment_class":%q,"requested_name":%q,"session_lifetime_seconds":%d}`, options.Class, options.RequestedName, int64(options.SessionLifetime/time.Second))
	}
	if err := auditTx(ctx, tx, networkID, nil, "enrollment_token.issue", "enrollment_token", &target, details, now); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, fmt.Errorf("commit enrollment token: %w", err)
	}
	return EnrollmentToken{ID: id, NetworkID: networkID, Label: label, Secret: secret, ExpiresAt: expiresAt, CreatedAt: now,
		EnrollmentClass: options.Class, SessionLifetime: options.SessionLifetime, RequestedName: options.RequestedName}, nil
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
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback()
	var tokenIDBytes, networkIDBytes []byte
	var expires int64
	var consumed sql.NullInt64
	var class string
	var sessionLifetime sql.NullInt64
	var requestedName sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,network_id,expires_at,consumed_at,enrollment_class,session_lifetime_seconds,requested_name FROM enrollment_tokens WHERE token_hash=?`, digest[:]).Scan(&tokenIDBytes, &networkIDBytes, &expires, &consumed, &class, &sessionLifetime, &requestedName)
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
	var leaseExpiresAt *time.Time
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
        (id,network_id,name,enabled_capabilities,created_at,enrollment_class,lease_expires_at,wireguard_public_key) VALUES(?,?,?,?,?,?,?,?)`,
		idBytes(nodeID), idBytes(networkID), name, int64(enabledCapabilities), unix(now), string(enrollmentClass), leaseUnix, nullableWireGuardKey(wireGuardPublicKey)); err != nil {
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
	if err := auditTx(ctx, tx, networkID, nil, "node.enroll", "node", &target, details, now); err != nil {
		return Enrollment{}, err
	}
	node := Node{ID: nodeID, NetworkID: networkID, Name: name, EnabledCapabilities: enabledCapabilities, IPv4Address: address, IPv6Address: address6, CreatedAt: now,
		EnrollmentClass: enrollmentClass, LeaseExpiresAt: leaseExpiresAt, WireGuardPublicKey: wireGuardPublicKey}
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
	return Enrollment{Node: node, Certificate: certificate}, nil
}
