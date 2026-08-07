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
	if label != strings.TrimSpace(label) || len(label) > MaxTokenLabelLength || strings.IndexByte(label, 0) >= 0 {
		return EnrollmentToken{}, fmt.Errorf("%w: invalid enrollment token label", ErrInvalid)
	}
	now := s.now()
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.Sub(now) > MaxTokenLifetime {
		return EnrollmentToken{}, fmt.Errorf("%w: token expiry must be in the next %s", ErrInvalid, MaxTokenLifetime)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens
        (id,network_id,token_hash,label,expires_at,created_at) VALUES(?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), digest[:], label, unix(expiresAt), unix(now)); err != nil {
		if isConstraint(err) {
			return EnrollmentToken{}, fmt.Errorf("%w: network does not exist", ErrNotFound)
		}
		return EnrollmentToken{}, fmt.Errorf("insert enrollment token: %w", err)
	}
	target := id
	if err := auditTx(ctx, tx, networkID, nil, "enrollment_token.issue", "enrollment_token", &target, `{}`, now); err != nil {
		return EnrollmentToken{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentToken{}, fmt.Errorf("commit enrollment token: %w", err)
	}
	return EnrollmentToken{ID: id, NetworkID: networkID, Label: label, Secret: secret, ExpiresAt: expiresAt, CreatedAt: now}, nil
}

// EnrollNode atomically consumes a single-use bearer token, creates a node and
// assigns its IPv4 and optional IPv6 overlay addresses. Any failure rolls back
// all changes.
func (s *Store) EnrollNode(ctx context.Context, secret, name string, enabledCapabilities uint64) (Node, error) {
	enrollment, err := s.enrollNode(ctx, secret, name, enabledCapabilities, nil)
	return enrollment.Node, err
}

// EnrollNodeWithCertificate atomically consumes a token and persists the node,
// overlay addresses, and issuer-produced certificate. Issuance or persistence
// failure leaves the token reusable and no partial enrollment records.
func (s *Store) EnrollNodeWithCertificate(ctx context.Context, secret, name string, enabledCapabilities uint64, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if issuer == nil {
		return Enrollment{}, fmt.Errorf("%w: enrollment certificate issuer is required", ErrInvalid)
	}
	return s.enrollNode(ctx, secret, name, enabledCapabilities, issuer)
}

func (s *Store) enrollNode(ctx context.Context, secret, name string, enabledCapabilities uint64, issuer EnrollmentCertificateIssuer) (Enrollment, error) {
	if err := validateName("node", name); err != nil {
		return Enrollment{}, err
	}
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
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin enrollment: %w", err)
	}
	defer tx.Rollback()
	var tokenIDBytes, networkIDBytes []byte
	var expires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT id,network_id,expires_at,consumed_at FROM enrollment_tokens WHERE token_hash=?`, digest[:]).Scan(&tokenIDBytes, &networkIDBytes, &expires, &consumed)
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
	nodeID, err := identity.NewNodeID()
	if err != nil {
		return Enrollment{}, fmt.Errorf("generate node ID: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes
        (id,network_id,name,enabled_capabilities,created_at) VALUES(?,?,?,?,?)`,
		idBytes(nodeID), idBytes(networkID), name, int64(enabledCapabilities), unix(now)); err != nil {
		if isConstraint(err) {
			return Enrollment{}, fmt.Errorf("%w: node name already exists", ErrConflict)
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
	details := fmt.Sprintf(`{"ipv4_address":%q}`, address.String())
	if address6.IsValid() {
		details = fmt.Sprintf(`{"ipv4_address":%q,"ipv6_address":%q}`, address.String(), address6.String())
	}
	if err := auditTx(ctx, tx, networkID, nil, "node.enroll", "node", &target, details, now); err != nil {
		return Enrollment{}, err
	}
	node := Node{ID: nodeID, NetworkID: networkID, Name: name, EnabledCapabilities: enabledCapabilities, IPv4Address: address, IPv6Address: address6, CreatedAt: now}
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
