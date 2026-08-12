package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

func validateAdministratorUsername(username string) error {
	if !adminauth.ValidateUsername(username) {
		return fmt.Errorf("%w: invalid administrator username", ErrInvalid)
	}
	return nil
}

func validatePasswordHash(hash string) error {
	if len(hash) < 64 || len(hash) > 512 {
		return fmt.Errorf("%w: invalid administrator password hash", ErrInvalid)
	}
	if err := adminauth.ValidatePasswordHash(hash); err != nil {
		return fmt.Errorf("%w: invalid administrator password hash", ErrInvalid)
	}
	return nil
}

func (s *Store) AdministratorAuthState(ctx context.Context) (AdministratorAuthState, error) {
	var state AdministratorAuthState
	var rootRaw, ownerRaw []byte
	var bootstrap, recovered sql.NullInt64
	var generation int64
	err := s.db.QueryRowContext(ctx, `SELECT root_service_principal_id,initial_owner_principal_id,
		bootstrap_completed_at,recovery_generation,last_recovered_at
		FROM administrator_auth_state WHERE singleton=1`).Scan(&rootRaw, &ownerRaw, &bootstrap, &generation, &recovered)
	if errors.Is(err, sql.ErrNoRows) {
		return state, fmt.Errorf("%w: administrator auth state", ErrNotFound)
	}
	if err != nil {
		return state, fmt.Errorf("read administrator auth state: %w", err)
	}
	root, err := scanID(rootRaw)
	if err != nil {
		return state, err
	}
	state.RootServicePrincipalID = root
	if ownerRaw != nil {
		owner, err := scanID(ownerRaw)
		if err != nil {
			return state, err
		}
		state.InitialOwnerPrincipalID = &owner
	}
	state.BootstrapCompletedAt = nullableTime(bootstrap)
	if generation < 0 {
		return state, errors.New("corrupt administrator recovery generation")
	}
	state.RecoveryGeneration = uint64(generation)
	state.LastRecoveredAt = nullableTime(recovered)
	return state, nil
}

// CreateFirstOwner atomically consumes a bootstrap grant and creates the sole
// initial owner. passwordHash must already have been produced by adminauth.
func (s *Store) CreateFirstOwner(ctx context.Context, actor adminauth.Actor, grantSecret, username, passwordHash string) (AdministratorRecord, error) {
	var result AdministratorRecord
	if !actor.Valid() {
		return result, fmt.Errorf("%w: invalid administrator bootstrap actor", ErrInvalid)
	}
	if err := validateAdministratorUsername(username); err != nil {
		return result, err
	}
	if err := validatePasswordHash(passwordHash); err != nil {
		return result, err
	}
	grantHash, err := adminauth.HashSecret(adminauth.SecretRecovery, grantSecret)
	if err != nil {
		return result, ErrRecoveryInvalid
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var ownerRaw []byte
	var completed sql.NullInt64
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT initial_owner_principal_id,bootstrap_completed_at,recovery_generation
		FROM administrator_auth_state WHERE singleton=1`).Scan(&ownerRaw, &completed, &generation); err != nil {
		return result, fmt.Errorf("read administrator bootstrap state: %w", err)
	}
	if ownerRaw != nil || completed.Valid {
		return result, ErrBootstrapComplete
	}
	grant, err := recoveryGrantByHashTx(ctx, tx, grantHash)
	if err != nil {
		return result, err
	}
	if grant.Purpose != AdministratorRecoveryBootstrapOwner || grant.TargetPrincipalID != nil || grant.RecoveryGeneration != uint64(generation) {
		return result, ErrRecoveryInvalid
	}
	if grant.ConsumedAt != nil {
		return result, ErrRecoveryConsumed
	}
	if grant.RevokedAt != nil {
		return result, ErrRecoveryInvalid
	}
	if !now.Before(grant.ExpiresAt) {
		return result, ErrRecoveryExpired
	}
	principalID, err := newID()
	if err != nil {
		return result, err
	}
	credentialID, err := newID()
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_principals
		(id,username,role,all_networks,enabled,created_at,updated_at)
		VALUES(?,?,?,1,1,?,?)`, idBytes(principalID), username, string(adminauth.RoleOwner), unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, fmt.Errorf("create initial administrator: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_credentials
		(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?, 'password',?,?)`,
		idBytes(credentialID), idBytes(principalID), passwordHash, unix(now)); err != nil {
		return result, fmt.Errorf("create initial administrator credential: %w", err)
	}
	consumed, err := tx.ExecContext(ctx, `UPDATE administrator_recovery_grants SET consumed_at=?
		WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`, unix(now), idBytes(grant.ID))
	if err != nil {
		return result, fmt.Errorf("consume administrator bootstrap grant: %w", err)
	}
	if rows, _ := consumed.RowsAffected(); rows != 1 {
		return result, ErrRecoveryConsumed
	}
	updated, err := tx.ExecContext(ctx, `UPDATE administrator_auth_state
		SET initial_owner_principal_id=?,bootstrap_completed_at=?
		WHERE singleton=1 AND initial_owner_principal_id IS NULL AND bootstrap_completed_at IS NULL`,
		idBytes(principalID), unix(now))
	if err != nil {
		return result, fmt.Errorf("complete administrator bootstrap: %w", err)
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return result, ErrBootstrapComplete
	}
	target := principalID
	if err := auditActorTx(ctx, tx, nil, actor,
		"administrator.bootstrap.complete", "administrator", &target, `{}`, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit initial administrator: %w", err)
	}
	return AdministratorRecord{
		Principal:  adminauth.Principal{ID: principalID, Username: username, Role: adminauth.RoleOwner, Enabled: true, AllNetworks: true},
		Credential: AdministratorCredential{ID: credentialID, PrincipalID: principalID, Type: "password", SecretHash: passwordHash, CreatedAt: now},
		CreatedAt:  now, UpdatedAt: now,
	}, nil
}

func (s *Store) AdministratorByUsername(ctx context.Context, username string) (AdministratorRecord, error) {
	if err := validateAdministratorUsername(username); err != nil {
		return AdministratorRecord{}, ErrNotFound
	}
	return administratorRecord(ctx, s.db, `p.username=?`, username)
}

func (s *Store) AdministratorPrincipal(ctx context.Context, principalID identity.ID) (AdministratorRecord, error) {
	if principalID.IsZero() {
		return AdministratorRecord{}, ErrNotFound
	}
	return administratorRecord(ctx, s.db, `p.id=?`, idBytes(principalID))
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func administratorRecord(ctx context.Context, queryer rowQueryer, predicate string, argument any) (AdministratorRecord, error) {
	var result AdministratorRecord
	var principalRaw, credentialRaw []byte
	var role string
	var allNetworks, enabled int
	var created, updated, credentialCreated int64
	var disabled, credentialRevoked sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT p.id,p.username,p.role,p.all_networks,p.enabled,p.created_at,p.updated_at,p.disabled_at,
		c.id,c.credential_type,c.secret_hash,c.created_at,c.revoked_at,c.revocation_reason
		FROM administrator_principals p
		JOIN administrator_credentials c ON c.principal_id=p.id AND c.credential_type='password' AND c.revoked_at IS NULL
		WHERE `+predicate, argument).Scan(&principalRaw, &result.Principal.Username, &role, &allNetworks, &enabled,
		&created, &updated, &disabled, &credentialRaw, &result.Credential.Type, &result.Credential.SecretHash,
		&credentialCreated, &credentialRevoked, &result.Credential.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, fmt.Errorf("read administrator: %w", err)
	}
	principalID, err := scanID(principalRaw)
	if err != nil {
		return result, err
	}
	result.Principal.ID = principalID
	result.Principal.Role = adminauth.Role(role)
	result.Principal.AllNetworks = allNetworks == 1
	result.Principal.Enabled = enabled == 1
	result.CreatedAt, result.UpdatedAt, result.DisabledAt = fromUnix(created), fromUnix(updated), nullableTime(disabled)
	if credentialRaw != nil {
		credentialID, err := scanID(credentialRaw)
		if err != nil {
			return result, err
		}
		result.Credential.ID, result.Credential.PrincipalID = credentialID, principalID
		result.Credential.CreatedAt = fromUnix(credentialCreated)
		result.Credential.RevokedAt = nullableTime(credentialRevoked)
	}
	rows, err := queryer.QueryContext(ctx, `SELECT network_id FROM administrator_principal_networks
		WHERE principal_id=? ORDER BY network_id`, idBytes(principalID))
	if err != nil {
		return result, fmt.Errorf("read administrator scopes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return result, err
		}
		id, err := scanID(raw)
		if err != nil {
			return result, err
		}
		result.Principal.NetworkIDs = append(result.Principal.NetworkIDs, identity.NetworkID(id))
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) IssueAdministratorRecoveryGrant(ctx context.Context, actor adminauth.Actor, purpose AdministratorRecoveryPurpose, target *identity.ID, expiresAt time.Time) (AdministratorRecoveryGrant, string, error) {
	var result AdministratorRecoveryGrant
	if !actor.Valid() || !purpose.Valid() || (purpose == AdministratorRecoveryBootstrapOwner) != (target == nil) {
		return result, "", fmt.Errorf("%w: invalid recovery grant purpose or target", ErrInvalid)
	}
	now := s.now()
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return result, "", fmt.Errorf("%w: recovery grant lifetime must be in (0,24h]", ErrInvalid)
	}
	secret, digest, err := adminauth.NewSecret(adminauth.SecretRecovery, nil)
	if err != nil {
		return result, "", err
	}
	id, err := newID()
	if err != nil {
		return result, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, "", err
	}
	defer tx.Rollback()
	var generation int64
	var initialOwner []byte
	if err := tx.QueryRowContext(ctx, `SELECT recovery_generation,initial_owner_principal_id FROM administrator_auth_state WHERE singleton=1`).Scan(&generation, &initialOwner); err != nil {
		return result, "", err
	}
	if purpose == AdministratorRecoveryBootstrapOwner && initialOwner != nil {
		return result, "", ErrBootstrapComplete
	}
	if target != nil {
		var role string
		var enabled int
		if err := tx.QueryRowContext(ctx, `SELECT role,enabled FROM administrator_principals WHERE id=?`, idBytes(*target)).Scan(&role, &enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return result, "", ErrNotFound
			}
			return result, "", err
		}
		if role != string(adminauth.RoleOwner) || enabled != 1 {
			return result, "", ErrRecoveryInvalid
		}
	}
	// Expired one-time records cannot participate in the partial unique indexes.
	if _, err := tx.ExecContext(ctx, `UPDATE administrator_recovery_grants
		SET revoked_at=?,revocation_reason='expired'
		WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at<=?`, unix(now), unix(now)); err != nil {
		return result, "", err
	}
	var targetBytes any
	if target != nil {
		targetBytes = idBytes(*target)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO administrator_recovery_grants
		(id,secret_hash,purpose,target_principal_id,recovery_generation,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?)`, idBytes(id), digest[:], string(purpose), targetBytes, generation, unix(now), unix(expiresAt))
	if err != nil {
		if isConstraint(err) {
			return result, "", ErrConflict
		}
		return result, "", fmt.Errorf("issue administrator recovery grant: %w", err)
	}
	targetID := id
	if err := auditActorTx(ctx, tx, nil, actor, "administrator.recovery.issue", "administrator_recovery_grant", &targetID,
		fmt.Sprintf(`{"purpose":%q}`, purpose), now); err != nil {
		return result, "", err
	}
	if err := tx.Commit(); err != nil {
		return result, "", err
	}
	result = AdministratorRecoveryGrant{ID: id, SecretHash: digest, Purpose: purpose, TargetPrincipalID: target,
		RecoveryGeneration: uint64(generation), CreatedAt: now, ExpiresAt: expiresAt}
	return result, secret, nil
}

func recoveryGrantByHashTx(ctx context.Context, tx *sql.Tx, hash [sha256.Size]byte) (AdministratorRecoveryGrant, error) {
	var result AdministratorRecoveryGrant
	var idRaw, hashRaw, targetRaw []byte
	var generation int64
	var created, expires int64
	var consumed, revoked sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,secret_hash,purpose,target_principal_id,recovery_generation,
		created_at,expires_at,consumed_at,revoked_at,revocation_reason
		FROM administrator_recovery_grants WHERE secret_hash=?`, hash[:]).Scan(&idRaw, &hashRaw, &result.Purpose,
		&targetRaw, &generation, &created, &expires, &consumed, &revoked, &result.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrRecoveryInvalid
	}
	if err != nil {
		return result, err
	}
	id, err := scanID(idRaw)
	if err != nil || len(hashRaw) != sha256.Size || generation < 0 {
		return result, errors.New("corrupt administrator recovery grant")
	}
	result.ID, result.RecoveryGeneration = id, uint64(generation)
	copy(result.SecretHash[:], hashRaw)
	if targetRaw != nil {
		target, err := scanID(targetRaw)
		if err != nil {
			return result, err
		}
		result.TargetPrincipalID = &target
	}
	result.CreatedAt, result.ExpiresAt = fromUnix(created), fromUnix(expires)
	result.ConsumedAt, result.RevokedAt = nullableTime(consumed), nullableTime(revoked)
	return result, nil
}
