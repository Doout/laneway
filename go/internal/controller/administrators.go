package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

var (
	administratorBootstrapGrantPolicy = adminauth.RoutePolicy{Method: http.MethodPost,
		Pattern: "/v1/admin/auth/bootstrap-grants", Operation: adminauth.OperationRecoveryManage,
		ScopeSource: adminauth.ScopeGlobal, Mutation: true}
	administratorOwnerRecoveryGrantPolicy = adminauth.RoutePolicy{Method: http.MethodPost,
		Pattern: "/v1/admin/administrators/{principal_id}/recovery-grants", Operation: adminauth.OperationRecoveryManage,
		ScopeSource: adminauth.ScopeObject, Mutation: true}
	administratorRootTokenRotationBeginPolicy = adminauth.RoutePolicy{Method: http.MethodPost,
		Pattern: "/v1/admin/auth/root-token-rotations/{rotation_id}/begin", Operation: adminauth.OperationRootTokenRotate,
		ScopeSource: adminauth.ScopeObject, Mutation: true}
	administratorRootTokenRotationCompletePolicy = adminauth.RoutePolicy{Method: http.MethodPost,
		Pattern: "/v1/admin/auth/root-token-rotations/{rotation_id}/complete", Operation: adminauth.OperationRootTokenRotate,
		ScopeSource: adminauth.ScopeObject, Mutation: true}
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

// BootstrapFirstAdministrator atomically consumes a bootstrap grant and
// creates the sole initial owner. The durable one-time grant is the successful
// audit actor; no caller-supplied label or service actor can alter attribution.
// passwordHash must already have been produced by adminauth.
func (s *Store) BootstrapFirstAdministrator(ctx context.Context, grantSecret, username, passwordHash string) (AdministratorRecord, error) {
	var result AdministratorRecord
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := s.now()
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
	if now.Before(grant.CreatedAt) {
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
	grantActor := adminauth.IDActor(adminauth.ActorRecoveryGrant, grant.ID)
	if err := auditActorTx(ctx, tx, nil, grantActor,
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

// AdministratorRecoveryCandidate validates a one-time grant before the caller
// spends Argon2 work hashing a replacement password. It returns the same
// unusable shape for malformed, missing, expired, revoked, consumed, stale-
// generation, or wrong-purpose grants. Consumption still performs a complete
// transactional recheck.
func (s *Store) AdministratorRecoveryCandidate(ctx context.Context, grantSecret string,
	purpose AdministratorRecoveryPurpose) (AdministratorRecoveryCandidate, error) {
	var candidate AdministratorRecoveryCandidate
	if !purpose.Valid() {
		return candidate, fmt.Errorf("%w: invalid recovery purpose", ErrInvalid)
	}
	digest, err := adminauth.HashSecret(adminauth.SecretRecovery, grantSecret)
	if err != nil {
		return candidate, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return candidate, err
	}
	defer tx.Rollback()
	grant, err := recoveryGrantByHashTx(ctx, tx, digest)
	if errors.Is(err, ErrRecoveryInvalid) {
		return candidate, nil
	}
	if err != nil {
		return candidate, err
	}
	var generation int64
	var initialOwner []byte
	var bootstrapCompleted sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT recovery_generation,initial_owner_principal_id,bootstrap_completed_at
		FROM administrator_auth_state WHERE singleton=1`).Scan(&generation, &initialOwner, &bootstrapCompleted); err != nil {
		return candidate, err
	}
	if generation < 0 {
		return candidate, errors.New("corrupt administrator recovery generation")
	}
	now := s.now()
	if grant.Purpose != purpose || grant.RecoveryGeneration != uint64(generation) || grant.ConsumedAt != nil ||
		grant.RevokedAt != nil || !now.Before(grant.ExpiresAt) {
		return candidate, nil
	}
	if now.Before(grant.CreatedAt) {
		return candidate, nil
	}
	if purpose == AdministratorRecoveryBootstrapOwner && grant.TargetPrincipalID != nil ||
		purpose == AdministratorRecoveryOwner && grant.TargetPrincipalID == nil {
		return candidate, nil
	}
	if purpose == AdministratorRecoveryBootstrapOwner && (initialOwner != nil || bootstrapCompleted.Valid) {
		return candidate, nil
	}
	if grant.TargetPrincipalID != nil {
		var role string
		if err := tx.QueryRowContext(ctx, `SELECT role FROM administrator_principals WHERE id=?`,
			idBytes(*grant.TargetPrincipalID)).Scan(&role); errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		} else if err != nil {
			return candidate, err
		}
		if role != string(adminauth.RoleOwner) {
			return candidate, nil
		}
	}
	if err := tx.Commit(); err != nil {
		return candidate, err
	}
	candidate = AdministratorRecoveryCandidate{GrantID: grant.ID, Purpose: grant.Purpose,
		TargetPrincipalID: grant.TargetPrincipalID, RecoveryGeneration: grant.RecoveryGeneration, Usable: true}
	return candidate, nil
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

func (s *Store) IssueAdministratorRecoveryGrant(ctx context.Context, decision adminauth.Decision, purpose AdministratorRecoveryPurpose, target *identity.ID, expiresAt time.Time) (AdministratorRecoveryGrant, string, error) {
	var result AdministratorRecoveryGrant
	if !decision.Valid() || !purpose.Valid() || (purpose == AdministratorRecoveryBootstrapOwner) != (target == nil) {
		return result, "", fmt.Errorf("%w: invalid recovery grant purpose or target", ErrInvalid)
	}
	if purpose == AdministratorRecoveryBootstrapOwner {
		if !decision.Matches(decision.Subject(), administratorBootstrapGrantPolicy, adminauth.GlobalTarget()) {
			return result, "", fmt.Errorf("%w: invalid bootstrap recovery decision", ErrInvalid)
		}
	} else if !decision.Matches(decision.Subject(), administratorOwnerRecoveryGrantPolicy, adminauth.ObjectTarget(*target)) {
		return result, "", fmt.Errorf("%w: invalid owner recovery decision", ErrInvalid)
	} else if matchErr := decisionObjectMatches(decision, *target, adminauth.OperationRecoveryManage); matchErr != nil {
		return result, "", matchErr
	}
	expiresAt = expiresAt.UTC().Truncate(time.Second)
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
	now := s.now()
	if !expiresAt.After(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return result, "", fmt.Errorf("%w: recovery grant lifetime must be in (0,24h]", ErrInvalid)
	}
	authorization, err := s.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return result, "", err
	}
	if err := authorizeAdministratorDecisionScope(authorization, decision, nil); err != nil {
		return result, "", err
	}
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
		if err := tx.QueryRowContext(ctx, `SELECT role FROM administrator_principals WHERE id=?`, idBytes(*target)).Scan(&role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return result, "", ErrNotFound
			}
			return result, "", err
		}
		if role != string(adminauth.RoleOwner) {
			return result, "", ErrRecoveryInvalid
		}
	}
	var targetBytes any
	if target != nil {
		targetBytes = idBytes(*target)
	}
	// Reissuing after a crashed CLI/HTTP response supersedes the lost plaintext
	// secret instead of trapping the operator behind a uniqueness conflict.
	// Expired grants are also revoked here so they cannot occupy a partial index.
	var supersedePredicate string
	var supersedeArguments []any
	if purpose == AdministratorRecoveryBootstrapOwner {
		supersedePredicate = `purpose='bootstrap_owner'`
	} else {
		supersedePredicate = `purpose='owner_recovery' AND target_principal_id=?`
		supersedeArguments = append(supersedeArguments, targetBytes)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM administrator_recovery_grants
		WHERE consumed_at IS NULL AND revoked_at IS NULL AND (`+supersedePredicate+` OR expires_at<=?)
		ORDER BY created_at,id`, append(supersedeArguments, unix(now))...)
	if err != nil {
		return result, "", err
	}
	var revokedGrantIDs []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return result, "", err
		}
		grantID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return result, "", err
		}
		revokedGrantIDs = append(revokedGrantIDs, grantID)
	}
	if err := rows.Close(); err != nil {
		return result, "", err
	}
	if err := rows.Err(); err != nil {
		return result, "", err
	}
	for _, grantID := range revokedGrantIDs {
		var grantCreated, grantExpires int64
		if err := tx.QueryRowContext(ctx, `SELECT created_at,expires_at FROM administrator_recovery_grants WHERE id=?`, idBytes(grantID)).Scan(&grantCreated, &grantExpires); err != nil {
			return result, "", err
		}
		reason := "superseded"
		if grantExpires <= unix(now) {
			reason = "expired"
		}
		revokedAt := now
		if revokedAt.Before(fromUnix(grantCreated)) {
			revokedAt = fromUnix(grantCreated)
		}
		updated, err := tx.ExecContext(ctx, `UPDATE administrator_recovery_grants
			SET revoked_at=?,revocation_reason=? WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`,
			unix(revokedAt), reason, idBytes(grantID))
		if err != nil {
			return result, "", err
		}
		if affected, _ := updated.RowsAffected(); affected != 1 {
			return result, "", ErrConflict
		}
		targetID := grantID
		if err := auditActorTx(ctx, tx, nil, authorization.actor, "administrator.recovery.revoke",
			"administrator_recovery_grant", &targetID, fmt.Sprintf(`{"reason":%q}`, reason), revokedAt); err != nil {
			return result, "", err
		}
	}
	issueAt := s.now()
	if !expiresAt.After(issueAt) || expiresAt.After(issueAt.Add(24*time.Hour)) {
		return result, "", fmt.Errorf("%w: recovery grant lifetime must be in (0,24h]", ErrInvalid)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO administrator_recovery_grants
		(id,secret_hash,purpose,target_principal_id,recovery_generation,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?)`, idBytes(id), digest[:], string(purpose), targetBytes, generation, unix(issueAt), unix(expiresAt))
	if err != nil {
		if isConstraint(err) {
			return result, "", ErrConflict
		}
		return result, "", fmt.Errorf("issue administrator recovery grant: %w", err)
	}
	targetID := id
	if err := auditActorTx(ctx, tx, nil, authorization.actor, "administrator.recovery.issue", "administrator_recovery_grant", &targetID,
		fmt.Sprintf(`{"purpose":%q}`, purpose), issueAt); err != nil {
		return result, "", err
	}
	if err := tx.Commit(); err != nil {
		return result, "", err
	}
	var resultTarget *identity.ID
	if target != nil {
		copyTarget := *target
		resultTarget = &copyTarget
	}
	result = AdministratorRecoveryGrant{ID: id, SecretHash: digest, Purpose: purpose, TargetPrincipalID: resultTarget,
		RecoveryGeneration: uint64(generation), CreatedAt: issueAt, ExpiresAt: expiresAt}
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

// RecoverAdministratorOwner consumes an owner-recovery grant, replaces the
// password credential, re-enables the owner, and invalidates every prior
// session and outstanding grant in one transaction. It intentionally does not
// create a session; the recovered owner must complete the normal login path.
func (s *Store) RecoverAdministratorOwner(ctx context.Context, grantSecret, newPasswordHash string) (AdministratorRecord, error) {
	var result AdministratorRecord
	if err := validatePasswordHash(newPasswordHash); err != nil {
		return result, err
	}
	grantHash, err := adminauth.HashSecret(adminauth.SecretRecovery, grantSecret)
	if err != nil {
		return result, ErrRecoveryInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	validationNow := s.now()
	grant, err := recoveryGrantByHashTx(ctx, tx, grantHash)
	if err != nil {
		return result, err
	}
	if grant.Purpose != AdministratorRecoveryOwner || grant.TargetPrincipalID == nil {
		return result, ErrRecoveryInvalid
	}
	if grant.ConsumedAt != nil {
		return result, ErrRecoveryConsumed
	}
	if grant.RevokedAt != nil {
		return result, ErrRecoveryInvalid
	}
	if validationNow.Before(grant.CreatedAt) {
		return result, ErrRecoveryInvalid
	}
	if !validationNow.Before(grant.ExpiresAt) {
		return result, ErrRecoveryExpired
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT recovery_generation FROM administrator_auth_state WHERE singleton=1`).Scan(&generation); err != nil {
		return result, err
	}
	if generation < 0 || grant.RecoveryGeneration != uint64(generation) {
		return result, ErrRecoveryInvalid
	}
	principalID := *grant.TargetPrincipalID
	var role string
	var username string
	var created, updatedAt int64
	if err := tx.QueryRowContext(ctx, `SELECT username,role,created_at,updated_at FROM administrator_principals WHERE id=?`,
		idBytes(principalID)).Scan(&username, &role, &created, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, ErrRecoveryInvalid
		}
		return result, err
	}
	if role != string(adminauth.RoleOwner) {
		return result, ErrRecoveryInvalid
	}
	grantActor := adminauth.IDActor(adminauth.ActorRecoveryGrant, grant.ID)
	mutationAt := latestTime(validationNow, grant.CreatedAt, fromUnix(created), fromUnix(updatedAt))
	mutationAt, err = administratorSessionMutationTimeTx(ctx, tx, principalID, mutationAt)
	if err != nil {
		return result, err
	}
	type staleGrant struct {
		id        identity.ID
		createdAt time.Time
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,created_at FROM administrator_recovery_grants
		WHERE id<>? AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY created_at,id`, idBytes(grant.ID))
	if err != nil {
		return result, err
	}
	var staleGrants []staleGrant
	for rows.Next() {
		var raw []byte
		var grantCreated int64
		if err := rows.Scan(&raw, &grantCreated); err != nil {
			rows.Close()
			return result, err
		}
		staleGrantID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return result, err
		}
		createdAt := fromUnix(grantCreated)
		staleGrants = append(staleGrants, staleGrant{id: staleGrantID, createdAt: createdAt})
		mutationAt = latestTime(mutationAt, createdAt)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	// Revoke every active credential before inserting the replacement. This
	// order satisfies the one-active-password partial unique index.
	rows, err = tx.QueryContext(ctx, `SELECT id,created_at FROM administrator_credentials
		WHERE principal_id=? AND credential_type='password' AND revoked_at IS NULL`, idBytes(principalID))
	if err != nil {
		return result, err
	}
	type activeCredential struct {
		id        identity.ID
		createdAt time.Time
	}
	var credentials []activeCredential
	for rows.Next() {
		var raw []byte
		var credentialCreated int64
		if err := rows.Scan(&raw, &credentialCreated); err != nil {
			rows.Close()
			return result, err
		}
		credentialID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return result, err
		}
		createdAt := fromUnix(credentialCreated)
		credentials = append(credentials, activeCredential{id: credentialID, createdAt: createdAt})
		mutationAt = latestTime(mutationAt, createdAt)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	for _, credential := range credentials {
		updated, err := tx.ExecContext(ctx, `UPDATE administrator_credentials SET revoked_at=?,revocation_reason='owner recovery'
			WHERE id=? AND revoked_at IS NULL`, unix(mutationAt), idBytes(credential.id))
		if err != nil {
			return result, err
		}
		if affected, _ := updated.RowsAffected(); affected != 1 {
			return result, ErrRecoveryInvalid
		}
		targetID := credential.id
		if err := auditActorTx(ctx, tx, nil, grantActor, "administrator.credential.revoke",
			"administrator_credential", &targetID, `{"reason":"owner recovery"}`, mutationAt); err != nil {
			return result, err
		}
	}
	if err := revokeAdministratorSessionsForPrincipalTx(ctx, tx, principalID, grantActor,
		"administrator.session.revoke", "owner recovery", mutationAt); err != nil {
		return result, err
	}
	credentialID, err := newID()
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_credentials
		(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?,'password',?,?)`,
		idBytes(credentialID), idBytes(principalID), newPasswordHash, unix(mutationAt)); err != nil {
		return result, fmt.Errorf("replace recovered owner credential: %w", err)
	}
	principalUpdate, err := tx.ExecContext(ctx, `UPDATE administrator_principals
		SET enabled=1,disabled_at=NULL,updated_at=? WHERE id=? AND role='owner'`, unix(mutationAt), idBytes(principalID))
	if err != nil {
		return result, err
	}
	if affected, _ := principalUpdate.RowsAffected(); affected != 1 {
		return result, ErrRecoveryInvalid
	}
	consumed, err := tx.ExecContext(ctx, `UPDATE administrator_recovery_grants SET consumed_at=?
		WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`, unix(validationNow), idBytes(grant.ID))
	if err != nil {
		return result, err
	}
	if affected, _ := consumed.RowsAffected(); affected != 1 {
		return result, ErrRecoveryConsumed
	}
	for _, staleGrant := range staleGrants {
		stale, err := tx.ExecContext(ctx, `UPDATE administrator_recovery_grants
			SET revoked_at=?,revocation_reason='recovery generation advanced'
			WHERE id=? AND consumed_at IS NULL AND revoked_at IS NULL`, unix(mutationAt), idBytes(staleGrant.id))
		if err != nil {
			return result, err
		}
		if affected, _ := stale.RowsAffected(); affected != 1 {
			return result, ErrRecoveryInvalid
		}
		targetID := staleGrant.id
		if err := auditActorTx(ctx, tx, nil, grantActor, "administrator.recovery.revoke",
			"administrator_recovery_grant", &targetID, `{"reason":"recovery generation advanced"}`, mutationAt); err != nil {
			return result, err
		}
	}
	state, err := tx.ExecContext(ctx, `UPDATE administrator_auth_state
		SET recovery_generation=recovery_generation+1,last_recovered_at=?
		WHERE singleton=1 AND recovery_generation=?`, unix(mutationAt), generation)
	if err != nil {
		return result, err
	}
	if affected, _ := state.RowsAffected(); affected != 1 {
		return result, ErrRecoveryInvalid
	}
	targetID := principalID
	if err := auditActorTx(ctx, tx, nil, grantActor, "administrator.recovery.complete", "administrator", &targetID,
		`{}`, mutationAt); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return AdministratorRecord{
		Principal: adminauth.Principal{ID: principalID, Username: username, Role: adminauth.RoleOwner,
			Enabled: true, AllNetworks: true},
		Credential: AdministratorCredential{ID: credentialID, PrincipalID: principalID, Type: "password",
			SecretHash: newPasswordHash, CreatedAt: mutationAt},
		CreatedAt: fromUnix(created), UpdatedAt: mutationAt,
	}, nil
}

// AuditAdministratorAuthenticationFailure records only a bounded reason class;
// usernames, source addresses, and supplied secrets never enter durable audit.
func (s *Store) AuditAdministratorAuthenticationFailure(ctx context.Context, kind AdministratorAuthFailure) error {
	if !kind.Valid() {
		return fmt.Errorf("%w: invalid administrator authentication failure", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	action := "administrator.login.failure"
	if kind == AdministratorAuthFailureRecovery {
		action = "administrator.recovery.failure"
	}
	if err := auditActorTx(ctx, tx, nil, adminauth.Actor{Kind: adminauth.ActorUnauthenticated},
		action, "administrator_authentication", nil,
		fmt.Sprintf(`{"reason":%q}`, kind), now); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditRootAdministratorTokenRotationBegin is the durable prerequisite for an
// external root-token file rotation. rotationID is a freshly generated,
// non-secret correlation identifier; no token material enters SQLite.
func (s *Store) AuditRootAdministratorTokenRotationBegin(ctx context.Context, decision adminauth.Decision,
	rotationID identity.ID) error {
	return s.auditRootAdministratorTokenRotation(ctx, decision, administratorRootTokenRotationBeginPolicy,
		rotationID, "administrator.root_token.rotate.begin")
}

// AuditRootAdministratorTokenRotationComplete is recorded after the external
// rotation has committed and the new root credential has authenticated. The
// decision must therefore be derived from that new root token.
func (s *Store) AuditRootAdministratorTokenRotationComplete(ctx context.Context, decision adminauth.Decision,
	rotationID identity.ID) error {
	return s.auditRootAdministratorTokenRotation(ctx, decision, administratorRootTokenRotationCompletePolicy,
		rotationID, "administrator.root_token.rotate.complete")
}

func (s *Store) auditRootAdministratorTokenRotation(ctx context.Context, decision adminauth.Decision,
	policy adminauth.RoutePolicy, rotationID identity.ID, action string) error {
	target := adminauth.ObjectTarget(rotationID)
	if rotationID.IsZero() || !decision.Valid() || !decision.Matches(decision.Subject(), policy, target) ||
		decision.Subject().Kind() != adminauth.SubjectRootServicePrincipal {
		return fmt.Errorf("%w: invalid root administrator token rotation", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := s.authorizeAdministratorDecisionTx(ctx, tx, decision, nil)
	if err != nil {
		return err
	}
	var beginAuditRaw, completeAuditRaw []byte
	var begunAt int64
	var completed sql.NullInt64
	markerErr := tx.QueryRowContext(ctx, `SELECT begin_audit_event_id,complete_audit_event_id,begun_at,completed_at
		FROM administrator_root_token_rotations WHERE rotation_id=?`, idBytes(rotationID)).
		Scan(&beginAuditRaw, &completeAuditRaw, &begunAt, &completed)
	isBegin := policy == administratorRootTokenRotationBeginPolicy
	if markerErr == nil {
		if _, err := scanID(beginAuditRaw); err != nil {
			return errors.New("corrupt root administrator token rotation marker")
		}
		if isBegin || completeAuditRaw != nil && completed.Valid {
			return tx.Commit()
		}
		if completeAuditRaw != nil || completed.Valid {
			return errors.New("corrupt root administrator token rotation completion marker")
		}
		if now.Before(fromUnix(begunAt)) {
			now = fromUnix(begunAt)
		}
	} else if !errors.Is(markerErr, sql.ErrNoRows) {
		return markerErr
	} else if !isBegin {
		return fmt.Errorf("%w: root token rotation has not begun", ErrConflict)
	}
	targetID := rotationID
	auditID, err := auditActorIDTx(ctx, tx, nil, actor, action, "root_administrator_token_rotation", &targetID,
		fmt.Sprintf(`{"rotation_id":%q}`, rotationID.String()), now)
	if err != nil {
		return err
	}
	if isBegin {
		if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_root_token_rotations
			(rotation_id,begin_audit_event_id,begun_at) VALUES(?,?,?)`,
			idBytes(rotationID), idBytes(auditID), unix(now)); err != nil {
			return err
		}
	} else {
		updated, err := tx.ExecContext(ctx, `UPDATE administrator_root_token_rotations
			SET complete_audit_event_id=?,completed_at=?
			WHERE rotation_id=? AND complete_audit_event_id IS NULL AND completed_at IS NULL`,
			idBytes(auditID), unix(now), idBytes(rotationID))
		if err != nil {
			return err
		}
		if affected, _ := updated.RowsAffected(); affected != 1 {
			return ErrConflict
		}
	}
	return tx.Commit()
}
