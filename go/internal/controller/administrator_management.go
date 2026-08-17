package controller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

var (
	administratorCreatePolicy          = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/administrators")
	administratorListPolicy            = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/administrators")
	administratorReadPolicy            = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/administrators/{principal_id}")
	administratorAccessUpdatePolicy    = mustAdministratorResourcePolicy(http.MethodPatch, "/v1/admin/administrators/{principal_id}")
	administratorPasswordReplacePolicy = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/administrators/{principal_id}/password")
	administratorSessionListPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/administrators/{principal_id}/sessions")
	administratorSessionRevokePolicy   = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/sessions/{session_id}/revoke")
)

// AdministratorSummary is the safe management representation of a principal.
// Password hashes and credential identifiers are intentionally absent.
type AdministratorSummary struct {
	ID                identity.ID
	Username          string
	Role              adminauth.Role
	Enabled           bool
	AllNetworks       bool
	NetworkIDs        []identity.NetworkID
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DisabledAt        *time.Time
	PasswordUpdatedAt time.Time
}

type AdministratorSessionState string

const (
	AdministratorSessionActive  AdministratorSessionState = "active"
	AdministratorSessionExpired AdministratorSessionState = "expired"
	AdministratorSessionRevoked AdministratorSessionState = "revoked"
)

// AdministratorSessionSummary excludes bearer, CSRF, and credential hashes.
type AdministratorSessionSummary struct {
	ID                identity.ID
	PrincipalID       identity.ID
	State             AdministratorSessionState
	Current           bool
	CreatedAt         time.Time
	LastSeenAt        time.Time
	IdleTimeout       time.Duration
	MaximumSessions   int
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevocationReason  string
}

func normalizeAdministratorAccess(spec AdministratorAccessSpec) (AdministratorAccessSpec, error) {
	if !spec.Role.Valid() || spec.Role == adminauth.RoleOwner && !spec.AllNetworks ||
		spec.AllNetworks && len(spec.NetworkIDs) != 0 {
		return AdministratorAccessSpec{}, fmt.Errorf("%w: invalid administrator access", ErrInvalid)
	}
	normalized := spec
	normalized.NetworkIDs = slices.Clone(spec.NetworkIDs)
	slices.SortFunc(normalized.NetworkIDs, func(left, right identity.NetworkID) int {
		return bytes.Compare(left[:], right[:])
	})
	for index, networkID := range normalized.NetworkIDs {
		if networkID.IsZero() || index > 0 && networkID == normalized.NetworkIDs[index-1] {
			return AdministratorAccessSpec{}, fmt.Errorf("%w: invalid administrator network scope", ErrInvalid)
		}
	}
	return normalized, nil
}

func validateAdministratorManagementObjectDecision(decision adminauth.Decision, policy adminauth.RoutePolicy,
	objectID identity.ID, operation adminauth.Operation) error {
	if err := validateAdministratorResourceDecision(decision, policy, adminauth.ObjectTarget(objectID)); err != nil {
		return err
	}
	return decisionObjectMatches(decision, objectID, operation)
}

func authorizeAdministratorManagementGlobalTx(ctx context.Context, store *Store, tx *sql.Tx,
	decision adminauth.Decision, policy adminauth.RoutePolicy) (adminauth.Actor, error) {
	if err := validateAdministratorResourceDecision(decision, policy, adminauth.GlobalTarget()); err != nil {
		return adminauth.Actor{}, err
	}
	authorization, err := store.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return adminauth.Actor{}, err
	}
	if err := authorizeAdministratorDecisionScope(authorization, decision, nil); err != nil {
		return adminauth.Actor{}, err
	}
	return authorization.actor, nil
}

func authorizeAdministratorManagementObjectTx(ctx context.Context, store *Store, tx *sql.Tx,
	decision adminauth.Decision, policy adminauth.RoutePolicy, objectID identity.ID,
	operation adminauth.Operation) (adminauth.Actor, error) {
	if err := validateAdministratorManagementObjectDecision(decision, policy, objectID, operation); err != nil {
		return adminauth.Actor{}, err
	}
	authorization, err := store.authenticateAdministratorDecisionSubjectTx(ctx, tx, decision)
	if err != nil {
		return adminauth.Actor{}, err
	}
	if err := authorizeAdministratorDecisionScope(authorization, decision, nil); err != nil {
		return adminauth.Actor{}, err
	}
	return authorization.actor, nil
}

func administratorManagementBootstrapCompletedTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	var initialOwnerRaw []byte
	var completed sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT initial_owner_principal_id,bootstrap_completed_at
		FROM administrator_auth_state WHERE singleton=1`).Scan(&initialOwnerRaw, &completed); err != nil {
		return false, fmt.Errorf("read administrator bootstrap state: %w", err)
	}
	if (initialOwnerRaw != nil) != completed.Valid {
		return false, errors.New("corrupt administrator bootstrap state")
	}
	if !completed.Valid {
		return false, nil
	}
	if _, err := scanID(initialOwnerRaw); err != nil {
		return false, err
	}
	return true, nil
}

func requireAdministratorManagementBootstrapTx(ctx context.Context, tx *sql.Tx) error {
	completed, err := administratorManagementBootstrapCompletedTx(ctx, tx)
	if err != nil {
		return err
	}
	if !completed {
		return fmt.Errorf("%w: administrator bootstrap is incomplete", ErrConflict)
	}
	return nil
}

func validateAdministratorNetworksTx(ctx context.Context, tx *sql.Tx, networkIDs []identity.NetworkID) error {
	for _, networkID := range networkIDs {
		var found int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM networks WHERE id=?`, idBytes(networkID)).Scan(&found); err != nil {
			return err
		}
		if found != 1 {
			return fmt.Errorf("%w: administrator network scope does not exist", ErrInvalid)
		}
	}
	return nil
}

func administratorSummary(ctx context.Context, queryer rowQueryer, principalID identity.ID) (AdministratorSummary, error) {
	record, err := administratorRecord(ctx, queryer, `p.id=?`, idBytes(principalID))
	if err != nil {
		return AdministratorSummary{}, err
	}
	return administratorSummaryFromRecord(record), nil
}

func administratorSummaryFromRecord(record AdministratorRecord) AdministratorSummary {
	return AdministratorSummary{
		ID:                record.Principal.ID,
		Username:          record.Principal.Username,
		Role:              record.Principal.Role,
		Enabled:           record.Principal.Enabled,
		AllNetworks:       record.Principal.AllNetworks,
		NetworkIDs:        slices.Clone(record.Principal.NetworkIDs),
		CreatedAt:         record.CreatedAt,
		UpdatedAt:         record.UpdatedAt,
		DisabledAt:        cloneTimePointer(record.DisabledAt),
		PasswordUpdatedAt: record.Credential.CreatedAt,
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func insertAdministratorScopesTx(ctx context.Context, tx *sql.Tx, principalID identity.ID,
	networkIDs []identity.NetworkID, now time.Time) error {
	for _, networkID := range networkIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_principal_networks
			(principal_id,network_id,created_at) VALUES(?,?,?)`, idBytes(principalID), idBytes(networkID), unix(now)); err != nil {
			return fmt.Errorf("create administrator network scope: %w", err)
		}
	}
	return nil
}

func administratorAccessAuditDetails(before, after AdministratorAccessSpec) (string, error) {
	details, err := json.Marshal(struct {
		Before AdministratorAccessSpec `json:"before"`
		After  AdministratorAccessSpec `json:"after"`
	}{Before: before, After: after})
	if err != nil {
		return "", err
	}
	return string(details), nil
}

// CreateAdministrator creates an enabled principal and its first immutable
// password credential in the same transaction as authorization and audit.
func (s *Store) CreateAdministrator(ctx context.Context, decision adminauth.Decision,
	spec CreateAdministratorSpec) (AdministratorSummary, error) {
	var result AdministratorSummary
	if err := validateAdministratorUsername(spec.Username); err != nil {
		return result, err
	}
	if err := validatePasswordHash(spec.PasswordHash); err != nil {
		return result, err
	}
	access, err := normalizeAdministratorAccess(spec.Access)
	if err != nil {
		return result, err
	}
	if !access.Enabled {
		return result, fmt.Errorf("%w: new administrator must be enabled", ErrInvalid)
	}
	principalID, err := newID()
	if err != nil {
		return result, err
	}
	credentialID, err := newID()
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, administratorCreatePolicy)
	if err != nil {
		return result, err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		return result, err
	}
	if err := validateAdministratorNetworksTx(ctx, tx, access.NetworkIDs); err != nil {
		return result, err
	}
	allNetworks := 0
	if access.AllNetworks {
		allNetworks = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_principals
		(id,username,role,all_networks,enabled,created_at,updated_at)
		VALUES(?,?,?,?,1,?,?)`, idBytes(principalID), spec.Username, string(access.Role), allNetworks,
		unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, fmt.Errorf("create administrator: %w", err)
	}
	if err := insertAdministratorScopesTx(ctx, tx, principalID, access.NetworkIDs, now); err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_credentials
		(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?,'password',?,?)`,
		idBytes(credentialID), idBytes(principalID), spec.PasswordHash, unix(now)); err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, fmt.Errorf("create administrator credential: %w", err)
	}
	details, err := administratorAccessAuditDetails(AdministratorAccessSpec{}, access)
	if err != nil {
		return result, err
	}
	target := principalID
	if err := auditActorTx(ctx, tx, nil, actor, "administrator.create", "administrator", &target, details, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit administrator creation: %w", err)
	}
	return AdministratorSummary{ID: principalID, Username: spec.Username, Role: access.Role, Enabled: true,
		AllNetworks: access.AllNetworks, NetworkIDs: slices.Clone(access.NetworkIDs), CreatedAt: now,
		UpdatedAt: now, PasswordUpdatedAt: now}, nil
}

// AdministratorPrincipals returns a bounded deterministic safe inventory.
func (s *Store) AdministratorPrincipals(ctx context.Context, decision adminauth.Decision,
	limit int) ([]AdministratorSummary, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, administratorListPolicy); err != nil {
		return nil, err
	}
	completed, err := administratorManagementBootstrapCompletedTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !completed {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return []AdministratorSummary{}, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM administrator_principals ORDER BY created_at,id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list administrators: %w", err)
	}
	var principalIDs []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		principalID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		principalIDs = append(principalIDs, principalID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]AdministratorSummary, 0, len(principalIDs))
	for _, principalID := range principalIDs {
		summary, err := administratorSummary(ctx, tx, principalID)
		if err != nil {
			return nil, err
		}
		result = append(result, summary)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// AdministratorPrincipalByUsername performs an exact, decision-authorized
// lookup without depending on the bounded inventory page. It is intended for
// management workflows that already possess a canonical username.
func (s *Store) AdministratorPrincipalByUsername(ctx context.Context, decision adminauth.Decision,
	username string) (AdministratorSummary, error) {
	var result AdministratorSummary
	if err := validateAdministratorUsername(username); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, administratorListPolicy); err != nil {
		return result, err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		if errors.Is(err, ErrConflict) {
			return result, ErrNotFound
		}
		return result, err
	}
	record, err := administratorRecord(ctx, tx, `p.username=?`, username)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return administratorSummaryFromRecord(record), nil
}

// AdministratorPrincipalAuthorized reads one principal only after revalidating
// the immutable object-target decision in the same transaction.
func (s *Store) AdministratorPrincipalAuthorized(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID) (AdministratorSummary, error) {
	var result AdministratorSummary
	if err := validateAdministratorManagementObjectDecision(decision, administratorReadPolicy,
		principalID, adminauth.OperationPrincipalManage); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, administratorReadPolicy,
		principalID, adminauth.OperationPrincipalManage); err != nil {
		return result, err
	}
	completed, err := administratorManagementBootstrapCompletedTx(ctx, tx)
	if err != nil {
		return result, err
	}
	if !completed {
		return result, ErrNotFound
	}
	result, err = administratorSummary(ctx, tx, principalID)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return AdministratorSummary{}, err
	}
	return result, nil
}

// UpdateAdministratorAccess replaces role, enabled state, and scope as one
// unit. The last enabled owner can never be demoted or disabled.
func (s *Store) UpdateAdministratorAccess(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, spec AdministratorAccessSpec) (AdministratorSummary, error) {
	enabled := spec.Enabled
	access := spec
	access.Enabled = false
	return s.UpdateAdministrator(ctx, decision, principalID,
		AdministratorUpdateSpec{Access: &access, Enabled: &enabled})
}

// UpdateAdministrator applies the frozen partial PATCH contract in one
// authorized transaction. It never pre-reads under another route decision.
func (s *Store) UpdateAdministrator(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, spec AdministratorUpdateSpec) (AdministratorSummary, error) {
	var result AdministratorSummary
	if err := validateAdministratorManagementObjectDecision(decision, administratorAccessUpdatePolicy,
		principalID, adminauth.OperationPrincipalManage); err != nil {
		return result, err
	}
	if spec.Access == nil && spec.Enabled == nil {
		return result, fmt.Errorf("%w: empty administrator update", ErrInvalid)
	}
	var requestedAccess *AdministratorAccessSpec
	if spec.Access != nil {
		accessCopy := *spec.Access
		// Enabled is not part of the access tuple in PATCH; normalize it only
		// after the current durable enabled state has been loaded below.
		accessCopy.Enabled = true
		normalized, err := normalizeAdministratorAccess(accessCopy)
		if err != nil {
			return result, err
		}
		requestedAccess = &normalized
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, administratorAccessUpdatePolicy,
		principalID, adminauth.OperationPrincipalManage)
	if err != nil {
		return result, err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		return result, err
	}
	currentRecord, err := administratorRecord(ctx, tx, `p.id=?`, idBytes(principalID))
	if err != nil {
		return result, err
	}
	mutationAt := latestTime(s.now(), currentRecord.CreatedAt, currentRecord.UpdatedAt,
		currentRecord.Credential.CreatedAt)
	mutationAt, err = administratorSessionMutationTimeTx(ctx, tx, principalID, mutationAt)
	if err != nil {
		return result, err
	}
	before := AdministratorAccessSpec{Role: currentRecord.Principal.Role, Enabled: currentRecord.Principal.Enabled,
		AllNetworks: currentRecord.Principal.AllNetworks, NetworkIDs: slices.Clone(currentRecord.Principal.NetworkIDs)}
	access := before
	if requestedAccess != nil {
		access.Role = requestedAccess.Role
		access.AllNetworks = requestedAccess.AllNetworks
		access.NetworkIDs = slices.Clone(requestedAccess.NetworkIDs)
	}
	if spec.Enabled != nil {
		access.Enabled = *spec.Enabled
	}
	if err := validateAdministratorNetworksTx(ctx, tx, access.NetworkIDs); err != nil {
		return result, err
	}
	if before.Role == access.Role && before.Enabled == access.Enabled && before.AllNetworks == access.AllNetworks &&
		slices.Equal(before.NetworkIDs, access.NetworkIDs) {
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return administratorSummaryFromRecord(currentRecord), nil
	}
	if before.Role == adminauth.RoleOwner && before.Enabled &&
		(access.Role != adminauth.RoleOwner || !access.Enabled) {
		var enabledOwners int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM administrator_principals
			WHERE role='owner' AND enabled=1`).Scan(&enabledOwners); err != nil {
			return result, err
		}
		if enabledOwners <= 1 {
			return result, fmt.Errorf("%w: cannot remove the last enabled owner", ErrConflict)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM administrator_principal_networks WHERE principal_id=?`,
		idBytes(principalID)); err != nil {
		return result, err
	}
	allNetworks, enabled := 0, 0
	if access.AllNetworks {
		allNetworks = 1
	}
	var disabledAt any = unix(mutationAt)
	if access.Enabled {
		enabled, disabledAt = 1, nil
	}
	updated, err := tx.ExecContext(ctx, `UPDATE administrator_principals
		SET role=?,all_networks=?,enabled=?,updated_at=?,disabled_at=? WHERE id=?`,
		string(access.Role), allNetworks, enabled, unix(mutationAt), disabledAt, idBytes(principalID))
	if err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, err
	}
	if affected, _ := updated.RowsAffected(); affected != 1 {
		return result, ErrNotFound
	}
	if err := insertAdministratorScopesTx(ctx, tx, principalID, access.NetworkIDs, mutationAt); err != nil {
		return result, err
	}
	details, err := administratorAccessAuditDetails(before, access)
	if err != nil {
		return result, err
	}
	target := principalID
	if err := auditActorTx(ctx, tx, nil, actor, "administrator.access.update", "administrator", &target,
		details, mutationAt); err != nil {
		return result, err
	}
	if err := revokeAdministratorSessionsForPrincipalTx(ctx, tx, principalID, actor,
		"administrator.session.revoke", "administrator access changed", mutationAt); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result = administratorSummaryFromRecord(currentRecord)
	result.Role, result.Enabled, result.AllNetworks = access.Role, access.Enabled, access.AllNetworks
	result.NetworkIDs, result.UpdatedAt = slices.Clone(access.NetworkIDs), mutationAt
	if access.Enabled {
		result.DisabledAt = nil
	} else {
		result.DisabledAt = cloneTimePointer(&mutationAt)
	}
	return result, nil
}

// ReplaceAdministratorPassword revokes the immutable old credential, creates
// its replacement, and invalidates every target session atomically.
func (s *Store) ReplaceAdministratorPassword(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, passwordHash string) (AdministratorSummary, error) {
	var result AdministratorSummary
	if err := validateAdministratorManagementObjectDecision(decision, administratorPasswordReplacePolicy,
		principalID, adminauth.OperationPrincipalManage); err != nil {
		return result, err
	}
	if err := validatePasswordHash(passwordHash); err != nil {
		return result, err
	}
	credentialID, err := newID()
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision,
		administratorPasswordReplacePolicy, principalID, adminauth.OperationPrincipalManage)
	if err != nil {
		return result, err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		return result, err
	}
	currentRecord, err := administratorRecord(ctx, tx, `p.id=?`, idBytes(principalID))
	if err != nil {
		return result, err
	}
	mutationAt := latestTime(s.now(), currentRecord.CreatedAt, currentRecord.UpdatedAt,
		currentRecord.Credential.CreatedAt)
	mutationAt, err = administratorSessionMutationTimeTx(ctx, tx, principalID, mutationAt)
	if err != nil {
		return result, err
	}
	revoked, err := tx.ExecContext(ctx, `UPDATE administrator_credentials
		SET revoked_at=?,revocation_reason='password replaced'
		WHERE id=? AND principal_id=? AND credential_type='password' AND revoked_at IS NULL`,
		unix(mutationAt), idBytes(currentRecord.Credential.ID), idBytes(principalID))
	if err != nil {
		return result, err
	}
	if affected, _ := revoked.RowsAffected(); affected != 1 {
		return result, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO administrator_credentials
		(id,principal_id,credential_type,secret_hash,created_at) VALUES(?,?,'password',?,?)`,
		idBytes(credentialID), idBytes(principalID), passwordHash, unix(mutationAt)); err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, fmt.Errorf("replace administrator credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE administrator_principals SET updated_at=? WHERE id=?`,
		unix(mutationAt), idBytes(principalID)); err != nil {
		return result, err
	}
	if err := revokeAdministratorSessionsForPrincipalTx(ctx, tx, principalID, actor,
		"administrator.session.revoke", "password replaced", mutationAt); err != nil {
		return result, err
	}
	target := principalID
	if err := auditActorTx(ctx, tx, nil, actor, "administrator.password.replace", "administrator", &target,
		`{}`, mutationAt); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result = administratorSummaryFromRecord(currentRecord)
	result.PasswordUpdatedAt, result.UpdatedAt = mutationAt, mutationAt
	return result, nil
}

// AdministratorSessions returns active, expired, and revoked sessions without
// exposing any stored authentication material.
func (s *Store) AdministratorSessions(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, limit int) ([]AdministratorSessionSummary, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	if err := validateAdministratorManagementObjectDecision(decision, administratorSessionListPolicy,
		principalID, adminauth.OperationSessionManage); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, administratorSessionListPolicy,
		principalID, adminauth.OperationSessionManage); err != nil {
		return nil, err
	}
	completed, err := administratorManagementBootstrapCompletedTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !completed {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return []AdministratorSessionSummary{}, nil
	}
	if _, err := administratorSummary(ctx, tx, principalID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM administrator_sessions
		WHERE principal_id=? ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(principalID), limit)
	if err != nil {
		return nil, err
	}
	var sessionIDs []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		sessionID, err := scanID(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		sessionIDs = append(sessionIDs, sessionID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var currentSession identity.ID
	if decision.Subject().Kind() == adminauth.SubjectAdministratorSession {
		currentSession, _ = decision.Subject().SessionID()
	}
	now := s.now()
	result := make([]AdministratorSessionSummary, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		session, err := administratorSessionBy(ctx, tx, `s.id=?`, idBytes(sessionID))
		if err != nil {
			return nil, err
		}
		state := AdministratorSessionActive
		if session.RevokedAt != nil {
			state = AdministratorSessionRevoked
		} else if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) {
			state = AdministratorSessionExpired
		}
		result = append(result, AdministratorSessionSummary{
			ID: session.ID, PrincipalID: session.PrincipalID, State: state,
			Current: session.ID == currentSession, CreatedAt: session.CreatedAt, LastSeenAt: session.LastSeenAt,
			IdleTimeout: session.IdleTimeout, MaximumSessions: session.MaximumSessions,
			IdleExpiresAt: session.IdleExpiresAt, AbsoluteExpiresAt: session.AbsoluteExpiresAt,
			RevokedAt: cloneTimePointer(session.RevokedAt), RevocationReason: session.RevocationReason,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// RevokeAdministratorSessionByDecision is idempotent for an already-revoked
// session and returns ErrNotFound only after authenticating the decision.
func (s *Store) RevokeAdministratorSessionByDecision(ctx context.Context, decision adminauth.Decision,
	sessionID identity.ID, reason string) error {
	if len(reason) < 1 || len(reason) > adminauth.MaxSessionReason {
		return fmt.Errorf("%w: invalid administrator session revocation", ErrInvalid)
	}
	if err := validateAdministratorManagementObjectDecision(decision, administratorSessionRevokePolicy,
		sessionID, adminauth.OperationSessionManage); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, administratorSessionRevokePolicy,
		sessionID, adminauth.OperationSessionManage)
	if err != nil {
		return err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		return err
	}
	family, err := administratorSessionFamilyTx(ctx, tx, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			return ErrNotFound
		}
		return err
	}
	for _, member := range family {
		if member.RevokedAt != nil {
			continue
		}
		if _, err := revokeAdministratorSessionTx(ctx, tx, member.ID, actor,
			"administrator.session.revoke", reason, administratorSessionRevocationTime(now, member)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
