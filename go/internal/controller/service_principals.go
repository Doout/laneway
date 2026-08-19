package controller

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	MaxServiceAccessTokenLifetime               = 365 * 24 * time.Hour
	MaxEnabledServicePrincipals                 = 100
	MaxUnrevokedServiceAccessTokensPerPrincipal = 100

	servicePrincipalDisabledTokenRevocationReason = "service principal disabled"
)

var (
	servicePrincipalCreatePolicy  = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/service-principals")
	servicePrincipalListPolicy    = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/service-principals")
	servicePrincipalDisablePolicy = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/service-principals/{principal_id}/disable")
	serviceTokenIssuePolicy       = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/service-principals/{principal_id}/tokens")
	serviceTokenListPolicy        = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/service-principals/{principal_id}/tokens")
	serviceTokenRevokePolicy      = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/service-access-tokens/{token_id}/revoke")
)

type ServicePrincipalSpec struct {
	Name        string
	AllNetworks bool
	NetworkIDs  []identity.NetworkID
	Permissions []adminauth.Operation
}

type ServicePrincipalSummary struct {
	Principal  adminauth.ServicePrincipal
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

type ServiceAccessTokenSummary struct {
	ID               identity.ID
	PrincipalID      identity.ID
	Label            string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason string
}

func normalizeServicePrincipalSpec(spec ServicePrincipalSpec) (ServicePrincipalSpec, error) {
	if !adminauth.ValidateServicePrincipalName(spec.Name) || len(spec.Permissions) == 0 ||
		spec.AllNetworks && len(spec.NetworkIDs) != 0 {
		return ServicePrincipalSpec{}, fmt.Errorf("%w: invalid service principal", ErrInvalid)
	}
	result := ServicePrincipalSpec{Name: spec.Name, AllNetworks: spec.AllNetworks,
		NetworkIDs: slices.Clone(spec.NetworkIDs), Permissions: slices.Clone(spec.Permissions)}
	slices.SortFunc(result.NetworkIDs, func(left, right identity.NetworkID) int {
		return bytes.Compare(left[:], right[:])
	})
	for index, networkID := range result.NetworkIDs {
		if networkID.IsZero() || index > 0 && networkID == result.NetworkIDs[index-1] {
			return ServicePrincipalSpec{}, fmt.Errorf("%w: invalid service principal network scope", ErrInvalid)
		}
	}
	slices.Sort(result.Permissions)
	requiresNetworkScope := false
	for index, operation := range result.Permissions {
		if !adminauth.AutomationGrantable(operation) || index > 0 && operation == result.Permissions[index-1] {
			return ServicePrincipalSpec{}, fmt.Errorf("%w: invalid service principal permission", ErrInvalid)
		}
		requiresNetworkScope = requiresNetworkScope || operation.NetworkScoped() || operation == adminauth.OperationNetworkList
	}
	hasNetworkScope := result.AllNetworks || len(result.NetworkIDs) != 0
	if requiresNetworkScope != hasNetworkScope {
		return ServicePrincipalSpec{}, fmt.Errorf("%w: service principal network scope does not match permissions", ErrInvalid)
	}
	return result, nil
}

func servicePrincipalRecord(ctx context.Context, queryer rowQueryer, principalID identity.ID) (ServicePrincipalSummary, error) {
	var result ServicePrincipalSummary
	var raw []byte
	var enabled, allNetworks int
	var created, updated int64
	var disabled sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT id,name,enabled,all_networks,created_at,updated_at,disabled_at
		FROM automation_service_principals WHERE id=?`, idBytes(principalID)).Scan(&raw,
		&result.Principal.Name, &enabled, &allNetworks, &created, &updated, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, fmt.Errorf("read service principal: %w", err)
	}
	id, err := scanID(raw)
	if err != nil {
		return result, err
	}
	result.Principal.ID = id
	result.Principal.Enabled = enabled == 1
	result.Principal.AllNetworks = allNetworks == 1
	result.CreatedAt, result.UpdatedAt, result.DisabledAt = fromUnix(created), fromUnix(updated), nullableTime(disabled)
	rows, err := queryer.QueryContext(ctx, `SELECT network_id FROM automation_service_principal_networks
		WHERE principal_id=? ORDER BY network_id`, idBytes(principalID))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var networkRaw []byte
		if err := rows.Scan(&networkRaw); err != nil {
			rows.Close()
			return result, err
		}
		network, err := scanID(networkRaw)
		if err != nil {
			rows.Close()
			return result, err
		}
		result.Principal.NetworkIDs = append(result.Principal.NetworkIDs, identity.NetworkID(network))
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	rows, err = queryer.QueryContext(ctx, `SELECT operation FROM automation_service_principal_permissions
		WHERE principal_id=? ORDER BY operation`, idBytes(principalID))
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var operation adminauth.Operation
		if err := rows.Scan(&operation); err != nil {
			return result, err
		}
		result.Principal.Permissions = append(result.Principal.Permissions, operation)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if !result.Principal.Valid() {
		return result, errors.New("corrupt service principal")
	}
	return result, nil
}

func servicePrincipalAuditDetails(principal adminauth.ServicePrincipal) (string, error) {
	return marshalAuditDetails(map[string]any{
		"name": principal.Name, "all_networks": principal.AllNetworks,
		"network_ids": principal.NetworkIDs, "permissions": principal.Permissions,
	})
}

func marshalAuditDetails(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > MaxAuditDetailLength {
		return "", fmt.Errorf("%w: audit details", ErrInvalid)
	}
	return string(payload), nil
}

func (s *Store) CreateServicePrincipal(ctx context.Context, decision adminauth.Decision,
	spec ServicePrincipalSpec) (ServicePrincipalSummary, error) {
	var result ServicePrincipalSummary
	spec, err := normalizeServicePrincipalSpec(spec)
	if err != nil {
		return result, err
	}
	principalID, err := newID()
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, servicePrincipalCreatePolicy)
	if err != nil {
		return result, err
	}
	if err := requireAdministratorManagementBootstrapTx(ctx, tx); err != nil {
		return result, err
	}
	if err := validateAdministratorNetworksTx(ctx, tx, spec.NetworkIDs); err != nil {
		return result, err
	}
	allNetworks := 0
	if spec.AllNetworks {
		allNetworks = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
		(id,name,enabled,all_networks,created_at,updated_at) VALUES(?,?,1,?,?,?)`,
		idBytes(principalID), spec.Name, allNetworks, unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return result, ErrConflict
		}
		return result, err
	}
	for _, networkID := range spec.NetworkIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_networks
			(principal_id,network_id,created_at) VALUES(?,?,?)`, idBytes(principalID), idBytes(networkID), unix(now)); err != nil {
			return result, err
		}
	}
	for _, operation := range spec.Permissions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_permissions
			(principal_id,operation,created_at) VALUES(?,?,?)`, idBytes(principalID), string(operation), unix(now)); err != nil {
			return result, err
		}
	}
	principal := adminauth.ServicePrincipal{ID: principalID, Name: spec.Name, Enabled: true,
		AllNetworks: spec.AllNetworks, NetworkIDs: slices.Clone(spec.NetworkIDs), Permissions: slices.Clone(spec.Permissions)}
	details, err := servicePrincipalAuditDetails(principal)
	if err != nil {
		return result, err
	}
	target := identity.ID(principalID)
	if err := auditActorTx(ctx, tx, nil, actor, "service_principal.create", "service_principal", &target, details, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ServicePrincipalSummary{Principal: principal, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) ServicePrincipals(ctx context.Context, decision adminauth.Decision,
	limit int) ([]ServicePrincipalSummary, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, servicePrincipalListPolicy); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM automation_service_principals
		ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	var ids []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var result []ServicePrincipalSummary
	for _, id := range ids {
		principal, err := servicePrincipalRecord(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, principal)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func validateServiceTokenLabel(label string) error {
	if label == "" || label != strings.TrimSpace(label) || len(label) > 64 || strings.IndexByte(label, 0) >= 0 {
		return fmt.Errorf("%w: service access token label must be 1..64 trimmed bytes", ErrInvalid)
	}
	return nil
}

func (s *Store) IssueServiceAccessToken(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, label string, expiresAt time.Time) (ServiceAccessTokenSummary, string, error) {
	var result ServiceAccessTokenSummary
	if principalID.IsZero() || validateServiceTokenLabel(label) != nil {
		return result, "", fmt.Errorf("%w: service access token", ErrInvalid)
	}
	tokenID, err := newID()
	if err != nil {
		return result, "", err
	}
	bearer, digest, err := adminauth.NewServiceAccessToken(tokenID, nil)
	if err != nil {
		return result, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, "", err
	}
	defer tx.Rollback()
	now := s.now()
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxServiceAccessTokenLifetime)) {
		return result, "", fmt.Errorf("%w: service access token lifetime", ErrInvalid)
	}
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, serviceTokenIssuePolicy,
		principalID, adminauth.OperationServicePrincipalManage)
	if err != nil {
		return result, "", err
	}
	principal, err := servicePrincipalRecord(ctx, tx, principalID)
	if err != nil || !principal.Principal.Enabled {
		if errors.Is(err, ErrNotFound) || err == nil {
			return result, "", ErrNotFound
		}
		return result, "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_access_tokens
		(id,principal_id,label,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)`, idBytes(tokenID),
		idBytes(principalID), label, digest[:], unix(now), unix(expiresAt)); err != nil {
		if isConstraint(err) {
			return result, "", ErrConflict
		}
		return result, "", err
	}
	details, err := marshalAuditDetails(map[string]any{"label": label, "expires_at_unix_seconds": expiresAt.Unix()})
	if err != nil {
		return result, "", err
	}
	target := tokenID
	if err := auditActorTx(ctx, tx, nil, actor, "service_access_token.issue", "service_access_token", &target, details, now); err != nil {
		return result, "", err
	}
	if err := tx.Commit(); err != nil {
		return result, "", err
	}
	return ServiceAccessTokenSummary{ID: tokenID, PrincipalID: principalID, Label: label,
		CreatedAt: now, ExpiresAt: expiresAt}, bearer, nil
}

func scanServiceAccessToken(row *sql.Row) (ServiceAccessTokenSummary, []byte, error) {
	var result ServiceAccessTokenSummary
	var idRaw, principalRaw, digest []byte
	var created, expires int64
	var revoked sql.NullInt64
	err := row.Scan(&idRaw, &principalRaw, &result.Label, &digest, &created, &expires, &revoked, &result.RevocationReason)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil, ErrNotFound
	}
	if err != nil {
		return result, nil, err
	}
	id, err := scanID(idRaw)
	if err != nil {
		return result, nil, err
	}
	principalID, err := scanID(principalRaw)
	if err != nil || len(digest) != 32 {
		return result, nil, errors.New("corrupt service access token")
	}
	result.ID, result.PrincipalID = id, principalID
	result.CreatedAt, result.ExpiresAt, result.RevokedAt = fromUnix(created), fromUnix(expires), nullableTime(revoked)
	return result, digest, nil
}

const serviceTokenSelect = `SELECT id,principal_id,label,token_hash,created_at,expires_at,revoked_at,revocation_reason
	FROM automation_service_access_tokens WHERE id=?`

func (s *Store) AuthenticateServiceAccessToken(ctx context.Context, bearer string) (ServiceAccessTokenSummary,
	adminauth.ServicePrincipal, error) {
	var principal adminauth.ServicePrincipal
	tokenID, gotDigest, err := adminauth.ParseServiceAccessToken(bearer)
	if err != nil {
		return ServiceAccessTokenSummary{}, principal, ErrCredentialInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServiceAccessTokenSummary{}, principal, err
	}
	defer tx.Rollback()
	token, wantDigest, err := scanServiceAccessToken(tx.QueryRowContext(ctx, serviceTokenSelect, idBytes(tokenID)))
	now := s.now()
	if err != nil || subtle.ConstantTimeCompare(gotDigest[:], wantDigest) != 1 || token.RevokedAt != nil ||
		!now.Before(token.ExpiresAt) || now.Before(token.CreatedAt) {
		return ServiceAccessTokenSummary{}, principal, ErrCredentialInvalid
	}
	servicePrincipal, err := servicePrincipalRecord(ctx, tx, token.PrincipalID)
	if err != nil || !servicePrincipal.Principal.Enabled || !servicePrincipal.Principal.Valid() {
		return ServiceAccessTokenSummary{}, principal, ErrCredentialInvalid
	}
	if err := tx.Commit(); err != nil {
		return ServiceAccessTokenSummary{}, principal, err
	}
	return token, servicePrincipal.Principal, nil
}

func (s *Store) ServiceAccessTokens(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID, limit int) ([]ServiceAccessTokenSummary, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, serviceTokenListPolicy,
		principalID, adminauth.OperationServicePrincipalManage); err != nil {
		return nil, err
	}
	if _, err := servicePrincipalRecord(ctx, tx, principalID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM automation_service_access_tokens
		WHERE principal_id=? ORDER BY
		CASE WHEN revoked_at IS NULL AND expires_at>? THEN 0
			WHEN revoked_at IS NULL THEN 1 ELSE 2 END,
		created_at DESC,id DESC LIMIT ?`, idBytes(principalID), unix(s.now()), limit)
	if err != nil {
		return nil, err
	}
	var ids []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	var result []ServiceAccessTokenSummary
	for _, id := range ids {
		token, _, err := scanServiceAccessToken(tx.QueryRowContext(ctx, serviceTokenSelect, idBytes(id)))
		if err != nil {
			return nil, err
		}
		result = append(result, token)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) RevokeServiceAccessToken(ctx context.Context, decision adminauth.Decision,
	tokenID identity.ID, reason string) error {
	if tokenID.IsZero() || !validServiceAccessTokenRevocationReason(reason) {
		return fmt.Errorf("%w: service access token revocation reason", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, serviceTokenRevokePolicy,
		tokenID, adminauth.OperationServicePrincipalManage)
	if err != nil {
		return err
	}
	token, _, err := scanServiceAccessToken(tx.QueryRowContext(ctx, serviceTokenSelect, idBytes(tokenID)))
	if err != nil {
		return err
	}
	if token.RevokedAt != nil {
		return ErrConflict
	}
	now = latestTime(now, token.CreatedAt)
	if _, err := tx.ExecContext(ctx, `UPDATE automation_service_access_tokens
		SET revoked_at=?,revocation_reason=? WHERE id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(tokenID)); err != nil {
		return err
	}
	details, err := marshalAuditDetails(map[string]any{"reason": reason})
	if err != nil {
		return err
	}
	target := tokenID
	if err := auditActorTx(ctx, tx, nil, actor, "service_access_token.revoke", "service_access_token", &target, details, now); err != nil {
		return err
	}
	return tx.Commit()
}

func validServiceAccessTokenRevocationReason(reason string) bool {
	return reason != "" && reason == strings.TrimSpace(reason) &&
		len(reason) <= adminauth.MaxSessionReason && strings.IndexByte(reason, 0) < 0 &&
		utf8.ValidString(reason)
}

func (s *Store) DisableServicePrincipal(ctx context.Context, decision adminauth.Decision,
	principalID identity.ID) error {
	if principalID.IsZero() {
		return fmt.Errorf("%w: service principal", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, servicePrincipalDisablePolicy,
		principalID, adminauth.OperationServicePrincipalManage)
	if err != nil {
		return err
	}
	principal, err := servicePrincipalRecord(ctx, tx, principalID)
	if err != nil {
		return err
	}
	if !principal.Principal.Enabled {
		return ErrConflict
	}
	now := latestTime(s.now(), principal.UpdatedAt)
	updated, err := tx.ExecContext(ctx, `UPDATE automation_service_principals
		SET enabled=0,updated_at=?,disabled_at=? WHERE id=? AND enabled=1`,
		unix(now), unix(now), idBytes(principalID))
	if err != nil {
		return err
	}
	if rows, _ := updated.RowsAffected(); rows != 1 {
		return ErrConflict
	}
	revoked, err := tx.ExecContext(ctx, `UPDATE automation_service_access_tokens
		SET revoked_at=max(created_at,?),revocation_reason=?
		WHERE principal_id=? AND revoked_at IS NULL`, unix(now),
		servicePrincipalDisabledTokenRevocationReason, idBytes(principalID))
	if err != nil {
		return err
	}
	revokedTokens, err := revoked.RowsAffected()
	if err != nil {
		return err
	}
	details, err := marshalAuditDetails(map[string]any{"revoked_tokens": revokedTokens})
	if err != nil {
		return err
	}
	target := principalID
	if err := auditActorTx(ctx, tx, nil, actor, "service_principal.disable", "service_principal",
		&target, details, now); err != nil {
		return err
	}
	return tx.Commit()
}
