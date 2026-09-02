package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/applicationauth"
	"github.com/Doout/laneway/go/internal/identity"
)

var (
	applicationInstallationListPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/application-installations")
	applicationAuthorizationApprovePolicy = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/application-authorization-requests/{request_id}/approve")
	applicationAuthorizationCancelPolicy  = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/application-authorization-requests/{request_id}/cancel")
	applicationInstallationDeletePolicy   = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/application-installations/{installation_id}")
	applicationNodeInstallerPolicy        = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/networks/{network_id}/node-installers")
)

func (s *Store) AdministratorIssueNodeInstallerToken(ctx context.Context, decision adminauth.Decision,
	networkID identity.NetworkID, name string, expiresAt time.Time, capabilities uint64) (EnrollmentToken, error) {
	return s.administratorIssueEnrollmentTokenWithPolicy(ctx, decision, applicationNodeInstallerPolicy,
		networkID, "node installer", expiresAt, EnrollmentTokenOptions{Class: EnrollmentClassDurable,
			RequestedName: name, EnabledCapabilities: capabilities})
}

type ApplicationAuthorizationRequest struct {
	ID            identity.ID
	Application   RegisteredApplication
	RedirectURI   string
	State         string
	Scopes        []string
	PKCEChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

type ApplicationInstallation struct {
	ID                   identity.ID
	ApplicationID        identity.ID
	NetworkID            identity.NetworkID
	ServicePrincipalID   identity.ID
	InstallerPrincipalID identity.ID
	Scopes               []string
	Enabled              bool
	CreatedAt            time.Time
	UpdatedAt            time.Time
	RevokedAt            *time.Time
}

type ApplicationAuthorizationApproval struct {
	Installation ApplicationInstallation
	Code         string
	State        string
	RedirectURI  string
}

func (s *Store) CreateApplicationAuthorizationRequest(ctx context.Context, clientID, redirectURI string,
	scopes []string, state, challenge string) (ApplicationAuthorizationRequest, error) {
	var result ApplicationAuthorizationRequest
	scopes, err := applicationauth.ValidateScopes(scopes)
	if err != nil || state == "" || len(state) > 1024 || !applicationauth.ValidatePKCEChallenge(challenge) {
		return result, fmt.Errorf("%w: invalid authorization request", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	application, err := registeredApplicationByClientID(ctx, tx, clientID)
	if err != nil || !application.Enabled || !slices.Contains(application.Manifest.RedirectURIs, redirectURI) ||
		!applicationauth.ScopesSubset(scopes, application.Manifest.Scopes) {
		return result, ErrCredentialInvalid
	}
	payload, _ := json.Marshal(scopes)
	id, err := newID()
	if err != nil {
		return result, err
	}
	now := s.now()
	expires := now.Add(ApplicationRequestLifetime)
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_authorization_requests
		(id,application_id,redirect_uri,state,scopes_json,pkce_challenge,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?)`, idBytes(id), idBytes(application.ID), redirectURI, state,
		string(payload), challenge, unix(now), unix(expires)); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ApplicationAuthorizationRequest{ID: id, Application: application, RedirectURI: redirectURI,
		State: state, Scopes: scopes, PKCEChallenge: challenge, CreatedAt: now, ExpiresAt: expires}, nil
}

func applicationAuthorizationRequestRecord(ctx context.Context, queryer rowQueryer, id identity.ID) (ApplicationAuthorizationRequest, error) {
	var result ApplicationAuthorizationRequest
	var applicationRaw []byte
	var scopesJSON string
	var created, expires int64
	var consumed sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT application_id,redirect_uri,state,scopes_json,pkce_challenge,created_at,expires_at,consumed_at
		FROM application_authorization_requests WHERE id=?`, idBytes(id)).Scan(&applicationRaw, &result.RedirectURI,
		&result.State, &scopesJSON, &result.PKCEChallenge, &created, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	applicationID, err := scanID(applicationRaw)
	if err != nil || json.Unmarshal([]byte(scopesJSON), &result.Scopes) != nil {
		return result, errors.New("corrupt authorization request")
	}
	application, err := registeredApplicationRecord(ctx, queryer, applicationID)
	if err != nil {
		return result, err
	}
	result.ID, result.Application = id, application
	result.CreatedAt, result.ExpiresAt, result.ConsumedAt = fromUnix(created), fromUnix(expires), nullableTime(consumed)
	return result, nil
}

func (s *Store) ApplicationAuthorizationRequest(ctx context.Context, id identity.ID) (ApplicationAuthorizationRequest, error) {
	request, err := applicationAuthorizationRequestRecord(ctx, s.db, id)
	if err != nil || request.ConsumedAt != nil || !request.Application.Enabled || !s.now().Before(request.ExpiresAt) {
		return ApplicationAuthorizationRequest{}, ErrNotFound
	}
	return request, nil
}

func applicationInstallationRecord(ctx context.Context, queryer rowQueryer, id identity.ID) (ApplicationInstallation, error) {
	var result ApplicationInstallation
	var applicationRaw, networkRaw, serviceRaw, installerRaw []byte
	var enabled int
	var created, updated int64
	var revoked sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT application_id,network_id,service_principal_id,installer_principal_id,
		enabled,created_at,updated_at,revoked_at FROM application_installations WHERE id=?`, idBytes(id)).Scan(
		&applicationRaw, &networkRaw, &serviceRaw, &installerRaw, &enabled, &created, &updated, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	applicationID, err := scanID(applicationRaw)
	if err != nil {
		return result, err
	}
	networkID, err := scanID(networkRaw)
	if err != nil {
		return result, err
	}
	serviceID, err := scanID(serviceRaw)
	if err != nil {
		return result, err
	}
	installerID, err := scanID(installerRaw)
	if err != nil {
		return result, err
	}
	result = ApplicationInstallation{ID: id, ApplicationID: applicationID, NetworkID: identity.NetworkID(networkID),
		ServicePrincipalID: serviceID, InstallerPrincipalID: installerID, Enabled: enabled == 1,
		CreatedAt: fromUnix(created), UpdatedAt: fromUnix(updated), RevokedAt: nullableTime(revoked)}
	rows, err := queryer.QueryContext(ctx, `SELECT scope FROM application_installation_scopes WHERE installation_id=? ORDER BY scope`, idBytes(id))
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return result, err
		}
		result.Scopes = append(result.Scopes, scope)
	}
	return result, rows.Err()
}

func administratorMayGrantApplicationScopesTx(ctx context.Context, tx *sql.Tx, actor adminauth.Actor,
	networkID identity.NetworkID, scopes []string) error {
	if actor.Kind != adminauth.ActorAdministrator || actor.ID == nil {
		return ErrPermissionDenied
	}
	record, err := administratorRecord(ctx, tx, `p.id=?`, idBytes(*actor.ID))
	if err != nil || !record.Principal.Enabled {
		return ErrPermissionDenied
	}
	for _, scope := range scopes {
		operation, ok := applicationauth.OperationForScope(scope)
		if !ok || !adminauth.Authorize(record.Principal, operation, &networkID) {
			return ErrPermissionDenied
		}
	}
	return nil
}

func createInstallationServicePrincipalTx(ctx context.Context, tx *sql.Tx, applicationID identity.ID,
	networkID identity.NetworkID, scopes []string, now time.Time) (identity.ID, error) {
	principalID, err := newID()
	if err != nil {
		return identity.ID{}, err
	}
	name := fmt.Sprintf("app-%s-%s-%s", applicationID.String()[:8], networkID.String()[:8], principalID.String()[:8])
	if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principals
		(id,name,enabled,all_networks,created_at,updated_at) VALUES(?,?,1,0,?,?)`,
		idBytes(principalID), name, unix(now), unix(now)); err != nil {
		return identity.ID{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_networks(principal_id,network_id,created_at) VALUES(?,?,?)`, idBytes(principalID), idBytes(networkID), unix(now)); err != nil {
		return identity.ID{}, err
	}
	for _, scope := range scopes {
		operation, ok := applicationauth.OperationForScope(scope)
		if !ok {
			return identity.ID{}, ErrInvalid
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_principal_permissions(principal_id,operation,created_at) VALUES(?,?,?)`, idBytes(principalID), string(operation), unix(now)); err != nil {
			return identity.ID{}, err
		}
	}
	return principalID, nil
}

func disableInstallationPrincipalTx(ctx context.Context, tx *sql.Tx, principalID identity.ID, now time.Time, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE automation_service_principals SET enabled=0,updated_at=max(updated_at,?),disabled_at=max(created_at,?) WHERE id=? AND enabled=1`, unix(now), unix(now), idBytes(principalID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?),revocation_reason=? WHERE principal_id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(principalID)); err != nil {
		return err
	}
	return nil
}

func (s *Store) AdministratorApproveApplicationAuthorization(ctx context.Context, decision adminauth.Decision,
	requestID identity.ID, networkID identity.NetworkID, grantedScopes []string) (ApplicationAuthorizationApproval, error) {
	var result ApplicationAuthorizationApproval
	grantedScopes, err := applicationauth.ValidateScopes(grantedScopes)
	if err != nil {
		return result, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, applicationAuthorizationApprovePolicy, networkID)
	if err != nil {
		return result, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return result, err
	}
	request, err := applicationAuthorizationRequestRecord(ctx, tx, requestID)
	now := s.now()
	if err != nil || request.ConsumedAt != nil || now.Before(request.CreatedAt) || !now.Before(request.ExpiresAt) ||
		!request.Application.Enabled || !applicationauth.ScopesSubset(grantedScopes, request.Scopes) {
		return result, ErrNotFound
	}
	if err := administratorMayGrantApplicationScopesTx(ctx, tx, actor, networkID, grantedScopes); err != nil {
		return result, err
	}
	var installation ApplicationInstallation
	var existingRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT id FROM application_installations WHERE application_id=? AND network_id=? AND enabled=1`, idBytes(request.Application.ID), idBytes(networkID)).Scan(&existingRaw)
	if err == nil {
		existingID, scanErr := scanID(existingRaw)
		if scanErr != nil {
			return result, scanErr
		}
		installation, err = applicationInstallationRecord(ctx, tx, existingID)
		if err != nil {
			return result, err
		}
		if !slices.Equal(installation.Scopes, grantedScopes) {
			replacement, createErr := createInstallationServicePrincipalTx(ctx, tx, request.Application.ID, networkID, grantedScopes, now)
			if createErr != nil {
				return result, createErr
			}
			if err := disableInstallationPrincipalTx(ctx, tx, installation.ServicePrincipalID, now, "application installation scopes replaced"); err != nil {
				return result, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE application_refresh_token_families
				SET revoked_at=max(created_at,?),revocation_reason='application installation scopes replaced'
				WHERE installation_id=? AND revoked_at IS NULL`, unix(now), idBytes(installation.ID)); err != nil {
				return result, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM application_installation_scopes WHERE installation_id=?`, idBytes(installation.ID)); err != nil {
				return result, err
			}
			for _, scope := range grantedScopes {
				if _, err := tx.ExecContext(ctx, `INSERT INTO application_installation_scopes(installation_id,scope) VALUES(?,?)`, idBytes(installation.ID), scope); err != nil {
					return result, err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE application_installations SET service_principal_id=?,installer_principal_id=?,updated_at=? WHERE id=? AND enabled=1`, idBytes(replacement), idBytes(*actor.ID), unix(now), idBytes(installation.ID)); err != nil {
				return result, err
			}
			installation.ServicePrincipalID, installation.InstallerPrincipalID, installation.Scopes, installation.UpdatedAt = replacement, *actor.ID, grantedScopes, now
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		principalID, createErr := createInstallationServicePrincipalTx(ctx, tx, request.Application.ID, networkID, grantedScopes, now)
		if createErr != nil {
			return result, createErr
		}
		installationID, idErr := newID()
		if idErr != nil {
			return result, idErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO application_installations(id,application_id,network_id,service_principal_id,installer_principal_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`, idBytes(installationID), idBytes(request.Application.ID), idBytes(networkID), idBytes(principalID), idBytes(*actor.ID), unix(now), unix(now)); err != nil {
			return result, err
		}
		for _, scope := range grantedScopes {
			if _, err := tx.ExecContext(ctx, `INSERT INTO application_installation_scopes(installation_id,scope) VALUES(?,?)`, idBytes(installationID), scope); err != nil {
				return result, err
			}
		}
		installation = ApplicationInstallation{ID: installationID, ApplicationID: request.Application.ID, NetworkID: networkID,
			ServicePrincipalID: principalID, InstallerPrincipalID: *actor.ID, Scopes: grantedScopes, Enabled: true, CreatedAt: now, UpdatedAt: now}
	} else {
		return result, err
	}
	codeID, err := newID()
	if err != nil {
		return result, err
	}
	code, digest, err := applicationauth.NewSecret(applicationauth.PurposeAuthorizationCode, codeID, nil)
	if err != nil {
		return result, err
	}
	scopeJSON, _ := json.Marshal(grantedScopes)
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_authorization_codes
		(id,installation_id,application_id,network_id,redirect_uri,scopes_json,code_hash,pkce_challenge,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, idBytes(codeID), idBytes(installation.ID), idBytes(request.Application.ID), idBytes(networkID),
		request.RedirectURI, string(scopeJSON), digest[:], request.PKCEChallenge, unix(now), unix(now.Add(ApplicationCodeLifetime))); err != nil {
		return result, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE application_authorization_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?`, unix(now), idBytes(requestID), unix(now))
	if err != nil {
		return result, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return result, ErrConflict
	}
	details, _ := marshalAuditDetails(map[string]any{
		"application_id":       request.Application.ID.String(),
		"service_principal_id": installation.ServicePrincipalID.String(),
		"scopes":               grantedScopes,
	})
	target := installation.ID
	if err := auditActorTx(ctx, tx, &networkID, actor, "application_installation.authorize", "application_installation", &target, details, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ApplicationAuthorizationApproval{Installation: installation, Code: code, State: request.State, RedirectURI: request.RedirectURI}, nil
}

func (s *Store) AdministratorCancelApplicationAuthorization(ctx context.Context, decision adminauth.Decision,
	requestID identity.ID, networkID identity.NetworkID) (ApplicationAuthorizationRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApplicationAuthorizationRequest{}, err
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, applicationAuthorizationCancelPolicy, networkID)
	if err != nil {
		return ApplicationAuthorizationRequest{}, err
	}
	if actor.Kind != adminauth.ActorAdministrator {
		return ApplicationAuthorizationRequest{}, ErrPermissionDenied
	}
	request, err := applicationAuthorizationRequestRecord(ctx, tx, requestID)
	if err != nil || request.ConsumedAt != nil {
		return ApplicationAuthorizationRequest{}, ErrNotFound
	}
	now := s.now()
	updated, err := tx.ExecContext(ctx, `UPDATE application_authorization_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, unix(now), idBytes(requestID))
	if err != nil {
		return ApplicationAuthorizationRequest{}, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return ApplicationAuthorizationRequest{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return ApplicationAuthorizationRequest{}, err
	}
	return request, nil
}

func (s *Store) AdministratorApplicationInstallations(ctx context.Context, decision adminauth.Decision,
	networkID identity.NetworkID, limit int) ([]ApplicationInstallation, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, applicationInstallationListPolicy, networkID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM application_installations WHERE network_id=? ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
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
	result := make([]ApplicationInstallation, 0, len(ids))
	for _, id := range ids {
		value, err := applicationInstallationRecord(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) AdministratorRevokeApplicationInstallation(ctx context.Context, decision adminauth.Decision,
	installationID identity.ID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, applicationInstallationDeletePolicy,
		installationID, `SELECT network_id FROM application_installations WHERE id=?`, idBytes(installationID))
	if err != nil {
		return err
	}
	installation, err := applicationInstallationRecord(ctx, tx, installationID)
	if err != nil || !installation.Enabled {
		return ErrNotFound
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE application_installations SET enabled=0,updated_at=?,revoked_at=? WHERE id=? AND enabled=1`, unix(now), unix(now), idBytes(installationID)); err != nil {
		return err
	}
	if err := disableInstallationPrincipalTx(ctx, tx, installation.ServicePrincipalID, now, "application installation revoked"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE application_refresh_token_families SET revoked_at=max(created_at,?),revocation_reason='application installation revoked' WHERE installation_id=? AND revoked_at IS NULL`, unix(now), idBytes(installationID)); err != nil {
		return err
	}
	target := installationID
	if err := auditActorTx(ctx, tx, &networkID, actor, "application_installation.revoke", "application_installation", &target, "{}", now); err != nil {
		return err
	}
	return tx.Commit()
}
