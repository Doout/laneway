package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/applicationauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	ApplicationAccessTokenLifetime  = time.Hour
	ApplicationRefreshTokenLifetime = 30 * 24 * time.Hour
	ApplicationRefreshGrace         = 5 * time.Second
	ApplicationCleanupLimit         = 100
)

type ApplicationTokenGrant struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	Installation ApplicationInstallation
	Application  RegisteredApplication
	Network      Network
}

func issueApplicationAccessTokenTx(ctx context.Context, tx *sql.Tx, principalID identity.ID,
	now time.Time) (ServiceAccessTokenSummary, string, error) {
	id, err := newID()
	if err != nil {
		return ServiceAccessTokenSummary{}, "", err
	}
	bearer, digest, err := adminauth.NewServiceAccessToken(id, nil)
	if err != nil {
		return ServiceAccessTokenSummary{}, "", err
	}
	expires := now.Add(ApplicationAccessTokenLifetime)
	if _, err := tx.ExecContext(ctx, `INSERT INTO automation_service_access_tokens
		(id,principal_id,label,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)`, idBytes(id),
		idBytes(principalID), "application installation", digest[:], unix(now), unix(expires)); err != nil {
		return ServiceAccessTokenSummary{}, "", err
	}
	return ServiceAccessTokenSummary{ID: id, PrincipalID: principalID, Label: "application installation",
		CreatedAt: now, ExpiresAt: expires}, bearer, nil
}

func newApplicationRefreshToken(id identity.ID) (string, [sha256.Size]byte, error) {
	return applicationauth.NewSecret(applicationauth.PurposeRefreshToken, id, nil)
}

func applicationNetworkRecord(ctx context.Context, queryer rowQueryer, networkID identity.NetworkID) (Network, error) {
	return networkByRow(queryer.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
		FROM networks WHERE id=?`, idBytes(networkID)), networkID)
}

func (s *Store) ExchangeApplicationAuthorizationCode(ctx context.Context, clientID, clientSecret, code,
	verifier, redirectURI string) (ApplicationTokenGrant, error) {
	var result ApplicationTokenGrant
	codeID, candidate, err := applicationauth.ParseSecret(applicationauth.PurposeAuthorizationCode, code)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	application, err := authenticateApplicationClientTx(ctx, tx, clientID, clientSecret)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	var installationRaw, applicationRaw, networkRaw, storedHash []byte
	var storedRedirect, scopesJSON, challenge string
	var created, expires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT installation_id,application_id,network_id,redirect_uri,scopes_json,
		code_hash,pkce_challenge,created_at,expires_at,consumed_at FROM application_authorization_codes WHERE id=?`,
		idBytes(codeID)).Scan(&installationRaw, &applicationRaw, &networkRaw, &storedRedirect, &scopesJSON,
		&storedHash, &challenge, &created, &expires, &consumed)
	now := s.now()
	if err != nil || len(storedHash) != sha256.Size || !slices.Equal(storedHash, candidate[:]) || consumed.Valid ||
		storedRedirect != redirectURI || now.Before(fromUnix(created)) || !now.Before(fromUnix(expires)) ||
		!applicationauth.VerifyPKCE(challenge, verifier) {
		return result, ErrCredentialInvalid
	}
	installationID, err := scanID(installationRaw)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	codeApplicationID, err := scanID(applicationRaw)
	if err != nil || codeApplicationID != application.ID {
		return result, ErrCredentialInvalid
	}
	networkValue, err := scanID(networkRaw)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	networkID := identity.NetworkID(networkValue)
	installation, err := applicationInstallationRecord(ctx, tx, installationID)
	if err != nil || !installation.Enabled || installation.ApplicationID != application.ID || installation.NetworkID != networkID {
		return result, ErrCredentialInvalid
	}
	var scopes []string
	if json.Unmarshal([]byte(scopesJSON), &scopes) != nil || !slices.Equal(scopes, installation.Scopes) {
		return result, ErrCredentialInvalid
	}
	principal, err := servicePrincipalRecord(ctx, tx, installation.ServicePrincipalID)
	if err != nil || !principal.Principal.Enabled || principal.Principal.AllNetworks ||
		!slices.Equal(principal.Principal.NetworkIDs, []identity.NetworkID{networkID}) {
		return result, ErrCredentialInvalid
	}
	updated, err := tx.ExecContext(ctx, `UPDATE application_authorization_codes SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?`, unix(now), idBytes(codeID), unix(now))
	if err != nil {
		return result, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return result, ErrCredentialInvalid
	}
	if _, err := cleanupExpiredServiceAccessTokensTx(ctx, tx, now, ApplicationCleanupLimit); err != nil {
		return result, err
	}
	access, accessBearer, err := issueApplicationAccessTokenTx(ctx, tx, installation.ServicePrincipalID, now)
	if err != nil {
		return result, err
	}
	familyID, err := newID()
	if err != nil {
		return result, err
	}
	refreshID, err := newID()
	if err != nil {
		return result, err
	}
	refresh, refreshDigest, err := newApplicationRefreshToken(refreshID)
	if err != nil {
		return result, err
	}
	refreshExpires := now.Add(ApplicationRefreshTokenLifetime)
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_refresh_token_families(id,installation_id,application_id,created_at,expires_at) VALUES(?,?,?,?,?)`, idBytes(familyID), idBytes(installation.ID), idBytes(application.ID), unix(now), unix(refreshExpires)); err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_refresh_tokens(id,family_id,token_hash,access_token_id,created_at,expires_at) VALUES(?,?,?,?,?,?)`, idBytes(refreshID), idBytes(familyID), refreshDigest[:], idBytes(access.ID), unix(now), unix(refreshExpires)); err != nil {
		return result, err
	}
	network, err := applicationNetworkRecord(ctx, tx, networkID)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ApplicationTokenGrant{AccessToken: accessBearer, RefreshToken: refresh,
		ExpiresIn: int64(ApplicationAccessTokenLifetime / time.Second), Installation: installation,
		Application: application, Network: network}, nil
}

func revokeRefreshFamilyTx(ctx context.Context, tx *sql.Tx, familyID identity.ID, now time.Time, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE application_refresh_token_families SET revoked_at=max(created_at,?),revocation_reason=? WHERE id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(familyID)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?),revocation_reason=?
		WHERE id IN (SELECT access_token_id FROM application_refresh_tokens WHERE family_id=? AND access_token_id IS NOT NULL) AND revoked_at IS NULL`, unix(now), reason, idBytes(familyID))
	return err
}

func (s *Store) RefreshApplicationToken(ctx context.Context, clientID, clientSecret, refreshToken string) (ApplicationTokenGrant, error) {
	var result ApplicationTokenGrant
	refreshID, candidate, err := applicationauth.ParseSecret(applicationauth.PurposeRefreshToken, refreshToken)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	application, err := authenticateApplicationClientTx(ctx, tx, clientID, clientSecret)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	var familyRaw, storedHash, accessRaw []byte
	var tokenCreated, tokenExpires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT family_id,token_hash,access_token_id,created_at,expires_at,consumed_at
		FROM application_refresh_tokens WHERE id=?`, idBytes(refreshID)).Scan(&familyRaw, &storedHash, &accessRaw, &tokenCreated, &tokenExpires, &consumed)
	if err != nil || len(storedHash) != sha256.Size || !slices.Equal(storedHash, candidate[:]) {
		return result, ErrCredentialInvalid
	}
	familyID, err := scanID(familyRaw)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	var installationRaw, applicationRaw []byte
	var familyCreated, familyExpires int64
	var familyRevoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT installation_id,application_id,created_at,expires_at,revoked_at FROM application_refresh_token_families WHERE id=?`, idBytes(familyID)).Scan(&installationRaw, &applicationRaw, &familyCreated, &familyExpires, &familyRevoked)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	now := s.now()
	familyApplicationID, err := scanID(applicationRaw)
	if err != nil || familyApplicationID != application.ID {
		return result, ErrCredentialInvalid
	}
	if consumed.Valid {
		// A second worker can observe the just-completed rotation before the
		// caller has received the replacement token. Reject it, but keep the one
		// valid family produced by that race. Reuse after this narrow grace period
		// is treated as credential theft and revokes the family.
		if elapsed := now.Sub(fromUnix(consumed.Int64)); elapsed >= 0 && elapsed < ApplicationRefreshGrace {
			return result, ErrCredentialInvalid
		}
		if err := revokeRefreshFamilyTx(ctx, tx, familyID, now, "refresh token reuse"); err != nil {
			return result, err
		}
		installationID, err := scanID(installationRaw)
		if err != nil {
			return result, err
		}
		installation, err := applicationInstallationRecord(ctx, tx, installationID)
		if err != nil {
			return result, err
		}
		if err := auditActorTx(ctx, tx, &installation.NetworkID,
			adminauth.IDActor(adminauth.ActorServicePrincipal, installation.ServicePrincipalID),
			"application_refresh.reuse", "application_refresh_family", &familyID, "{}", now); err != nil {
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return result, ErrCredentialInvalid
	}
	if familyRevoked.Valid || now.Before(fromUnix(tokenCreated)) || !now.Before(fromUnix(tokenExpires)) ||
		now.Before(fromUnix(familyCreated)) || !now.Before(fromUnix(familyExpires)) {
		return result, ErrCredentialInvalid
	}
	installationID, err := scanID(installationRaw)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	installation, err := applicationInstallationRecord(ctx, tx, installationID)
	if err != nil || !installation.Enabled || installation.ApplicationID != application.ID {
		return result, ErrCredentialInvalid
	}
	principal, err := servicePrincipalRecord(ctx, tx, installation.ServicePrincipalID)
	if err != nil || !principal.Principal.Enabled {
		return result, ErrCredentialInvalid
	}
	if _, err := cleanupExpiredServiceAccessTokensTx(ctx, tx, now, ApplicationCleanupLimit); err != nil {
		return result, err
	}
	access, accessBearer, err := issueApplicationAccessTokenTx(ctx, tx, installation.ServicePrincipalID, now)
	if err != nil {
		return result, err
	}
	nextID, err := newID()
	if err != nil {
		return result, err
	}
	nextRefresh, nextDigest, err := newApplicationRefreshToken(nextID)
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_refresh_tokens(id,family_id,token_hash,access_token_id,created_at,expires_at) VALUES(?,?,?,?,?,?)`, idBytes(nextID), idBytes(familyID), nextDigest[:], idBytes(access.ID), unix(now), familyExpires); err != nil {
		return result, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE application_refresh_tokens SET consumed_at=?,replaced_by=? WHERE id=? AND consumed_at IS NULL`, unix(now), idBytes(nextID), idBytes(refreshID))
	if err != nil {
		return result, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return result, ErrCredentialInvalid
	}
	if len(accessRaw) == identity.IDSize {
		if oldAccess, scanErr := scanID(accessRaw); scanErr == nil {
			_, _ = tx.ExecContext(ctx, `UPDATE automation_service_access_tokens SET revoked_at=max(created_at,?),revocation_reason='refresh token rotated' WHERE id=? AND revoked_at IS NULL`, unix(now), idBytes(oldAccess))
		}
	}
	network, err := applicationNetworkRecord(ctx, tx, installation.NetworkID)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ApplicationTokenGrant{AccessToken: accessBearer, RefreshToken: nextRefresh, ExpiresIn: int64(ApplicationAccessTokenLifetime / time.Second), Installation: installation, Application: application, Network: network}, nil
}

func (s *Store) RevokeApplicationRefreshToken(ctx context.Context, clientID, clientSecret, refreshToken string) error {
	refreshID, candidate, err := applicationauth.ParseSecret(applicationauth.PurposeRefreshToken, refreshToken)
	if err != nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	application, err := authenticateApplicationClientTx(ctx, tx, clientID, clientSecret)
	if err != nil {
		return ErrCredentialInvalid
	}
	var familyRaw, stored []byte
	err = tx.QueryRowContext(ctx, `SELECT family_id,token_hash FROM application_refresh_tokens WHERE id=?`, idBytes(refreshID)).Scan(&familyRaw, &stored)
	if err != nil || len(stored) != sha256.Size || !slices.Equal(stored, candidate[:]) {
		return tx.Commit()
	}
	familyID, err := scanID(familyRaw)
	if err != nil {
		return tx.Commit()
	}
	var installationRaw, familyApplication []byte
	if err := tx.QueryRowContext(ctx, `SELECT installation_id,application_id FROM application_refresh_token_families WHERE id=?`, idBytes(familyID)).Scan(&installationRaw, &familyApplication); err != nil {
		return tx.Commit()
	}
	appID, err := scanID(familyApplication)
	if err != nil || appID != application.ID {
		return tx.Commit()
	}
	installationID, err := scanID(installationRaw)
	if err != nil {
		return err
	}
	installation, err := applicationInstallationRecord(ctx, tx, installationID)
	if err != nil || installation.ApplicationID != application.ID {
		return ErrCredentialInvalid
	}
	now := s.now()
	if err := revokeRefreshFamilyTx(ctx, tx, familyID, now, "client revocation"); err != nil {
		return err
	}
	if err := auditActorTx(ctx, tx, &installation.NetworkID,
		adminauth.IDActor(adminauth.ActorServicePrincipal, installation.ServicePrincipalID),
		"application_refresh.revoke", "application_refresh_family", &familyID, "{}", now); err != nil {
		return err
	}
	return tx.Commit()
}

func cleanupExpiredServiceAccessTokensTx(ctx context.Context, tx *sql.Tx, now time.Time, limit int) (int64, error) {
	result, err := tx.ExecContext(ctx, `UPDATE automation_service_access_tokens
		SET revoked_at=max(created_at,?),revocation_reason='expired token cleanup'
		WHERE id IN (SELECT id FROM automation_service_access_tokens WHERE revoked_at IS NULL AND expires_at<=? ORDER BY expires_at,id LIMIT ?)`, unix(now), unix(now), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) CleanupApplicationCredentials(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := s.now()
	var total int64
	count, err := cleanupExpiredServiceAccessTokensTx(ctx, tx, now, limit)
	if err != nil {
		return 0, err
	}
	total += count
	for _, statement := range []string{
		`DELETE FROM application_registration_requests WHERE id IN (SELECT id FROM application_registration_requests WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)`,
		`DELETE FROM application_registration_codes WHERE id IN (SELECT id FROM application_registration_codes WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)`,
		`DELETE FROM application_authorization_requests WHERE id IN (SELECT id FROM application_authorization_requests WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)`,
		`DELETE FROM application_authorization_codes WHERE id IN (SELECT id FROM application_authorization_codes WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?)`,
	} {
		result, execErr := tx.ExecContext(ctx, statement, unix(now), limit)
		if execErr != nil {
			return 0, execErr
		}
		affected, _ := result.RowsAffected()
		total += affected
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM application_refresh_token_families WHERE expires_at<=? ORDER BY expires_at,id LIMIT ?`, unix(now), limit)
	if err != nil {
		return 0, err
	}
	var families []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return 0, err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return 0, err
		}
		families = append(families, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, familyID := range families {
		if err := revokeRefreshFamilyTx(ctx, tx, familyID, now, "refresh family expired"); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM application_refresh_token_families WHERE id=? AND expires_at<=?`, idBytes(familyID), unix(now)); err != nil {
			return 0, err
		}
		total++
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *Store) AdministratorDisableApplication(ctx context.Context, decision adminauth.Decision, applicationID identity.ID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, applicationDisablePolicy, applicationID, adminauth.OperationApplicationManage)
	if err != nil {
		return err
	}
	application, err := registeredApplicationRecord(ctx, tx, applicationID)
	if err != nil || !application.Enabled {
		return ErrNotFound
	}
	now := s.now()
	rows, err := tx.QueryContext(ctx, `SELECT service_principal_id FROM application_installations WHERE application_id=? AND enabled=1`, idBytes(applicationID))
	if err != nil {
		return err
	}
	var principals []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return err
		}
		principals = append(principals, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registered_applications SET enabled=0,updated_at=?,disabled_at=? WHERE id=? AND enabled=1`, unix(now), unix(now), idBytes(applicationID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registered_application_credentials SET revoked_at=max(created_at,?) WHERE application_id=? AND revoked_at IS NULL`, unix(now), idBytes(applicationID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE application_installations SET enabled=0,updated_at=?,revoked_at=? WHERE application_id=? AND enabled=1`, unix(now), unix(now), idBytes(applicationID)); err != nil {
		return err
	}
	for _, principalID := range principals {
		if err := disableInstallationPrincipalTx(ctx, tx, principalID, now, "registered application disabled"); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE application_refresh_token_families SET revoked_at=max(created_at,?),revocation_reason='registered application disabled' WHERE application_id=? AND revoked_at IS NULL`, unix(now), idBytes(applicationID)); err != nil {
		return err
	}
	if err := auditActorTx(ctx, tx, nil, actor, "application.disable", "application", &applicationID, "{}", now); err != nil {
		return err
	}
	return tx.Commit()
}

// AdministratorDeleteApplication permanently removes a disabled application
// and its installation records. Audit events and disabled service principals
// remain available for investigation.
func (s *Store) AdministratorDeleteApplication(ctx context.Context, decision adminauth.Decision, applicationID identity.ID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, applicationDeletePolicy, applicationID, adminauth.OperationApplicationManage)
	if err != nil {
		return err
	}
	application, err := registeredApplicationRecord(ctx, tx, applicationID)
	if err != nil {
		return err
	}
	if application.Enabled {
		return fmt.Errorf("%w: disable the application before deleting it", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM application_installations WHERE application_id=?`, idBytes(applicationID)); err != nil {
		return err
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM registered_applications WHERE id=? AND enabled=0`, idBytes(applicationID))
	if err != nil {
		return err
	}
	if count, _ := deleted.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	if err := auditActorTx(ctx, tx, nil, actor, "application.delete", "application", &applicationID, "{}", s.now()); err != nil {
		return err
	}
	return tx.Commit()
}
