package controller

import (
	"context"
	"crypto/sha256"
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

const (
	ApplicationRequestLifetime = 10 * time.Minute
	ApplicationCodeLifetime    = 5 * time.Minute
	MaxRegisteredApplications  = 500
)

var (
	applicationListPolicy                = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/applications")
	applicationReadPolicy                = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/applications/{application_id}")
	applicationDeletePolicy              = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/applications/{application_id}")
	applicationSecretPolicy              = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/applications/{application_id}/client-secrets")
	applicationDisablePolicy             = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/applications/{application_id}/disable")
	applicationRegistrationReadPolicy    = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/application-registration-requests/{request_id}")
	applicationRegistrationApprovePolicy = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/application-registration-requests/{request_id}/approve")
	applicationRegistrationCancelPolicy  = mustAdministratorResourcePolicy(http.MethodPost, "/v1/admin/application-registration-requests/{request_id}/cancel")
)

type RegisteredApplication struct {
	ID                 identity.ID
	ClientID           string
	Manifest           applicationauth.Manifest
	Enabled            bool
	CreatorPrincipalID identity.ID
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DisabledAt         *time.Time
}

type ApplicationRegistrationRequest struct {
	ID            identity.ID
	Manifest      applicationauth.Manifest
	State         string
	PKCEChallenge string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}

type ApplicationRegistrationApproval struct {
	Application RegisteredApplication
	Code        string
	State       string
	SetupURI    string
}

type ApplicationRegistrationExchange struct {
	Application  RegisteredApplication
	ClientSecret string
}

func (s *Store) CreateApplicationRegistrationRequest(ctx context.Context, manifest applicationauth.Manifest,
	state, challenge string) (ApplicationRegistrationRequest, error) {
	var result ApplicationRegistrationRequest
	manifest, err := applicationauth.ValidateManifest(manifest, true)
	if err != nil || state == "" || len(state) > 1024 || !applicationauth.ValidatePKCEChallenge(challenge) {
		return result, fmt.Errorf("%w: invalid application registration request", ErrInvalid)
	}
	payload, err := json.Marshal(manifest)
	if err != nil || len(payload) > 32768 {
		return result, fmt.Errorf("%w: invalid application manifest", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return result, err
	}
	now := s.now()
	expires := now.Add(ApplicationRequestLifetime)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO application_registration_requests
		(id,manifest_json,state,pkce_challenge,created_at,expires_at) VALUES(?,?,?,?,?,?)`,
		idBytes(id), string(payload), state, challenge, unix(now), unix(expires)); err != nil {
		return result, err
	}
	return ApplicationRegistrationRequest{ID: id, Manifest: manifest, State: state,
		PKCEChallenge: challenge, CreatedAt: now, ExpiresAt: expires}, nil
}

func applicationRegistrationRequestRecord(ctx context.Context, queryer rowQueryer, id identity.ID) (ApplicationRegistrationRequest, error) {
	var result ApplicationRegistrationRequest
	var raw []byte
	var payload string
	var created, expires int64
	var consumed sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT id,manifest_json,state,pkce_challenge,created_at,expires_at,consumed_at
		FROM application_registration_requests WHERE id=?`, idBytes(id)).Scan(&raw, &payload, &result.State,
		&result.PKCEChallenge, &created, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	parsed, err := scanID(raw)
	if err != nil || json.Unmarshal([]byte(payload), &result.Manifest) != nil {
		return result, errors.New("corrupt application registration request")
	}
	result.ID, result.CreatedAt, result.ExpiresAt, result.ConsumedAt = parsed, fromUnix(created), fromUnix(expires), nullableTime(consumed)
	return result, nil
}

func (s *Store) AdministratorApplicationRegistrationRequest(ctx context.Context, decision adminauth.Decision,
	id identity.ID) (ApplicationRegistrationRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision,
		applicationRegistrationReadPolicy, id, adminauth.OperationApplicationRead); err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	request, err := applicationRegistrationRequestRecord(ctx, tx, id)
	if err != nil || request.ConsumedAt != nil || !s.now().Before(request.ExpiresAt) {
		return ApplicationRegistrationRequest{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	return request, nil
}

func (s *Store) AdministratorApproveApplicationRegistration(ctx context.Context, decision adminauth.Decision,
	requestID identity.ID) (ApplicationRegistrationApproval, error) {
	var result ApplicationRegistrationApproval
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision,
		applicationRegistrationApprovePolicy, requestID, adminauth.OperationApplicationManage)
	if err != nil {
		return result, err
	}
	if actor.Kind != adminauth.ActorAdministrator || actor.ID == nil {
		return result, ErrPermissionDenied
	}
	request, err := applicationRegistrationRequestRecord(ctx, tx, requestID)
	now := s.now()
	if err != nil || request.ConsumedAt != nil || now.Before(request.CreatedAt) || !now.Before(request.ExpiresAt) {
		return result, ErrNotFound
	}
	applicationID, err := newID()
	if err != nil {
		return result, err
	}
	codeID, err := newID()
	if err != nil {
		return result, err
	}
	code, digest, err := applicationauth.NewSecret(applicationauth.PurposeRegistrationCode, codeID, nil)
	if err != nil {
		return result, err
	}
	clientID := applicationauth.ClientID(applicationID)
	if _, err := tx.ExecContext(ctx, `INSERT INTO registered_applications
		(id,client_id,name,homepage_uri,setup_uri,token_endpoint_auth_method,creator_principal_id,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, idBytes(applicationID), clientID, request.Manifest.Name,
		request.Manifest.HomepageURI, request.Manifest.SetupURI, request.Manifest.TokenEndpointAuthMethod,
		idBytes(*actor.ID), unix(now), unix(now)); err != nil {
		return result, err
	}
	for _, redirect := range request.Manifest.RedirectURIs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO registered_application_redirect_uris(application_id,redirect_uri) VALUES(?,?)`, idBytes(applicationID), redirect); err != nil {
			return result, err
		}
	}
	for _, scope := range request.Manifest.Scopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO registered_application_scopes(application_id,scope) VALUES(?,?)`, idBytes(applicationID), scope); err != nil {
			return result, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO application_registration_codes
		(id,application_id,setup_uri,code_hash,pkce_challenge,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		idBytes(codeID), idBytes(applicationID), request.Manifest.SetupURI, digest[:], request.PKCEChallenge,
		unix(now), unix(now.Add(ApplicationCodeLifetime))); err != nil {
		return result, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE application_registration_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?`, unix(now), idBytes(requestID), unix(now))
	if err != nil {
		return result, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return result, ErrConflict
	}
	details, _ := marshalAuditDetails(map[string]any{"name": request.Manifest.Name, "scopes": request.Manifest.Scopes})
	if err := auditActorTx(ctx, tx, nil, actor, "application.create", "application", &applicationID, details, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	application := RegisteredApplication{ID: applicationID, ClientID: clientID, Manifest: request.Manifest,
		Enabled: true, CreatorPrincipalID: *actor.ID, CreatedAt: now, UpdatedAt: now}
	return ApplicationRegistrationApproval{Application: application, Code: code,
		State: request.State, SetupURI: request.Manifest.SetupURI}, nil
}

func (s *Store) AdministratorCancelApplicationRegistration(ctx context.Context, decision adminauth.Decision,
	requestID identity.ID) (ApplicationRegistrationRequest, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision,
		applicationRegistrationCancelPolicy, requestID, adminauth.OperationApplicationManage)
	if err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	if actor.Kind != adminauth.ActorAdministrator {
		return ApplicationRegistrationRequest{}, ErrPermissionDenied
	}
	request, err := applicationRegistrationRequestRecord(ctx, tx, requestID)
	if err != nil || request.ConsumedAt != nil {
		return ApplicationRegistrationRequest{}, ErrNotFound
	}
	now := s.now()
	updated, err := tx.ExecContext(ctx, `UPDATE application_registration_requests SET consumed_at=? WHERE id=? AND consumed_at IS NULL`, unix(now), idBytes(requestID))
	if err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return ApplicationRegistrationRequest{}, ErrConflict
	}
	if err := auditActorTx(ctx, tx, nil, actor, "application.registration_cancel", "application_registration_request", &requestID, "{}", now); err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return ApplicationRegistrationRequest{}, err
	}
	return request, nil
}

func registeredApplicationRecord(ctx context.Context, queryer rowQueryer, applicationID identity.ID) (RegisteredApplication, error) {
	var result RegisteredApplication
	var raw, creatorRaw []byte
	var enabled int
	var created, updated int64
	var disabled sql.NullInt64
	err := queryer.QueryRowContext(ctx, `SELECT id,client_id,name,homepage_uri,setup_uri,token_endpoint_auth_method,
		enabled,creator_principal_id,created_at,updated_at,disabled_at FROM registered_applications WHERE id=?`,
		idBytes(applicationID)).Scan(&raw, &result.ClientID, &result.Manifest.Name, &result.Manifest.HomepageURI,
		&result.Manifest.SetupURI, &result.Manifest.TokenEndpointAuthMethod, &enabled, &creatorRaw, &created, &updated, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	result.ID, err = scanID(raw)
	if err != nil {
		return result, err
	}
	creator, err := scanID(creatorRaw)
	if err != nil {
		return result, err
	}
	result.CreatorPrincipalID, result.Enabled = creator, enabled == 1
	result.CreatedAt, result.UpdatedAt, result.DisabledAt = fromUnix(created), fromUnix(updated), nullableTime(disabled)
	rows, err := queryer.QueryContext(ctx, `SELECT redirect_uri FROM registered_application_redirect_uris WHERE application_id=? ORDER BY redirect_uri`, idBytes(applicationID))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			return result, err
		}
		result.Manifest.RedirectURIs = append(result.Manifest.RedirectURIs, value)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	rows, err = queryer.QueryContext(ctx, `SELECT scope FROM registered_application_scopes WHERE application_id=? ORDER BY scope`, idBytes(applicationID))
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return result, err
		}
		result.Manifest.Scopes = append(result.Manifest.Scopes, value)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func registeredApplicationByClientID(ctx context.Context, queryer rowQueryer, clientID string) (RegisteredApplication, error) {
	applicationID, err := applicationauth.ParseClientID(clientID)
	if err != nil {
		return RegisteredApplication{}, ErrNotFound
	}
	application, err := registeredApplicationRecord(ctx, queryer, applicationID)
	if err != nil || application.ClientID != clientID {
		return RegisteredApplication{}, ErrNotFound
	}
	return application, nil
}

func (s *Store) ExchangeApplicationRegistration(ctx context.Context, code, verifier string) (ApplicationRegistrationExchange, error) {
	var result ApplicationRegistrationExchange
	codeID, candidate, err := applicationauth.ParseSecret(applicationauth.PurposeRegistrationCode, code)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var applicationRaw, storedHash []byte
	var challenge string
	var created, expires int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT application_id,code_hash,pkce_challenge,created_at,expires_at,consumed_at
		FROM application_registration_codes WHERE id=?`, idBytes(codeID)).Scan(&applicationRaw, &storedHash, &challenge, &created, &expires, &consumed)
	now := s.now()
	if err != nil || len(storedHash) != sha256.Size || !slices.Equal(storedHash, candidate[:]) || consumed.Valid ||
		now.Before(fromUnix(created)) || !now.Before(fromUnix(expires)) || !applicationauth.VerifyPKCE(challenge, verifier) {
		return result, ErrCredentialInvalid
	}
	applicationValue, err := scanID(applicationRaw)
	if err != nil {
		return result, ErrCredentialInvalid
	}
	application, err := registeredApplicationRecord(ctx, tx, applicationValue)
	if err != nil || !application.Enabled {
		return result, ErrCredentialInvalid
	}
	credentialID, err := newID()
	if err != nil {
		return result, err
	}
	secret, digest, err := applicationauth.NewSecret(applicationauth.PurposeClientSecret, credentialID, nil)
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO registered_application_credentials(id,application_id,secret_hash,created_at) VALUES(?,?,?,?)`, idBytes(credentialID), idBytes(application.ID), digest[:], unix(now)); err != nil {
		return result, err
	}
	updated, err := tx.ExecContext(ctx, `UPDATE application_registration_codes SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?`, unix(now), idBytes(codeID), unix(now))
	if err != nil {
		return result, err
	}
	if count, _ := updated.RowsAffected(); count != 1 {
		return result, ErrCredentialInvalid
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return ApplicationRegistrationExchange{Application: application, ClientSecret: secret}, nil
}

func (s *Store) AdministratorApplications(ctx context.Context, decision adminauth.Decision, limit int) ([]RegisteredApplication, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementGlobalTx(ctx, s, tx, decision, applicationListPolicy); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM registered_applications ORDER BY enabled DESC,created_at DESC,id DESC LIMIT ?`, limit)
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
	result := make([]RegisteredApplication, 0, len(ids))
	for _, id := range ids {
		value, err := registeredApplicationRecord(ctx, tx, id)
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

func (s *Store) AdministratorApplication(ctx context.Context, decision adminauth.Decision, id identity.ID) (RegisteredApplication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RegisteredApplication{}, err
	}
	defer tx.Rollback()
	if _, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, applicationReadPolicy, id, adminauth.OperationApplicationRead); err != nil {
		return RegisteredApplication{}, err
	}
	value, err := registeredApplicationRecord(ctx, tx, id)
	if err != nil {
		return RegisteredApplication{}, err
	}
	if err := tx.Commit(); err != nil {
		return RegisteredApplication{}, err
	}
	return value, nil
}

func (s *Store) AdministratorRotateApplicationClientSecret(ctx context.Context, decision adminauth.Decision, applicationID identity.ID) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	actor, err := authorizeAdministratorManagementObjectTx(ctx, s, tx, decision, applicationSecretPolicy, applicationID, adminauth.OperationApplicationManage)
	if err != nil {
		return "", err
	}
	application, err := registeredApplicationRecord(ctx, tx, applicationID)
	if err != nil || !application.Enabled {
		return "", ErrNotFound
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	secret, digest, err := applicationauth.NewSecret(applicationauth.PurposeClientSecret, id, nil)
	if err != nil {
		return "", err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE registered_application_credentials SET revoked_at=max(created_at,?) WHERE application_id=? AND revoked_at IS NULL`, unix(now), idBytes(applicationID)); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO registered_application_credentials(id,application_id,secret_hash,created_at) VALUES(?,?,?,?)`, idBytes(id), idBytes(applicationID), digest[:], unix(now)); err != nil {
		return "", err
	}
	if err := auditActorTx(ctx, tx, nil, actor, "application.client_secret_rotate", "application", &applicationID, "{}", now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return secret, nil
}

func authenticateApplicationClientTx(ctx context.Context, tx *sql.Tx, clientID, clientSecret string) (RegisteredApplication, error) {
	application, err := registeredApplicationByClientID(ctx, tx, clientID)
	if err != nil || !application.Enabled {
		return RegisteredApplication{}, ErrCredentialInvalid
	}
	credentialID, candidate, err := applicationauth.ParseSecret(applicationauth.PurposeClientSecret, clientSecret)
	if err != nil {
		return RegisteredApplication{}, ErrCredentialInvalid
	}
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT secret_hash FROM registered_application_credentials WHERE id=? AND application_id=? AND revoked_at IS NULL`, idBytes(credentialID), idBytes(application.ID)).Scan(&stored)
	if err != nil || len(stored) != sha256.Size || !slices.Equal(stored, candidate[:]) {
		return RegisteredApplication{}, ErrCredentialInvalid
	}
	return application, nil
}

// AuthenticateApplicationClient validates a registered application's current
// client credential without disclosing whether either identifier exists.
func (s *Store) AuthenticateApplicationClient(ctx context.Context, clientID, clientSecret string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := authenticateApplicationClientTx(ctx, tx, clientID, clientSecret); err != nil {
		return ErrCredentialInvalid
	}
	return tx.Commit()
}
