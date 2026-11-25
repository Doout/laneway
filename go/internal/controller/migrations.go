package controller

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
)

// Published migrations are shared with the Rust maintenance candidate.
//
//go:embed migrations.sql
var migrationSQL string

var migrations = strings.Split(migrationSQL, "\n-- Next Laneway schema migration --\n")

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_versions (
        version INTEGER PRIMARY KEY CHECK(version > 0),
        applied_at INTEGER NOT NULL
    ) STRICT`); err != nil {
		return fmt.Errorf("create schema version table: %w", err)
	}
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_versions`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > currentSchemaVersion {
		return fmt.Errorf("%w: database=%d controller=%d", ErrUnsupportedDB, current, currentSchemaVersion)
	}
	for version := current + 1; version <= currentSchemaVersion; version++ {
		if _, err := tx.ExecContext(ctx, migrations[version-1]); err != nil {
			return fmt.Errorf("apply schema migration %d: %w", version, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_versions(version, applied_at) VALUES(?, ?)`, version, unix(s.now())); err != nil {
			return fmt.Errorf("record schema migration %d: %w", version, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migrations: %w", err)
	}
	return nil
}

func auditTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, actor *identity.NodeID, action, targetType string, targetID *identity.ID, details string, at time.Time) error {
	if authorization, ok := administratorMutationAuthorizationFrom(ctx); ok {
		canonicalNetwork := &networkID
		if !authorization.operation.NetworkScoped() {
			canonicalNetwork = nil
		} else if authorization.networkID != nil && *authorization.networkID != networkID {
			return fmt.Errorf("%w: administrator mutation audit scope mismatch", ErrInvalid)
		}
		if err := authorizeAdministratorMutationTx(ctx, tx, authorization.actor, authorization.operation, canonicalNetwork); err != nil {
			return err
		}
		return auditActorTx(ctx, tx, &networkID, authorization.actor, action, targetType, targetID, details, at)
	}
	auditActor := adminauth.Actor{Kind: adminauth.ActorLegacyUnknown}
	if actor != nil {
		auditActor = adminauth.IDActor(adminauth.ActorNode, identity.ID(*actor))
	} else if action == "route.expire" || action == "ephemeral.expire" {
		auditActor = adminauth.SystemActor()
	}
	return auditActorTx(ctx, tx, &networkID, auditActor, action, targetType, targetID, details, at)
}

func authorizeAdministratorMutationTx(ctx context.Context, tx *sql.Tx, actor adminauth.Actor, operation adminauth.Operation, networkID *identity.NetworkID) error {
	switch actor.Kind {
	case adminauth.ActorServicePrincipal:
		var rootRaw []byte
		if err := tx.QueryRowContext(ctx, `SELECT root_service_principal_id FROM administrator_auth_state WHERE singleton=1`).Scan(&rootRaw); err != nil {
			return fmt.Errorf("revalidate administrator service principal: %w", err)
		}
		rootID, err := scanID(rootRaw)
		if err != nil || actor.ID == nil || *actor.ID != rootID {
			return ErrCredentialInvalid
		}
		return nil
	default:
		return ErrCredentialInvalid
	}
}

func auditActorTx(ctx context.Context, tx *sql.Tx, networkID *identity.NetworkID, actor adminauth.Actor, action, targetType string, targetID *identity.ID, details string, at time.Time) error {
	_, err := auditActorIDTx(ctx, tx, networkID, actor, action, targetType, targetID, details, at)
	return err
}

func auditActorIDTx(ctx context.Context, tx *sql.Tx, networkID *identity.NetworkID, actor adminauth.Actor, action, targetType string, targetID *identity.ID, details string, at time.Time) (identity.ID, error) {
	if action == "" || len(action) > 128 || targetType == "" || len(targetType) > 64 || len(details) < 2 || len(details) > MaxAuditDetailLength || !json.Valid([]byte(details)) {
		return identity.ID{}, fmt.Errorf("%w: invalid audit event", ErrInvalid)
	}
	if !actor.Valid() {
		return identity.ID{}, fmt.Errorf("%w: invalid audit actor", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return identity.ID{}, err
	}
	var networkBytes, actorBytes, targetBytes any
	if networkID != nil {
		networkBytes = idBytes(*networkID)
	}
	if actor.ID != nil {
		actorBytes = idBytes(*actor.ID)
	}
	if targetID != nil {
		targetBytes = idBytes(*targetID)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
		(id, network_id, actor_kind, actor_id, action, target_type, target_id, details_json, created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, idBytes(id), networkBytes, string(actor.Kind), actorBytes, action, targetType, targetBytes, details, unix(at))
	if err != nil {
		return identity.ID{}, fmt.Errorf("write audit event: %w", err)
	}
	return id, nil
}
