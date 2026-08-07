package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/identity"
)

var migrations = []string{`
CREATE TABLE networks (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 253),
    ipv4_address BLOB NOT NULL CHECK(length(ipv4_address) = 4),
    ipv4_prefix_length INTEGER NOT NULL CHECK(ipv4_prefix_length BETWEEN 8 AND 30),
    next_ipv4 INTEGER NOT NULL DEFAULT 1 CHECK(next_ipv4 >= 1),
    configuration_epoch INTEGER NOT NULL DEFAULT 1 CHECK(configuration_epoch >= 1),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE nodes (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253),
    enabled_capabilities INTEGER NOT NULL DEFAULT 0 CHECK(enabled_capabilities >= 0),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
	UNIQUE(network_id, name),
	UNIQUE(network_id, id)
) STRICT;

CREATE TABLE certificates (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
	node_id BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    serial BLOB NOT NULL CHECK(length(serial) BETWEEN 1 AND 32),
    der BLOB NOT NULL CHECK(length(der) BETWEEN 1 AND 65536),
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL CHECK(not_after > not_before),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(length(revocation_reason) <= 1024),
	UNIQUE(network_id, serial),
	FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE overlay_addresses (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    node_id BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK(length(address) IN (4, 16)),
	prefix_length INTEGER NOT NULL CHECK(
		(length(address) = 4 AND prefix_length BETWEEN 0 AND 32) OR
		(length(address) = 16 AND prefix_length BETWEEN 0 AND 128)
	),
    created_at INTEGER NOT NULL,
    released_at INTEGER,
	UNIQUE(network_id, address),
	FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX one_active_ipv4_per_node ON overlay_addresses(node_id)
    WHERE length(address) = 4 AND released_at IS NULL;

CREATE TABLE routes (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    node_id BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    prefix_address BLOB NOT NULL CHECK(length(prefix_address) IN (4, 16)),
	prefix_length INTEGER NOT NULL CHECK(
		(length(prefix_address) = 4 AND prefix_length BETWEEN 0 AND 32) OR
		(length(prefix_address) = 16 AND prefix_length BETWEEN 0 AND 128)
	),
    kind TEXT NOT NULL CHECK(kind IN ('overlay','subnet','exit')),
    mode TEXT NOT NULL CHECK(mode IN ('none','nat','routed')),
    metric INTEGER NOT NULL CHECK(metric BETWEEN 0 AND 1000000),
    state TEXT NOT NULL CHECK(state IN ('advertised','approved','withdrawn','rejected')),
    valid_until INTEGER,
    created_at INTEGER NOT NULL,
    approved_at INTEGER,
    withdrawn_at INTEGER,
	CHECK(
		(kind = 'exit' AND prefix_length = 0 AND mode IN ('nat','routed')) OR
		(kind = 'subnet' AND prefix_length > 0 AND mode IN ('nat','routed')) OR
		(kind = 'overlay' AND mode = 'none' AND
		 ((length(prefix_address) = 4 AND prefix_length = 32) OR
		  (length(prefix_address) = 16 AND prefix_length = 128)))
	),
	CHECK(valid_until IS NULL OR valid_until > created_at),
	FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX routes_network_state ON routes(network_id, state);
CREATE UNIQUE INDEX one_active_route_advertisement ON routes
	(network_id,node_id,prefix_address,prefix_length,kind)
	WHERE state IN ('advertised','approved');

CREATE TABLE acl_rules (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 4294967295),
    action TEXT NOT NULL CHECK(action IN ('accept','deny')),
    selector_json TEXT NOT NULL CHECK(length(selector_json) BETWEEN 2 AND 16384),
    description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 1024),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX acl_rules_order ON acl_rules(network_id, priority, id);

CREATE TABLE relays (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    node_id BLOB REFERENCES nodes(id) ON DELETE SET NULL,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253),
    endpoint TEXT NOT NULL CHECK(length(endpoint) BETWEEN 1 AND 2048),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    UNIQUE(network_id, name),
	UNIQUE(network_id, endpoint)
) STRICT;

CREATE TABLE enrollment_tokens (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
    label TEXT NOT NULL DEFAULT '' CHECK(length(label) <= 256),
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    consumed_at INTEGER,
	consumed_by BLOB REFERENCES nodes(id) ON DELETE SET NULL,
	CHECK(expires_at > created_at)
) STRICT;
CREATE INDEX enrollment_tokens_expiry ON enrollment_tokens(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE audit_events (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    actor_node_id BLOB REFERENCES nodes(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
    target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
    target_id BLOB CHECK(target_id IS NULL OR length(target_id) = 16),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(length(details_json) BETWEEN 2 AND 16384),
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX audit_events_network_time ON audit_events(network_id, created_at, id);
`, `
ALTER TABLE networks ADD COLUMN ipv6_address BLOB CHECK(ipv6_address IS NULL OR length(ipv6_address) = 16);
ALTER TABLE networks ADD COLUMN ipv6_prefix_length INTEGER CHECK(ipv6_prefix_length IS NULL OR ipv6_prefix_length BETWEEN 64 AND 120);
ALTER TABLE networks ADD COLUMN next_ipv6 INTEGER NOT NULL DEFAULT 1 CHECK(next_ipv6 >= 1);
CREATE UNIQUE INDEX one_active_ipv6_per_node ON overlay_addresses(node_id)
    WHERE length(address) = 16 AND released_at IS NULL;
`, `
ALTER TABLE relays ADD COLUMN service_id BLOB CHECK(service_id IS NULL OR length(service_id) = 16);
CREATE UNIQUE INDEX relays_network_service_identity ON relays(network_id, service_id)
    WHERE service_id IS NOT NULL;
`, `
ALTER TABLE nodes ADD COLUMN enrollment_class TEXT NOT NULL DEFAULT 'durable'
    CHECK(enrollment_class IN ('durable','ephemeral','remembered'));
ALTER TABLE nodes ADD COLUMN lease_expires_at INTEGER;
CREATE INDEX nodes_ephemeral_expiry ON nodes(lease_expires_at)
    WHERE enrollment_class='ephemeral' AND revoked_at IS NULL;

ALTER TABLE enrollment_tokens ADD COLUMN enrollment_class TEXT NOT NULL DEFAULT 'durable'
    CHECK(enrollment_class IN ('durable','ephemeral','remembered'));
ALTER TABLE enrollment_tokens ADD COLUMN session_lifetime_seconds INTEGER;
CREATE INDEX enrollment_tokens_class_expiry ON enrollment_tokens(enrollment_class,expires_at)
    WHERE consumed_at IS NULL;
`, `
ALTER TABLE enrollment_tokens ADD COLUMN requested_name TEXT
    CHECK(requested_name IS NULL OR length(requested_name) BETWEEN 1 AND 253);
`, `
ALTER TABLE nodes ADD COLUMN wireguard_public_key BLOB
    CHECK(wireguard_public_key IS NULL OR length(wireguard_public_key) = 32);
CREATE UNIQUE INDEX nodes_wireguard_public_key ON nodes(wireguard_public_key)
    WHERE wireguard_public_key IS NOT NULL;
`}

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
	if action == "" || len(action) > 128 || targetType == "" || len(targetType) > 64 || len(details) < 2 || len(details) > MaxAuditDetailLength || !json.Valid([]byte(details)) {
		return fmt.Errorf("%w: invalid audit event", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	var actorBytes, targetBytes any
	if actor != nil {
		actorBytes = idBytes(*actor)
	}
	if targetID != nil {
		targetBytes = idBytes(*targetID)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
        (id, network_id, actor_node_id, action, target_type, target_id, details_json, created_at)
        VALUES(?,?,?,?,?,?,?,?)`, idBytes(id), idBytes(networkID), actorBytes, action, targetType, targetBytes, details, unix(at))
	if err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}
