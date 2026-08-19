package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
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
`, `
ALTER TABLE enrollment_tokens ADD COLUMN enabled_capabilities INTEGER NOT NULL DEFAULT 0
    CHECK(enabled_capabilities BETWEEN 0 AND 9223372036854775807);
`, `
CREATE TABLE administrator_principals (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    username TEXT NOT NULL UNIQUE CHECK(
        length(username) BETWEEN 3 AND 64 AND
        username = trim(username) AND
        username GLOB '[a-z0-9]*' AND
        substr(username, -1, 1) GLOB '[a-z0-9]' AND
        username NOT GLOB '*[^a-z0-9._-]*'
    ),
    role TEXT NOT NULL CHECK(role IN ('owner','operator','auditor')),
    all_networks INTEGER NOT NULL CHECK(all_networks IN (0,1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    disabled_at INTEGER,
    CHECK(role <> 'owner' OR all_networks = 1),
    CHECK(
        (enabled = 1 AND disabled_at IS NULL) OR
        (enabled = 0 AND disabled_at IS NOT NULL AND disabled_at >= created_at)
    )
) STRICT;

CREATE TABLE administrator_principal_networks (
    principal_id BLOB NOT NULL REFERENCES administrator_principals(id) ON DELETE CASCADE
        CHECK(length(principal_id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(principal_id, network_id)
) STRICT;
CREATE INDEX administrator_principal_networks_network
    ON administrator_principal_networks(network_id, principal_id);

CREATE TABLE administrator_credentials (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    principal_id BLOB NOT NULL REFERENCES administrator_principals(id) ON DELETE CASCADE
        CHECK(length(principal_id) = 16),
    credential_type TEXT NOT NULL CHECK(credential_type = 'password'),
    secret_hash TEXT NOT NULL CHECK(length(secret_hash) BETWEEN 64 AND 512),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(length(revocation_reason) <= 256),
    UNIQUE(principal_id, id),
    CHECK(
        (revoked_at IS NULL AND revocation_reason = '') OR
        (revoked_at IS NOT NULL AND revoked_at >= created_at AND length(revocation_reason) > 0)
    )
) STRICT;
CREATE UNIQUE INDEX one_active_administrator_password
    ON administrator_credentials(principal_id)
    WHERE credential_type = 'password' AND revoked_at IS NULL;
CREATE TRIGGER administrator_credentials_immutable_secret
    BEFORE UPDATE OF principal_id, credential_type, secret_hash ON administrator_credentials
BEGIN
    SELECT RAISE(ABORT, 'administrator credential identity is immutable');
END;

CREATE TABLE administrator_sessions (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    principal_id BLOB NOT NULL CHECK(length(principal_id) = 16),
    credential_id BLOB NOT NULL CHECK(length(credential_id) = 16),
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
    csrf_hash BLOB NOT NULL UNIQUE CHECK(length(csrf_hash) = 32),
    previous_session_id BLOB REFERENCES administrator_sessions(id) ON DELETE SET NULL
        CHECK(previous_session_id IS NULL OR length(previous_session_id) = 16),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_lifetime_seconds INTEGER NOT NULL CHECK(idle_lifetime_seconds BETWEEN 60 AND 86400),
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(length(revocation_reason) <= 256),
    FOREIGN KEY(principal_id, credential_id)
        REFERENCES administrator_credentials(principal_id, id) ON DELETE CASCADE,
    CHECK(token_hash <> csrf_hash),
    CHECK(previous_session_id IS NULL OR previous_session_id <> id),
    CHECK(last_seen_at >= created_at),
    CHECK(idle_expires_at = min(last_seen_at + idle_lifetime_seconds, absolute_expires_at)),
    CHECK(absolute_expires_at > created_at),
    CHECK(
        (revoked_at IS NULL AND revocation_reason = '') OR
        (revoked_at IS NOT NULL AND revoked_at >= created_at AND length(revocation_reason) > 0)
    )
) STRICT;
CREATE INDEX administrator_sessions_active_principal
    ON administrator_sessions(principal_id, created_at, id)
    WHERE revoked_at IS NULL;
CREATE INDEX administrator_sessions_active_expiry
    ON administrator_sessions(idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE administrator_recovery_grants (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    secret_hash BLOB NOT NULL UNIQUE CHECK(length(secret_hash) = 32),
    purpose TEXT NOT NULL CHECK(purpose IN ('bootstrap_owner','owner_recovery')),
    target_principal_id BLOB REFERENCES administrator_principals(id) ON DELETE RESTRICT
        CHECK(target_principal_id IS NULL OR length(target_principal_id) = 16),
    recovery_generation INTEGER NOT NULL CHECK(recovery_generation >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
    consumed_at INTEGER,
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(length(revocation_reason) <= 256),
    CHECK(
        (purpose = 'bootstrap_owner' AND target_principal_id IS NULL) OR
        (purpose = 'owner_recovery' AND target_principal_id IS NOT NULL)
    ),
    CHECK(consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at <= expires_at)),
    CHECK(revoked_at IS NULL OR revoked_at >= created_at),
    CHECK(NOT (consumed_at IS NOT NULL AND revoked_at IS NOT NULL)),
    CHECK(
        (revoked_at IS NULL AND revocation_reason = '') OR
        (revoked_at IS NOT NULL AND length(revocation_reason) > 0)
    )
) STRICT;
CREATE UNIQUE INDEX one_pending_owner_bootstrap
    ON administrator_recovery_grants(purpose)
    WHERE purpose = 'bootstrap_owner' AND consumed_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX one_pending_recovery_per_owner
    ON administrator_recovery_grants(target_principal_id)
    WHERE purpose = 'owner_recovery' AND consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX administrator_recovery_grants_pending_expiry
    ON administrator_recovery_grants(expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE administrator_auth_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    root_service_principal_id BLOB NOT NULL UNIQUE CHECK(
        length(root_service_principal_id) = 16 AND root_service_principal_id <> zeroblob(16)
    ),
    initial_owner_principal_id BLOB REFERENCES administrator_principals(id) ON DELETE RESTRICT
        CHECK(initial_owner_principal_id IS NULL OR length(initial_owner_principal_id) = 16),
    bootstrap_completed_at INTEGER,
    recovery_generation INTEGER NOT NULL DEFAULT 0 CHECK(recovery_generation >= 0),
    last_recovered_at INTEGER,
    CHECK(
        (initial_owner_principal_id IS NULL AND bootstrap_completed_at IS NULL) OR
        (initial_owner_principal_id IS NOT NULL AND bootstrap_completed_at IS NOT NULL)
    )
) STRICT;
INSERT INTO administrator_auth_state(singleton, root_service_principal_id)
VALUES(1, randomblob(16));

DROP INDEX audit_events_network_time;
ALTER TABLE audit_events RENAME TO audit_events_v7;
CREATE TABLE audit_events (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB REFERENCES networks(id) ON DELETE SET NULL
        CHECK(network_id IS NULL OR length(network_id) = 16),
    actor_kind TEXT NOT NULL CHECK(actor_kind IN (
        'system','node','administrator','service_principal','unauthenticated','legacy_unknown'
    )),
    actor_id BLOB CHECK(actor_id IS NULL OR (length(actor_id) = 16 AND actor_id <> zeroblob(16))),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
    target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
    target_id BLOB CHECK(target_id IS NULL OR length(target_id) = 16),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(length(details_json) BETWEEN 2 AND 16384),
    created_at INTEGER NOT NULL,
    CHECK(
        (actor_kind IN ('system','unauthenticated','legacy_unknown') AND actor_id IS NULL) OR
        (actor_kind IN ('node','administrator','service_principal') AND actor_id IS NOT NULL)
    )
) STRICT;
INSERT INTO audit_events
    (id, network_id, actor_kind, actor_id, action, target_type, target_id, details_json, created_at)
SELECT id, network_id,
    CASE
        WHEN actor_node_id IS NOT NULL THEN 'node'
        WHEN action IN ('route.expire','ephemeral.expire') THEN 'system'
        ELSE 'legacy_unknown'
    END,
    actor_node_id, action, target_type, target_id, details_json, created_at
FROM audit_events_v7;
DROP TABLE audit_events_v7;
CREATE INDEX audit_events_network_time
    ON audit_events(network_id, created_at DESC, id DESC)
    WHERE network_id IS NOT NULL;
CREATE INDEX audit_events_global_time
    ON audit_events(created_at DESC, id DESC);
CREATE INDEX audit_events_actor_time
    ON audit_events(actor_kind, actor_id, created_at DESC, id DESC);
`, `
-- Schema v9 is an explicit upgrade from the published administrator-security
-- foundation v8. Keep migration 8 byte-for-byte compatible with that branch;
-- runtime session/RBAC hardening belongs here so stacked deployments migrate.

DELETE FROM administrator_principal_networks
WHERE principal_id IN (SELECT id FROM administrator_principals WHERE all_networks=1);
CREATE TRIGGER administrator_scope_requires_scoped_principal
    BEFORE INSERT ON administrator_principal_networks
BEGIN
    SELECT CASE WHEN COALESCE((SELECT all_networks FROM administrator_principals
        WHERE id=NEW.principal_id), 1) <> 0
        THEN RAISE(ABORT, 'administrator scope requires a scoped principal') END;
END;
CREATE TRIGGER administrator_scope_identity_immutable
    BEFORE UPDATE OF principal_id, network_id ON administrator_principal_networks
BEGIN
    SELECT RAISE(ABORT, 'administrator scope identity is immutable');
END;
CREATE TRIGGER administrator_all_networks_requires_no_scopes
    BEFORE UPDATE OF all_networks ON administrator_principals
    WHEN NEW.all_networks=1 AND EXISTS(
        SELECT 1 FROM administrator_principal_networks WHERE principal_id=NEW.id
    )
BEGIN
    SELECT RAISE(ABORT, 'all-network administrator cannot retain network scopes');
END;

INSERT INTO audit_events
    (id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
SELECT randomblob(16),NULL,'system',NULL,'administrator.recovery.invalidate_schema_v9',
    'administrator_recovery_grant',NULL,'{"reason":"schema v9 static-root boundary"}',unixepoch()
WHERE EXISTS(SELECT 1 FROM administrator_recovery_grants
    WHERE consumed_at IS NULL AND revoked_at IS NULL);
UPDATE administrator_auth_state
SET recovery_generation=recovery_generation+1
WHERE singleton=1 AND EXISTS(SELECT 1 FROM administrator_recovery_grants
    WHERE consumed_at IS NULL AND revoked_at IS NULL);
UPDATE administrator_recovery_grants
SET revoked_at=max(created_at,unixepoch()),revocation_reason='schema v9 security upgrade'
WHERE consumed_at IS NULL AND revoked_at IS NULL;

DROP INDEX administrator_sessions_active_principal;
DROP INDEX administrator_sessions_active_expiry;
ALTER TABLE administrator_sessions RENAME TO administrator_sessions_v8;
CREATE TABLE administrator_sessions (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    principal_id BLOB NOT NULL CHECK(length(principal_id) = 16),
    credential_id BLOB NOT NULL CHECK(length(credential_id) = 16),
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
    csrf_hash BLOB NOT NULL UNIQUE CHECK(length(csrf_hash) = 32),
    previous_session_id BLOB REFERENCES administrator_sessions(id) ON DELETE SET NULL
        CHECK(previous_session_id IS NULL OR length(previous_session_id) = 16),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    idle_lifetime_seconds INTEGER NOT NULL CHECK(idle_lifetime_seconds BETWEEN 60 AND 86400),
    maximum_sessions INTEGER NOT NULL CHECK(maximum_sessions BETWEEN 1 AND 20),
    idle_expires_at INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(length(revocation_reason) <= 256),
    FOREIGN KEY(principal_id, credential_id)
        REFERENCES administrator_credentials(principal_id, id) ON DELETE CASCADE,
    CHECK(token_hash <> csrf_hash),
    CHECK(previous_session_id IS NULL OR previous_session_id <> id),
    CHECK(last_seen_at >= created_at),
    CHECK(last_seen_at < absolute_expires_at),
    CHECK(idle_expires_at = min(last_seen_at + idle_lifetime_seconds, absolute_expires_at)),
    CHECK(absolute_expires_at > created_at),
    CHECK(
        (revoked_at IS NULL AND revocation_reason = '') OR
        (revoked_at IS NOT NULL AND revoked_at >= created_at AND length(revocation_reason) > 0)
    )
) STRICT;
INSERT INTO administrator_sessions
    (id,principal_id,credential_id,token_hash,csrf_hash,previous_session_id,
     created_at,last_seen_at,idle_lifetime_seconds,maximum_sessions,
     idle_expires_at,absolute_expires_at,revoked_at,revocation_reason)
SELECT id,principal_id,credential_id,token_hash,csrf_hash,
	NULL,
    created_at,
    min(last_seen_at,absolute_expires_at-1),
    idle_lifetime_seconds,
    5,
    min(min(last_seen_at,absolute_expires_at-1)+idle_lifetime_seconds,absolute_expires_at),
    absolute_expires_at,
	COALESCE(revoked_at,max(created_at,unixepoch())),
    CASE WHEN revoked_at IS NULL THEN 'schema v9 security upgrade' ELSE revocation_reason END
FROM administrator_sessions_v8;
INSERT INTO audit_events
    (id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
SELECT randomblob(16),NULL,'system',NULL,'administrator.sessions.invalidate_schema_v9',
    'administrator_session',NULL,'{"reason":"schema v9 security upgrade"}',unixepoch()
WHERE EXISTS(SELECT 1 FROM administrator_sessions_v8 WHERE revoked_at IS NULL);
DROP TABLE administrator_sessions_v8;
CREATE INDEX administrator_sessions_active_principal
    ON administrator_sessions(principal_id, created_at, id)
    WHERE revoked_at IS NULL;
CREATE INDEX administrator_sessions_active_expiry
    ON administrator_sessions(idle_expires_at, absolute_expires_at)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX one_administrator_session_successor
    ON administrator_sessions(previous_session_id)
    WHERE previous_session_id IS NOT NULL;

DROP INDEX audit_events_network_time;
DROP INDEX audit_events_global_time;
DROP INDEX audit_events_actor_time;
ALTER TABLE audit_events RENAME TO audit_events_v8;
CREATE TABLE audit_events (
    id BLOB PRIMARY KEY CHECK(length(id) = 16),
    network_id BLOB REFERENCES networks(id) ON DELETE SET NULL
        CHECK(network_id IS NULL OR length(network_id) = 16),
    actor_kind TEXT NOT NULL CHECK(actor_kind IN (
        'system','node','administrator','service_principal','recovery_grant','unauthenticated','legacy_unknown'
    )),
    actor_id BLOB CHECK(actor_id IS NULL OR (length(actor_id) = 16 AND actor_id <> zeroblob(16))),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 128),
    target_type TEXT NOT NULL CHECK(length(target_type) BETWEEN 1 AND 64),
    target_id BLOB CHECK(target_id IS NULL OR length(target_id) = 16),
    details_json TEXT NOT NULL DEFAULT '{}' CHECK(length(details_json) BETWEEN 2 AND 16384),
    created_at INTEGER NOT NULL,
    CHECK(
        (actor_kind IN ('system','unauthenticated','legacy_unknown') AND actor_id IS NULL) OR
        (actor_kind IN ('node','administrator','service_principal','recovery_grant') AND actor_id IS NOT NULL)
    )
) STRICT;
INSERT INTO audit_events
    (id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at)
SELECT id,network_id,actor_kind,actor_id,action,target_type,target_id,details_json,created_at
FROM audit_events_v8;
DROP TABLE audit_events_v8;
CREATE INDEX audit_events_network_time
    ON audit_events(network_id, created_at DESC, id DESC)
    WHERE network_id IS NOT NULL;
CREATE INDEX audit_events_global_time
    ON audit_events(created_at DESC, id DESC);
CREATE INDEX audit_events_actor_time
    ON audit_events(actor_kind, actor_id, created_at DESC, id DESC);
CREATE TABLE administrator_root_token_rotations (
    rotation_id BLOB PRIMARY KEY CHECK(length(rotation_id) = 16 AND rotation_id <> zeroblob(16)),
    begin_audit_event_id BLOB NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT
        CHECK(length(begin_audit_event_id) = 16),
    complete_audit_event_id BLOB UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT
        CHECK(complete_audit_event_id IS NULL OR length(complete_audit_event_id) = 16),
    begun_at INTEGER NOT NULL,
    completed_at INTEGER,
    CHECK(
        (complete_audit_event_id IS NULL AND completed_at IS NULL) OR
        (complete_audit_event_id IS NOT NULL AND completed_at IS NOT NULL AND completed_at >= begun_at)
    )
) STRICT;
`, `
CREATE TABLE ephemeral_exit_sessions (
    node_id BLOB PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE
        CHECK(length(node_id) = 16 AND node_id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9223372036854775807),
    last_heartbeat_at INTEGER NOT NULL,
    suspect_at INTEGER NOT NULL,
    revoke_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    terminated_at INTEGER,
    CHECK(last_heartbeat_at >= created_at),
    CHECK(suspect_at = last_heartbeat_at + 20),
    CHECK(revoke_at = last_heartbeat_at + 60),
    CHECK(terminated_at IS NULL OR terminated_at >= created_at),
    FOREIGN KEY(network_id,node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE INDEX ephemeral_exit_sessions_revoke
    ON ephemeral_exit_sessions(revoke_at,node_id) WHERE terminated_at IS NULL;
CREATE TRIGGER ephemeral_exit_sessions_identity_immutable
    BEFORE UPDATE OF node_id,network_id,generation,created_at ON ephemeral_exit_sessions
BEGIN
    SELECT RAISE(ABORT, 'ephemeral Exit session identity is immutable');
END;
`, `
CREATE TABLE access_users (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253 AND name = trim(name)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    UNIQUE(network_id,name),
    UNIQUE(network_id,id)
) STRICT;

CREATE TABLE access_teams (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253 AND name = trim(name)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    UNIQUE(network_id,name),
    UNIQUE(network_id,id)
) STRICT;

CREATE TABLE access_team_members (
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    team_id BLOB NOT NULL CHECK(length(team_id) = 16 AND team_id <> zeroblob(16)),
    user_id BLOB NOT NULL CHECK(length(user_id) = 16 AND user_id <> zeroblob(16)),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(team_id,user_id),
    FOREIGN KEY(network_id,team_id) REFERENCES access_teams(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,user_id) REFERENCES access_users(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE INDEX access_team_members_user ON access_team_members(network_id,user_id,team_id);

CREATE TABLE access_grants (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('user','team')),
    user_id BLOB CHECK(user_id IS NULL OR (length(user_id) = 16 AND user_id <> zeroblob(16))),
    team_id BLOB CHECK(team_id IS NULL OR (length(team_id) = 16 AND team_id <> zeroblob(16))),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('network','node','exit')),
    node_id BLOB CHECK(node_id IS NULL OR (length(node_id) = 16 AND node_id <> zeroblob(16))),
    created_at INTEGER NOT NULL,
    CHECK((subject_kind='user' AND user_id IS NOT NULL AND team_id IS NULL) OR
          (subject_kind='team' AND team_id IS NOT NULL AND user_id IS NULL)),
    CHECK((target_kind='network' AND node_id IS NULL) OR
          (target_kind IN ('node','exit') AND node_id IS NOT NULL)),
    FOREIGN KEY(network_id,user_id) REFERENCES access_users(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,team_id) REFERENCES access_teams(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX access_grants_user_target ON access_grants(
    network_id,user_id,target_kind,COALESCE(node_id,zeroblob(16))) WHERE subject_kind='user';
CREATE UNIQUE INDEX access_grants_team_target ON access_grants(
    network_id,team_id,target_kind,COALESCE(node_id,zeroblob(16))) WHERE subject_kind='team';
CREATE INDEX access_grants_node ON access_grants(network_id,node_id) WHERE node_id IS NOT NULL;

ALTER TABLE nodes ADD COLUMN user_id BLOB REFERENCES access_users(id) ON DELETE SET NULL
    CHECK(user_id IS NULL OR (length(user_id) = 16 AND user_id <> zeroblob(16)));
ALTER TABLE enrollment_tokens ADD COLUMN user_id BLOB REFERENCES access_users(id) ON DELETE SET NULL
    CHECK(user_id IS NULL OR (length(user_id) = 16 AND user_id <> zeroblob(16)));
CREATE INDEX nodes_access_user ON nodes(network_id,user_id) WHERE user_id IS NOT NULL;
CREATE INDEX enrollment_tokens_access_user ON enrollment_tokens(network_id,user_id) WHERE user_id IS NOT NULL;

CREATE TRIGGER nodes_access_user_network_insert
    BEFORE INSERT ON nodes WHEN NEW.user_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM access_users WHERE id=NEW.user_id AND network_id=NEW.network_id)
BEGIN
    SELECT RAISE(ABORT, 'node access user must belong to the same network');
END;
CREATE TRIGGER nodes_access_user_network_update
    BEFORE UPDATE OF network_id,user_id ON nodes WHEN NEW.user_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM access_users WHERE id=NEW.user_id AND network_id=NEW.network_id)
BEGIN
    SELECT RAISE(ABORT, 'node access user must belong to the same network');
END;
CREATE TRIGGER enrollment_tokens_access_user_network_insert
    BEFORE INSERT ON enrollment_tokens WHEN NEW.user_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM access_users WHERE id=NEW.user_id AND network_id=NEW.network_id AND enabled=1)
BEGIN
    SELECT RAISE(ABORT, 'enrollment token access user must be enabled in the same network');
END;
CREATE TRIGGER enrollment_tokens_access_user_network_update
    BEFORE UPDATE OF network_id,user_id ON enrollment_tokens WHEN NEW.user_id IS NOT NULL AND NOT EXISTS(
        SELECT 1 FROM access_users WHERE id=NEW.user_id AND network_id=NEW.network_id AND enabled=1)
BEGIN
    SELECT RAISE(ABORT, 'enrollment token access user must be enabled in the same network');
END;

CREATE TRIGGER access_users_identity_immutable
    BEFORE UPDATE OF id,network_id,created_at ON access_users
BEGIN
    SELECT RAISE(ABORT, 'access user identity is immutable');
END;
CREATE TRIGGER access_teams_identity_immutable
    BEFORE UPDATE OF id,network_id,created_at ON access_teams
BEGIN
    SELECT RAISE(ABORT, 'access team identity is immutable');
END;
CREATE TRIGGER access_grants_immutable
    BEFORE UPDATE ON access_grants
BEGIN
    SELECT RAISE(ABORT, 'access grant is immutable');
END;
`, `
CREATE TABLE controller_identity_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    network_id BLOB NOT NULL UNIQUE REFERENCES networks(id) ON DELETE RESTRICT
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    controller_service_id BLOB NOT NULL UNIQUE
        CHECK(length(controller_service_id) = 16 AND controller_service_id <> zeroblob(16)),
    created_at INTEGER NOT NULL
) STRICT;
CREATE TRIGGER controller_identity_state_immutable
    BEFORE UPDATE ON controller_identity_state
BEGIN
    SELECT RAISE(ABORT, 'controller identity binding is immutable');
END;
CREATE TRIGGER controller_identity_state_undeletable
    BEFORE DELETE ON controller_identity_state
BEGIN
    SELECT RAISE(ABORT, 'controller identity binding cannot be deleted');
END;
`, `
CREATE TABLE endpoint_status_latest (
    node_id BLOB PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE
        CHECK(length(node_id) = 16 AND node_id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    observed_at INTEGER NOT NULL,
    valid_for_seconds INTEGER NOT NULL CHECK(valid_for_seconds BETWEEN 10 AND 300),
    expires_at INTEGER NOT NULL CHECK(expires_at = observed_at + valid_for_seconds),
    product_version TEXT NOT NULL CHECK(length(product_version) BETWEEN 1 AND 64),
    platform TEXT NOT NULL CHECK(platform IN ('linux','darwin','windows','other','unknown')),
    certificate_state TEXT NOT NULL CHECK(certificate_state IN ('healthy','renewal_due','expired','revoked','unknown')),
    configuration_state TEXT NOT NULL CHECK(configuration_state IN ('current','stale','expired','unknown')),
    carrier_state TEXT NOT NULL CHECK(carrier_state IN ('direct','relay_quic','relay_tcp','negotiating','degraded','disconnected','unknown')),
    route_state TEXT NOT NULL CHECK(route_state IN ('ready','degraded','unavailable','unknown')),
    selected_exit_state TEXT NOT NULL CHECK(selected_exit_state IN ('not_selected','ready','degraded','unavailable','unknown')),
    cleanup_failure_count INTEGER NOT NULL CHECK(cleanup_failure_count BETWEEN 0 AND 1000000000),
    configuration_epoch INTEGER NOT NULL CHECK(configuration_epoch BETWEEN 0 AND 9223372036854775807),
    FOREIGN KEY(network_id,node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE INDEX endpoint_status_latest_network
    ON endpoint_status_latest(network_id,node_id);
CREATE INDEX endpoint_status_latest_expiry
    ON endpoint_status_latest(expires_at,node_id);
CREATE INDEX certificates_endpoint_status_validity
    ON certificates(network_id,node_id,revoked_at,not_before,not_after);
CREATE TRIGGER endpoint_status_latest_identity_immutable
    BEFORE UPDATE OF node_id,network_id ON endpoint_status_latest
BEGIN
    SELECT RAISE(ABORT, 'endpoint status identity is immutable');
END;
`, `
CREATE UNIQUE INDEX routes_network_identity ON routes(network_id,id);
CREATE TRIGGER routes_identity_immutable
    BEFORE UPDATE OF id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,valid_until,created_at ON routes
BEGIN
    SELECT RAISE(ABORT, 'route identity and target are immutable');
END;

CREATE TABLE access_resources (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253 AND name = trim(name)),
    target_kind TEXT NOT NULL CHECK(target_kind IN ('node','prefix')),
    node_id BLOB CHECK(node_id IS NULL OR (length(node_id) = 16 AND node_id <> zeroblob(16))),
    route_id BLOB CHECK(route_id IS NULL OR (length(route_id) = 16 AND route_id <> zeroblob(16))),
    route_node_id BLOB CHECK(route_node_id IS NULL OR (length(route_node_id) = 16 AND route_node_id <> zeroblob(16))),
    route_prefix_address BLOB CHECK(route_prefix_address IS NULL OR length(route_prefix_address) IN (4,16)),
    route_prefix_length INTEGER CHECK(route_prefix_length IS NULL OR route_prefix_length BETWEEN 1 AND 128),
    prefix_address BLOB CHECK(prefix_address IS NULL OR length(prefix_address) IN (4,16)),
    prefix_length INTEGER CHECK(prefix_length IS NULL OR prefix_length BETWEEN 1 AND 128),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    UNIQUE(network_id,name),
    UNIQUE(network_id,id),
    CHECK(
        (target_kind='node' AND node_id IS NOT NULL AND route_id IS NULL AND route_node_id IS NULL AND
            route_prefix_address IS NULL AND route_prefix_length IS NULL AND prefix_address IS NULL AND prefix_length IS NULL) OR
        (target_kind='prefix' AND node_id IS NULL AND route_id IS NOT NULL AND route_node_id IS NOT NULL AND
            route_prefix_address IS NOT NULL AND route_prefix_length IS NOT NULL AND prefix_address IS NOT NULL AND
            length(route_prefix_address)=length(prefix_address) AND
            ((length(route_prefix_address)=4 AND route_prefix_length BETWEEN 1 AND 32) OR
             (length(route_prefix_address)=16 AND route_prefix_length BETWEEN 1 AND 128)) AND
            ((length(prefix_address)=4 AND prefix_length BETWEEN 1 AND 32) OR
             (length(prefix_address)=16 AND prefix_length BETWEEN 1 AND 128)))
    ),
    FOREIGN KEY(network_id,node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,route_node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,route_id) REFERENCES routes(network_id,id) ON DELETE CASCADE
) STRICT;

CREATE TABLE access_services (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 253 AND name = trim(name)),
    protocol TEXT NOT NULL CHECK(protocol IN ('any','tcp','udp','icmp','icmpv6')),
    ports_sealed INTEGER NOT NULL DEFAULT 0 CHECK(ports_sealed IN (0,1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    UNIQUE(network_id,name),
    UNIQUE(network_id,id)
) STRICT;
CREATE TRIGGER access_services_staged_insert
    BEFORE INSERT ON access_services WHEN NEW.ports_sealed<>0
BEGIN
    SELECT RAISE(ABORT, 'access service must begin with staged ports');
END;

CREATE TABLE access_service_ports (
    service_id BLOB NOT NULL REFERENCES access_services(id) ON DELETE CASCADE
        CHECK(length(service_id) = 16 AND service_id <> zeroblob(16)),
    first_port INTEGER NOT NULL CHECK(first_port BETWEEN 1 AND 65535),
    last_port INTEGER NOT NULL CHECK(last_port BETWEEN first_port AND 65535),
    PRIMARY KEY(service_id,first_port,last_port)
) STRICT;
CREATE TRIGGER access_service_ports_staged_insert
    BEFORE INSERT ON access_service_ports WHEN NOT EXISTS(
        SELECT 1 FROM access_services WHERE id=NEW.service_id AND protocol IN ('tcp','udp') AND ports_sealed=0)
BEGIN
    SELECT RAISE(ABORT, 'ports may be inserted only while creating a TCP or UDP service');
END;
CREATE TRIGGER access_services_seal
    BEFORE UPDATE OF ports_sealed ON access_services WHEN
        OLD.ports_sealed<>0 OR NEW.ports_sealed<>1 OR
        (NEW.protocol IN ('tcp','udp') AND NOT EXISTS(
            SELECT 1 FROM access_service_ports WHERE service_id=NEW.id)) OR
        (NEW.protocol NOT IN ('tcp','udp') AND EXISTS(
            SELECT 1 FROM access_service_ports WHERE service_id=NEW.id))
BEGIN
    SELECT RAISE(ABORT, 'access service ports must be complete before sealing');
END;
CREATE TRIGGER access_service_ports_immutable_update
    BEFORE UPDATE ON access_service_ports
BEGIN
    SELECT RAISE(ABORT, 'access service port ranges are immutable');
END;
CREATE TRIGGER access_service_ports_immutable_delete
    BEFORE DELETE ON access_service_ports WHEN EXISTS(
        SELECT 1 FROM access_services WHERE id=OLD.service_id AND ports_sealed=1)
BEGIN
    SELECT RAISE(ABORT, 'sealed access service port ranges cannot be deleted');
END;

CREATE TABLE access_resource_grants (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16 AND network_id <> zeroblob(16)),
    subject_kind TEXT NOT NULL CHECK(subject_kind IN ('user','team')),
    user_id BLOB CHECK(user_id IS NULL OR (length(user_id) = 16 AND user_id <> zeroblob(16))),
    team_id BLOB CHECK(team_id IS NULL OR (length(team_id) = 16 AND team_id <> zeroblob(16))),
    resource_id BLOB NOT NULL CHECK(length(resource_id) = 16 AND resource_id <> zeroblob(16)),
    service_id BLOB NOT NULL CHECK(length(service_id) = 16 AND service_id <> zeroblob(16)),
    created_at INTEGER NOT NULL,
    CHECK((subject_kind='user' AND user_id IS NOT NULL AND team_id IS NULL) OR
          (subject_kind='team' AND team_id IS NOT NULL AND user_id IS NULL)),
    FOREIGN KEY(network_id,user_id) REFERENCES access_users(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,team_id) REFERENCES access_teams(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,resource_id) REFERENCES access_resources(network_id,id) ON DELETE CASCADE,
    FOREIGN KEY(network_id,service_id) REFERENCES access_services(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX access_resource_grants_user ON access_resource_grants(
    network_id,user_id,resource_id,service_id) WHERE subject_kind='user';
CREATE UNIQUE INDEX access_resource_grants_team ON access_resource_grants(
    network_id,team_id,resource_id,service_id) WHERE subject_kind='team';
CREATE INDEX access_resource_grants_resource ON access_resource_grants(network_id,resource_id);
CREATE INDEX access_resource_grants_service ON access_resource_grants(network_id,service_id);

CREATE TRIGGER access_resources_identity_immutable
    BEFORE UPDATE OF id,network_id,name,target_kind,node_id,route_id,route_node_id,route_prefix_address,
        route_prefix_length,prefix_address,prefix_length,created_at ON access_resources
BEGIN
    SELECT RAISE(ABORT, 'access resource identity is immutable');
END;
CREATE TRIGGER access_services_identity_immutable
    BEFORE UPDATE OF id,network_id,name,protocol,created_at ON access_services
BEGIN
    SELECT RAISE(ABORT, 'access service identity is immutable');
END;
CREATE TRIGGER access_resource_grants_immutable
    BEFORE UPDATE ON access_resource_grants
BEGIN
    SELECT RAISE(ABORT, 'access resource grant is immutable');
END;
`, `
CREATE TABLE automation_service_principals (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    name TEXT NOT NULL UNIQUE CHECK(
        length(name) BETWEEN 3 AND 64 AND
        name = trim(name) AND
        name GLOB '[a-z0-9]*' AND
        substr(name, -1, 1) GLOB '[a-z0-9]' AND
        name NOT GLOB '*[^a-z0-9._-]*'
    ),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    all_networks INTEGER NOT NULL DEFAULT 0 CHECK(all_networks IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK(updated_at >= created_at),
    disabled_at INTEGER,
    CHECK(
        (enabled = 1 AND disabled_at IS NULL) OR
        (enabled = 0 AND disabled_at IS NOT NULL AND disabled_at >= created_at)
    )
) STRICT;

CREATE TABLE automation_service_principal_networks (
    principal_id BLOB NOT NULL REFERENCES automation_service_principals(id) ON DELETE CASCADE
        CHECK(length(principal_id) = 16),
    network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE
        CHECK(length(network_id) = 16),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(principal_id,network_id)
) STRICT;
CREATE INDEX automation_service_principal_networks_network
    ON automation_service_principal_networks(network_id,principal_id);

CREATE TABLE automation_service_principal_permissions (
    principal_id BLOB NOT NULL REFERENCES automation_service_principals(id) ON DELETE CASCADE
        CHECK(length(principal_id) = 16),
    operation TEXT NOT NULL CHECK(operation IN (
        'network.list','network.read','network.create','enrollment.issue',
        'bootstrap_bundle.create','node.read','node.manage','route.read','route.manage',
        'acl.read','acl.manage','relay.read','relay.manage','certificate.read',
        'certificate.revoke','audit.read','audit.read_global'
    )),
    created_at INTEGER NOT NULL,
    PRIMARY KEY(principal_id,operation)
) STRICT;

CREATE TABLE automation_service_access_tokens (
    id BLOB PRIMARY KEY CHECK(length(id) = 16 AND id <> zeroblob(16)),
    principal_id BLOB NOT NULL REFERENCES automation_service_principals(id) ON DELETE CASCADE
        CHECK(length(principal_id) = 16),
    label TEXT NOT NULL CHECK(
        length(CAST(label AS BLOB)) BETWEEN 1 AND 64 AND
        label = trim(label) AND
        instr(label,char(0)) = 0
    ),
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash) = 32),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > created_at),
    revoked_at INTEGER,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK(
        length(CAST(revocation_reason AS BLOB)) <= 256 AND
        (revocation_reason = '' OR revocation_reason = trim(revocation_reason)) AND
        instr(revocation_reason,char(0)) = 0
    ),
    CHECK(
        (revoked_at IS NULL AND revocation_reason = '') OR
        (revoked_at IS NOT NULL AND revoked_at >= created_at AND length(revocation_reason) > 0)
    )
) STRICT;
CREATE INDEX automation_service_access_tokens_principal
    ON automation_service_access_tokens(principal_id,created_at,id);
CREATE INDEX automation_service_access_tokens_active_expiry
    ON automation_service_access_tokens(expires_at,id) WHERE revoked_at IS NULL;

CREATE TRIGGER automation_service_principals_identity_immutable
    BEFORE UPDATE OF id,name,all_networks,created_at ON automation_service_principals
BEGIN
    SELECT RAISE(ABORT, 'automation service principal identity is immutable');
END;
CREATE TRIGGER automation_service_principals_enabled_limit
    BEFORE INSERT ON automation_service_principals
    WHEN NEW.enabled=1 AND (SELECT count(*) FROM automation_service_principals WHERE enabled=1) >= 100
BEGIN
    SELECT RAISE(ABORT, 'enabled automation service principal limit reached');
END;
CREATE TRIGGER automation_service_principal_disable_immutable
    BEFORE UPDATE OF enabled,disabled_at ON automation_service_principals
    WHEN OLD.enabled=0
BEGIN
    SELECT RAISE(ABORT, 'disabled automation service principal is immutable');
END;
CREATE TRIGGER automation_service_principal_scope_requires_scoped
    BEFORE INSERT ON automation_service_principal_networks
BEGIN
    SELECT CASE WHEN COALESCE((SELECT all_networks FROM automation_service_principals
        WHERE id=NEW.principal_id),1) <> 0
        THEN RAISE(ABORT, 'all-network service principal cannot retain network scopes') END;
END;
CREATE TRIGGER automation_service_principal_scope_immutable
    BEFORE UPDATE ON automation_service_principal_networks
BEGIN
    SELECT RAISE(ABORT, 'automation service principal scope is immutable');
END;
CREATE TRIGGER automation_service_principal_permission_immutable
    BEFORE UPDATE ON automation_service_principal_permissions
BEGIN
    SELECT RAISE(ABORT, 'automation service principal permission is immutable');
END;
CREATE TRIGGER automation_service_access_token_immutable
    BEFORE UPDATE OF id,principal_id,label,token_hash,created_at,expires_at
    ON automation_service_access_tokens
BEGIN
    SELECT RAISE(ABORT, 'automation service access token identity is immutable');
END;
CREATE TRIGGER automation_service_access_token_unrevoked_limit
    BEFORE INSERT ON automation_service_access_tokens
    WHEN NEW.revoked_at IS NULL AND (
        SELECT count(*) FROM automation_service_access_tokens
        WHERE principal_id=NEW.principal_id AND revoked_at IS NULL
    ) >= 100
BEGIN
    SELECT RAISE(ABORT, 'unrevoked automation service access token limit reached');
END;
CREATE TRIGGER automation_service_access_token_revocation_immutable
    BEFORE UPDATE OF revoked_at,revocation_reason ON automation_service_access_tokens
    WHEN OLD.revoked_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'automation service access token revocation is immutable');
END;
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
