CREATE TABLE node_credential_recovery_grants (
 token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),
 network_id BLOB NOT NULL REFERENCES networks(id),
 node_id BLOB NOT NULL REFERENCES nodes(id),
 certificate_id BLOB NOT NULL REFERENCES certificates(id),
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX node_credential_recovery_node ON node_credential_recovery_grants(node_id);
CREATE TABLE fleet_updates (
 id BLOB PRIMARY KEY CHECK(length(id)=16),
 network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 version TEXT NOT NULL,
 component TEXT NOT NULL CHECK(component IN ('node','connector')),
 channel TEXT NOT NULL CHECK(channel IN ('stable','manual')),
 target_count INTEGER NOT NULL CHECK(target_count BETWEEN 1 AND 200),
 canary_count INTEGER NOT NULL CHECK(canary_count BETWEEN 1 AND target_count),
 state TEXT NOT NULL CHECK(state IN ('canary','rollout','paused','complete','cancelled')),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 UNIQUE(network_id,id)
) STRICT;
CREATE TABLE fleet_update_targets (
 update_id BLOB NOT NULL,
 network_id BLOB NOT NULL,
 node_id BLOB NOT NULL,
 canary INTEGER NOT NULL CHECK(canary IN (0,1)),
 state TEXT NOT NULL CHECK(state IN ('pending','running','healthy','rolled_back','failed')),
 previous_version TEXT NOT NULL DEFAULT '',
 observed_version TEXT NOT NULL DEFAULT '',
 detail TEXT NOT NULL DEFAULT '',
 updated_at INTEGER NOT NULL,
 PRIMARY KEY(update_id,node_id),
 FOREIGN KEY(network_id,update_id) REFERENCES fleet_updates(network_id,id) ON DELETE CASCADE,
 FOREIGN KEY(network_id,node_id) REFERENCES nodes(network_id,id) ON DELETE CASCADE
) STRICT;
CREATE INDEX fleet_update_node_queue ON fleet_update_targets(node_id,state);
CREATE TABLE fleet_update_agents (
 node_id BLOB PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 component TEXT NOT NULL CHECK(component IN ('node','connector')),
 channel TEXT NOT NULL CHECK(channel IN ('stable','manual')),
 version TEXT NOT NULL,
 last_polled_at INTEGER NOT NULL
) STRICT;
CREATE TABLE node_topology (
 node_id BLOB PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 observed_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 peers_json TEXT NOT NULL CHECK(length(peers_json)<=32768)
) STRICT;
CREATE INDEX node_topology_expiry ON node_topology(expires_at);
CREATE TABLE operational_alerts (
 id TEXT PRIMARY KEY, network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 node_id BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','acknowledged','resolved')),
 summary TEXT NOT NULL, remediation_path TEXT NOT NULL,
 opened_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, acknowledged_at INTEGER,
 UNIQUE(node_id,kind)
) STRICT;
CREATE TABLE operational_alert_events (
 id TEXT PRIMARY KEY, alert_id TEXT NOT NULL REFERENCES operational_alerts(id) ON DELETE CASCADE,
 payload TEXT NOT NULL, created_at INTEGER NOT NULL,
 delivery_state TEXT NOT NULL DEFAULT 'pending' CHECK(delivery_state IN ('pending','delivered','failed','disabled')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX operational_alert_delivery ON operational_alert_events(delivery_state,next_attempt_at);
CREATE TABLE policy_revisions (
 network_id BLOB NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL CHECK(revision>=1),
 configuration_epoch INTEGER NOT NULL CHECK(configuration_epoch>=1),
 rules_json TEXT NOT NULL CHECK(json_valid(rules_json)),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(network_id,revision), UNIQUE(network_id,configuration_epoch)
) STRICT;
