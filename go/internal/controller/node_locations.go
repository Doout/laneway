package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodelocation"
)

var (
	administratorNodeLocationsPolicy     = mustAdministratorResourcePolicy(http.MethodGet, "/v1/admin/networks/{network_id}/node-locations")
	administratorNodeLocationSetPolicy   = mustAdministratorResourcePolicy(http.MethodPut, "/v1/admin/nodes/{node_id}/location")
	administratorNodeLocationClearPolicy = mustAdministratorResourcePolicy(http.MethodDelete, "/v1/admin/nodes/{node_id}/location")
)

type NodeLocation struct {
	NodeID         string                 `json:"node_id"`
	Location       *nodelocation.Location `json:"location,omitempty"`
	Source         string                 `json:"source"`
	ObservedAt     int64                  `json:"observed_at_unix_seconds"`
	Stale          bool                   `json:"stale"`
	LastSeen       int64                  `json:"last_seen_unix_seconds"`
	Online         bool                   `json:"online"`
	IdentityActive bool                   `json:"identity_active"`
	PublicIP       string                 `json:"public_ip,omitempty"`
}

// RecordNodeLocation stores only the latest public IP and location, not history. Unknown observations
// clear the previous inferred location, without changing a manual override.
func (s *Store) RecordNodeLocation(ctx context.Context, caller identity.NodeIdentity, location *nodelocation.Location, at time.Time, publicIP ...string) error {
	if err := caller.Validate(); err != nil {
		return err
	}
	if at.IsZero() {
		return ErrInvalid
	}
	var payload any
	if location != nil {
		if err := location.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		encoded, err := json.Marshal(location)
		if err != nil {
			return err
		}
		payload = string(encoded)
	}
	address := ""
	if len(publicIP) > 0 {
		address = publicIP[0]
	}
	if address != "" {
		ip, err := netip.ParseAddr(address)
		if err != nil || !nodelocation.PublicIP(ip) {
			return ErrInvalid
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_locations(node_id,automatic_json,observed_at,public_ip)
		SELECT id,?,?,? FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL
		AND (enrollment_class<>'ephemeral' OR lease_expires_at>?)
		ON CONFLICT(node_id) DO UPDATE SET automatic_json=excluded.automatic_json,observed_at=excluded.observed_at,public_ip=excluded.public_ip
		WHERE excluded.observed_at>=node_locations.observed_at`, payload, unix(at), address, idBytes(caller.NodeID), idBytes(caller.NetworkID), unix(at))
	return err
}

func (s *Store) AdministratorSetNodeLocation(ctx context.Context, decision adminauth.Decision, nodeID identity.NodeID, location *nodelocation.Location) error {
	policy := administratorNodeLocationClearPolicy
	var payload any
	if location != nil {
		policy = administratorNodeLocationSetPolicy
		if err := location.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		value := *location
		value.AccuracyKM = 0
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		payload = string(encoded)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	objectID := identity.ID(nodeID)
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, policy, objectID,
		`SELECT network_id FROM nodes WHERE id=?`, idBytes(nodeID))
	if err != nil {
		return err
	}
	at := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO node_locations(node_id,manual_json,manual_updated_at,observed_at) VALUES(?,?,?,0)
		ON CONFLICT(node_id) DO UPDATE SET manual_json=excluded.manual_json,manual_updated_at=excluded.manual_updated_at`, idBytes(nodeID), payload, unix(at)); err != nil {
		return err
	}
	action := "node.location.set"
	if location == nil {
		action = "node.location.clear"
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, action, "node", &objectID, `{}`, at); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AdministratorNodeLocations(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, limit int) ([]NodeLocation, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorNodeLocationsPolicy, networkID); err != nil {
		return nil, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.id,COALESCE(l.manual_json,l.automatic_json,''),
		CASE WHEN l.manual_json IS NOT NULL THEN 'manual' WHEN l.automatic_json IS NOT NULL THEN 'ip' ELSE 'unknown' END,
		CASE WHEN l.manual_json IS NOT NULL THEN l.manual_updated_at ELSE COALESCE(l.observed_at,0) END,
		COALESCE(l.observed_at,0),COALESCE(l.public_ip,''),
		CASE WHEN n.revoked_at IS NULL AND (n.enrollment_class<>'ephemeral' OR n.lease_expires_at>?)
		AND EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=n.id AND c.revoked_at IS NULL AND c.not_before<=? AND c.not_after>?) THEN 1 ELSE 0 END
		FROM nodes n LEFT JOIN node_locations l ON l.node_id=n.id WHERE n.network_id=? ORDER BY n.created_at,n.id LIMIT ?`, s.now().Unix(), s.now().Unix(), s.now().Unix(), idBytes(networkID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]NodeLocation, 0)
	for rows.Next() {
		var raw []byte
		var payload string
		var v NodeLocation
		var active bool
		if err := rows.Scan(&raw, &payload, &v.Source, &v.ObservedAt, &v.LastSeen, &v.PublicIP, &active); err != nil {
			return nil, err
		}
		id, err := scanID(raw)
		if err != nil {
			return nil, err
		}
		v.NodeID = id.String()
		v.Online = active && v.LastSeen > 0 && s.now().Unix()-v.LastSeen < 360
		v.IdentityActive = active
		if payload != "" {
			if err := json.Unmarshal([]byte(payload), &v.Location); err != nil {
				return nil, err
			}
		}
		v.Stale = v.Source == "ip" && s.now().Unix()-v.ObservedAt >= int64((24*time.Hour)/time.Second)
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return values, nil
}
