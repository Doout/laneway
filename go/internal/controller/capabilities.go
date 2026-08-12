package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

// NodePolicyCapabilities are privileges granted by the controller. Transport,
// address-family, and implementation support are negotiated separately.
const NodePolicyCapabilities = protocol.CapabilitySubnetRouterV1 | protocol.CapabilityExitNodeV1

func routePolicyCapability(kind RouteKind) protocol.Capability {
	switch kind {
	case RouteKindSubnet:
		return protocol.CapabilitySubnetRouterV1
	case RouteKindExit:
		return protocol.CapabilityExitNodeV1
	default:
		return 0
	}
}

// SetNodeCapabilities atomically replaces controller-authorized node-role
// capabilities and advances the network epoch.
func (s *Store) SetNodeCapabilities(ctx context.Context, nodeID identity.NodeID, capabilities protocol.Capability) (uint64, error) {
	if nodeID.IsZero() || capabilities&^NodePolicyCapabilities != 0 {
		return 0, fmt.Errorf("%w: unsupported node policy capabilities %s", ErrInvalid, capabilities)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin node capability update: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT network_id,enabled_capabilities FROM nodes WHERE id=? AND revoked_at IS NULL`, idBytes(nodeID)).Scan(&networkBytes, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read node capabilities: %w", err)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if uint64(current) == uint64(capabilities) {
		return currentEpochTx(ctx, tx, networkID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET enabled_capabilities=? WHERE id=? AND revoked_at IS NULL`, uint64(capabilities), idBytes(nodeID)); err != nil {
		return 0, fmt.Errorf("update node capabilities: %w", err)
	}
	for kind, required := range map[RouteKind]protocol.Capability{
		RouteKindSubnet: protocol.CapabilitySubnetRouterV1,
		RouteKindExit:   protocol.CapabilityExitNodeV1,
	} {
		if capabilities.Has(required) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=?
			WHERE node_id=? AND kind=? AND state IN ('advertised','approved')`, unix(now), idBytes(nodeID), string(kind)); err != nil {
			return 0, fmt.Errorf("withdraw routes after capability removal: %w", err)
		}
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	details, _ := json.Marshal(struct {
		Capabilities uint64 `json:"capabilities"`
	}{uint64(capabilities)})
	target := identity.ID(nodeID)
	if err := auditTx(ctx, tx, networkID, nil, "node.capabilities.set", "node", &target, string(details), now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit node capabilities: %w", err)
	}
	return epoch, nil
}

func (s *Store) AdministratorSetNodeCapabilities(ctx context.Context, decision adminauth.Decision, nodeID identity.NodeID, capabilities protocol.Capability) (uint64, error) {
	if nodeID.IsZero() || capabilities&^NodePolicyCapabilities != 0 {
		return 0, fmt.Errorf("%w: unsupported node policy capabilities %s", ErrInvalid, capabilities)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin authorized node capability update: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	objectID := identity.ID(nodeID)
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision,
		administratorNodeCapabilitiesPolicy, objectID, `SELECT network_id FROM nodes WHERE id=?`, idBytes(nodeID))
	if err != nil {
		return 0, err
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT enabled_capabilities FROM nodes WHERE id=? AND revoked_at IS NULL`, idBytes(nodeID)).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read node capabilities: %w", err)
	}
	if uint64(current) == uint64(capabilities) {
		epoch, err := currentEpochTx(ctx, tx, networkID)
		if err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return epoch, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET enabled_capabilities=? WHERE id=? AND revoked_at IS NULL`, uint64(capabilities), idBytes(nodeID)); err != nil {
		return 0, fmt.Errorf("update node capabilities: %w", err)
	}
	for kind, required := range map[RouteKind]protocol.Capability{
		RouteKindSubnet: protocol.CapabilitySubnetRouterV1,
		RouteKindExit:   protocol.CapabilityExitNodeV1,
	} {
		if capabilities.Has(required) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=?
			WHERE node_id=? AND kind=? AND state IN ('advertised','approved')`, unix(now), idBytes(nodeID), string(kind)); err != nil {
			return 0, fmt.Errorf("withdraw routes after capability removal: %w", err)
		}
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	details, _ := json.Marshal(struct {
		Capabilities uint64 `json:"capabilities"`
	}{uint64(capabilities)})
	if err := auditActorTx(ctx, tx, &networkID, actor, "node.capabilities.set", "node", &objectID, string(details), now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit authorized node capabilities: %w", err)
	}
	return epoch, nil
}
