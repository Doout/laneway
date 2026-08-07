package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"laneway.dev/laneway/internal/identity"
)

func (s *Store) AddACLRule(ctx context.Context, networkID identity.NetworkID, priority uint32, action ACLAction, selectorJSON, description string) (ACLRule, uint64, error) {
	if action != ACLActionAccept && action != ACLActionDeny {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL action", ErrInvalid)
	}
	if len(selectorJSON) < 2 || len(selectorJSON) > MaxAuditDetailLength || !json.Valid([]byte(selectorJSON)) {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL selector JSON", ErrInvalid)
	}
	if len(description) > 1024 || strings.IndexByte(description, 0) >= 0 {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL description", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return ACLRule{}, 0, err
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ACLRule{}, 0, fmt.Errorf("begin add ACL rule: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO acl_rules
        (id,network_id,priority,action,selector_json,description,enabled,created_at,updated_at)
        VALUES(?,?,?,?,?,?,1,?,?)`, idBytes(id), idBytes(networkID), priority, string(action), selectorJSON, description, unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return ACLRule{}, 0, fmt.Errorf("%w: missing network or invalid ACL rule", ErrNotFound)
		}
		return ACLRule{}, 0, fmt.Errorf("insert ACL rule: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return ACLRule{}, 0, err
	}
	if err := auditTx(ctx, tx, networkID, nil, "acl_rule.create", "acl_rule", &id, `{}`, now); err != nil {
		return ACLRule{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return ACLRule{}, 0, err
	}
	return ACLRule{ID: id, NetworkID: networkID, Priority: priority, Action: action, SelectorJSON: selectorJSON, Description: description, Enabled: true, CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) DeleteACLRule(ctx context.Context, ruleID identity.ID) (uint64, error) {
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var networkBytes []byte
	err = tx.QueryRowContext(ctx, `SELECT network_id FROM acl_rules WHERE id=?`, idBytes(ruleID)).Scan(&networkBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if _, err := tx.ExecContext(ctx, `DELETE FROM acl_rules WHERE id=?`, idBytes(ruleID)); err != nil {
		return 0, err
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditTx(ctx, tx, networkID, nil, "acl_rule.delete", "acl_rule", &ruleID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return epoch, nil
}
