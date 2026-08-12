package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"laneway.dev/laneway/internal/adminauth"
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

func (s *Store) UpdateACLRule(ctx context.Context, ruleID identity.ID, priority uint32, action ACLAction, selectorJSON, description string, enabled bool) (ACLRule, uint64, error) {
	if action != ACLActionAccept && action != ACLActionDeny {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL action", ErrInvalid)
	}
	if len(selectorJSON) < 2 || len(selectorJSON) > MaxAuditDetailLength || !json.Valid([]byte(selectorJSON)) {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL selector JSON", ErrInvalid)
	}
	if len(description) > 1024 || strings.IndexByte(description, 0) >= 0 {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL description", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ACLRule{}, 0, fmt.Errorf("begin update ACL rule: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var created int64
	err = tx.QueryRowContext(ctx, `SELECT network_id,created_at FROM acl_rules WHERE id=?`, idBytes(ruleID)).Scan(&networkBytes, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ACLRule{}, 0, ErrNotFound
	}
	if err != nil {
		return ACLRule{}, 0, fmt.Errorf("read ACL rule: %w", err)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return ACLRule{}, 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if _, err := tx.ExecContext(ctx, `UPDATE acl_rules SET priority=?,action=?,selector_json=?,description=?,enabled=?,updated_at=? WHERE id=?`,
		priority, string(action), selectorJSON, description, enabled, unix(now), idBytes(ruleID)); err != nil {
		return ACLRule{}, 0, fmt.Errorf("update ACL rule: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return ACLRule{}, 0, err
	}
	details := fmt.Sprintf(`{"enabled":%t}`, enabled)
	if err := auditTx(ctx, tx, networkID, nil, "acl_rule.update", "acl_rule", &ruleID, details, now); err != nil {
		return ACLRule{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return ACLRule{}, 0, err
	}
	return ACLRule{ID: ruleID, NetworkID: networkID, Priority: priority, Action: action, SelectorJSON: selectorJSON, Description: description, Enabled: enabled, CreatedAt: fromUnix(created), UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorAddACLRule(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, priority uint32, action ACLAction, selectorJSON, description string) (ACLRule, uint64, error) {
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ACLRule{}, 0, fmt.Errorf("begin authorized ACL creation: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorACLCreatePolicy, networkID)
	if err != nil {
		return ACLRule{}, 0, err
	}
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
	if err := auditActorTx(ctx, tx, &networkID, actor, "acl_rule.create", "acl_rule", &id, `{}`, now); err != nil {
		return ACLRule{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return ACLRule{}, 0, err
	}
	return ACLRule{ID: id, NetworkID: networkID, Priority: priority, Action: action, SelectorJSON: selectorJSON, Description: description, Enabled: true, CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorDeleteACLRule(ctx context.Context, decision adminauth.Decision, ruleID identity.ID) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := s.now()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision,
		administratorACLDeletePolicy, ruleID, `SELECT network_id FROM acl_rules WHERE id=?`, idBytes(ruleID))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM acl_rules WHERE id=?`, idBytes(ruleID)); err != nil {
		return 0, err
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, "acl_rule.delete", "acl_rule", &ruleID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return epoch, nil
}

func (s *Store) AdministratorUpdateACLRule(ctx context.Context, decision adminauth.Decision, ruleID identity.ID, priority uint32, action ACLAction, selectorJSON, description string, enabled bool) (ACLRule, uint64, error) {
	if action != ACLActionAccept && action != ACLActionDeny {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL action", ErrInvalid)
	}
	if len(selectorJSON) < 2 || len(selectorJSON) > MaxAuditDetailLength || !json.Valid([]byte(selectorJSON)) {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL selector JSON", ErrInvalid)
	}
	if len(description) > 1024 || strings.IndexByte(description, 0) >= 0 {
		return ACLRule{}, 0, fmt.Errorf("%w: ACL description", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ACLRule{}, 0, fmt.Errorf("begin authorized ACL update: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision,
		administratorACLUpdatePolicy, ruleID, `SELECT network_id FROM acl_rules WHERE id=?`, idBytes(ruleID))
	if err != nil {
		return ACLRule{}, 0, err
	}
	var created int64
	if err := tx.QueryRowContext(ctx, `SELECT created_at FROM acl_rules WHERE id=?`, idBytes(ruleID)).Scan(&created); err != nil {
		return ACLRule{}, 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE acl_rules SET priority=?,action=?,selector_json=?,description=?,enabled=?,updated_at=? WHERE id=?`,
		priority, string(action), selectorJSON, description, enabled, unix(now), idBytes(ruleID)); err != nil {
		return ACLRule{}, 0, fmt.Errorf("update ACL rule: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return ACLRule{}, 0, err
	}
	details := fmt.Sprintf(`{"enabled":%t}`, enabled)
	if err := auditActorTx(ctx, tx, &networkID, actor, "acl_rule.update", "acl_rule", &ruleID, details, now); err != nil {
		return ACLRule{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return ACLRule{}, 0, err
	}
	return ACLRule{ID: ruleID, NetworkID: networkID, Priority: priority, Action: action, SelectorJSON: selectorJSON, Description: description, Enabled: enabled, CreatedAt: fromUnix(created), UpdatedAt: now}, epoch, nil
}
