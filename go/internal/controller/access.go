package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func (s *Store) AdministratorAccessInventory(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID) (AccessInventory, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessInventory{}, fmt.Errorf("begin access inventory: %w", err)
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessInventoryPolicy, networkID); err != nil {
		return AccessInventory{}, err
	}
	inventory, err := accessInventoryTx(ctx, tx, networkID)
	if err != nil {
		return AccessInventory{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessInventory{}, fmt.Errorf("commit access inventory authorization: %w", err)
	}
	return inventory, nil
}

func accessInventoryTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID) (AccessInventory, error) {
	var result AccessInventory
	userRows, err := tx.QueryContext(ctx, `SELECT id,name,enabled,created_at,updated_at FROM access_users WHERE network_id=? ORDER BY name,id`, idBytes(networkID))
	if err != nil {
		return result, fmt.Errorf("read access users: %w", err)
	}
	for userRows.Next() {
		var raw []byte
		var user AccessUser
		var enabled int
		var created, updated int64
		if err := userRows.Scan(&raw, &user.Name, &enabled, &created, &updated); err != nil {
			userRows.Close()
			return result, fmt.Errorf("scan access user: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			userRows.Close()
			return result, err
		}
		user.ID, user.NetworkID, user.Enabled = id, networkID, enabled == 1
		user.CreatedAt, user.UpdatedAt = fromUnix(created), fromUnix(updated)
		result.Users = append(result.Users, user)
	}
	if err := userRows.Close(); err != nil {
		return result, fmt.Errorf("close access users: %w", err)
	}
	if err := userRows.Err(); err != nil {
		return result, fmt.Errorf("iterate access users: %w", err)
	}

	teamRows, err := tx.QueryContext(ctx, `SELECT id,name,created_at,updated_at FROM access_teams WHERE network_id=? ORDER BY name,id`, idBytes(networkID))
	if err != nil {
		return result, fmt.Errorf("read access teams: %w", err)
	}
	for teamRows.Next() {
		var raw []byte
		var team AccessTeam
		var created, updated int64
		if err := teamRows.Scan(&raw, &team.Name, &created, &updated); err != nil {
			teamRows.Close()
			return result, fmt.Errorf("scan access team: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			teamRows.Close()
			return result, err
		}
		team.ID, team.NetworkID = id, networkID
		team.CreatedAt, team.UpdatedAt = fromUnix(created), fromUnix(updated)
		result.Teams = append(result.Teams, team)
	}
	if err := teamRows.Close(); err != nil {
		return result, fmt.Errorf("close access teams: %w", err)
	}
	if err := teamRows.Err(); err != nil {
		return result, fmt.Errorf("iterate access teams: %w", err)
	}

	memberRows, err := tx.QueryContext(ctx, `SELECT team_id,user_id,created_at FROM access_team_members WHERE network_id=? ORDER BY team_id,user_id`, idBytes(networkID))
	if err != nil {
		return result, fmt.Errorf("read access team members: %w", err)
	}
	for memberRows.Next() {
		var teamRaw, userRaw []byte
		var created int64
		if err := memberRows.Scan(&teamRaw, &userRaw, &created); err != nil {
			memberRows.Close()
			return result, fmt.Errorf("scan access team member: %w", err)
		}
		teamID, err := scanID(teamRaw)
		if err != nil {
			memberRows.Close()
			return result, err
		}
		userID, err := scanID(userRaw)
		if err != nil {
			memberRows.Close()
			return result, err
		}
		result.Memberships = append(result.Memberships, AccessTeamMember{NetworkID: networkID, TeamID: teamID, UserID: userID, CreatedAt: fromUnix(created)})
	}
	if err := memberRows.Close(); err != nil {
		return result, fmt.Errorf("close access team members: %w", err)
	}
	if err := memberRows.Err(); err != nil {
		return result, fmt.Errorf("iterate access team members: %w", err)
	}

	grantRows, err := tx.QueryContext(ctx, `SELECT id,subject_kind,user_id,team_id,target_kind,node_id,created_at FROM access_grants WHERE network_id=? ORDER BY created_at,id`, idBytes(networkID))
	if err != nil {
		return result, fmt.Errorf("read access grants: %w", err)
	}
	for grantRows.Next() {
		grant, err := scanAccessGrant(grantRows, networkID)
		if err != nil {
			grantRows.Close()
			return result, err
		}
		result.Grants = append(result.Grants, grant)
	}
	if err := grantRows.Close(); err != nil {
		return result, fmt.Errorf("close access grants: %w", err)
	}
	if err := grantRows.Err(); err != nil {
		return result, fmt.Errorf("iterate access grants: %w", err)
	}
	if err := appendNamedAccessInventoryTx(ctx, tx, networkID, &result); err != nil {
		return result, err
	}
	return result, nil
}

type accessGrantScanner interface {
	Scan(...any) error
}

func scanAccessGrant(scanner accessGrantScanner, networkID identity.NetworkID) (AccessGrant, error) {
	var idRaw, userRaw, teamRaw, nodeRaw []byte
	var subjectKind, targetKind string
	var created int64
	if err := scanner.Scan(&idRaw, &subjectKind, &userRaw, &teamRaw, &targetKind, &nodeRaw, &created); err != nil {
		return AccessGrant{}, fmt.Errorf("scan access grant: %w", err)
	}
	id, err := scanID(idRaw)
	if err != nil {
		return AccessGrant{}, err
	}
	grant := AccessGrant{ID: id, NetworkID: networkID, SubjectKind: AccessSubjectKind(subjectKind), TargetKind: AccessTargetKind(targetKind), CreatedAt: fromUnix(created)}
	if !grant.SubjectKind.Valid() || !grant.TargetKind.Valid() {
		return AccessGrant{}, errors.New("corrupt access grant kind")
	}
	subjectRaw := userRaw
	if grant.SubjectKind == AccessSubjectTeam {
		subjectRaw = teamRaw
	}
	grant.SubjectID, err = scanID(subjectRaw)
	if err != nil {
		return AccessGrant{}, err
	}
	if grant.TargetKind != AccessTargetNetwork {
		nodeID, err := scanID(nodeRaw)
		if err != nil {
			return AccessGrant{}, err
		}
		value := identity.NodeID(nodeID)
		grant.NodeID = &value
	}
	return grant, nil
}

func (s *Store) AdministratorCreateAccessUser(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, name string) (AccessUser, uint64, error) {
	if err := validateName("user", name); err != nil {
		return AccessUser{}, 0, err
	}
	return s.createAccessUser(ctx, decision, networkID, name)
}

func (s *Store) createAccessUser(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, name string) (AccessUser, uint64, error) {
	id, err := newID()
	if err != nil {
		return AccessUser{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessUser{}, 0, fmt.Errorf("begin create access user: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessUserCreatePolicy, networkID)
	if err != nil {
		return AccessUser{}, 0, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_users(id,network_id,name,enabled,created_at,updated_at) VALUES(?,?,?,1,?,?)`, idBytes(id), idBytes(networkID), name, unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return AccessUser{}, 0, fmt.Errorf("%w: user name already exists", ErrConflict)
		}
		return AccessUser{}, 0, fmt.Errorf("insert access user: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessUser{}, 0, err
	}
	target := id
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_user.create", "access_user", &target, `{}`, now); err != nil {
		return AccessUser{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessUser{}, 0, fmt.Errorf("commit access user: %w", err)
	}
	return AccessUser{ID: id, NetworkID: networkID, Name: name, Enabled: true, CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorSetAccessUserEnabled(ctx context.Context, decision adminauth.Decision, userID identity.ID, enabled bool) (AccessUser, uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessUser{}, 0, fmt.Errorf("begin update access user: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, administratorAccessUserUpdatePolicy, userID, `SELECT network_id FROM access_users WHERE id=?`, idBytes(userID))
	if err != nil {
		return AccessUser{}, 0, err
	}
	var name string
	var current int
	var created int64
	if err := tx.QueryRowContext(ctx, `SELECT name,enabled,created_at FROM access_users WHERE id=?`, idBytes(userID)).Scan(&name, &current, &created); err != nil {
		return AccessUser{}, 0, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `UPDATE access_users SET enabled=?,updated_at=? WHERE id=?`, enabled, unix(now), idBytes(userID)); err != nil {
		return AccessUser{}, 0, fmt.Errorf("update access user: %w", err)
	}
	epoch, err := currentEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessUser{}, 0, err
	}
	if (current == 1) != enabled {
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return AccessUser{}, 0, err
		}
		details, _ := json.Marshal(map[string]bool{"enabled": enabled})
		target := userID
		if err := auditActorTx(ctx, tx, &networkID, actor, "access_user.update", "access_user", &target, string(details), now); err != nil {
			return AccessUser{}, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AccessUser{}, 0, fmt.Errorf("commit access user update: %w", err)
	}
	return AccessUser{ID: userID, NetworkID: networkID, Name: name, Enabled: enabled, CreatedAt: fromUnix(created), UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorCreateAccessTeam(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, name string) (AccessTeam, uint64, error) {
	if err := validateName("team", name); err != nil {
		return AccessTeam{}, 0, err
	}
	id, err := newID()
	if err != nil {
		return AccessTeam{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessTeam{}, 0, fmt.Errorf("begin create access team: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessTeamCreatePolicy, networkID)
	if err != nil {
		return AccessTeam{}, 0, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_teams(id,network_id,name,created_at,updated_at) VALUES(?,?,?,?,?)`, idBytes(id), idBytes(networkID), name, unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return AccessTeam{}, 0, fmt.Errorf("%w: team name already exists", ErrConflict)
		}
		return AccessTeam{}, 0, fmt.Errorf("insert access team: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessTeam{}, 0, err
	}
	target := id
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_team.create", "access_team", &target, `{}`, now); err != nil {
		return AccessTeam{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessTeam{}, 0, fmt.Errorf("commit access team: %w", err)
	}
	return AccessTeam{ID: id, NetworkID: networkID, Name: name, CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorSetAccessTeamMember(ctx context.Context, decision adminauth.Decision, teamID, userID identity.ID, present bool) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin update access team member: %w", err)
	}
	defer tx.Rollback()
	policy := administratorAccessMemberAddPolicy
	if !present {
		policy = administratorAccessMemberDeletePolicy
	}
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, policy, teamID, `SELECT network_id FROM access_teams WHERE id=?`, idBytes(teamID))
	if err != nil {
		return 0, err
	}
	var userNetwork []byte
	if err := tx.QueryRowContext(ctx, `SELECT network_id FROM access_users WHERE id=?`, idBytes(userID)).Scan(&userNetwork); errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	} else if err != nil {
		return 0, fmt.Errorf("read access team member user: %w", err)
	}
	parsedUserNetwork, err := scanID(userNetwork)
	if err != nil || identity.NetworkID(parsedUserNetwork) != networkID {
		return 0, fmt.Errorf("%w: team and user must belong to the same network", ErrInvalid)
	}
	now := s.now()
	changed := false
	if present {
		result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO access_team_members(network_id,team_id,user_id,created_at) VALUES(?,?,?,?)`, idBytes(networkID), idBytes(teamID), idBytes(userID), unix(now))
		if err != nil {
			return 0, fmt.Errorf("add access team member: %w", err)
		}
		rows, _ := result.RowsAffected()
		changed = rows == 1
	} else {
		result, err := tx.ExecContext(ctx, `DELETE FROM access_team_members WHERE network_id=? AND team_id=? AND user_id=?`, idBytes(networkID), idBytes(teamID), idBytes(userID))
		if err != nil {
			return 0, fmt.Errorf("remove access team member: %w", err)
		}
		rows, _ := result.RowsAffected()
		changed = rows == 1
	}
	epoch, err := currentEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if changed {
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return 0, err
		}
		target := teamID
		details, _ := json.Marshal(map[string]any{"user_id": userID.String(), "present": present})
		if err := auditActorTx(ctx, tx, &networkID, actor, "access_team.member", "access_team", &target, string(details), now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit access team member: %w", err)
	}
	return epoch, nil
}

func (s *Store) AdministratorCreateAccessGrant(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, subjectKind AccessSubjectKind, subjectID identity.ID, targetKind AccessTargetKind, nodeID *identity.NodeID) (AccessGrant, uint64, error) {
	if !subjectKind.Valid() || subjectID.IsZero() || !targetKind.Valid() || (targetKind == AccessTargetNetwork) != (nodeID == nil) || nodeID != nil && nodeID.IsZero() {
		return AccessGrant{}, 0, fmt.Errorf("%w: invalid access grant", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return AccessGrant{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessGrant{}, 0, fmt.Errorf("begin create access grant: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessGrantCreatePolicy, networkID)
	if err != nil {
		return AccessGrant{}, 0, err
	}
	subjectTable := "access_users"
	if subjectKind == AccessSubjectTeam {
		subjectTable = "access_teams"
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+subjectTable+` WHERE id=? AND network_id=?`, idBytes(subjectID), idBytes(networkID)).Scan(&exists); err != nil || exists != 1 {
		if err != nil {
			return AccessGrant{}, 0, fmt.Errorf("read access grant subject: %w", err)
		}
		return AccessGrant{}, 0, ErrNotFound
	}
	if nodeID != nil {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL AND (lease_expires_at IS NULL OR lease_expires_at>?)`, idBytes(*nodeID), idBytes(networkID), unix(s.now())).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return AccessGrant{}, 0, ErrNotFound
		}
		if err != nil {
			return AccessGrant{}, 0, fmt.Errorf("read access grant node: %w", err)
		}
		if exists != 1 {
			return AccessGrant{}, 0, ErrNotFound
		}
		if targetKind == AccessTargetExit {
			var exits int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes WHERE network_id=? AND node_id=? AND kind='exit' AND state='approved' AND (valid_until IS NULL OR valid_until>?)`, idBytes(networkID), idBytes(*nodeID), unix(s.now())).Scan(&exits); err != nil || exits == 0 {
				if err != nil {
					return AccessGrant{}, 0, fmt.Errorf("read access grant Exit route: %w", err)
				}
				return AccessGrant{}, 0, fmt.Errorf("%w: exit grant target has no approved Exit route", ErrInvalid)
			}
		}
	}
	var userValue, teamValue, nodeValue any
	if subjectKind == AccessSubjectUser {
		userValue = idBytes(subjectID)
	} else {
		teamValue = idBytes(subjectID)
	}
	if nodeID != nil {
		nodeValue = idBytes(*nodeID)
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_grants(id,network_id,subject_kind,user_id,team_id,target_kind,node_id,created_at) VALUES(?,?,?,?,?,?,?,?)`, idBytes(id), idBytes(networkID), string(subjectKind), userValue, teamValue, string(targetKind), nodeValue, unix(now)); err != nil {
		if isConstraint(err) {
			return AccessGrant{}, 0, fmt.Errorf("%w: access grant already exists", ErrConflict)
		}
		return AccessGrant{}, 0, fmt.Errorf("insert access grant: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessGrant{}, 0, err
	}
	target := id
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_grant.create", "access_grant", &target, `{}`, now); err != nil {
		return AccessGrant{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessGrant{}, 0, fmt.Errorf("commit access grant: %w", err)
	}
	return AccessGrant{ID: id, NetworkID: networkID, SubjectKind: subjectKind, SubjectID: subjectID, TargetKind: targetKind, NodeID: nodeID, CreatedAt: now}, epoch, nil
}

func (s *Store) AdministratorDeleteAccessGrant(ctx context.Context, decision adminauth.Decision, grantID identity.ID) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin delete access grant: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, administratorAccessGrantDeletePolicy, grantID, `SELECT network_id FROM access_grants WHERE id=?`, idBytes(grantID))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_grants WHERE id=?`, idBytes(grantID)); err != nil {
		return 0, fmt.Errorf("delete access grant: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	target := grantID
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_grant.delete", "access_grant", &target, `{}`, s.now()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit delete access grant: %w", err)
	}
	return epoch, nil
}
