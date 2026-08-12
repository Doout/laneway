package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/protocol"
)

func validateRoute(prefix netip.Prefix, kind RouteKind, mode RouteMode, metric uint32, validUntil *time.Time, now time.Time) error {
	if netvalidate.RoutablePrefix(prefix, kind == RouteKindExit) != nil {
		return fmt.Errorf("%w: route prefix must be canonical", ErrInvalid)
	}
	if metric > MaxRouteMetric {
		return fmt.Errorf("%w: route metric exceeds %d", ErrInvalid, MaxRouteMetric)
	}
	if validUntil != nil && !validUntil.After(now) {
		return fmt.Errorf("%w: route already expired", ErrInvalid)
	}
	switch kind {
	case RouteKindOverlay:
		hostBits := 128
		if prefix.Addr().Is4() {
			hostBits = 32
		}
		if mode != RouteModeNone || prefix.Bits() != hostBits {
			return fmt.Errorf("%w: overlay routes must be host routes with mode none", ErrInvalid)
		}
	case RouteKindSubnet:
		if mode != RouteModeNAT && mode != RouteModeRouted {
			return fmt.Errorf("%w: subnet route mode", ErrInvalid)
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("%w: default prefix must be an exit route", ErrInvalid)
		}
	case RouteKindExit:
		if prefix.Bits() != 0 {
			return fmt.Errorf("%w: exit route must be a default prefix", ErrInvalid)
		}
		if mode != RouteModeNAT && mode != RouteModeRouted {
			return fmt.Errorf("%w: exit route mode", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: route kind", ErrInvalid)
	}
	return nil
}

func (s *Store) AdvertiseRoute(ctx context.Context, nodeID identity.NodeID, prefix netip.Prefix, kind RouteKind, mode RouteMode, metric uint32, validUntil *time.Time) (Route, error) {
	now := s.now()
	if validUntil != nil {
		normalized := validUntil.UTC().Truncate(time.Second)
		validUntil = &normalized
	}
	if err := validateRoute(prefix, kind, mode, metric, validUntil, now); err != nil {
		return Route{}, err
	}
	id, err := newID()
	if err != nil {
		return Route{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Route{}, fmt.Errorf("begin route advertisement: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var enabled uint64
	err = tx.QueryRowContext(ctx, `SELECT network_id,enabled_capabilities FROM nodes WHERE id=? AND revoked_at IS NULL`, idBytes(nodeID)).Scan(&networkBytes, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("read route advertiser: %w", err)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return Route{}, err
	}
	networkID := identity.NetworkID(networkRaw)
	if required := routePolicyCapability(kind); required != 0 && !protocol.Capability(enabled).Has(required) {
		return Route{}, fmt.Errorf("%w: node lacks %s policy capability", ErrInvalid, required)
	}
	addr := prefix.Addr().AsSlice()
	var valid any
	if validUntil != nil {
		valid = unix(*validUntil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO routes
        (id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,valid_until,created_at)
        VALUES(?,?,?,?,?,?,?,?,'advertised',?,?)`, idBytes(id), idBytes(networkID), idBytes(nodeID), addr,
		prefix.Bits(), string(kind), string(mode), metric, valid, unix(now)); err != nil {
		if isConstraint(err) {
			return Route{}, fmt.Errorf("%w: active route advertisement already exists", ErrConflict)
		}
		return Route{}, fmt.Errorf("insert route advertisement: %w", err)
	}
	target := id
	if err := auditTx(ctx, tx, networkID, &nodeID, "route.advertise", "route", &target, fmt.Sprintf(`{"prefix":%q}`, prefix.String()), now); err != nil {
		return Route{}, err
	}
	if err := tx.Commit(); err != nil {
		return Route{}, fmt.Errorf("commit route advertisement: %w", err)
	}
	return Route{ID: id, NetworkID: networkID, NodeID: nodeID, Prefix: prefix, Kind: kind, Mode: mode, Metric: metric, State: RouteStateAdvertised, ValidUntil: validUntil, CreatedAt: now}, nil
}

func (s *Store) ApproveRoute(ctx context.Context, routeID identity.ID) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin route approval: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var state, kind string
	var enabled uint64
	var valid sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT r.network_id,r.state,r.valid_until,r.kind,n.enabled_capabilities
		FROM routes r JOIN nodes n ON n.id=r.node_id WHERE r.id=? AND n.revoked_at IS NULL`, idBytes(routeID)).Scan(&networkBytes, &state, &valid, &kind, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read route approval: %w", err)
	}
	if state == string(RouteStateApproved) {
		return 0, ErrAlreadyApproved
	}
	if state != string(RouteStateAdvertised) {
		return 0, fmt.Errorf("%w: route is %s", ErrConflict, state)
	}
	if required := routePolicyCapability(RouteKind(kind)); required != 0 && !protocol.Capability(enabled).Has(required) {
		return 0, fmt.Errorf("%w: route owner lacks %s policy capability", ErrConflict, required)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	var ambiguous int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes candidate JOIN routes requested ON requested.id=?
		WHERE candidate.network_id=requested.network_id AND candidate.id<>requested.id
		AND candidate.prefix_address=requested.prefix_address AND candidate.prefix_length=requested.prefix_length
		AND candidate.metric=requested.metric AND candidate.state='approved'`, idBytes(routeID)).Scan(&ambiguous); err != nil {
		return 0, fmt.Errorf("check route ambiguity: %w", err)
	}
	if ambiguous != 0 {
		return 0, fmt.Errorf("%w: approved route with equal prefix and metric exists", ErrConflict)
	}
	now := s.now()
	if valid.Valid && valid.Int64 <= unix(now) {
		return 0, fmt.Errorf("%w: route advertisement expired", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE routes SET state='approved',approved_at=?
		WHERE id=? AND state='advertised' AND (valid_until IS NULL OR valid_until>?)`, unix(now), idBytes(routeID), unix(now))
	if err != nil {
		return 0, fmt.Errorf("approve route: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: route concurrently changed or expired", ErrConflict)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditTx(ctx, tx, networkID, nil, "route.approve", "route", &routeID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit route approval: %w", err)
	}
	return epoch, nil
}

func (s *Store) WithdrawRoute(ctx context.Context, routeID identity.ID, actor *identity.NodeID) (uint64, error) {
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin route withdrawal: %w", err)
	}
	defer tx.Rollback()
	var networkBytes, ownerBytes []byte
	var state string
	err = tx.QueryRowContext(ctx, `SELECT network_id,node_id,state FROM routes WHERE id=?`, idBytes(routeID)).Scan(&networkBytes, &ownerBytes, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read route withdrawal: %w", err)
	}
	if state == string(RouteStateWithdrawn) {
		return 0, fmt.Errorf("%w: route already withdrawn", ErrConflict)
	}
	if actor != nil && string(ownerBytes) != string(idBytes(*actor)) {
		return 0, fmt.Errorf("%w: only owner may withdraw route", ErrInvalid)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE id=?`, unix(now), idBytes(routeID)); err != nil {
		return 0, fmt.Errorf("withdraw route: %w", err)
	}
	var epoch uint64
	if state == string(RouteStateApproved) {
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return 0, err
		}
	} else {
		epoch, err = currentEpochTx(ctx, tx, networkID)
		if err != nil {
			return 0, err
		}
	}
	if err := auditTx(ctx, tx, networkID, actor, "route.withdraw", "route", &routeID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit route withdrawal: %w", err)
	}
	return epoch, nil
}

func (s *Store) AdministratorNetworkRoutes(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID, limit int) ([]Route, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("%w: route limit must be 1..1000", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorRouteListPolicy, networkID); err != nil {
		return nil, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,node_id,prefix_address,prefix_length,kind,mode,metric,state,
		valid_until,created_at,approved_at,withdrawn_at FROM routes WHERE network_id=?
		ORDER BY created_at DESC,id DESC LIMIT ?`, idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("read authorized network routes: %w", err)
	}
	routes, err := scanNetworkRoutes(rows, networkID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return routes, nil
}

func (s *Store) AdministratorApproveRoute(ctx context.Context, decision adminauth.Decision, routeID identity.ID) (uint64, error) {
	if routeID.IsZero() {
		return 0, fmt.Errorf("%w: route ID", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin authorized route approval: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision,
		administratorRouteApprovePolicy, routeID, `SELECT network_id FROM routes WHERE id=?`, idBytes(routeID))
	if err != nil {
		return 0, err
	}
	var state, kind string
	var enabled uint64
	var valid sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT r.state,r.valid_until,r.kind,n.enabled_capabilities
		FROM routes r JOIN nodes n ON n.id=r.node_id WHERE r.id=? AND n.revoked_at IS NULL`, idBytes(routeID)).
		Scan(&state, &valid, &kind, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read route approval: %w", err)
	}
	if state == string(RouteStateApproved) {
		return 0, ErrAlreadyApproved
	}
	if state != string(RouteStateAdvertised) {
		return 0, fmt.Errorf("%w: route is %s", ErrConflict, state)
	}
	if required := routePolicyCapability(RouteKind(kind)); required != 0 && !protocol.Capability(enabled).Has(required) {
		return 0, fmt.Errorf("%w: route owner lacks %s policy capability", ErrConflict, required)
	}
	var ambiguous int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes candidate JOIN routes requested ON requested.id=?
		WHERE candidate.network_id=requested.network_id AND candidate.id<>requested.id
		AND candidate.prefix_address=requested.prefix_address AND candidate.prefix_length=requested.prefix_length
		AND candidate.metric=requested.metric AND candidate.state='approved'`, idBytes(routeID)).Scan(&ambiguous); err != nil {
		return 0, fmt.Errorf("check route ambiguity: %w", err)
	}
	if ambiguous != 0 {
		return 0, fmt.Errorf("%w: approved route with equal prefix and metric exists", ErrConflict)
	}
	now := s.now()
	if valid.Valid && valid.Int64 <= unix(now) {
		return 0, fmt.Errorf("%w: route advertisement expired", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE routes SET state='approved',approved_at=?
		WHERE id=? AND state='advertised' AND (valid_until IS NULL OR valid_until>?)`, unix(now), idBytes(routeID), unix(now))
	if err != nil {
		return 0, fmt.Errorf("approve route: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: route concurrently changed or expired", ErrConflict)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, "route.approve", "route", &routeID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit authorized route approval: %w", err)
	}
	return epoch, nil
}

func (s *Store) AdministratorWithdrawRoute(ctx context.Context, decision adminauth.Decision, routeID identity.ID) (uint64, error) {
	if routeID.IsZero() {
		return 0, fmt.Errorf("%w: route ID", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin authorized route withdrawal: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision,
		administratorRouteWithdrawPolicy, routeID, `SELECT network_id FROM routes WHERE id=?`, idBytes(routeID))
	if err != nil {
		return 0, err
	}
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM routes WHERE id=?`, idBytes(routeID)).Scan(&state); err != nil {
		return 0, err
	}
	if state == string(RouteStateWithdrawn) {
		return 0, fmt.Errorf("%w: route already withdrawn", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE id=? AND state<>'withdrawn'`, unix(now), idBytes(routeID))
	if err != nil {
		return 0, fmt.Errorf("withdraw route: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("%w: route concurrently withdrawn", ErrConflict)
	}
	var epoch uint64
	if state == string(RouteStateApproved) {
		epoch, err = incrementEpochTx(ctx, tx, networkID)
	} else {
		epoch, err = currentEpochTx(ctx, tx, networkID)
	}
	if err != nil {
		return 0, err
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, "route.withdraw", "route", &routeID, `{}`, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit authorized route withdrawal: %w", err)
	}
	return epoch, nil
}

// AdministratorAssignRoute atomically grants the subnet-router capability if
// needed, creates or reuses an exact route, approves it, advances epochs, and
// writes every audit event. Any later failure rolls the entire assignment back.
func (s *Store) AdministratorAssignRoute(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID,
	nodeID identity.NodeID, prefix netip.Prefix, mode RouteMode, metric uint32) (Route, uint64, bool, error) {
	if networkID.IsZero() || nodeID.IsZero() {
		return Route{}, 0, false, fmt.Errorf("%w: route assignment identity", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Route{}, 0, false, fmt.Errorf("begin authorized route assignment: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorRouteAssignPolicy, networkID)
	if err != nil {
		return Route{}, 0, false, err
	}
	now := s.now()
	if err := validateRoute(prefix, RouteKindSubnet, mode, metric, nil, now); err != nil {
		return Route{}, 0, false, err
	}
	var capabilities uint64
	err = tx.QueryRowContext(ctx, `SELECT enabled_capabilities FROM nodes
		WHERE id=? AND network_id=? AND revoked_at IS NULL`, idBytes(nodeID), idBytes(networkID)).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, 0, false, ErrNotFound
	}
	if err != nil {
		return Route{}, 0, false, err
	}
	address := prefix.Addr().AsSlice()
	var route Route
	var routeRaw, ownerRaw []byte
	var kind, storedMode, state string
	var storedMetric uint32
	var valid, approved sql.NullInt64
	var createdAtUnix int64
	var activeDestinations int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM routes
		WHERE network_id=? AND prefix_address=? AND prefix_length=? AND state IN ('advertised','approved')`,
		idBytes(networkID), address, prefix.Bits()).Scan(&activeDestinations); err != nil {
		return Route{}, 0, false, err
	}
	if activeDestinations > 1 {
		return Route{}, 0, false, fmt.Errorf("%w: destination has multiple active routes", ErrConflict)
	}
	err = tx.QueryRowContext(ctx, `SELECT id,node_id,kind,mode,metric,state,valid_until,created_at,approved_at
		FROM routes WHERE network_id=? AND prefix_address=? AND prefix_length=?
		AND state IN ('advertised','approved') ORDER BY created_at,id LIMIT 1`,
		idBytes(networkID), address, prefix.Bits()).Scan(&routeRaw, &ownerRaw, &kind, &storedMode, &storedMetric, &state, &valid, &createdAtUnix, &approved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Route{}, 0, false, err
	}
	if err == nil {
		routeID, scanErr := scanID(routeRaw)
		ownerID, ownerErr := scanID(ownerRaw)
		if scanErr != nil || ownerErr != nil {
			return Route{}, 0, false, errors.Join(scanErr, ownerErr)
		}
		route = Route{ID: routeID, NetworkID: networkID, NodeID: identity.NodeID(ownerID), Prefix: prefix,
			Kind: RouteKind(kind), Mode: RouteMode(storedMode), Metric: storedMetric, State: RouteState(state),
			ValidUntil: nullableTime(valid), CreatedAt: fromUnix(createdAtUnix), ApprovedAt: nullableTime(approved)}
		if route.NodeID != nodeID || route.Kind != RouteKindSubnet || route.Mode != mode || route.Metric != metric {
			return Route{}, 0, false, fmt.Errorf("%w: destination already has a different active route", ErrConflict)
		}
	}
	created := route.ID.IsZero()
	var epoch uint64
	required := protocol.CapabilitySubnetRouterV1
	if !protocol.Capability(capabilities).Has(required) {
		newCapabilities := protocol.Capability(capabilities) | required
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET enabled_capabilities=?
			WHERE id=? AND network_id=? AND revoked_at IS NULL AND enabled_capabilities=?`,
			uint64(newCapabilities), idBytes(nodeID), idBytes(networkID), capabilities)
		if err != nil {
			return Route{}, 0, false, err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			if err != nil {
				return Route{}, 0, false, err
			}
			return Route{}, 0, false, fmt.Errorf("%w: node capabilities concurrently changed", ErrConflict)
		}
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return Route{}, 0, false, err
		}
		details := fmt.Sprintf(`{"capabilities":%d}`, uint64(newCapabilities))
		target := identity.ID(nodeID)
		if err := auditActorTx(ctx, tx, &networkID, actor, "node.capabilities.set", "node", &target, details, now); err != nil {
			return Route{}, 0, false, err
		}
	}
	if route.ID.IsZero() {
		routeID, err := newID()
		if err != nil {
			return Route{}, 0, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO routes
			(id,network_id,node_id,prefix_address,prefix_length,kind,mode,metric,state,created_at)
			VALUES(?,?,?,?,?,'subnet',?,?,'advertised',?)`, idBytes(routeID), idBytes(networkID), idBytes(nodeID),
			address, prefix.Bits(), string(mode), metric, unix(now)); err != nil {
			if isConstraint(err) {
				return Route{}, 0, false, fmt.Errorf("%w: active route advertisement already exists", ErrConflict)
			}
			return Route{}, 0, false, err
		}
		route = Route{ID: routeID, NetworkID: networkID, NodeID: nodeID, Prefix: prefix, Kind: RouteKindSubnet,
			Mode: mode, Metric: metric, State: RouteStateAdvertised, CreatedAt: now}
		if err := auditActorTx(ctx, tx, &networkID, actor, "route.advertise", "route", &routeID,
			fmt.Sprintf(`{"prefix":%q}`, prefix.String()), now); err != nil {
			return Route{}, 0, false, err
		}
	}
	if route.State == RouteStateAdvertised {
		approvalNow := s.now()
		if route.ValidUntil != nil && !approvalNow.Before(*route.ValidUntil) {
			return Route{}, 0, false, fmt.Errorf("%w: route advertisement expired", ErrConflict)
		}
		result, err := tx.ExecContext(ctx, `UPDATE routes SET state='approved',approved_at=?
			WHERE id=? AND state='advertised' AND (valid_until IS NULL OR valid_until>?)`,
			unix(approvalNow), idBytes(route.ID), unix(approvalNow))
		if err != nil {
			return Route{}, 0, false, err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			if err != nil {
				return Route{}, 0, false, err
			}
			return Route{}, 0, false, fmt.Errorf("%w: route concurrently changed", ErrConflict)
		}
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return Route{}, 0, false, err
		}
		if err := auditActorTx(ctx, tx, &networkID, actor, "route.approve", "route", &route.ID, `{}`, approvalNow); err != nil {
			return Route{}, 0, false, err
		}
		route.State = RouteStateApproved
		approvedAt := approvalNow
		route.ApprovedAt = &approvedAt
	}
	if epoch == 0 {
		epoch, err = currentEpochTx(ctx, tx, networkID)
		if err != nil {
			return Route{}, 0, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Route{}, 0, false, fmt.Errorf("commit authorized route assignment: %w", err)
	}
	return route, epoch, created, nil
}

// ExpireApprovedRoutes transactionally withdraws every approved route whose
// validity ended at or before now. A non-empty expiry batch advances the
// network configuration epoch exactly once, ensuring conditional node and
// relay polls cannot retain a route that disappeared only because time passed.
func (s *Store) ExpireApprovedRoutes(ctx context.Context, networkID identity.NetworkID, now time.Time) (uint64, int, error) {
	if networkID.IsZero() || now.IsZero() {
		return 0, 0, ErrInvalid
	}
	now = now.UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin route expiry: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=?
		WHERE network_id=? AND state='approved' AND valid_until IS NOT NULL AND valid_until<=?
		RETURNING id`, unix(now), idBytes(networkID), unix(now))
	if err != nil {
		return 0, 0, fmt.Errorf("expire approved routes: %w", err)
	}
	var expired []identity.ID
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("scan expired route: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			rows.Close()
			return 0, 0, err
		}
		expired = append(expired, id)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, fmt.Errorf("close expired routes: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate expired routes: %w", err)
	}
	var epoch uint64
	if len(expired) == 0 {
		epoch, err = currentEpochTx(ctx, tx, networkID)
	} else {
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err == nil {
			for i := range expired {
				if err = auditTx(ctx, tx, networkID, nil, "route.expire", "route", &expired[i], `{"reason":"expired"}`, now); err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit route expiry: %w", err)
	}
	return epoch, len(expired), nil
}

func incrementEpochTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID) (uint64, error) {
	var epoch int64
	err := tx.QueryRowContext(ctx, `UPDATE networks SET configuration_epoch=configuration_epoch+1
        WHERE id=? AND configuration_epoch < 9223372036854775807 RETURNING configuration_epoch`, idBytes(networkID)).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: network missing or epoch exhausted", ErrConflict)
	}
	if err != nil {
		return 0, fmt.Errorf("increment configuration epoch: %w", err)
	}
	return uint64(epoch), nil
}

func currentEpochTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID) (uint64, error) {
	var epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT configuration_epoch FROM networks WHERE id=?`, idBytes(networkID)).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("read configuration epoch: %w", err)
	}
	return uint64(epoch), nil
}
