package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const maxAccessServicePortRanges = 256

func canonicalAccessPortRanges(protocol AccessServiceProtocol, values []AccessPortRange) ([]AccessPortRange, error) {
	if !protocol.Valid() || !protocol.SupportsPorts() && len(values) != 0 {
		return nil, fmt.Errorf("%w: only TCP and UDP services may select ports", ErrInvalid)
	}
	if protocol.SupportsPorts() && len(values) == 0 {
		return nil, fmt.Errorf("%w: TCP and UDP services must select at least one port range", ErrInvalid)
	}
	if len(values) > maxAccessServicePortRanges {
		return nil, fmt.Errorf("%w: services may select at most %d port ranges", ErrInvalid, maxAccessServicePortRanges)
	}
	result := append([]AccessPortRange(nil), values...)
	for _, value := range result {
		if value.First == 0 || value.Last < value.First {
			return nil, fmt.Errorf("%w: service ports must be within 1..65535", ErrInvalid)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].First != result[j].First {
			return result[i].First < result[j].First
		}
		return result[i].Last < result[j].Last
	})
	canonical := make([]AccessPortRange, 0, len(result))
	for _, value := range result {
		if len(canonical) == 0 {
			canonical = append(canonical, value)
			continue
		}
		last := &canonical[len(canonical)-1]
		if uint32(value.First) <= uint32(last.Last)+1 {
			if value.Last > last.Last {
				last.Last = value.Last
			}
			continue
		}
		canonical = append(canonical, value)
	}
	return canonical, nil
}

func equalAccessPortRanges(first, second []AccessPortRange) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (s *Store) AdministratorCreateAccessResource(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID,
	name string, targetKind AccessResourceTargetKind, nodeID *identity.NodeID, routeID *identity.ID, prefix netip.Prefix) (AccessResource, uint64, error) {
	if err := validateName("resource", name); err != nil {
		return AccessResource{}, 0, err
	}
	validNode := targetKind == AccessResourceTargetNode && nodeID != nil && !nodeID.IsZero() && routeID == nil && !prefix.IsValid()
	validPrefix := targetKind == AccessResourceTargetPrefix && nodeID == nil && routeID != nil && !routeID.IsZero() &&
		prefix.IsValid() && prefix == prefix.Masked() && prefix.Bits() > 0 && !prefix.Addr().Is4In6()
	if !targetKind.Valid() || !validNode && !validPrefix {
		return AccessResource{}, 0, fmt.Errorf("%w: invalid access resource target", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return AccessResource{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessResource{}, 0, fmt.Errorf("begin create access resource: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessResourceCreatePolicy, networkID)
	if err != nil {
		return AccessResource{}, 0, err
	}
	now := s.now()
	var nodeValue, routeValue, routeNodeValue, routePrefixAddress, routePrefixLength, prefixAddress, prefixLength any
	var storedRouteNodeID *identity.NodeID
	var storedRoutePrefix netip.Prefix
	if validNode {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL
			AND (lease_expires_at IS NULL OR lease_expires_at>?)`, idBytes(*nodeID), idBytes(networkID), unix(now)).Scan(&exists); err != nil {
			return AccessResource{}, 0, fmt.Errorf("read access resource node: %w", err)
		}
		if exists != 1 {
			return AccessResource{}, 0, ErrNotFound
		}
		nodeValue = idBytes(*nodeID)
	} else {
		var routeNodeRaw, address []byte
		var bits int
		var kind string
		if err := tx.QueryRowContext(ctx, `SELECT r.node_id,r.prefix_address,r.prefix_length,r.kind FROM routes r JOIN nodes n ON n.id=r.node_id
			WHERE r.id=? AND r.network_id=? AND r.state='approved' AND (r.valid_until IS NULL OR r.valid_until>?)
			AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?)`,
			idBytes(*routeID), idBytes(networkID), unix(now), unix(now)).Scan(&routeNodeRaw, &address, &bits, &kind); errors.Is(err, sql.ErrNoRows) {
			return AccessResource{}, 0, ErrNotFound
		} else if err != nil {
			return AccessResource{}, 0, fmt.Errorf("read access resource route: %w", err)
		}
		routeNodeID, err := scanID(routeNodeRaw)
		if err != nil {
			return AccessResource{}, 0, err
		}
		routeAddress, ok := netip.AddrFromSlice(address)
		routePrefix := netip.PrefixFrom(routeAddress, bits)
		if !ok || routeAddress.Is4In6() || kind != string(RouteKindSubnet) || !routePrefix.IsValid() || routePrefix != routePrefix.Masked() ||
			routePrefix.Addr().BitLen() != prefix.Addr().BitLen() || routePrefix.Bits() > prefix.Bits() || !routePrefix.Contains(prefix.Addr()) {
			return AccessResource{}, 0, fmt.Errorf("%w: resource prefix must be inside its approved subnet route", ErrInvalid)
		}
		routeValue, routeNodeValue = idBytes(*routeID), idBytes(routeNodeID)
		routePrefixAddress, routePrefixLength = routePrefix.Addr().AsSlice(), routePrefix.Bits()
		prefixAddress, prefixLength = prefix.Addr().AsSlice(), prefix.Bits()
		value := identity.NodeID(routeNodeID)
		storedRouteNodeID, storedRoutePrefix = &value, routePrefix
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_resources
		(id,network_id,name,target_kind,node_id,route_id,route_node_id,route_prefix_address,route_prefix_length,
		 prefix_address,prefix_length,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?)`, idBytes(id), idBytes(networkID), name, string(targetKind), nodeValue, routeValue,
		routeNodeValue, routePrefixAddress, routePrefixLength, prefixAddress, prefixLength, unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return AccessResource{}, 0, fmt.Errorf("%w: resource name already exists or target is invalid", ErrConflict)
		}
		return AccessResource{}, 0, fmt.Errorf("insert access resource: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessResource{}, 0, err
	}
	details, _ := json.Marshal(map[string]string{"target_kind": string(targetKind)})
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_resource.create", "access_resource", &id, string(details), now); err != nil {
		return AccessResource{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessResource{}, 0, fmt.Errorf("commit access resource: %w", err)
	}
	var storedNodeID *identity.NodeID
	if nodeID != nil {
		value := *nodeID
		storedNodeID = &value
	}
	var storedRouteID *identity.ID
	if routeID != nil {
		value := *routeID
		storedRouteID = &value
	}
	return AccessResource{ID: id, NetworkID: networkID, Name: name, TargetKind: targetKind, NodeID: storedNodeID, RouteID: storedRouteID,
		RouteNodeID: storedRouteNodeID, RoutePrefix: storedRoutePrefix,
		Prefix: prefix, Enabled: true, CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorSetAccessResourceEnabled(ctx context.Context, decision adminauth.Decision, resourceID identity.ID, enabled bool) (AccessResource, uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessResource{}, 0, fmt.Errorf("begin update access resource: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, administratorAccessResourceUpdatePolicy,
		resourceID, `SELECT network_id FROM access_resources WHERE id=?`, idBytes(resourceID))
	if err != nil {
		return AccessResource{}, 0, err
	}
	resource, current, err := accessResourceTx(ctx, tx, networkID, resourceID)
	if err != nil {
		return AccessResource{}, 0, err
	}
	now := s.now()
	epoch, err := currentEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessResource{}, 0, err
	}
	if current != enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE access_resources SET enabled=?,updated_at=? WHERE id=?`, enabled, unix(now), idBytes(resourceID)); err != nil {
			return AccessResource{}, 0, fmt.Errorf("update access resource: %w", err)
		}
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return AccessResource{}, 0, err
		}
		details, _ := json.Marshal(map[string]bool{"enabled": enabled})
		if err := auditActorTx(ctx, tx, &networkID, actor, "access_resource.update", "access_resource", &resourceID, string(details), now); err != nil {
			return AccessResource{}, 0, err
		}
		resource.Enabled, resource.UpdatedAt = enabled, now
	}
	if err := tx.Commit(); err != nil {
		return AccessResource{}, 0, fmt.Errorf("commit access resource update: %w", err)
	}
	return resource, epoch, nil
}

func (s *Store) AdministratorCreateAccessService(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID,
	name string, protocol AccessServiceProtocol, ports []AccessPortRange) (AccessService, uint64, error) {
	if err := validateName("service", name); err != nil {
		return AccessService{}, 0, err
	}
	canonical, err := canonicalAccessPortRanges(protocol, ports)
	if err != nil {
		return AccessService{}, 0, err
	}
	id, err := newID()
	if err != nil {
		return AccessService{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessService{}, 0, fmt.Errorf("begin create access service: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessServiceCreatePolicy, networkID)
	if err != nil {
		return AccessService{}, 0, err
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_services(id,network_id,name,protocol,enabled,created_at,updated_at)
		VALUES(?,?,?,?,1,?,?)`, idBytes(id), idBytes(networkID), name, string(protocol), unix(now), unix(now)); err != nil {
		if isConstraint(err) {
			return AccessService{}, 0, fmt.Errorf("%w: service name already exists", ErrConflict)
		}
		return AccessService{}, 0, fmt.Errorf("insert access service: %w", err)
	}
	for _, portRange := range canonical {
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_service_ports(service_id,first_port,last_port) VALUES(?,?,?)`,
			idBytes(id), portRange.First, portRange.Last); err != nil {
			return AccessService{}, 0, fmt.Errorf("insert access service ports: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE access_services SET ports_sealed=1 WHERE id=? AND ports_sealed=0`, idBytes(id))
	if err != nil {
		return AccessService{}, 0, fmt.Errorf("seal access service ports: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return AccessService{}, 0, errors.New("seal access service ports: service was not staged")
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessService{}, 0, err
	}
	details, _ := json.Marshal(map[string]string{"protocol": string(protocol)})
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_service.create", "access_service", &id, string(details), now); err != nil {
		return AccessService{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessService{}, 0, fmt.Errorf("commit access service: %w", err)
	}
	return AccessService{ID: id, NetworkID: networkID, Name: name, Protocol: protocol, Ports: canonical, Enabled: true,
		CreatedAt: now, UpdatedAt: now}, epoch, nil
}

func (s *Store) AdministratorSetAccessServiceEnabled(ctx context.Context, decision adminauth.Decision, serviceID identity.ID, enabled bool) (AccessService, uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessService{}, 0, fmt.Errorf("begin update access service: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, administratorAccessServiceUpdatePolicy,
		serviceID, `SELECT network_id FROM access_services WHERE id=?`, idBytes(serviceID))
	if err != nil {
		return AccessService{}, 0, err
	}
	service, current, err := accessServiceTx(ctx, tx, networkID, serviceID)
	if err != nil {
		return AccessService{}, 0, err
	}
	now := s.now()
	epoch, err := currentEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessService{}, 0, err
	}
	if current != enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE access_services SET enabled=?,updated_at=? WHERE id=?`, enabled, unix(now), idBytes(serviceID)); err != nil {
			return AccessService{}, 0, fmt.Errorf("update access service: %w", err)
		}
		epoch, err = incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return AccessService{}, 0, err
		}
		details, _ := json.Marshal(map[string]bool{"enabled": enabled})
		if err := auditActorTx(ctx, tx, &networkID, actor, "access_service.update", "access_service", &serviceID, string(details), now); err != nil {
			return AccessService{}, 0, err
		}
		service.Enabled, service.UpdatedAt = enabled, now
	}
	if err := tx.Commit(); err != nil {
		return AccessService{}, 0, fmt.Errorf("commit access service update: %w", err)
	}
	return service, epoch, nil
}

func (s *Store) AdministratorCreateAccessResourceGrant(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID,
	subjectKind AccessSubjectKind, subjectID, resourceID, serviceID identity.ID) (AccessResourceGrant, uint64, error) {
	if !subjectKind.Valid() || subjectID.IsZero() || resourceID.IsZero() || serviceID.IsZero() {
		return AccessResourceGrant{}, 0, fmt.Errorf("%w: invalid resource access grant", ErrInvalid)
	}
	id, err := newID()
	if err != nil {
		return AccessResourceGrant{}, 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessResourceGrant{}, 0, fmt.Errorf("begin create resource access grant: %w", err)
	}
	defer tx.Rollback()
	actor, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorAccessResourceGrantCreatePolicy, networkID)
	if err != nil {
		return AccessResourceGrant{}, 0, err
	}
	subjectTable := "access_users"
	if subjectKind == AccessSubjectTeam {
		subjectTable = "access_teams"
	}
	checks := []struct {
		label string
		query string
		value identity.ID
	}{
		{label: "subject", query: `SELECT count(*) FROM ` + subjectTable + ` WHERE id=? AND network_id=?`, value: subjectID},
		{label: "resource", query: `SELECT count(*) FROM access_resources WHERE id=? AND network_id=? AND enabled=1`, value: resourceID},
		{label: "service", query: `SELECT count(*) FROM access_services WHERE id=? AND network_id=? AND enabled=1 AND ports_sealed=1`, value: serviceID},
	}
	for _, check := range checks {
		var exists int
		if err := tx.QueryRowContext(ctx, check.query, idBytes(check.value), idBytes(networkID)).Scan(&exists); err != nil {
			return AccessResourceGrant{}, 0, fmt.Errorf("read resource access grant %s: %w", check.label, err)
		}
		if exists != 1 {
			return AccessResourceGrant{}, 0, ErrNotFound
		}
	}
	var userValue, teamValue any
	if subjectKind == AccessSubjectUser {
		userValue = idBytes(subjectID)
	} else {
		teamValue = idBytes(subjectID)
	}
	now := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_resource_grants
		(id,network_id,subject_kind,user_id,team_id,resource_id,service_id,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), string(subjectKind), userValue, teamValue, idBytes(resourceID), idBytes(serviceID), unix(now)); err != nil {
		if isConstraint(err) {
			return AccessResourceGrant{}, 0, fmt.Errorf("%w: resource access grant already exists", ErrConflict)
		}
		return AccessResourceGrant{}, 0, fmt.Errorf("insert resource access grant: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return AccessResourceGrant{}, 0, err
	}
	details, _ := json.Marshal(map[string]string{"resource_id": resourceID.String(), "service_id": serviceID.String()})
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_resource_grant.create", "access_resource_grant", &id, string(details), now); err != nil {
		return AccessResourceGrant{}, 0, err
	}
	if err := tx.Commit(); err != nil {
		return AccessResourceGrant{}, 0, fmt.Errorf("commit resource access grant: %w", err)
	}
	return AccessResourceGrant{ID: id, NetworkID: networkID, SubjectKind: subjectKind, SubjectID: subjectID,
		ResourceID: resourceID, ServiceID: serviceID, CreatedAt: now}, epoch, nil
}

func (s *Store) AdministratorDeleteAccessResourceGrant(ctx context.Context, decision adminauth.Decision, grantID identity.ID) (uint64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin delete resource access grant: %w", err)
	}
	defer tx.Rollback()
	actor, networkID, err := s.authorizeAdministratorObjectResourceTx(ctx, tx, decision, administratorAccessResourceGrantDeletePolicy,
		grantID, `SELECT network_id FROM access_resource_grants WHERE id=?`, idBytes(grantID))
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_resource_grants WHERE id=?`, idBytes(grantID)); err != nil {
		return 0, fmt.Errorf("delete resource access grant: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditActorTx(ctx, tx, &networkID, actor, "access_resource_grant.delete", "access_resource_grant", &grantID, `{}`, s.now()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit delete resource access grant: %w", err)
	}
	return epoch, nil
}

func accessResourceTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, resourceID identity.ID) (AccessResource, bool, error) {
	var resource AccessResource
	var nodeRaw, routeRaw, routeNodeRaw, routeAddress, address []byte
	var routeBits, bits sql.NullInt64
	var kind string
	var enabled int
	var created, updated int64
	if err := tx.QueryRowContext(ctx, `SELECT name,target_kind,node_id,route_id,route_node_id,route_prefix_address,
		route_prefix_length,prefix_address,prefix_length,enabled,created_at,updated_at
		FROM access_resources WHERE id=? AND network_id=?`, idBytes(resourceID), idBytes(networkID)).Scan(
		&resource.Name, &kind, &nodeRaw, &routeRaw, &routeNodeRaw, &routeAddress, &routeBits,
		&address, &bits, &enabled, &created, &updated); err != nil {
		return AccessResource{}, false, err
	}
	resource.ID, resource.NetworkID, resource.TargetKind = resourceID, networkID, AccessResourceTargetKind(kind)
	resource.Enabled, resource.CreatedAt, resource.UpdatedAt = enabled == 1, fromUnix(created), fromUnix(updated)
	if !resource.TargetKind.Valid() {
		return AccessResource{}, false, errors.New("corrupt access resource kind")
	}
	if len(nodeRaw) != 0 {
		id, err := scanID(nodeRaw)
		if err != nil {
			return AccessResource{}, false, err
		}
		value := identity.NodeID(id)
		resource.NodeID = &value
	}
	if len(routeRaw) != 0 {
		id, err := scanID(routeRaw)
		if err != nil {
			return AccessResource{}, false, err
		}
		resource.RouteID = &id
	}
	if len(routeNodeRaw) != 0 {
		id, err := scanID(routeNodeRaw)
		if err != nil {
			return AccessResource{}, false, err
		}
		value := identity.NodeID(id)
		resource.RouteNodeID = &value
	}
	if len(routeAddress) != 0 {
		addr, ok := netip.AddrFromSlice(routeAddress)
		if !ok || addr.Is4In6() || !routeBits.Valid {
			return AccessResource{}, false, errors.New("corrupt access resource route prefix")
		}
		resource.RoutePrefix = netip.PrefixFrom(addr, int(routeBits.Int64))
		if !resource.RoutePrefix.IsValid() || resource.RoutePrefix != resource.RoutePrefix.Masked() || resource.RoutePrefix.Bits() == 0 {
			return AccessResource{}, false, errors.New("corrupt access resource route prefix")
		}
	}
	if len(address) != 0 {
		addr, ok := netip.AddrFromSlice(address)
		if !ok || addr.Is4In6() || !bits.Valid {
			return AccessResource{}, false, errors.New("corrupt access resource prefix")
		}
		resource.Prefix = netip.PrefixFrom(addr, int(bits.Int64))
		if !resource.Prefix.IsValid() || resource.Prefix != resource.Prefix.Masked() {
			return AccessResource{}, false, errors.New("corrupt access resource prefix")
		}
	}
	validNode := resource.TargetKind == AccessResourceTargetNode && resource.NodeID != nil && resource.RouteID == nil &&
		resource.RouteNodeID == nil && !resource.RoutePrefix.IsValid() && !resource.Prefix.IsValid()
	validPrefix := resource.TargetKind == AccessResourceTargetPrefix && resource.NodeID == nil && resource.RouteID != nil &&
		resource.RouteNodeID != nil && resource.RoutePrefix.IsValid() && resource.Prefix.IsValid() &&
		resource.RoutePrefix.Addr().BitLen() == resource.Prefix.Addr().BitLen() &&
		resource.RoutePrefix.Bits() <= resource.Prefix.Bits() && resource.RoutePrefix.Contains(resource.Prefix.Addr())
	if !validNode && !validPrefix {
		return AccessResource{}, false, errors.New("corrupt access resource target")
	}
	return resource, enabled == 1, nil
}

func accessServiceTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, serviceID identity.ID) (AccessService, bool, error) {
	var service AccessService
	var protocol string
	var enabled, portsSealed int
	var created, updated int64
	if err := tx.QueryRowContext(ctx, `SELECT name,protocol,ports_sealed,enabled,created_at,updated_at FROM access_services
		WHERE id=? AND network_id=?`, idBytes(serviceID), idBytes(networkID)).Scan(
		&service.Name, &protocol, &portsSealed, &enabled, &created, &updated); err != nil {
		return AccessService{}, false, err
	}
	service.ID, service.NetworkID, service.Protocol = serviceID, networkID, AccessServiceProtocol(protocol)
	service.Enabled, service.CreatedAt, service.UpdatedAt = enabled == 1, fromUnix(created), fromUnix(updated)
	if !service.Protocol.Valid() || portsSealed != 1 {
		return AccessService{}, false, errors.New("corrupt access service protocol")
	}
	rows, err := tx.QueryContext(ctx, `SELECT first_port,last_port FROM access_service_ports WHERE service_id=? ORDER BY first_port,last_port`, idBytes(serviceID))
	if err != nil {
		return AccessService{}, false, fmt.Errorf("read access service ports: %w", err)
	}
	for rows.Next() {
		var first, last uint16
		if err := rows.Scan(&first, &last); err != nil {
			rows.Close()
			return AccessService{}, false, fmt.Errorf("scan access service ports: %w", err)
		}
		service.Ports = append(service.Ports, AccessPortRange{First: first, Last: last})
	}
	if err := rows.Close(); err != nil {
		return AccessService{}, false, fmt.Errorf("close access service ports: %w", err)
	}
	if err := rows.Err(); err != nil {
		return AccessService{}, false, fmt.Errorf("iterate access service ports: %w", err)
	}
	canonical, err := canonicalAccessPortRanges(service.Protocol, service.Ports)
	if err != nil || !equalAccessPortRanges(canonical, service.Ports) {
		return AccessService{}, false, errors.New("corrupt access service ports")
	}
	return service, enabled == 1, nil
}

func appendNamedAccessInventoryTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, result *AccessInventory) error {
	resourceRows, err := tx.QueryContext(ctx, `SELECT id FROM access_resources WHERE network_id=? ORDER BY name,id`, idBytes(networkID))
	if err != nil {
		return fmt.Errorf("read access resources: %w", err)
	}
	var resourceIDs []identity.ID
	for resourceRows.Next() {
		var raw []byte
		if err := resourceRows.Scan(&raw); err != nil {
			resourceRows.Close()
			return fmt.Errorf("scan access resource ID: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			resourceRows.Close()
			return err
		}
		resourceIDs = append(resourceIDs, id)
	}
	if err := resourceRows.Close(); err != nil {
		return err
	}
	if err := resourceRows.Err(); err != nil {
		return err
	}
	for _, id := range resourceIDs {
		resource, _, err := accessResourceTx(ctx, tx, networkID, id)
		if err != nil {
			return err
		}
		result.Resources = append(result.Resources, resource)
	}
	serviceRows, err := tx.QueryContext(ctx, `SELECT id FROM access_services WHERE network_id=? ORDER BY name,id`, idBytes(networkID))
	if err != nil {
		return fmt.Errorf("read access services: %w", err)
	}
	var serviceIDs []identity.ID
	for serviceRows.Next() {
		var raw []byte
		if err := serviceRows.Scan(&raw); err != nil {
			serviceRows.Close()
			return fmt.Errorf("scan access service ID: %w", err)
		}
		id, err := scanID(raw)
		if err != nil {
			serviceRows.Close()
			return err
		}
		serviceIDs = append(serviceIDs, id)
	}
	if err := serviceRows.Close(); err != nil {
		return err
	}
	if err := serviceRows.Err(); err != nil {
		return err
	}
	for _, id := range serviceIDs {
		service, _, err := accessServiceTx(ctx, tx, networkID, id)
		if err != nil {
			return err
		}
		result.Services = append(result.Services, service)
	}
	grantRows, err := tx.QueryContext(ctx, `SELECT id,subject_kind,user_id,team_id,resource_id,service_id,created_at
		FROM access_resource_grants WHERE network_id=? ORDER BY created_at,id`, idBytes(networkID))
	if err != nil {
		return fmt.Errorf("read resource access grants: %w", err)
	}
	for grantRows.Next() {
		var idRaw, userRaw, teamRaw, resourceRaw, serviceRaw []byte
		var subjectKind string
		var created int64
		if err := grantRows.Scan(&idRaw, &subjectKind, &userRaw, &teamRaw, &resourceRaw, &serviceRaw, &created); err != nil {
			grantRows.Close()
			return fmt.Errorf("scan resource access grant: %w", err)
		}
		id, err := scanID(idRaw)
		if err != nil {
			grantRows.Close()
			return err
		}
		kind := AccessSubjectKind(subjectKind)
		if !kind.Valid() {
			grantRows.Close()
			return errors.New("corrupt resource access grant subject")
		}
		subjectRaw := userRaw
		if kind == AccessSubjectTeam {
			subjectRaw = teamRaw
		}
		subjectID, err := scanID(subjectRaw)
		if err != nil {
			grantRows.Close()
			return err
		}
		resourceID, err := scanID(resourceRaw)
		if err != nil {
			grantRows.Close()
			return err
		}
		serviceID, err := scanID(serviceRaw)
		if err != nil {
			grantRows.Close()
			return err
		}
		result.ResourceGrants = append(result.ResourceGrants, AccessResourceGrant{ID: id, NetworkID: networkID,
			SubjectKind: kind, SubjectID: subjectID, ResourceID: resourceID, ServiceID: serviceID, CreatedAt: fromUnix(created)})
	}
	if err := grantRows.Close(); err != nil {
		return err
	}
	return grantRows.Err()
}
