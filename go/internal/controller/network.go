package controller

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/netvalidate"
)

func CreateNetwork(ctx context.Context, s *Store, name string, pool netip.Prefix) (Network, error) {
	return s.CreateNetwork(ctx, name, pool)
}

func (s *Store) CreateNetwork(ctx context.Context, name string, pool netip.Prefix) (Network, error) {
	return s.CreateNetworkDualStack(ctx, name, pool, netip.Prefix{})
}

func (s *Store) CreateNetworkDualStack(ctx context.Context, name string, pool netip.Prefix, ipv6Pool netip.Prefix) (Network, error) {
	id, err := identity.NewNetworkID()
	if err != nil {
		return Network{}, fmt.Errorf("generate network ID: %w", err)
	}
	return s.CreateNetworkDualStackWithID(ctx, id, name, pool, ipv6Pool)
}

// CreateNetworkDualStackWithID creates a network using an administrator-
// generated immutable ID. This breaks the controller-certificate bootstrap
// cycle: operators can generate the network ID first, issue the controller
// service certificate for it, then create the durable row with the same ID.
func (s *Store) CreateNetworkDualStackWithID(ctx context.Context, id identity.NetworkID, name string, pool netip.Prefix, ipv6Pool netip.Prefix) (Network, error) {
	if err := validateNetworkDefinition(id, name, pool, ipv6Pool); err != nil {
		return Network{}, err
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, fmt.Errorf("begin create network: %w", err)
	}
	defer tx.Rollback()
	a4 := pool.Addr().As4()
	var a6 any
	var bits6 any
	if ipv6Pool.IsValid() {
		value := ipv6Pool.Addr().As16()
		a6, bits6 = value[:], ipv6Pool.Bits()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO networks
		(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length)
		VALUES(?,?,?,?,1,1,?,?,?)`, idBytes(id), name, a4[:], pool.Bits(), unix(now), a6, bits6); err != nil {
		if isConstraint(err) {
			return Network{}, fmt.Errorf("%w: network name or ID", ErrConflict)
		}
		return Network{}, fmt.Errorf("insert network: %w", err)
	}
	target := identity.ID(id)
	if err := auditTx(ctx, tx, id, nil, "network.create", "network", &target, `{}`, now); err != nil {
		return Network{}, err
	}
	if err := tx.Commit(); err != nil {
		return Network{}, fmt.Errorf("commit create network: %w", err)
	}
	return Network{ID: id, Name: name, IPv4Pool: pool, IPv6Pool: ipv6Pool, ConfigurationEpoch: 1, CreatedAt: now}, nil
}

// EnsureControllerInitialNetwork establishes or revalidates the controller's
// durable identity binding and optional initial network. authenticated must be
// obtained from a cryptographically verified controller certificate before
// this method is called.
//
// A zero configured value supports legacy deployments. If no binding exists,
// the result is the zero Network and no state is changed. If a binding already
// exists, it is always enforced even when configured is zero.
func (s *Store) EnsureControllerInitialNetwork(ctx context.Context, configured ControllerInitialNetwork, authenticated identity.AuthenticatedIdentity) (Network, bool, error) {
	if err := authenticated.Validate(); err != nil {
		return Network{}, false, fmt.Errorf("%w: controller certificate identity", ErrInvalid)
	}
	if err := authenticated.RequireRole(identity.IdentityRoleController); err != nil {
		return Network{}, false, fmt.Errorf("%w: controller certificate role", ErrInvalid)
	}
	configuredPresent := controllerInitialNetworkPresent(configured)
	if configuredPresent {
		if err := validateNetworkDefinition(configured.NetworkID, configured.Name, configured.IPv4Pool, configured.IPv6Pool); err != nil {
			return Network{}, false, err
		}
		if configured.NetworkID != authenticated.NetworkID {
			return Network{}, false, fmt.Errorf("%w: initial network differs from controller certificate identity", ErrConflict)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, false, fmt.Errorf("begin ensure controller initial network: %w", err)
	}
	defer tx.Rollback()

	var boundNetworkRaw, boundServiceRaw []byte
	var boundCreated int64
	err = tx.QueryRowContext(ctx, `SELECT network_id,controller_service_id,created_at
		FROM controller_identity_state WHERE singleton=1`).Scan(&boundNetworkRaw, &boundServiceRaw, &boundCreated)
	if err == nil {
		boundNetworkValue, scanErr := scanID(boundNetworkRaw)
		if scanErr != nil {
			return Network{}, false, fmt.Errorf("corrupt controller network binding: %w", scanErr)
		}
		boundServiceID, scanErr := scanID(boundServiceRaw)
		if scanErr != nil {
			return Network{}, false, fmt.Errorf("corrupt controller service binding: %w", scanErr)
		}
		boundNetworkID := identity.NetworkID(boundNetworkValue)
		if boundNetworkID != authenticated.NetworkID || boundServiceID != authenticated.SubjectID {
			return Network{}, false, fmt.Errorf("%w: controller certificate identity differs from durable binding", ErrConflict)
		}
		network, readErr := networkByRow(tx.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
			FROM networks WHERE id=?`, idBytes(boundNetworkID)), boundNetworkID)
		if errors.Is(readErr, ErrNotFound) {
			return Network{}, false, errors.New("corrupt controller identity binding references a missing network")
		}
		if readErr != nil {
			return Network{}, false, readErr
		}
		if fromUnix(boundCreated).Before(network.CreatedAt) {
			return Network{}, false, errors.New("corrupt controller identity binding timestamp")
		}
		var bindingAudits, totalBindingAudits int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
			WHERE network_id=? AND actor_kind='system' AND actor_id IS NULL
			AND action='controller.identity.bind' AND target_type='controller_service'
			AND target_id=? AND created_at=?`, idBytes(boundNetworkID), idBytes(boundServiceID), boundCreated).
			Scan(&bindingAudits); err != nil {
			return Network{}, false, fmt.Errorf("validate controller identity binding audit: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
			WHERE action='controller.identity.bind'`).Scan(&totalBindingAudits); err != nil {
			return Network{}, false, fmt.Errorf("count controller identity binding audits: %w", err)
		}
		if bindingAudits != 1 || totalBindingAudits != 1 {
			return Network{}, false, errors.New("corrupt controller identity binding audit")
		}
		if configuredPresent && !initialNetworkMatches(network, configured) {
			return Network{}, false, fmt.Errorf("%w: configured initial network differs from durable state", ErrConflict)
		}
		if err := tx.Commit(); err != nil {
			return Network{}, false, fmt.Errorf("finish controller identity validation: %w", err)
		}
		return network, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Network{}, false, fmt.Errorf("read controller identity binding: %w", err)
	}
	var staleBindingAudits int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='controller.identity.bind'`).Scan(&staleBindingAudits); err != nil {
		return Network{}, false, fmt.Errorf("count controller identity binding audits: %w", err)
	}
	if staleBindingAudits != 0 {
		return Network{}, false, errors.New("corrupt controller identity binding audit without durable state")
	}
	if !configuredPresent {
		if err := tx.Commit(); err != nil {
			return Network{}, false, fmt.Errorf("finish legacy controller identity check: %w", err)
		}
		return Network{}, false, nil
	}

	now := s.now()
	var latestAudit sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(created_at) FROM audit_events`).Scan(&latestAudit); err != nil {
		return Network{}, false, fmt.Errorf("read controller audit clock: %w", err)
	}
	if latestAudit.Valid {
		now = latestTime(now, fromUnix(latestAudit.Int64))
	}
	network, readErr := networkByRow(tx.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
		FROM networks WHERE id=?`, idBytes(configured.NetworkID)), configured.NetworkID)
	created := false
	switch {
	case readErr == nil:
		if !initialNetworkMatches(network, configured) {
			return Network{}, false, fmt.Errorf("%w: existing initial network differs from configuration", ErrConflict)
		}
		now = latestTime(now, network.CreatedAt)
	case errors.Is(readErr, ErrNotFound):
		var networkCount int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM networks`).Scan(&networkCount); err != nil {
			return Network{}, false, fmt.Errorf("count existing networks: %w", err)
		}
		if networkCount != 0 {
			return Network{}, false, fmt.Errorf("%w: configured initial network is absent from nonempty controller state", ErrConflict)
		}
		a4 := configured.IPv4Pool.Addr().As4()
		var a6, bits6 any
		if configured.IPv6Pool.IsValid() {
			value := configured.IPv6Pool.Addr().As16()
			a6, bits6 = value[:], configured.IPv6Pool.Bits()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO networks
			(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length)
			VALUES(?,?,?,?,1,1,?,?,?)`, idBytes(configured.NetworkID), configured.Name, a4[:], configured.IPv4Pool.Bits(), unix(now), a6, bits6); err != nil {
			if isConstraint(err) {
				return Network{}, false, fmt.Errorf("%w: initial network name or ID", ErrConflict)
			}
			return Network{}, false, fmt.Errorf("insert initial network: %w", err)
		}
		network = Network{ID: configured.NetworkID, Name: configured.Name, IPv4Pool: configured.IPv4Pool,
			IPv6Pool: configured.IPv6Pool, ConfigurationEpoch: 1, CreatedAt: now}
		target := identity.ID(configured.NetworkID)
		if err := auditActorTx(ctx, tx, &configured.NetworkID, adminauth.SystemActor(),
			"network.create", "network", &target, `{"source":"controller_initial_network"}`, now); err != nil {
			return Network{}, false, err
		}
		created = true
	default:
		return Network{}, false, readErr
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO controller_identity_state
		(singleton,network_id,controller_service_id,created_at) VALUES(1,?,?,?)`,
		idBytes(configured.NetworkID), idBytes(authenticated.SubjectID), unix(now)); err != nil {
		if isConstraint(err) {
			return Network{}, false, fmt.Errorf("%w: controller identity binding", ErrConflict)
		}
		return Network{}, false, fmt.Errorf("bind controller identity: %w", err)
	}
	target := authenticated.SubjectID
	if err := auditActorTx(ctx, tx, &configured.NetworkID, adminauth.SystemActor(),
		"controller.identity.bind", "controller_service", &target, `{}`, now); err != nil {
		return Network{}, false, err
	}
	var bindingAudits, totalBindingAudits int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE network_id=? AND actor_kind='system' AND actor_id IS NULL
		AND action='controller.identity.bind' AND target_type='controller_service'
		AND target_id=? AND created_at=?`, idBytes(configured.NetworkID), idBytes(authenticated.SubjectID), unix(now)).Scan(&bindingAudits); err != nil {
		return Network{}, false, fmt.Errorf("validate new controller identity binding audit: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events
		WHERE action='controller.identity.bind'`).Scan(&totalBindingAudits); err != nil {
		return Network{}, false, fmt.Errorf("count new controller identity binding audits: %w", err)
	}
	if bindingAudits != 1 || totalBindingAudits != 1 {
		return Network{}, false, errors.New("controller identity binding audit is ambiguous")
	}
	if err := tx.Commit(); err != nil {
		return Network{}, false, fmt.Errorf("commit controller initial network: %w", err)
	}
	return network, created, nil
}

// PreflightControllerInitialNetwork validates the controller certificate,
// configured initial Network, optional bootstrap Network, and any existing
// database without creating the database or applying migrations. Callers use
// it before opening listeners' services so deterministic startup failures
// cannot leave a partially migrated or newly bound controller database.
func PreflightControllerInitialNetwork(ctx context.Context, databasePath string, configured ControllerInitialNetwork, authenticated identity.AuthenticatedIdentity, requiredNetworkID identity.NetworkID) error {
	if err := authenticated.Validate(); err != nil {
		return fmt.Errorf("%w: controller certificate identity", ErrInvalid)
	}
	if err := authenticated.RequireRole(identity.IdentityRoleController); err != nil {
		return fmt.Errorf("%w: controller certificate role", ErrInvalid)
	}
	configuredPresent := controllerInitialNetworkPresent(configured)
	if configuredPresent {
		if err := validateNetworkDefinition(configured.NetworkID, configured.Name, configured.IPv4Pool, configured.IPv6Pool); err != nil {
			return err
		}
		if configured.NetworkID != authenticated.NetworkID {
			return fmt.Errorf("%w: initial network differs from controller certificate identity", ErrConflict)
		}
	}
	if !requiredNetworkID.IsZero() && requiredNetworkID != authenticated.NetworkID {
		return fmt.Errorf("%w: required network differs from controller certificate identity", ErrConflict)
	}

	info, err := os.Lstat(databasePath)
	if errors.Is(err, os.ErrNotExist) {
		if !requiredNetworkID.IsZero() && !configuredPresent {
			return fmt.Errorf("%w: required network is absent from fresh controller state", ErrConflict)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect controller database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("controller database is not a regular file: %s", databasePath)
	}
	if err := validateDatabase(ctx, databasePath, currentSchemaVersion); err != nil {
		return fmt.Errorf("validate controller database before startup: %w", err)
	}
	db, err := openReadOnlyDatabase(databasePath)
	if err != nil {
		return fmt.Errorf("open controller database before startup: %w", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_versions`).Scan(&version); err != nil {
		return fmt.Errorf("read controller schema before startup: %w", err)
	}
	if version >= 12 {
		var boundNetworkRaw, boundServiceRaw []byte
		var boundCreated int64
		err = db.QueryRowContext(ctx, `SELECT network_id,controller_service_id,created_at
			FROM controller_identity_state WHERE singleton=1`).Scan(&boundNetworkRaw, &boundServiceRaw, &boundCreated)
		switch {
		case err == nil:
			boundNetworkValue, scanErr := scanID(boundNetworkRaw)
			if scanErr != nil {
				return fmt.Errorf("corrupt controller network binding: %w", scanErr)
			}
			boundServiceID, scanErr := scanID(boundServiceRaw)
			if scanErr != nil {
				return fmt.Errorf("corrupt controller service binding: %w", scanErr)
			}
			boundNetworkID := identity.NetworkID(boundNetworkValue)
			if boundNetworkID != authenticated.NetworkID || boundServiceID != authenticated.SubjectID {
				return fmt.Errorf("%w: controller certificate identity differs from durable binding", ErrConflict)
			}
			network, readErr := networkByRow(db.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
				FROM networks WHERE id=?`, idBytes(boundNetworkID)), boundNetworkID)
			if errors.Is(readErr, ErrNotFound) {
				return errors.New("corrupt controller identity binding references a missing network")
			}
			if readErr != nil {
				return readErr
			}
			if fromUnix(boundCreated).Before(network.CreatedAt) {
				return errors.New("corrupt controller identity binding timestamp")
			}
			if configuredPresent && !initialNetworkMatches(network, configured) {
				return fmt.Errorf("%w: configured initial network differs from durable state", ErrConflict)
			}
			if !requiredNetworkID.IsZero() && requiredNetworkID != boundNetworkID {
				return fmt.Errorf("%w: required network differs from durable controller state", ErrConflict)
			}
			return nil
		case errors.Is(err, sql.ErrNoRows):
			// validateDatabase already proves there is no surviving binding audit.
		default:
			return fmt.Errorf("read controller identity binding before startup: %w", err)
		}
	}

	if configuredPresent {
		network, readErr := networkByRow(db.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
			FROM networks WHERE id=?`, idBytes(configured.NetworkID)), configured.NetworkID)
		switch {
		case readErr == nil:
			if !initialNetworkMatches(network, configured) {
				return fmt.Errorf("%w: existing initial network differs from configuration", ErrConflict)
			}
		case errors.Is(readErr, ErrNotFound):
			var networkCount int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM networks`).Scan(&networkCount); err != nil {
				return fmt.Errorf("count existing networks before startup: %w", err)
			}
			if networkCount != 0 {
				return fmt.Errorf("%w: configured initial network is absent from nonempty controller state", ErrConflict)
			}
		default:
			return readErr
		}
	}
	if !requiredNetworkID.IsZero() && !configuredPresent {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM networks WHERE id=?`, idBytes(requiredNetworkID)).Scan(&count); err != nil {
			return fmt.Errorf("find required network before startup: %w", err)
		}
		if count != 1 {
			return fmt.Errorf("%w: required network is absent from controller state", ErrConflict)
		}
	}
	return nil
}

func controllerInitialNetworkPresent(value ControllerInitialNetwork) bool {
	return !value.NetworkID.IsZero() || value.Name != "" || value.IPv4Pool.IsValid() || value.IPv6Pool.IsValid()
}

func validateNetworkDefinition(id identity.NetworkID, name string, pool netip.Prefix, ipv6Pool netip.Prefix) error {
	if id.IsZero() {
		return fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateName("network", name); err != nil {
		return err
	}
	if netvalidate.RoutablePrefix(pool, false) != nil || !pool.Addr().Is4() || pool.Bits() < 8 || pool.Bits() > 30 {
		return fmt.Errorf("%w: IPv4 pool must be a canonical /8 through /30", ErrInvalid)
	}
	if ipv6Pool.IsValid() && (netvalidate.RoutablePrefix(ipv6Pool, false) != nil || !ipv6Pool.Addr().Is6() || ipv6Pool.Bits() < 64 || ipv6Pool.Bits() > 120) {
		return fmt.Errorf("%w: IPv6 pool must be a canonical /64 through /120", ErrInvalid)
	}
	return nil
}

func initialNetworkMatches(network Network, configured ControllerInitialNetwork) bool {
	return network.ID == configured.NetworkID && network.Name == configured.Name &&
		network.IPv4Pool == configured.IPv4Pool && network.IPv6Pool == configured.IPv6Pool
}

// AdministratorCreateNetworkDualStack creates a network only after the
// decision's durable subject is revalidated in the insertion and audit
// transaction.
func (s *Store) AdministratorCreateNetworkDualStack(ctx context.Context, decision adminauth.Decision, name string, pool netip.Prefix, ipv6Pool netip.Prefix) (Network, error) {
	id, err := identity.NewNetworkID()
	if err != nil {
		return Network{}, fmt.Errorf("generate network ID: %w", err)
	}
	return s.AdministratorCreateNetworkDualStackWithID(ctx, decision, id, name, pool, ipv6Pool)
}

func (s *Store) AdministratorCreateNetworkDualStackWithID(ctx context.Context, decision adminauth.Decision, id identity.NetworkID, name string, pool netip.Prefix, ipv6Pool netip.Prefix) (Network, error) {
	if id.IsZero() {
		return Network{}, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	if err := validateName("network", name); err != nil {
		return Network{}, err
	}
	if netvalidate.RoutablePrefix(pool, false) != nil || !pool.Addr().Is4() || pool.Bits() < 8 || pool.Bits() > 30 {
		return Network{}, fmt.Errorf("%w: IPv4 pool must be a canonical /8 through /30", ErrInvalid)
	}
	if ipv6Pool.IsValid() && (netvalidate.RoutablePrefix(ipv6Pool, false) != nil || ipv6Pool.Addr().Is4() || ipv6Pool.Bits() < 64 || ipv6Pool.Bits() > 120) {
		return Network{}, fmt.Errorf("%w: IPv6 pool must be a canonical /64 through /120", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, fmt.Errorf("begin authorized network creation: %w", err)
	}
	defer tx.Rollback()
	now := s.now()
	actor, err := s.authorizeAdministratorGlobalResourceTx(ctx, tx, decision, administratorNetworkCreatePolicy, adminauth.GlobalTarget())
	if err != nil {
		return Network{}, err
	}
	a4 := pool.Addr().As4()
	var a6, bits6 any
	if ipv6Pool.IsValid() {
		value := ipv6Pool.Addr().As16()
		a6, bits6 = value[:], ipv6Pool.Bits()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO networks
		(id,name,ipv4_address,ipv4_prefix_length,next_ipv4,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length)
		VALUES(?,?,?,?,1,1,?,?,?)`, idBytes(id), name, a4[:], pool.Bits(), unix(now), a6, bits6); err != nil {
		if isConstraint(err) {
			return Network{}, fmt.Errorf("%w: network name or ID", ErrConflict)
		}
		return Network{}, fmt.Errorf("insert network: %w", err)
	}
	target := identity.ID(id)
	if err := auditActorTx(ctx, tx, &id, actor, "network.create", "network", &target, `{}`, now); err != nil {
		return Network{}, err
	}
	if err := tx.Commit(); err != nil {
		return Network{}, fmt.Errorf("commit authorized network creation: %w", err)
	}
	return Network{ID: id, Name: name, IPv4Pool: pool, IPv6Pool: ipv6Pool, ConfigurationEpoch: 1, CreatedAt: now}, nil
}

func (s *Store) Network(ctx context.Context, networkID identity.NetworkID) (Network, error) {
	return networkByRow(s.db.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
		FROM networks WHERE id=?`, idBytes(networkID)), networkID)
}

func (s *Store) AdministratorNetwork(ctx context.Context, decision adminauth.Decision, networkID identity.NetworkID) (Network, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision, administratorNetworkReadPolicy, networkID); err != nil {
		return Network{}, err
	}
	result, err := networkByRow(tx.QueryRowContext(ctx, `SELECT name,ipv4_address,ipv4_prefix_length,configuration_epoch,created_at,ipv6_address,ipv6_prefix_length
		FROM networks WHERE id=?`, idBytes(networkID)), networkID)
	if err != nil {
		return Network{}, err
	}
	if err := tx.Commit(); err != nil {
		return Network{}, err
	}
	return result, nil
}

func networkByRow(row rowScanner, networkID identity.NetworkID) (Network, error) {
	var name string
	var addr, addr6 []byte
	var bits int
	var bits6 sql.NullInt64
	var epoch int64
	var created int64
	err := row.Scan(&name, &addr, &bits, &epoch, &created, &addr6, &bits6)
	if errors.Is(err, sql.ErrNoRows) {
		return Network{}, ErrNotFound
	}
	if err != nil {
		return Network{}, fmt.Errorf("read network: %w", err)
	}
	ip, ok := netip.AddrFromSlice(addr)
	if !ok || !ip.Is4() || epoch < 1 {
		return Network{}, errors.New("corrupt network row")
	}
	result := Network{ID: networkID, Name: name, IPv4Pool: netip.PrefixFrom(ip, bits), ConfigurationEpoch: uint64(epoch), CreatedAt: fromUnix(created)}
	if len(addr6) != 0 {
		ip6, ok := netip.AddrFromSlice(addr6)
		if !ok || !ip6.Is6() || !bits6.Valid {
			return Network{}, errors.New("corrupt network IPv6 pool")
		}
		result.IPv6Pool = netip.PrefixFrom(ip6, int(bits6.Int64))
	}
	return result, nil
}

func (s *Store) Node(ctx context.Context, nodeID identity.NodeID) (Node, error) {
	var network, address, address6, wireGuardPublicKey, userRaw []byte
	var name string
	var capabilities, created int64
	var revoked sql.NullInt64
	var enrollmentClass string
	var leaseExpires sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT n.network_id,n.name,n.enabled_capabilities,n.created_at,n.revoked_at,a.address,a6.address,n.enrollment_class,n.lease_expires_at,n.wireguard_public_key,n.user_id
		FROM nodes n LEFT JOIN overlay_addresses a ON a.id=(
			SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND length(oa.address)=4
			ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		LEFT JOIN overlay_addresses a6 ON a6.id=(
			SELECT oa.id FROM overlay_addresses oa WHERE oa.node_id=n.id AND length(oa.address)=16
			ORDER BY oa.created_at DESC,oa.id DESC LIMIT 1)
		WHERE n.id=?`, idBytes(nodeID)).Scan(&network, &name, &capabilities, &created, &revoked, &address, &address6, &enrollmentClass, &leaseExpires, &wireGuardPublicKey, &userRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	if err != nil {
		return Node{}, fmt.Errorf("read node: %w", err)
	}
	nid, err := scanID(network)
	if err != nil {
		return Node{}, err
	}
	class := EnrollmentClass(enrollmentClass)
	if !class.Valid() || (class == EnrollmentClassEphemeral) != leaseExpires.Valid {
		return Node{}, errors.New("corrupt node enrollment class")
	}
	wireGuardKey, err := scanWireGuardPublicKey(wireGuardPublicKey)
	if err != nil {
		return Node{}, err
	}
	result := Node{ID: nodeID, NetworkID: identity.NetworkID(nid), Name: name, EnabledCapabilities: uint64(capabilities), CreatedAt: fromUnix(created), RevokedAt: nullableTime(revoked), EnrollmentClass: class, LeaseExpiresAt: nullableTime(leaseExpires), WireGuardPublicKey: wireGuardKey}
	if len(userRaw) != 0 {
		userID, err := scanID(userRaw)
		if err != nil {
			return Node{}, err
		}
		result.UserID = &userID
	}
	if len(address) != 0 {
		addr, ok := netip.AddrFromSlice(address)
		if !ok || !addr.Is4() {
			return Node{}, errors.New("corrupt node overlay address")
		}
		result.IPv4Address = addr
	} else if !revoked.Valid {
		return Node{}, errors.New("active node has no IPv4 overlay address")
	}
	if len(address6) != 0 {
		ipv6, ok := netip.AddrFromSlice(address6)
		if !ok || !ipv6.Is6() {
			return Node{}, errors.New("corrupt node IPv6 overlay address")
		}
		result.IPv6Address = ipv6
	}
	return result, nil
}

func (s *Store) AllocateIPv4(ctx context.Context, networkID identity.NetworkID, nodeID identity.NodeID) (netip.Addr, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("begin address allocation: %w", err)
	}
	defer tx.Rollback()
	var actualNetwork []byte
	if err := tx.QueryRowContext(ctx, `SELECT network_id FROM nodes WHERE id=? AND revoked_at IS NULL`, idBytes(nodeID)).Scan(&actualNetwork); errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, ErrNotFound
	} else if err != nil {
		return netip.Addr{}, fmt.Errorf("read allocation node: %w", err)
	}
	if string(actualNetwork) != string(idBytes(networkID)) {
		return netip.Addr{}, fmt.Errorf("%w: node belongs to another network", ErrInvalid)
	}
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT address FROM overlay_addresses WHERE node_id=? AND released_at IS NULL AND length(address)=4`, idBytes(nodeID)).Scan(&existing)
	if err == nil {
		addr, ok := netip.AddrFromSlice(existing)
		if !ok {
			return netip.Addr{}, errors.New("corrupt overlay address")
		}
		if err := tx.Commit(); err != nil {
			return netip.Addr{}, err
		}
		return addr, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, fmt.Errorf("read existing overlay address: %w", err)
	}
	addr, err := allocateIPv4Tx(ctx, tx, networkID, nodeID, s.now())
	if err != nil {
		return netip.Addr{}, err
	}
	if _, err := incrementEpochTx(ctx, tx, networkID); err != nil {
		return netip.Addr{}, err
	}
	if err := tx.Commit(); err != nil {
		return netip.Addr{}, fmt.Errorf("commit address allocation: %w", err)
	}
	return addr, nil
}

func allocateIPv4Tx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, nodeID identity.NodeID, now time.Time) (netip.Addr, error) {
	var poolBytes []byte
	var bits int
	var next int64
	if err := tx.QueryRowContext(ctx, `SELECT ipv4_address,ipv4_prefix_length,next_ipv4 FROM networks WHERE id=?`, idBytes(networkID)).Scan(&poolBytes, &bits, &next); errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, ErrNotFound
	} else if err != nil {
		return netip.Addr{}, fmt.Errorf("read IPv4 pool: %w", err)
	}
	if len(poolBytes) != 4 || bits < 8 || bits > 30 || next < 1 {
		return netip.Addr{}, errors.New("corrupt IPv4 pool")
	}
	base := binary.BigEndian.Uint32(poolBytes)
	poolSize := uint64(1) << uint(32-bits)
	// Network and broadcast addresses are deliberately not assigned.
	usable := poolSize - 2
	start := uint64(next)
	if start < 1 || start > usable {
		start = 1
	}
	for checked := uint64(0); checked < usable; checked++ {
		offset := 1 + ((start - 1 + checked) % usable)
		candidateRaw := base + uint32(offset)
		var candidate [4]byte
		binary.BigEndian.PutUint32(candidate[:], candidateRaw)
		addressID, err := newID()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("generate overlay address ID: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO overlay_addresses
            (id,network_id,node_id,address,prefix_length,created_at) VALUES(?,?,?,?,32,?)`,
			idBytes(addressID), idBytes(networkID), idBytes(nodeID), candidate[:], unix(now))
		if err != nil {
			if isConstraint(err) {
				reused, reuseErr := reuseReleasedAddressTx(ctx, tx, addressID, networkID, nodeID, candidate[:], 32, now)
				if reuseErr != nil {
					return netip.Addr{}, reuseErr
				}
				if !reused {
					continue
				}
			} else {
				return netip.Addr{}, fmt.Errorf("insert overlay address: %w", err)
			}
		}
		nextOffset := offset + 1
		if nextOffset > usable {
			nextOffset = 1
		}
		if nextOffset > math.MaxInt64 {
			return netip.Addr{}, errors.New("IPv4 pool cursor overflow")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE networks SET next_ipv4=? WHERE id=?`, int64(nextOffset), idBytes(networkID)); err != nil {
			return netip.Addr{}, fmt.Errorf("advance IPv4 pool: %w", err)
		}
		return netip.AddrFrom4(candidate), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

func allocateIPv6Tx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, nodeID identity.NodeID, now time.Time) (netip.Addr, error) {
	var poolBytes []byte
	var bits sql.NullInt64
	var next int64
	if err := tx.QueryRowContext(ctx, `SELECT ipv6_address,ipv6_prefix_length,next_ipv6 FROM networks WHERE id=?`, idBytes(networkID)).Scan(&poolBytes, &bits, &next); errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, ErrNotFound
	} else if err != nil {
		return netip.Addr{}, fmt.Errorf("read IPv6 pool: %w", err)
	}
	if len(poolBytes) == 0 && !bits.Valid {
		return netip.Addr{}, nil
	}
	if len(poolBytes) != 16 || !bits.Valid || bits.Int64 < 64 || bits.Int64 > 120 || next < 1 {
		return netip.Addr{}, errors.New("corrupt IPv6 pool")
	}
	base := [16]byte(poolBytes)
	hostBits := 128 - int(bits.Int64)
	usable := uint64(math.MaxInt64)
	if hostBits < 63 {
		usable = (uint64(1) << uint(hostBits)) - 1
	}
	start := uint64(next)
	if start < 1 || start > usable {
		start = 1
	}
	for checked := uint64(0); checked < usable; checked++ {
		offset := 1 + ((start - 1 + checked) % usable)
		candidate := base
		low := binary.BigEndian.Uint64(candidate[8:])
		binary.BigEndian.PutUint64(candidate[8:], low+offset)
		addressID, err := newID()
		if err != nil {
			return netip.Addr{}, fmt.Errorf("generate IPv6 overlay address ID: %w", err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO overlay_addresses
            (id,network_id,node_id,address,prefix_length,created_at) VALUES(?,?,?,?,128,?)`,
			idBytes(addressID), idBytes(networkID), idBytes(nodeID), candidate[:], unix(now))
		if err != nil {
			if isConstraint(err) {
				reused, reuseErr := reuseReleasedAddressTx(ctx, tx, addressID, networkID, nodeID, candidate[:], 128, now)
				if reuseErr != nil {
					return netip.Addr{}, reuseErr
				}
				if !reused {
					continue
				}
			} else {
				return netip.Addr{}, fmt.Errorf("insert IPv6 overlay address: %w", err)
			}
		}
		nextOffset := offset + 1
		if nextOffset > usable {
			nextOffset = 1
		}
		if _, err := tx.ExecContext(ctx, `UPDATE networks SET next_ipv6=? WHERE id=?`, int64(nextOffset), idBytes(networkID)); err != nil {
			return netip.Addr{}, fmt.Errorf("advance IPv6 pool: %w", err)
		}
		return netip.AddrFrom16(candidate), nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

func reuseReleasedAddressTx(ctx context.Context, tx *sql.Tx, addressID identity.ID, networkID identity.NetworkID, nodeID identity.NodeID, address []byte, bits int, now time.Time) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE overlay_addresses SET id=?,node_id=?,prefix_length=?,created_at=?,released_at=NULL
		WHERE network_id=? AND address=? AND released_at IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM certificates c WHERE c.node_id=overlay_addresses.node_id AND c.not_after>? AND c.revoked_at IS NULL)`,
		idBytes(addressID), idBytes(nodeID), bits, unix(now), idBytes(networkID), address, unix(now))
	if err != nil {
		return false, fmt.Errorf("reuse released overlay address: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check released overlay address reuse: %w", err)
	}
	return changed == 1, nil
}
