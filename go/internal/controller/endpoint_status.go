package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	MinEndpointStatusValiditySeconds uint32 = 10
	MaxEndpointStatusValiditySeconds uint32 = 300
	MaxEndpointProductVersionBytes          = 64
	MaxEndpointCleanupFailures       uint32 = 1_000_000_000
)

func (report EndpointStatusReport) Validate() error {
	if report.ValidForSeconds < MinEndpointStatusValiditySeconds || report.ValidForSeconds > MaxEndpointStatusValiditySeconds {
		return fmt.Errorf("%w: endpoint status valid_for_seconds must be %d..%d", ErrInvalid,
			MinEndpointStatusValiditySeconds, MaxEndpointStatusValiditySeconds)
	}
	if !validProductVersion(report.ProductVersion) {
		return fmt.Errorf("%w: endpoint status product_version must be 1..%d printable ASCII bytes", ErrInvalid,
			MaxEndpointProductVersionBytes)
	}
	if !report.Platform.Valid() || !report.CertificateState.Valid() || !report.ConfigurationState.Valid() ||
		!report.CarrierState.Valid() || !report.RouteState.Valid() || !report.SelectedExitState.Valid() {
		return fmt.Errorf("%w: endpoint status contains an unknown state", ErrInvalid)
	}
	if report.CleanupFailures > MaxEndpointCleanupFailures {
		return fmt.Errorf("%w: endpoint cleanup failure count is too large", ErrInvalid)
	}
	if report.ConfigurationEpoch > math.MaxInt64 {
		return fmt.Errorf("%w: endpoint configuration epoch is too large", ErrInvalid)
	}
	return nil
}

func validProductVersion(value string) bool {
	if value == "" || len(value) > MaxEndpointProductVersionBytes || value != strings.TrimSpace(value) {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// RecordEndpointStatus atomically replaces one node's latest observation.
// The controller clock owns observed_at and expires_at; clients can only select
// a short bounded validity. This operation never writes audit or history rows.
func (s *Store) RecordEndpointStatus(ctx context.Context, caller identity.NodeIdentity, report EndpointStatusReport, observedAt time.Time) error {
	if err := caller.Validate(); err != nil {
		return fmt.Errorf("%w: invalid endpoint status identity", ErrInvalid)
	}
	if err := report.Validate(); err != nil {
		return err
	}
	observedAt = observedAt.UTC().Truncate(time.Second)
	if observedAt.IsZero() {
		return fmt.Errorf("%w: invalid endpoint status time", ErrInvalid)
	}
	expiresAt := observedAt.Add(time.Duration(report.ValidForSeconds) * time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin endpoint status update: %w", err)
	}
	defer tx.Rollback()

	var revokedAt, leaseExpiresAt sql.NullInt64
	var enrollmentClass string
	var authoritativeEpoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT n.revoked_at,n.enrollment_class,n.lease_expires_at,w.configuration_epoch
		FROM nodes n JOIN networks w ON w.id=n.network_id WHERE n.id=? AND n.network_id=?`,
		idBytes(caller.NodeID), idBytes(caller.NetworkID)).
		Scan(&revokedAt, &enrollmentClass, &leaseExpiresAt, &authoritativeEpoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPermissionDenied
		}
		return fmt.Errorf("authorize endpoint status update: %w", err)
	}
	if revokedAt.Valid || EnrollmentClass(enrollmentClass) == EnrollmentClassEphemeral &&
		(!leaseExpiresAt.Valid || observedAt.Unix() >= leaseExpiresAt.Int64) {
		return ErrPermissionDenied
	}
	if report.ConfigurationEpoch > authoritativeEpoch {
		return fmt.Errorf("%w: endpoint configuration epoch is ahead of the controller", ErrConflict)
	}
	if report.ConfigurationEpoch < authoritativeEpoch {
		report.ConfigurationState = ConfigurationStatusStale
	}

	result, err := tx.ExecContext(ctx, `INSERT INTO endpoint_status_latest
		(node_id,network_id,observed_at,expires_at,valid_for_seconds,product_version,platform,
		 certificate_state,configuration_state,carrier_state,route_state,selected_exit_state,
		 cleanup_failure_count,configuration_epoch)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET
		 observed_at=excluded.observed_at,expires_at=excluded.expires_at,
		 valid_for_seconds=excluded.valid_for_seconds,product_version=excluded.product_version,
		 platform=excluded.platform,certificate_state=excluded.certificate_state,
		 configuration_state=excluded.configuration_state,carrier_state=excluded.carrier_state,
		 route_state=excluded.route_state,selected_exit_state=excluded.selected_exit_state,
		 cleanup_failure_count=excluded.cleanup_failure_count,configuration_epoch=excluded.configuration_epoch
		WHERE excluded.observed_at >= endpoint_status_latest.observed_at`,
		idBytes(caller.NodeID), idBytes(caller.NetworkID), unix(observedAt), unix(expiresAt),
		report.ValidForSeconds, report.ProductVersion, string(report.Platform), string(report.CertificateState),
		string(report.ConfigurationState), string(report.CarrierState), string(report.RouteState),
		string(report.SelectedExitState), report.CleanupFailures, report.ConfigurationEpoch)
	if err != nil {
		if isConstraint(err) {
			return fmt.Errorf("%w: invalid endpoint status", ErrInvalid)
		}
		return fmt.Errorf("record endpoint status: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("count endpoint status update: %w", err)
		}
		return fmt.Errorf("%w: endpoint status observation predates the retained report", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit endpoint status update: %w", err)
	}
	return nil
}

// AdministratorNetworkEndpointStatuses returns one bounded row per node so a
// missing report is explicit. Expired or inactive rows retain only timestamps
// as evidence; their stale runtime fields are never returned.
func (s *Store) AdministratorNetworkEndpointStatuses(ctx context.Context, decision adminauth.Decision,
	networkID identity.NetworkID, limit int, at time.Time) ([]EndpointStatus, error) {
	if err := validateListLimit(limit); err != nil {
		return nil, err
	}
	at = at.UTC().Truncate(time.Second)
	if networkID.IsZero() || at.IsZero() {
		return nil, fmt.Errorf("%w: endpoint status query scope", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin endpoint status list: %w", err)
	}
	defer tx.Rollback()
	if _, err := s.authorizeAdministratorNetworkResourceTx(ctx, tx, decision,
		administratorEndpointStatusListPolicy, networkID); err != nil {
		return nil, err
	}
	if err := administratorNetworkExistsTx(ctx, tx, networkID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.id,n.name,n.revoked_at,n.enrollment_class,n.lease_expires_at,w.configuration_epoch,
		s.observed_at,s.expires_at,s.valid_for_seconds,s.product_version,s.platform,s.certificate_state,
		s.configuration_state,s.carrier_state,s.route_state,s.selected_exit_state,
		s.cleanup_failure_count,s.configuration_epoch,
		EXISTS(SELECT 1 FROM certificates c WHERE c.node_id=n.id AND c.network_id=n.network_id
			AND c.revoked_at IS NULL AND c.not_before<=? AND c.not_after>?)
		FROM nodes n JOIN networks w ON w.id=n.network_id LEFT JOIN endpoint_status_latest s ON s.node_id=n.id
		WHERE n.network_id=? ORDER BY n.created_at,n.id LIMIT ?`, unix(at), unix(at), idBytes(networkID), limit)
	if err != nil {
		return nil, fmt.Errorf("list endpoint statuses: %w", err)
	}
	values, err := scanEndpointStatuses(rows, networkID, at)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit endpoint status list: %w", err)
	}
	return values, nil
}

func scanEndpointStatuses(rows *sql.Rows, networkID identity.NetworkID, at time.Time) ([]EndpointStatus, error) {
	defer rows.Close()
	result := make([]EndpointStatus, 0)
	for rows.Next() {
		var nodeRaw []byte
		var name, enrollmentClass string
		var revokedAt, leaseExpiresAt sql.NullInt64
		var observedAt, expiresAt, validity, cleanupFailures, configurationEpoch sql.NullInt64
		var authoritativeEpoch uint64
		var productVersion, platform, certificateState, configurationState sql.NullString
		var carrierState, routeState, selectedExitState sql.NullString
		var hasValidCertificate bool
		if err := rows.Scan(&nodeRaw, &name, &revokedAt, &enrollmentClass, &leaseExpiresAt, &authoritativeEpoch,
			&observedAt, &expiresAt, &validity, &productVersion, &platform, &certificateState,
			&configurationState, &carrierState, &routeState, &selectedExitState,
			&cleanupFailures, &configurationEpoch, &hasValidCertificate); err != nil {
			return nil, fmt.Errorf("scan endpoint status: %w", err)
		}
		nodeValue, err := scanID(nodeRaw)
		if err != nil {
			return nil, err
		}
		value := EndpointStatus{NodeID: identity.NodeID(nodeValue), NetworkID: networkID, NodeName: name,
			AuthoritativeConfigurationEpoch: authoritativeEpoch}
		if observedAt.Valid != expiresAt.Valid {
			return nil, errors.New("corrupt endpoint status timestamps")
		}
		if observedAt.Valid {
			if !validity.Valid || validity.Int64 < int64(MinEndpointStatusValiditySeconds) ||
				validity.Int64 > int64(MaxEndpointStatusValiditySeconds) ||
				observedAt.Int64 > math.MaxInt64-validity.Int64 ||
				expiresAt.Int64 != observedAt.Int64+validity.Int64 {
				return nil, errors.New("corrupt endpoint status TTL")
			}
			observed := fromUnix(observedAt.Int64)
			expires := fromUnix(expiresAt.Int64)
			value.LastReportedAt, value.ExpiresAt = &observed, &expires
		}
		inactive := revokedAt.Valid || !hasValidCertificate || EnrollmentClass(enrollmentClass) == EnrollmentClassEphemeral &&
			(!leaseExpiresAt.Valid || at.Unix() >= leaseExpiresAt.Int64)
		switch {
		case inactive:
			value.Freshness = EndpointStatusNodeInactive
		case !observedAt.Valid:
			value.Freshness = EndpointStatusNeverReported
		case at.Unix() >= expiresAt.Int64:
			value.Freshness = EndpointStatusExpired
		default:
			if !validity.Valid || !productVersion.Valid || !platform.Valid || !certificateState.Valid ||
				!configurationState.Valid || !carrierState.Valid || !routeState.Valid || !selectedExitState.Valid ||
				!cleanupFailures.Valid || !configurationEpoch.Valid {
				return nil, errors.New("corrupt endpoint status report")
			}
			report := EndpointStatusReport{
				ValidForSeconds: uint32(validity.Int64), ProductVersion: productVersion.String,
				Platform: EndpointPlatform(platform.String), CertificateState: CertificateStatusState(certificateState.String),
				ConfigurationState: ConfigurationStatusState(configurationState.String),
				CarrierState:       CarrierStatusState(carrierState.String), RouteState: RouteStatusState(routeState.String),
				SelectedExitState: SelectedExitStatusState(selectedExitState.String),
				CleanupFailures:   uint32(cleanupFailures.Int64), ConfigurationEpoch: uint64(configurationEpoch.Int64),
			}
			if err := report.Validate(); err != nil {
				return nil, fmt.Errorf("corrupt endpoint status report: %w", err)
			}
			if report.ConfigurationEpoch > authoritativeEpoch {
				return nil, errors.New("corrupt endpoint status configuration epoch")
			}
			if report.ConfigurationEpoch < authoritativeEpoch {
				report.ConfigurationState = ConfigurationStatusStale
			}
			value.Freshness, value.Report = EndpointStatusCurrent, &report
		}
		result = append(result, value)
	}
	return result, rows.Err()
}
