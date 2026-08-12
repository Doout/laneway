package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"laneway.dev/laneway/internal/identity"
)

func (s *Store) AddCertificate(ctx context.Context, networkID identity.NetworkID, nodeID identity.NodeID, serial, der []byte, notBefore, notAfter time.Time) (Certificate, error) {
	material, err := normalizeCertificateMaterial(CertificateMaterial{
		Serial: serial, DER: der, NotBefore: notBefore, NotAfter: notAfter,
	})
	if err != nil {
		return Certificate{}, err
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Certificate{}, fmt.Errorf("begin add certificate: %w", err)
	}
	defer tx.Rollback()
	var class string
	var lease sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT enrollment_class,lease_expires_at FROM nodes WHERE id=? AND network_id=? AND revoked_at IS NULL`, idBytes(nodeID), idBytes(networkID)).Scan(&class, &lease); errors.Is(err, sql.ErrNoRows) {
		return Certificate{}, ErrNotFound
	} else if err != nil {
		return Certificate{}, fmt.Errorf("read certificate node: %w", err)
	}
	if EnrollmentClass(class) == EnrollmentClassEphemeral {
		if !lease.Valid || material.NotAfter.After(fromUnix(lease.Int64)) {
			return Certificate{}, fmt.Errorf("%w: ephemeral certificate exceeds identity lease", ErrInvalid)
		}
	}
	certificate, err := addCertificateTx(ctx, tx, networkID, nodeID, material, now)
	if err != nil {
		return Certificate{}, err
	}
	if err := tx.Commit(); err != nil {
		return Certificate{}, fmt.Errorf("commit certificate: %w", err)
	}
	return certificate, nil
}

// RenewNodeBound validates the current durable identity and commits the
// replacement certificate and WireGuard key as one transaction. If the key
// changes, the network epoch advances in that same commit so no successful
// response can leave peers indefinitely authorizing the old key.
func (s *Store) RenewNodeBound(ctx context.Context, networkID identity.NetworkID, nodeID identity.NodeID, wireGuardPublicKey WireGuardPublicKey, issuer EnrollmentCertificateIssuer) (NodeRenewal, error) {
	if networkID.IsZero() || nodeID.IsZero() || issuer == nil {
		return NodeRenewal{}, fmt.Errorf("%w: renewal identity and issuer are required", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NodeRenewal{}, fmt.Errorf("begin node renewal: %w", err)
	}
	defer tx.Rollback()
	var name, class string
	var capabilities, created, epoch int64
	var lease sql.NullInt64
	var currentKey []byte
	if err := tx.QueryRowContext(ctx, `SELECT n.name,n.enabled_capabilities,n.created_at,n.enrollment_class,n.lease_expires_at,n.wireguard_public_key,w.configuration_epoch
		FROM nodes n JOIN networks w ON w.id=n.network_id
		WHERE n.id=? AND n.network_id=? AND n.revoked_at IS NULL AND (n.lease_expires_at IS NULL OR n.lease_expires_at>?)`,
		idBytes(nodeID), idBytes(networkID), unix(now)).Scan(&name, &capabilities, &created, &class, &lease, &currentKey, &epoch); errors.Is(err, sql.ErrNoRows) {
		return NodeRenewal{}, ErrNotFound
	} else if err != nil {
		return NodeRenewal{}, fmt.Errorf("read renewal node: %w", err)
	}
	enrollmentClass := EnrollmentClass(class)
	if !enrollmentClass.Valid() || (enrollmentClass == EnrollmentClassEphemeral) != lease.Valid || epoch < 1 {
		return NodeRenewal{}, errors.New("corrupt renewal node")
	}
	existingKey, err := scanWireGuardPublicKey(currentKey)
	if err != nil {
		return NodeRenewal{}, err
	}
	// Absence is the stable-v1 compatibility value: an already-bound node keeps
	// its key, while a pre-v6 node remains unbound and therefore ineligible for
	// the hybrid dataplane. Updated clients always send an explicit key.
	if wireGuardPublicKey.IsZero() {
		wireGuardPublicKey = existingKey
	}
	node := Node{ID: nodeID, NetworkID: networkID, Name: name, EnabledCapabilities: uint64(capabilities), CreatedAt: fromUnix(created), EnrollmentClass: enrollmentClass, LeaseExpiresAt: nullableTime(lease), WireGuardPublicKey: wireGuardPublicKey}
	material, err := issuer(ctx, node)
	if err != nil {
		return NodeRenewal{}, fmt.Errorf("issue renewal certificate: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return NodeRenewal{}, fmt.Errorf("issue renewal certificate: %w", err)
	}
	material, err = normalizeCertificateMaterial(material)
	if err != nil {
		return NodeRenewal{}, fmt.Errorf("persist renewal certificate: %w", err)
	}
	if lease.Valid && material.NotAfter.After(fromUnix(lease.Int64)) {
		return NodeRenewal{}, fmt.Errorf("persist renewal certificate: %w: certificate exceeds identity lease", ErrInvalid)
	}
	certificate, err := addCertificateTx(ctx, tx, networkID, nodeID, material, now)
	if err != nil {
		return NodeRenewal{}, fmt.Errorf("persist renewal certificate: %w", err)
	}
	if existingKey != wireGuardPublicKey {
		if _, err := tx.ExecContext(ctx, `UPDATE nodes SET wireguard_public_key=? WHERE id=? AND network_id=?`, wireGuardPublicKey[:], idBytes(nodeID), idBytes(networkID)); err != nil {
			if isConstraint(err) {
				return NodeRenewal{}, fmt.Errorf("%w: WireGuard public key already belongs to another node", ErrConflict)
			}
			return NodeRenewal{}, fmt.Errorf("rotate WireGuard public key: %w", err)
		}
		newEpoch, err := incrementEpochTx(ctx, tx, networkID)
		if err != nil {
			return NodeRenewal{}, err
		}
		epoch = int64(newEpoch)
		target := identity.ID(nodeID)
		if err := auditTx(ctx, tx, networkID, &nodeID, "node.wireguard_key.rotate", "node", &target, `{}`, now); err != nil {
			return NodeRenewal{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return NodeRenewal{}, fmt.Errorf("commit node renewal: %w", err)
	}
	return NodeRenewal{Node: node, Certificate: certificate, Epoch: uint64(epoch)}, nil
}

func normalizeCertificateMaterial(material CertificateMaterial) (CertificateMaterial, error) {
	material.NotBefore = material.NotBefore.UTC().Truncate(time.Second)
	material.NotAfter = material.NotAfter.UTC().Truncate(time.Second)
	if len(material.Serial) < 1 || len(material.Serial) > 32 || len(material.DER) < 1 || len(material.DER) > 65536 || !material.NotAfter.After(material.NotBefore) {
		return CertificateMaterial{}, fmt.Errorf("%w: invalid certificate fields", ErrInvalid)
	}
	material.Serial = append([]byte(nil), material.Serial...)
	material.DER = append([]byte(nil), material.DER...)
	return material, nil
}

func addCertificateTx(ctx context.Context, tx *sql.Tx, networkID identity.NetworkID, nodeID identity.NodeID, material CertificateMaterial, now time.Time) (Certificate, error) {
	id, err := newID()
	if err != nil {
		return Certificate{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO certificates
        (id,network_id,node_id,serial,der,not_before,not_after,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		idBytes(id), idBytes(networkID), idBytes(nodeID), material.Serial, material.DER, unix(material.NotBefore), unix(material.NotAfter), unix(now)); err != nil {
		if isConstraint(err) {
			return Certificate{}, fmt.Errorf("%w: duplicate certificate serial", ErrConflict)
		}
		return Certificate{}, fmt.Errorf("insert certificate: %w", err)
	}
	target := id
	if err := auditTx(ctx, tx, networkID, &nodeID, "certificate.issue", "certificate", &target, `{}`, now); err != nil {
		return Certificate{}, err
	}
	return Certificate{
		ID: id, NetworkID: networkID, NodeID: nodeID,
		Serial: material.Serial, DER: material.DER,
		NotBefore: material.NotBefore, NotAfter: material.NotAfter, CreatedAt: now,
	}, nil
}

func (s *Store) RevokeCertificate(ctx context.Context, certificateID identity.ID, reason string) (uint64, error) {
	if reason != strings.TrimSpace(reason) || reason == "" || len(reason) > 1024 {
		return 0, fmt.Errorf("%w: revocation reason", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin certificate revocation: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT network_id,revoked_at FROM certificates WHERE id=?`, idBytes(certificateID)).Scan(&networkBytes, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read certificate: %w", err)
	}
	if revoked.Valid {
		return 0, fmt.Errorf("%w: certificate already revoked", ErrConflict)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at=?,revocation_reason=? WHERE id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(certificateID)); err != nil {
		return 0, fmt.Errorf("revoke certificate: %w", err)
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	if err := auditTx(ctx, tx, networkID, nil, "certificate.revoke", "certificate", &certificateID, fmt.Sprintf(`{"reason":%q}`, reason), now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit certificate revocation: %w", err)
	}
	return epoch, nil
}

// RevokeCertificateBySerial revokes exactly one certificate in the requested
// network. Serial numbers are only unique within a network, so administrative
// callers must always supply both values.
func (s *Store) RevokeCertificateBySerial(ctx context.Context, networkID identity.NetworkID, serial []byte, reason string) (uint64, error) {
	if networkID.IsZero() || len(serial) < 1 || len(serial) > 32 || serial[0] == 0 {
		return 0, fmt.Errorf("%w: certificate network or serial", ErrInvalid)
	}
	var certificateRaw []byte
	err := s.db.QueryRowContext(ctx, `SELECT id FROM certificates WHERE network_id=? AND serial=?`, idBytes(networkID), serial).Scan(&certificateRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read certificate by network serial: %w", err)
	}
	certificateID, err := scanID(certificateRaw)
	if err != nil {
		return 0, err
	}
	return s.RevokeCertificate(ctx, certificateID, reason)
}

// RevokedCertificateSerials returns canonical serials for revoked
// certificates that have not yet expired. Expired certificates cannot
// authenticate and are omitted to keep distributed snapshots bounded by the
// active credential population.
func (s *Store) RevokedCertificateSerials(ctx context.Context, networkID identity.NetworkID, now time.Time) ([][]byte, error) {
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: network ID", ErrInvalid)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT serial FROM certificates
		WHERE network_id=? AND revoked_at IS NOT NULL AND not_after>? ORDER BY serial`, idBytes(networkID), unix(now))
	if err != nil {
		return nil, fmt.Errorf("query revoked certificate serials: %w", err)
	}
	defer rows.Close()
	var result [][]byte
	for rows.Next() {
		var serial []byte
		if err := rows.Scan(&serial); err != nil {
			return nil, fmt.Errorf("scan revoked certificate serial: %w", err)
		}
		if len(serial) < 1 || len(serial) > 32 || serial[0] == 0 {
			return nil, errors.New("stored certificate has a noncanonical serial")
		}
		result = append(result, append([]byte(nil), serial...))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate revoked certificate serials: %w", err)
	}
	return result, nil
}

func (s *Store) RevokeNode(ctx context.Context, nodeID identity.NodeID, reason string) (uint64, error) {
	if reason != strings.TrimSpace(reason) || reason == "" || len(reason) > 1024 {
		return 0, fmt.Errorf("%w: revocation reason", ErrInvalid)
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin node revocation: %w", err)
	}
	defer tx.Rollback()
	var networkBytes []byte
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT network_id,revoked_at FROM nodes WHERE id=?`, idBytes(nodeID)).Scan(&networkBytes, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("read node: %w", err)
	}
	if revoked.Valid {
		return 0, fmt.Errorf("%w: node already revoked", ErrConflict)
	}
	networkRaw, err := scanID(networkBytes)
	if err != nil {
		return 0, err
	}
	networkID := identity.NetworkID(networkRaw)
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET revoked_at=? WHERE id=?`, unix(now), idBytes(nodeID)); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at=?,revocation_reason=? WHERE node_id=? AND revoked_at IS NULL`, unix(now), reason, idBytes(nodeID)); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE overlay_addresses SET released_at=? WHERE node_id=? AND released_at IS NULL`, unix(now), idBytes(nodeID)); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET state='withdrawn',withdrawn_at=? WHERE node_id=? AND state IN ('advertised','approved')`, unix(now), idBytes(nodeID)); err != nil {
		return 0, err
	}
	epoch, err := incrementEpochTx(ctx, tx, networkID)
	if err != nil {
		return 0, err
	}
	target := identity.ID(nodeID)
	if err := auditTx(ctx, tx, networkID, nil, "node.revoke", "node", &target, fmt.Sprintf(`{"reason":%q}`, reason), now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit node revocation: %w", err)
	}
	return epoch, nil
}
