package controller

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
)

func TestEndpointStatusLatestOnlyExpiryAndConfigurationDrift(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_100_000, 0).UTC()
	store.now = func() time.Time { return now }
	network := resourceTestNetwork(t, store, "status-network", "10.110.0.0/24")
	node := resourceTestNode(t, store, network.ID, "status-node", 0)
	if _, err := store.AddCertificate(ctx, network.ID, node.ID, []byte{1}, []byte{1},
		now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	decision := administratorRootDecision(t, store, administratorEndpointStatusListPolicy,
		adminauth.NetworkTarget(network.ID))

	values, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, now)
	if err != nil || len(values) != 1 || values[0].Freshness != EndpointStatusNeverReported || values[0].Report != nil {
		t.Fatalf("unreported statuses=%+v err=%v", values, err)
	}
	currentNetwork, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := testEndpointStatusReport()
	report.ConfigurationEpoch = currentNetwork.ConfigurationEpoch
	caller := identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}
	if err := store.RecordEndpointStatus(ctx, caller, report, now); err != nil {
		t.Fatal(err)
	}
	equalSecond := report
	equalSecond.ProductVersion = "1.2.4"
	if err := store.RecordEndpointStatus(ctx, caller, equalSecond, now); err != nil {
		t.Fatalf("replace equal-second report: %v", err)
	}
	report = equalSecond
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, now)
	if err != nil || len(values) != 1 || values[0].Freshness != EndpointStatusCurrent || values[0].Report == nil ||
		values[0].Report.ConfigurationState != ConfigurationStatusCurrent ||
		values[0].AuthoritativeConfigurationEpoch != report.ConfigurationEpoch {
		t.Fatalf("current statuses=%+v err=%v", values, err)
	}

	_, newEpoch, err := store.AddACLRule(ctx, network.ID, 10, ACLActionDeny, `{}`, "advance status epoch")
	if err != nil {
		t.Fatal(err)
	}
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, now.Add(time.Second))
	if err != nil || values[0].Report == nil || values[0].Report.ConfigurationState != ConfigurationStatusStale ||
		values[0].AuthoritativeConfigurationEpoch != newEpoch {
		t.Fatalf("drifted statuses=%+v err=%v", values, err)
	}
	future := report
	future.ConfigurationEpoch = newEpoch + 1
	if err := store.RecordEndpointStatus(ctx, caller, future, now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("future configuration epoch error=%v", err)
	}

	older := report
	older.ProductVersion = "0.9.0"
	if err := store.RecordEndpointStatus(ctx, caller, older, now.Add(-time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("older report error=%v", err)
	}
	var retained string
	var rowCount int
	if err := store.db.QueryRowContext(ctx, `SELECT product_version,count(*) OVER() FROM endpoint_status_latest WHERE node_id=?`,
		idBytes(node.ID)).Scan(&retained, &rowCount); err != nil {
		t.Fatal(err)
	}
	if retained != "1.2.4" || rowCount != 1 {
		t.Fatalf("latest-only version=%q rows=%d", retained, rowCount)
	}

	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10,
		now.Add(time.Duration(report.ValidForSeconds)*time.Second))
	if err != nil || values[0].Freshness != EndpointStatusExpired || values[0].Report != nil ||
		values[0].LastReportedAt == nil || values[0].ExpiresAt == nil {
		t.Fatalf("expired statuses=%+v err=%v", values, err)
	}
}

func TestEndpointStatusValidationAndInactiveProjection(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_200_000, 0).UTC()
	store.now = func() time.Time { return now }
	network := resourceTestNetwork(t, store, "inactive-status-network", "10.111.0.0/24")
	node := resourceTestNode(t, store, network.ID, "inactive-status-node", 0)
	caller := identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}

	invalid := testEndpointStatusReport()
	invalid.Platform = "free-form-platform"
	if err := store.RecordEndpointStatus(ctx, caller, invalid, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid enum error=%v", err)
	}
	currentNetwork, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	valid := testEndpointStatusReport()
	valid.ConfigurationEpoch = currentNetwork.ConfigurationEpoch
	if err := store.RecordEndpointStatus(ctx, caller, valid, now); err != nil {
		t.Fatal(err)
	}
	decision := administratorRootDecision(t, store, administratorEndpointStatusListPolicy,
		adminauth.NetworkTarget(network.ID))
	values, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, now)
	if err != nil || len(values) != 1 || values[0].Freshness != EndpointStatusNodeInactive || values[0].Report != nil {
		t.Fatalf("credentialless status projection=%+v err=%v", values, err)
	}
}

func TestEndpointStatusReportBoundaries(t *testing.T) {
	base := testEndpointStatusReport()
	tests := []struct {
		name    string
		mutate  func(*EndpointStatusReport)
		invalid bool
	}{
		{"minimum validity", func(report *EndpointStatusReport) { report.ValidForSeconds = 10 }, false},
		{"below minimum validity", func(report *EndpointStatusReport) { report.ValidForSeconds = 9 }, true},
		{"maximum validity", func(report *EndpointStatusReport) { report.ValidForSeconds = 300 }, false},
		{"above maximum validity", func(report *EndpointStatusReport) { report.ValidForSeconds = 301 }, true},
		{"maximum version", func(report *EndpointStatusReport) { report.ProductVersion = strings.Repeat("v", 64) }, false},
		{"long version", func(report *EndpointStatusReport) { report.ProductVersion = strings.Repeat("v", 65) }, true},
		{"space in version", func(report *EndpointStatusReport) { report.ProductVersion = "1.2 beta" }, true},
		{"non ASCII version", func(report *EndpointStatusReport) { report.ProductVersion = "1.2.β" }, true},
		{"maximum cleanup failures", func(report *EndpointStatusReport) { report.CleanupFailures = MaxEndpointCleanupFailures }, false},
		{"excess cleanup failures", func(report *EndpointStatusReport) { report.CleanupFailures = MaxEndpointCleanupFailures + 1 }, true},
		{"maximum epoch", func(report *EndpointStatusReport) { report.ConfigurationEpoch = math.MaxInt64 }, false},
		{"excess epoch", func(report *EndpointStatusReport) { report.ConfigurationEpoch = uint64(math.MaxInt64) + 1 }, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := base
			test.mutate(&report)
			err := report.Validate()
			if test.invalid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("validation error=%v want ErrInvalid", err)
			}
			if !test.invalid && err != nil {
				t.Fatalf("valid report rejected: %v", err)
			}
		})
	}
}

func TestEndpointStatusWriteRejectsWrongOrInactiveIdentity(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_300_000, 0).UTC()
	store.now = func() time.Time { return now }
	first := resourceTestNetwork(t, store, "write-status-network", "10.112.0.0/24")
	second := resourceTestNetwork(t, store, "other-status-network", "10.113.0.0/24")
	node := resourceTestNode(t, store, first.ID, "write-status-node", 0)
	current, err := store.Network(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := testEndpointStatusReport()
	report.ConfigurationEpoch = current.ConfigurationEpoch

	for name, caller := range map[string]identity.NodeIdentity{
		"wrong network": {NetworkID: second.ID, NodeID: node.ID},
		"unknown node":  {NetworkID: first.ID, NodeID: identity.NodeID{0x7f}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.RecordEndpointStatus(ctx, caller, report, now); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("write error=%v want ErrPermissionDenied", err)
			}
		})
	}
	if _, err := store.RevokeNode(ctx, node.ID, "status test"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: first.ID, NodeID: node.ID}, report, now); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked node write error=%v want ErrPermissionDenied", err)
	}

	ephemeralToken, err := store.IssueEnrollmentTokenWithOptions(ctx, second.ID, "ephemeral-status", now.Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := store.EnrollNode(ctx, ephemeralToken.Secret, "ephemeral-status", 0)
	if err != nil {
		t.Fatal(err)
	}
	secondCurrent, err := store.Network(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	report.ConfigurationEpoch = secondCurrent.ConfigurationEpoch
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: second.ID, NodeID: ephemeral.ID}, report,
		*ephemeral.LeaseExpiresAt); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("expired lease write error=%v want ErrPermissionDenied", err)
	}
}

func TestEndpointStatusInactiveProjectionBoundaries(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_400_000, 0).UTC()
	store.now = func() time.Time { return now }
	network := resourceTestNetwork(t, store, "status-boundary-network", "10.114.0.0/24")
	current, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := testEndpointStatusReport()
	report.ConfigurationEpoch = current.ConfigurationEpoch
	decision := administratorRootDecision(t, store, administratorEndpointStatusListPolicy,
		adminauth.NetworkTarget(network.ID))

	certificateNode := resourceTestNode(t, store, network.ID, "certificate-boundary-node", 0)
	current, err = store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report.ConfigurationEpoch = current.ConfigurationEpoch
	certificateExpiry := now.Add(30 * time.Second)
	if _, err := store.AddCertificate(ctx, network.ID, certificateNode.ID, []byte{2}, []byte{2},
		now.Add(-time.Second), certificateExpiry); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: certificateNode.ID}, report, now); err != nil {
		t.Fatal(err)
	}
	values, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, certificateExpiry.Add(-time.Second))
	if err != nil || len(values) != 1 || values[0].Freshness != EndpointStatusCurrent {
		t.Fatalf("pre-expiry statuses=%+v err=%v", values, err)
	}
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, certificateExpiry)
	if err != nil || len(values) != 1 || values[0].Freshness != EndpointStatusNodeInactive || values[0].Report != nil {
		t.Fatalf("certificate-expiry statuses=%+v err=%v", values, err)
	}

	revokedNode := resourceTestNode(t, store, network.ID, "revoked-status-node", 0)
	current, err = store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report.ConfigurationEpoch = current.ConfigurationEpoch
	if _, err := store.AddCertificate(ctx, network.ID, revokedNode.ID, []byte{3}, []byte{3},
		now.Add(-time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: revokedNode.ID}, report, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE nodes SET revoked_at=? WHERE id=?`,
		unix(now), idBytes(revokedNode.ID)); err != nil {
		t.Fatal(err)
	}
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, now)
	if err != nil || len(values) != 2 {
		t.Fatalf("revoked-node statuses=%+v err=%v", values, err)
	}
	foundRevoked := false
	for _, value := range values {
		if value.NodeID == revokedNode.ID && (value.Freshness != EndpointStatusNodeInactive || value.Report != nil) {
			t.Fatalf("revoked-node status=%+v", value)
		}
		foundRevoked = foundRevoked || value.NodeID == revokedNode.ID
	}
	if !foundRevoked {
		t.Fatalf("revoked node missing from statuses=%+v", values)
	}

	ephemeralToken, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "lease-boundary-status", now.Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := store.EnrollNode(ctx, ephemeralToken.Secret, "lease-boundary-status", 0)
	if err != nil {
		t.Fatal(err)
	}
	current, err = store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report.ConfigurationEpoch = current.ConfigurationEpoch
	report.ValidForSeconds = 10
	if _, err := store.AddCertificate(ctx, network.ID, ephemeral.ID, []byte{4}, []byte{4},
		now, *ephemeral.LeaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	beforeLeaseExpiry := ephemeral.LeaseExpiresAt.Add(-time.Second)
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: ephemeral.ID}, report,
		beforeLeaseExpiry); err != nil {
		t.Fatal(err)
	}
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, beforeLeaseExpiry)
	if err != nil {
		t.Fatal(err)
	}
	foundCurrentEphemeral := false
	for _, value := range values {
		foundCurrentEphemeral = foundCurrentEphemeral || value.NodeID == ephemeral.ID && value.Freshness == EndpointStatusCurrent
	}
	if !foundCurrentEphemeral {
		t.Fatalf("ephemeral node not current before lease expiry: %+v", values)
	}
	values, err = store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10, *ephemeral.LeaseExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	foundInactiveEphemeral := false
	for _, value := range values {
		foundInactiveEphemeral = foundInactiveEphemeral || value.NodeID == ephemeral.ID &&
			value.Freshness == EndpointStatusNodeInactive && value.Report == nil
	}
	if !foundInactiveEphemeral {
		t.Fatalf("ephemeral node not inactive at lease expiry: %+v", values)
	}
}

func TestEndpointStatusAdministratorScopeDoesNotLeakOtherNetworks(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	allowed := resourceTestNetwork(t, store, "allowed-status-network", "10.115.0.0/24")
	denied := resourceTestNetwork(t, store, "denied-status-network", "10.116.0.0/24")
	subject := administratorSessionSubject(t, store, "status-operator", adminauth.RoleOperator, false, allowed.ID)
	decision := administratorDecisionForSubject(t, subject, administratorEndpointStatusListPolicy,
		adminauth.NetworkTarget(denied.ID))
	if _, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, denied.ID, 10, store.now()); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("out-of-scope endpoint statuses error=%v want ErrPermissionDenied", err)
	}
}

func TestEndpointStatusTamperedExpiryCannotRemainCurrent(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_900_500_000, 0).UTC()
	store.now = func() time.Time { return now }
	network := resourceTestNetwork(t, store, "tampered-status-network", "10.117.0.0/24")
	node := resourceTestNode(t, store, network.ID, "tampered-status-node", 0)
	if _, err := store.AddCertificate(ctx, network.ID, node.ID, []byte{5}, []byte{5},
		now.Add(-time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	current, err := store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	report := testEndpointStatusReport()
	report.ConfigurationEpoch = current.ConfigurationEpoch
	if err := store.RecordEndpointStatus(ctx, identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}, report, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON;
		UPDATE endpoint_status_latest SET expires_at=observed_at+10000 WHERE node_id=?;
		PRAGMA ignore_check_constraints=OFF`, idBytes(node.ID)); err != nil {
		t.Fatal(err)
	}
	decision := administratorRootDecision(t, store, administratorEndpointStatusListPolicy,
		adminauth.NetworkTarget(network.ID))
	if _, err := store.AdministratorNetworkEndpointStatuses(ctx, decision, network.ID, 10,
		now.Add(time.Duration(MaxEndpointStatusValiditySeconds+1)*time.Second)); err == nil ||
		!strings.Contains(err.Error(), "corrupt endpoint status TTL") {
		t.Fatalf("tampered expiry read error=%v", err)
	}
}
