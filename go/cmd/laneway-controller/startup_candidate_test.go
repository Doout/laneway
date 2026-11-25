//go:build linux

package main

import (
	"context"
	"database/sql"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

// Set LANEWAY_CONTROLLER_STARTUP_BIN to a built Rust maintenance candidate.
func TestStartupPreparationBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("LANEWAY_CONTROLLER_STARTUP_BIN")
	if binary == "" {
		t.Skip("set LANEWAY_CONTROLLER_STARTUP_BIN to the absolute path of a controller candidate")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("LANEWAY_CONTROLLER_STARTUP_BIN must be an absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	database := filepath.Join(dir, "controller.db")
	now := time.Now().UTC()
	network, subject := identity.NetworkID{1}, identity.ID{2}
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issueController := func(id identity.ID) pki.Material {
		t.Helper()
		material, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
			NetworkID: network, ServiceID: id, Role: pki.RoleController,
		}, []string{"controller.example"}, nil, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return material
	}
	paths := writeControllerRunPKI(t, dir, root, issuer, issuerMaterial, issueController(subject))
	config := writeRunnableControllerConfig(t, dir, database, network, paths)
	run := func(config, wantError string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, binary, "-config", config, "-prepare-startup").CombinedOutput()
		if wantError == "" {
			if err != nil || !strings.Contains(string(out), "startup state prepared") {
				t.Fatalf("startup preparation failed: %v\n%s", err, out)
			}
		} else if err == nil || !strings.Contains(string(out), wantError) {
			t.Fatalf("expected %q, got %v\n%s", wantError, err, out)
		}
	}
	config = writeRunnableControllerConfig(t, dir, database, identity.NetworkID{9}, paths)
	run(config, "does not match the verified controller certificate")
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatalf("invalid identity reached database creation: %v", err)
	}

	badToken := filepath.Join(dir, "bad-token")
	if err := os.WriteFile(badToken, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	badTokenPaths := paths
	badTokenPaths.adminToken = badToken
	run(writeRunnableControllerConfig(t, dir, database, network, badTokenPaths), "at least 32 characters")
	if _, err := os.Stat(database); !os.IsNotExist(err) {
		t.Fatalf("invalid administrator token reached database creation: %v", err)
	}

	// Create an existing network with the Go Store, then expose a v9 copy
	// without the controller identity table to the Rust candidate.
	store, err := controller.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	pool := netip.MustParsePrefix("100.96.0.0/16")
	existing, err := store.CreateNetworkDualStackWithID(ctx, network, "production", pool, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	createDowngradedV9Database(t, database)

	original := mustFileDigest(t, database)
	mismatchPaths := paths
	mismatchPaths.issuerPrivateKey = paths.serverPrivateKey
	run(writeRunnableControllerConfig(t, dir, database, network, mismatchPaths), "verify issuing authority key")
	if mustFileDigest(t, database) != original {
		t.Fatal("wrong issuer key modified v9 database")
	}
	config = writeRunnableControllerConfig(t, dir, database, network, paths)
	run(config, "")
	run(config, "")
	checkStoredControllerIdentity(t, database, network, subject)

	store, err = controller.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	got, created, err := store.EnsureControllerInitialNetwork(ctx, controller.ControllerInitialNetwork{
		NetworkID: network, Name: "production", IPv4Pool: pool,
	}, identity.AuthenticatedIdentity{
		NetworkID: network, Role: identity.IdentityRoleController, SubjectID: subject,
	})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil || created || got.CreatedAt != existing.CreatedAt {
		t.Fatalf("Go could not revalidate candidate's adopted network: created=%t, network=%+v, error=%v", created, got, err)
	}
	newCert, newKey := writeServicePair(t, dir, "foreign", issueController(identity.ID{3}), issuer.Raw)
	foreign := paths
	foreign.serverCertificate, foreign.serverPrivateKey = newCert, newKey
	run(writeRunnableControllerConfig(t, dir, database, network, foreign), "differs from durable binding")
	checkStoredControllerIdentity(t, database, network, subject)

	fresh := filepath.Join(dir, "fresh.db")
	run(writeRunnableControllerConfig(t, dir, fresh, network, paths), "")
	checkStoredControllerIdentity(t, fresh, network, subject)
	db, err := sql.Open("sqlite", "file:"+fresh+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var audits int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action IN ('network.create','controller.identity.bind')").
		Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("fresh startup created %d expected audit events: %v", audits, err)
	}
}
