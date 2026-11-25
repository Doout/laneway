package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

// Point LANEWAY_CONTROLLER_BIN at either the released controller or a candidate
// implementing its command, wire, and database contracts.
func TestControllerBinaryCompatibility(t *testing.T) {
	binary := os.Getenv("LANEWAY_CONTROLLER_BIN")
	if binary == "" {
		t.Skip("set LANEWAY_CONTROLLER_BIN to the absolute path of a controller binary")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("LANEWAY_CONTROLLER_BIN must be an absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	database := filepath.Join(dir, "controller.db")
	backup := filepath.Join(dir, "backup.db")
	networkID, controllerID, relayID := identity.NetworkID{1}, identity.ID{2}, identity.ID{3}
	pool := netip.MustParsePrefix("100.96.0.0/16")
	store, err := controller.Open(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.CreateNetworkDualStackWithID(ctx, networkID, "production", pool, netip.Prefix{})
	if closeErr := store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	createDowngradedV9Database(t, database)

	now := time.Now().UTC()
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey,
		"issuer", now.Add(-30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	controllerMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: controllerID, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	paths := writeControllerRunPKI(t, dir, root, issuer, issuerMaterial, controllerMaterial)
	relayMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: networkID, ServiceID: relayID, Role: pki.RoleRelay,
	}, nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCert, relayKey := writeServicePair(t, dir, "relay", relayMaterial, issuer.Raw)
	wrongToken := filepath.Join(dir, "wrong.token")
	if err := os.WriteFile(wrongToken, []byte(strings.Repeat("z", 48)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, config, wantError string, args ...string) {
		t.Helper()
		output, err := exec.CommandContext(ctx, binary, append([]string{"-config", config}, args...)...).CombinedOutput()
		if ctx.Err() != nil || (err == nil) != (wantError == "") {
			t.Fatalf("controller %q: %v\n%s", args, err, output)
		}
		if wantError != "" {
			if _, ok := err.(*exec.ExitError); !ok {
				t.Fatalf("controller did not execute: %v", err)
			}
			if !strings.Contains(string(output), wantError) {
				t.Fatalf("controller %q: wanted error containing %q, got %s", args, wantError, output)
			}
		}
	}
	config := writeRunnableControllerConfig(t, dir, database, identity.NetworkID{9}, paths)
	before := mustFileDigest(t, database)
	run(t, config, "does not match the verified controller certificate")
	if after := mustFileDigest(t, database); after != before {
		t.Fatal("certificate/config mismatch modified the v9 database")
	}
	config = writeRunnableControllerConfig(t, dir, database, networkID, paths)

	check := func(t *testing.T, config string, first bool, whileRunning func()) {
		t.Helper()
		https, quic := startContractController(t, ctx, binary, config)
		options := controllerclient.Options{
			Endpoint: "https://controller.example", DialAddress: https, CAFile: paths.rootCertificate,
			ExpectedNetworkID: networkID, ExpectedServiceID: controllerID, AdminTokenFile: paths.adminToken,
		}
		admin, err := controllerclient.New(options)
		if err != nil {
			t.Fatal(err)
		}
		options.AdminTokenFile = wrongToken
		invalidAdmin, err := controllerclient.New(options)
		if err != nil {
			t.Fatal(err)
		}
		if accepted, err := invalidAdmin.RootAuthenticationAccepted(ctx); err != nil || accepted {
			t.Fatalf("wrong root bearer accepted=%t: %v", accepted, err)
		}
		network, err := admin.Network(ctx, networkID)
		if err != nil {
			t.Fatal(err)
		}
		if network.NetworkID != networkID.String() || network.Name != original.Name ||
			network.IPv4Pool != pool.String() || network.CreatedAtUnix != original.CreatedAt.Unix() {
			t.Fatalf("network no longer matches v9 state: %+v", network)
		}
		expectedEpoch := network.ConfigurationEpoch
		if first {
			registered, err := admin.RegisterRelay(ctx, networkID, relayID, nil, "test-relay", "relay.example:4433")
			if err != nil {
				t.Fatal(err)
			}
			if registered.ConfigurationEpoch <= expectedEpoch {
				t.Fatalf("relay registration did not advance configuration epoch: %+v", registered)
			}
			expectedEpoch = registered.ConfigurationEpoch
		}
		options.AdminTokenFile = ""
		options.CertificateFile, options.PrivateKeyFile = relayCert, relayKey
		options.QUICEndpoint, options.QUICDialAddress = quic, quic
		relay, err := controllerclient.New(options)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, notModified, err := relay.RelayConfiguration(ctx, 0)
		if err != nil || notModified || snapshot.GetConfigurationEpoch() != expectedEpoch ||
			!bytes.Equal(snapshot.GetNetworkId(), networkID[:]) {
			t.Fatalf("mTLS QUIC relay configuration=%v unchanged=%t: %v", snapshot, notModified, err)
		}
		lease, unchanged, err := relay.RelayConfiguration(ctx, expectedEpoch)
		if err != nil || !unchanged || lease.GetValidUntilUnixSeconds() <= uint64(time.Now().Unix()) {
			t.Fatalf("mTLS QUIC relay lease=%v unchanged=%t: %v", lease, unchanged, err)
		}
		if whileRunning != nil {
			whileRunning()
		}
	}
	t.Run("v9-adoption-and-online-backup", func(t *testing.T) {
		check(t, config, true, func() {
			run(t, config, "", "-backup", backup)
			backupDigest := mustFileDigest(t, backup)
			run(t, config, "already exists", "-backup", backup)
			if mustFileDigest(t, backup) != backupDigest {
				t.Fatal("second backup modified the first backup")
			}
			if runtime.GOOS == "linux" {
				run(t, config, "requires a stopped controller", "-restore", backup)
			}
		})
	})
	t.Run("restart", func(t *testing.T) {
		check(t, config, false, nil)
	})
	checkStoredControllerIdentity(t, database, networkID, controllerID)
	t.Run("restore", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("production restore lifecycle locking is Linux-specific")
		}
		referenceRestored := filepath.Join(dir, "go-restored.db")
		if err := controller.RestoreDatabase(ctx, backup, referenceRestored); err != nil {
			t.Fatalf("Go could not restore candidate backup: %v", err)
		}
		checkStoredControllerIdentity(t, referenceRestored, networkID, controllerID)
		referenceBackup := filepath.Join(dir, "go-backup.db")
		if err := controller.BackupDatabase(ctx, database, referenceBackup); err != nil {
			t.Fatal(err)
		}

		restoredPath := filepath.Join(dir, "restored.db")
		restoredConfig := writeRunnableControllerConfig(t, dir, restoredPath, networkID, paths)
		run(t, restoredConfig, "", "-restore", referenceBackup)
		check(t, restoredConfig, false, nil)
		checkStoredControllerIdentity(t, restoredPath, networkID, controllerID)
	})
}

func checkStoredControllerIdentity(t *testing.T, path string, networkID identity.NetworkID, controllerID identity.ID) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var network, service string
	if err := db.QueryRow(`SELECT lower(hex(network_id)), lower(hex(controller_service_id))
		FROM controller_identity_state WHERE singleton = 1`).Scan(&network, &service); err != nil {
		t.Fatal(err)
	}
	if network != networkID.String() || service != controllerID.String() {
		t.Fatalf("durable identity = network %s, service %s", network, service)
	}
}

func startContractController(t *testing.T, ctx context.Context, binary, config string, args ...string) (https, quic string) {
	t.Helper()
	command := exec.CommandContext(ctx, binary, append([]string{"-config", config}, args...)...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		if err := command.Wait(); err != nil {
			t.Errorf("controller stopped with %v: %s", err, stderr.String())
		}
	})
	ready := make(chan string, 1)
	go func() {
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			if strings.HasPrefix(lines.Text(), "laneway-controller HTTPS=") {
				ready <- lines.Text()
				break
			}
		}
		close(ready)
		for lines.Scan() {
			// Keep draining the process output after startup.
		}
	}()
	select {
	case line := <-ready:
		for _, field := range strings.Fields(line) {
			key, value, _ := strings.Cut(field, "=")
			switch key {
			case "HTTPS":
				https = value
			case "QUIC":
				quic = value
			}
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if https == "" || quic == "" {
		t.Fatal("controller did not announce both HTTPS and QUIC listeners")
	}
	return https, quic
}
