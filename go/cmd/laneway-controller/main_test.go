package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"laneway.dev/laneway/internal/controller"
	"laneway.dev/laneway/internal/controllerservice"
)

func TestBearerAuthorizerFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := strings.Repeat("a", 48)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authorize, err := bearerAuthorizerFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, "https://controller/v1/admin/enrollment-tokens", nil)
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("missing credential error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if err := authorize(request); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token+"x")
	if err := authorize(request); !errors.Is(err, controllerservice.ErrUnauthenticated) {
		t.Fatalf("wrong credential error = %v", err)
	}
}

func TestBearerAuthorizerRejectsWeakAndOversizeFiles(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(weak); err == nil {
		t.Fatal("weak token accepted")
	}
	large := filepath.Join(dir, "large")
	if err := os.WriteFile(large, []byte(strings.Repeat("x", maxAdminTokenFile+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bearerAuthorizerFromFile(large); err == nil {
		t.Fatal("oversized token accepted")
	}
}

func TestMaintenanceBackupAndFreshRestore(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.db")
	store, err := controller.Open(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(directory, "backup.db")
	if err := runBackup(writeControllerConfig(t, source), backup); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(directory, "restored.db")
	if err := runRestore(writeControllerConfig(t, restored), backup); err != nil {
		t.Fatal(err)
	}
	reopened, err := controller.Open(context.Background(), restored)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if version, err := reopened.SchemaVersion(context.Background()); err != nil || version == 0 {
		t.Fatalf("restored schema version = %d, %v", version, err)
	}
}

func TestMaintenanceBackupRefusesMissingSource(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing.db")
	destination := filepath.Join(directory, "backup.db")
	if err := runBackup(writeControllerConfig(t, missing), destination); err == nil {
		t.Fatal("runBackup accepted a missing source database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created missing source database: %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup created destination after source failure: %v", err)
	}
}

func TestMaintenanceRestoreRefusesActiveController(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("lifecycle lock is Linux-specific")
	}
	directory := t.TempDir()
	database := filepath.Join(directory, "controller.db")
	lock, err := acquireControllerDatabaseLock(database)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	err = runRestore(writeControllerConfig(t, database), filepath.Join(directory, "unused-backup.db"))
	if err == nil || !strings.Contains(err.Error(), "requires a stopped controller") {
		t.Fatalf("runRestore error = %v, want active-controller refusal", err)
	}
	if _, err := os.Stat(database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active-controller refusal created database: %v", err)
	}
}

func writeControllerConfig(t *testing.T, database string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.toml")
	contents := fmt.Sprintf(`mode = "controller"
state_dir = %q
socket_path = %q

[tls]
certificate = "unused.crt"
private_key = "unused.key"
ca = "unused-ca.crt"

[controller]
listen = ":8443"
quic_listen = ":8443"
database = %q
ca_private_key = "unused-ca.key"
admin_token_file = "unused-token"
leaf_validity = "720h"
`, filepath.Dir(database), filepath.Join(filepath.Dir(database), "controller.sock"), database)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
