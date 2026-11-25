//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
)

// TestReadonlyServingBinaryCompatibility exercises the candidate through both
// the production management CLI and a TLS client checking error contracts.
func TestReadonlyServingBinaryCompatibility(t *testing.T) {
	binary, cli := os.Getenv("LANEWAY_CONTROLLER_SERVE_BIN"), os.Getenv("LANEWAY_GO_CONFIG_BIN")
	if binary == "" || cli == "" {
		t.Skip("set LANEWAY_CONTROLLER_SERVE_BIN and LANEWAY_GO_CONFIG_BIN to absolute binary paths")
	}
	if !filepath.IsAbs(binary) || !filepath.IsAbs(cli) {
		t.Fatal("both binary paths must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	dir := t.TempDir()
	database := filepath.Join(dir, "controller.db")
	now := time.Now()
	network, service := identity.NetworkID{1}, identity.ID{2}
	rootMaterial, root, err := pki.NewAuthority("root", now.Add(-time.Hour), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuerMaterial, issuer, err := pki.IssueIntermediate(root, rootMaterial.PrivateKey, "issuer", now.Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafMaterial, _, err := pki.IssueService(issuer, issuerMaterial.PrivateKey, pki.ServiceIdentity{
		NetworkID: network, ServiceID: service, Role: pki.RoleController,
	}, []string{"controller.example"}, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	paths := writeControllerRunPKI(t, dir, root, issuer, issuerMaterial, leafMaterial)
	config := writeRunnableControllerConfig(t, dir, database, network, paths)
	process := exec.CommandContext(ctx, binary, "-config", config, "-serve-readonly", "-diagnostics", "127.0.0.1:0")
	process.Stderr = os.Stderr
	stdout, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Signal(os.Interrupt)
		if err := process.Wait(); err != nil && ctx.Err() == nil {
			t.Errorf("controller exited unsuccessfully: %v", err)
		}
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
		}
		close(ready)
		for scanner.Scan() {
		}
	}()
	var https, diagnostics string
	select {
	case line := <-ready:
		for _, field := range strings.Fields(line) {
			name, value, _ := strings.Cut(field, "=")
			switch name {
			case "HTTPS":
				https = "https://" + value
			case "diagnostics":
				diagnostics = "http://" + value
			}
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if https == "" || diagnostics == "" {
		t.Fatal("candidate did not announce HTTPS and diagnostics")
	}
	token, err := os.ReadFile(paths.adminToken)
	if err != nil {
		t.Fatal(err)
	}
	credentials := []string{
		"--controller", https, "--ca", paths.rootCertificate, "--server-name", "controller.example",
		"--controller-network-id", network.String(), "--controller-service-id", service.String(),
		"--admin-token-file", paths.adminToken,
	}
	runCLI := func(action string, args ...string) {
		t.Helper()
		command := append([]string{"controller", "network", action}, credentials...)
		output, err := exec.CommandContext(ctx, cli, append(command, args...)...).CombinedOutput()
		if err != nil || !strings.Contains(string(output), `"network_id": "`+network.String()+`"`) {
			t.Fatalf("network %s failed: %v\n%s", action, err, output)
		}
	}
	runCLI("list", "--limit", "1")
	runCLI("get", "--network-id", network.String())

	rootPEM, err := os.ReadFile(paths.rootCertificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("load test trust anchor")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "controller.example", MinVersion: tls.VersionTLS13,
	}}}
	defer client.CloseIdleConnections()
	bearer := "Bearer " + strings.TrimSpace(string(token))
	previous := ""
	for _, test := range []struct {
		method, path, auth, origin, cookie string
		status                             int
	}{
		{"GET", "/v1/admin/auth/root", bearer, "", "", 204},
		{"GET", "/v1/admin/networks", "", "", "", 401},
		{"GET", "/v1/admin/networks", "Bearer scoped-session-token", "", "", 401},
		{"GET", "/v1/admin/networks", "", "", "__Host-laneway_admin_session=session", 401},
		{"GET", "/v1/admin/networks", bearer, "", "__Host-laneway_admin_session=session", 401},
		{"GET", "/v1/admin/networks", bearer, "https://controller.example", "", 401},
		{"GET", "/v1/admin/networks?limit=1001", bearer, "", "", 400},
		{"GET", "/v1/admin/%6eetworks", bearer, "", "", 400},
		{"GET", "/v1/admin/networks/" + (identity.NetworkID{9}).String(), bearer, "", "", 404},
		{"POST", "/v1/admin/networks", bearer, "", "", 405},
		{"POST", "/v1/enroll", "", "", "", 404},
	} {
		request, err := http.NewRequestWithContext(ctx, test.method, https+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Laneway-Request-ID", "caller-request-id")
		for name, value := range map[string]string{"Authorization": test.auth, "Origin": test.origin, "Cookie": test.cookie} {
			if value != "" {
				request.Header.Set(name, value)
			}
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		id := response.Header.Get("X-Laneway-Request-ID")
		if response.StatusCode != test.status || len(id) != 32 || id == previous {
			response.Body.Close()
			t.Fatalf("%s %s status=%d id=%q, want status %d and fresh ID", test.method, test.path, response.StatusCode, id, test.status)
		}
		if response.StatusCode >= 400 {
			var body map[string]any
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body["request_id"] != id || body["code"] == nil {
				response.Body.Close()
				t.Fatalf("unmatched error envelope: %v %v", body, err)
			}
		}
		response.Body.Close()
		previous = id
	}

	metricsRequest, err := http.NewRequestWithContext(ctx, "GET", diagnostics+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := client.Do(metricsRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer metrics.Body.Close()
	contents, err := io.ReadAll(metrics.Body)
	if err != nil || metrics.StatusCode != 200 || !strings.Contains(string(contents), "laneway_controller_up 1\n") {
		t.Fatalf("metrics status %d: %v %s", metrics.StatusCode, err, contents)
	}
}
