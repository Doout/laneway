//go:build rustinterop && unix

package controllerservice

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

func TestRustControllerFleetUpdates(t *testing.T) {
	f := newFixture(t, 0, nil)
	_, session, csrf, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "fleet-owner", "fleet updates fixture password")
	now := time.Now()
	netID := f.network.ID
	foreign, err := f.store.CreateNetwork(t.Context(), "other fleet", netip.MustParsePrefix("10.214.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.service.ca)
	client := func(certs ...tls.Certificate) *http.Client {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13,
		}}, Timeout: 5 * time.Second}
		t.Cleanup(c.CloseIdleConnections)
		return c
	}
	enroll := func(net identity.NetworkID, name string, options controller.EnrollmentTokenOptions) (string, *http.Client) {
		t.Helper()
		token, err := f.store.IssueEnrollmentTokenWithOptions(t.Context(), net, name, now.Add(time.Hour), options)
		if err != nil {
			t.Fatal(err)
		}
		var cert tls.Certificate
		enrolled, err := f.store.EnrollNodeWithCertificate(t.Context(), token.Secret, name, 0, func(_ context.Context, n controller.Node) (controller.CertificateMaterial, error) {
			certLifetime := time.Hour
			if options.Class == controller.EnrollmentClassEphemeral {
				certLifetime = options.SessionLifetime
			}
			m, leaf, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: net, NodeID: n.ID}, now, certLifetime)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			cert = tls.Certificate{Certificate: [][]byte{m.CertificateDER}, PrivateKey: m.PrivateKey}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return enrolled.Node.ID.String(), client(cert)
	}
	durable := controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable}
	canary, c := enroll(netID, "fleet-canary", durable)
	later, l := enroll(netID, "fleet-later", durable)
	otherNode, _ := enroll(foreign.ID, "foreign-fleet", durable)
	ephemeralID, ephemeral := enroll(netID, "temporary-fleet", controller.EnrollmentTokenOptions{
		Class: controller.EnrollmentClassEphemeral, SessionLifetime: controller.MinEphemeralLifetime,
	})
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	serviceID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	serverCert, _, err := pki.IssueService(f.service.ca, f.service.caKey,
		pki.ServiceIdentity{NetworkID: netID, ServiceID: serviceID, Role: pki.RoleController},
		nil, []net.IP{net.ParseIP("127.0.0.1")}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.PrivateKeyPEM(serverCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := write("server.crt", pki.CertificatePEM(serverCert.CertificateDER))
	keyPath := write("server.key", key)
	ca := write("ca.crt", pki.CertificatePEM(f.service.ca.Raw))
	issueKey, err := pki.PrivateKeyPEM(f.service.caKey)
	if err != nil {
		t.Fatal(err)
	}
	caKey := write("ca.key", issueKey)
	rootFile := write("root.token", []byte(testRootBearer+"\n"))
	start := func() (string, string, func()) {
		return startControllerTLSLab(t, f.dbPath, certPath, keyPath, "--root-token-file", rootFile, "--node-issuer", ca, caKey, "3600", "--node-client-ca", ca, "--node-quic")
	}
	owner := labCredentials{session: session, csrf: csrf}
	root := labCredentials{bearer: testRootBearer}
	anon := labCredentials{}
	base := "/v1/admin/networks/" + netID.String()
	path := base + "/fleet-updates"
	const pollPath = "/v1/node/fleet-updates/poll"
	pollBody := func(node, lane string) string {
		return fmt.Sprintf(`{"runtime_node_id":%q,"runtime_network_id":%q,"component":"node","channel":%q,"current_version":"v1.2.0"}`, node, netID.String(), lane)
	}
	send := labManagementHTTP(t, client())
	endpoint, quic, stop := start()
	send(endpoint, "GET", path, "", owner, 404)
	labManagementHTTP(t, c)(endpoint, "POST", pollPath, pollBody(canary, "stable"), anon, 404)
	stop()
	cmd := exec.CommandContext(t.Context(), os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate fleet: %v %s", err, output)
	}
	endpoint, quic, stop = start()
	defer stop()
	epoch := send(endpoint, "GET", base, "", owner, 200)["configuration_epoch"]
	bot := func(permission string) labCredentials {
		t.Helper()
		id := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, "fleet-"+permission, permission, netID.String()), root, 201)["principal_id"].(string)
		token := send(endpoint, "POST", "/v1/admin/service-principals/"+id+"/tokens", fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, now.Add(time.Hour).Unix()), root, 201)["access_token"].(string)
		return labCredentials{bearer: token}
	}
	reader, manager := bot("node.read"), bot("node.manage")
	plan := func(nodes ...string) string {
		data, err := json.Marshal(map[string]any{"version": "v1.2.1", "component": "node", "channel": "stable", "node_ids": nodes, "canary_count": 1})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	send(endpoint, "GET", path+"?limit=0", "", reader, 400)
	send(endpoint, "GET", "/v1/admin/networks/"+foreign.ID.String()+"/fleet-updates", "", reader, 403)
	send(endpoint, "POST", path, plan(canary), reader, 403)
	send(endpoint, "POST", path, plan(canary), labCredentials{session: session}, 403)
	send(endpoint, "POST", path, plan(canary, canary), manager, 400)
	send(endpoint, "POST", path, plan(canary, otherNode), manager, 404)
	send(endpoint, "POST", path, plan(canary, ephemeralID), manager, 404)
	send(endpoint, "POST", path, strings.ReplaceAll(plan(canary), "v1.2.1", "v1.2.1-dev"), manager, 400)
	first := send(endpoint, "POST", path, plan(canary, later), owner, 201)
	firstID := first["id"].(string)
	if targets := first["targets"].([]any); len(targets) != 2 || targets[0].(map[string]any)["node_id"] != canary || targets[0].(map[string]any)["canary"] != true || targets[1].(map[string]any)["canary"] != false {
		t.Fatalf("canary order lost: %#v", targets)
	}
	send(endpoint, "POST", path, plan(canary), manager, 409)
	send(endpoint, "POST", path+"/"+firstID+"/promote", "", owner, 409)
	send(endpoint, "POST", pollPath, pollBody(canary, "stable"), anon, 401)
	labManagementHTTP(t, c)(endpoint, "POST", pollPath, pollBody(later, "stable"), anon, 400)
	labManagementHTTP(t, ephemeral)(endpoint, "POST", pollPath, pollBody(ephemeralID, "stable"), anon, 404)
	expectPoll := func(client *http.Client, node, lane, id string) {
		t.Helper()
		got := labManagementHTTP(t, client)(endpoint, "POST", pollPath, pollBody(node, lane), anon, 200)["update"]
		if id == "" && got == nil {
			return
		}
		if update, ok := got.(map[string]any); id == "" || !ok || update["id"] != id || update["version"] != "v1.2.1" || update["targets"] != nil {
			t.Fatalf("unexpected poll assignment: %#v", got)
		}
	}
	expectPoll(l, later, "stable", "")
	expectPoll(c, canary, "manual", "")
	// Make parallel real TLS requests and count the number of non-null claims.
	replies := make(chan error, 6)
	claims := make(chan string, 6)
	for range 6 {
		go func() {
			req, err := http.NewRequestWithContext(t.Context(), "POST", endpoint+pollPath, strings.NewReader(pollBody(canary, "stable")))
			if err != nil {
				replies <- err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			res, err := c.Do(req)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode != 200 {
					err = fmt.Errorf("poll status %d", res.StatusCode)
				} else {
					var body struct{ Update *struct{ ID string } }
					err = json.NewDecoder(res.Body).Decode(&body)
					if err == nil && body.Update != nil {
						claims <- body.Update.ID
					}
				}
			}
			replies <- err
		}()
	}
	for range 6 {
		if err := <-replies; err != nil {
			t.Fatal(err)
		}
	}
	if len(claims) != 1 || <-claims != firstID {
		t.Fatal("parallel polls did not produce exactly one claim for the canary")
	}
	report := func(client *http.Client, id, node, result, version string, want int) {
		t.Helper()
		body := fmt.Sprintf(`{"runtime_node_id":%q,"runtime_network_id":%q,"state":%q,"observed_version":%q,"detail":"lab evidence"}`, node, netID.String(), result, version)
		labManagementHTTP(t, client)(endpoint, "POST", "/v1/node/fleet-updates/"+id+"/result", body, anon, want)
	}
	report(l, firstID, later, "healthy", "v1.2.1", 409)
	report(l, firstID, canary, "healthy", "v1.2.1", 400)
	report(c, firstID, canary, "healthy", "v1.2.0", 400)
	report(c, firstID, canary, "healthy", "v1.2.1", 204)
	report(c, firstID, canary, "healthy", "v1.2.1", 204)
	send(endpoint, "POST", path+"/"+firstID+"/promote", "", manager, 204)
	expectPoll(l, later, "stable", firstID)
	report(l, firstID, later, "rolled_back", "v1.2.1", 400)
	report(l, firstID, later, "rolled_back", "v1.2.0", 204)
	assertState := func(id, state string) {
		t.Helper()
		for _, entry := range send(endpoint, "GET", path, "", reader, 200)["fleet_updates"].([]any) {
			update := entry.(map[string]any)
			if update["id"] == id && update["state"] == state {
				return
			}
		}
		t.Fatalf("update %s did not reach %s", id, state)
	}
	assertState(firstID, "paused")
	send(endpoint, "POST", path+"/"+firstID+"/promote", "", manager, 409)
	send(endpoint, "POST", path+"/"+firstID+"/cancel", "", manager, 204)
	failedCanary := send(endpoint, "POST", path, plan(canary, later), manager, 201)["id"].(string)
	expectPoll(c, canary, "stable", failedCanary)
	report(c, failedCanary, canary, "failed", "", 204)
	assertState(failedCanary, "paused")
	expectPoll(l, later, "stable", "")
	send(endpoint, "POST", path, plan(later), manager, 409)
	send(endpoint, "POST", path+"/"+failedCanary+"/cancel", "", manager, 204)
	secondID := send(endpoint, "POST", path, plan(canary, later), manager, 201)["id"].(string)
	expectPoll(c, canary, "stable", secondID)
	send(endpoint, "POST", path+"/"+secondID+"/cancel", "", manager, 204)
	expectPoll(l, later, "stable", "")
	send(endpoint, "POST", path, plan(canary), manager, 409)
	report(c, secondID, canary, "failed", "", 204)
	assertState(secondID, "cancelled")
	finalID := send(endpoint, "POST", path, plan(canary), manager, 201)["id"].(string)
	expectPoll(c, canary, "stable", finalID)
	report(c, finalID, canary, "healthy", "v1.2.1", 204)
	assertState(finalID, "complete")
	send(endpoint, "POST", path+"/"+finalID+"/cancel", "", manager, 409)
	agents := send(endpoint, "GET", path, "", reader, 200)["agents"].([]any)
	if len(agents) != 2 {
		t.Fatalf("expected two agents within this network, got %#v", agents)
	}
	for _, row := range agents {
		agent := row.(map[string]any)
		if agent["last_polled_at_unix_seconds"].(float64) < float64(now.Unix()) || agent["version"] != "v1.2.0" {
			t.Fatalf("unexpected updater presence: %#v", agent)
		}
	}
	if after := send(endpoint, "GET", base, "", owner, 200)["configuration_epoch"]; after != epoch {
		t.Fatalf("fleet updates bumped network epoch: before=%v after=%v", epoch, after)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action='fleet_update.result' AND actor_kind='node'").Scan(&count); err != nil || count != 5 {
		t.Fatalf("expected one audit per terminal update: %d %v", count, err)
	}
	if updater := os.Getenv("LANEWAY_RUST_UPDATER"); updater != "" {
		t.Run("managed-worker", func(t *testing.T) {
			send := labManagementHTTP(t, client())
			relayID, err := identity.NewID()
			if err != nil {
				t.Fatal(err)
			}
			send(endpoint, "POST", base+"/relays", fmt.Sprintf(`{"service_id":%q,"name":"lab relay","endpoint":"127.0.0.1:4433"}`, relayID.String()), root, 201)
			activation := os.Getenv("LANEWAY_RUST_SYSTEMD_ACTIVATION_TEST")
			worker := startRustFleetUpdateNode(t, dir, endpoint, quic, ca, netID.String(), serviceID.String(), canary, c, activation != "")
			nodeVersion, err := exec.CommandContext(t.Context(), worker, "--version").Output()
			if err != nil {
				t.Fatal(err)
			}
			tag := "v" + strings.TrimPrefix(strings.TrimSpace(string(nodeVersion)), "v")
			run := func() {
				t.Helper()
				if out, err := exec.CommandContext(t.Context(), updater).CombinedOutput(); err != nil {
					t.Fatalf("run native worker: %v %s", err, out)
				}
			}
			update := send(endpoint, "POST", path, strings.ReplaceAll(plan(canary), "v1.2.1", tag), manager, 201)["id"].(string)
			assertWorkerState := func(want string) {
				t.Helper()
				for _, row := range send(endpoint, "GET", path, "", reader, 200)["fleet_updates"].([]any) {
					plan := row.(map[string]any)
					if plan["id"] == update && plan["state"] == want {
						return
					}
				}
				t.Fatalf("native worker's update did not reach %s", want)
			}
			run() // Opt-out must not claim or report.
			assertWorkerState("canary")
			const config = "/etc/laneway/managed-updates-rust.toml"
			if err := os.WriteFile(config, []byte("enabled=true\nchannel=\"stable\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			const trust = "/etc/laneway/ca.crt"
			if err := os.Chmod(trust, 0666); err != nil {
				t.Fatal(err)
			}
			if err := exec.CommandContext(t.Context(), updater).Run(); err == nil {
				t.Fatal("native worker trusted a CA writable by the daemon")
			}
			assertWorkerState("canary")
			if err := os.Chmod(trust, 0600); err != nil {
				t.Fatal(err)
			}
			run()
			assertWorkerState("complete")
			run() // Next timer invocation finds no outstanding work.
			var claims int
			if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action='fleet_update.claim' AND lower(hex(target_id))=?", update).Scan(&claims); err != nil || claims != 1 {
				t.Fatalf("native worker did not claim exactly once: count=%d %v", claims, err)
			}
			if _, err := os.Stat("/var/lib/laneway-updater/rust-journal.json"); !os.IsNotExist(err) {
				t.Fatalf("confirmed ACK did not clear the journal: %v", err)
			}
			if activation != "" {
				candidate := os.Getenv("LANEWAY_LAB_NODE_CANDIDATE")
				if !filepath.IsAbs(candidate) || !filepath.IsAbs(activation) {
					t.Fatal("the activation test binary and candidate must have absolute paths")
				}
				cmd := exec.CommandContext(t.Context(), activation, "--ignored", "--exact", "--nocapture",
					"fleet_update::tests::activation_on_live_systemd_node")
				cmd.Env = append(os.Environ(), "LANEWAY_LAB_NODE_SOCKET="+filepath.Join(dir, "worker.sock"))
				out, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "1 passed; 0 failed") {
					t.Fatalf("real systemd activation test: %v\n%s", err, out)
				}
				t.Logf("activation and rollback:\n%s", out)
			}
		})
	}
}

// Exercise the unchanged worker binary, the real Unix health API, and pinned
// client/server mTLS. The assigned version is already serving, so the test
// uses no public downloads. Optionally serve through a fixture systemd unit
// to exercise the real restart and rollback path separately.
func startRustFleetUpdateNode(t *testing.T, dir, endpoint, quic, ca, network, service, node string, tlsClient *http.Client, systemd bool) string {
	t.Helper()
	const installed = "/usr/local/sbin/lanewayd-rs"
	const settings = "/etc/laneway/managed-updates-rust.toml"
	const config = "/etc/laneway/node-rust.toml"
	const trust = "/etc/laneway/ca.crt"
	if os.Geteuid() != 0 {
		t.Fatal("native updater lab requires root in a disposable Linux environment")
	}
	if systemd {
		marker, err := os.Lstat("/run/.laneway-isolated-systemd-lab")
		comm, commErr := os.ReadFile("/proc/1/comm")
		if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 ||
			marker.Sys().(*syscall.Stat_t).Uid != 0 || commErr != nil || strings.TrimSpace(string(comm)) != "systemd" {
			t.Fatal("activation test requires the marked disposable systemd VM")
		}
		out, err := exec.CommandContext(t.Context(), "systemctl", "show", "-p", "LoadState", "--value", "lanewayd-rs.service").Output()
		if err != nil || strings.TrimSpace(string(out)) != "not-found" {
			t.Fatalf("refusing to replace a pre-existing systemd service: %q %v", out, err)
		}
	} else if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("native updater lab refuses to use installed paths outside Docker")
	}
	for _, path := range []string{installed, "/etc/laneway", "/var/lib/laneway-updater"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("native updater lab refuses existing path %s", path)
		}
	}
	src, err := os.Open(os.Getenv("LANEWAY_RUST_NODE"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(installed, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(installed) })
	_, copyErr := io.Copy(dst, src)
	if err := dst.Close(); copyErr != nil || err != nil {
		t.Fatalf("stage disposable runtime: %v %v", copyErr, err)
	}
	if err := os.Mkdir("/etc/laneway", 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, path := range []string{config, settings, trust, "/etc/laneway",
			"/var/lib/laneway-updater/rust-journal.json", "/var/lib/laneway-updater/lock", "/var/lib/laneway-updater"} {
			_ = os.Remove(path)
		}
	})
	write := func(path string, content []byte) {
		t.Helper()
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	credential := tlsClient.Transport.(*http.Transport).TLSClientConfig.Certificates[0]
	certFile, keyFile := filepath.Join(dir, "worker-client.crt"), filepath.Join(dir, "worker-client.key")
	key, err := pki.PrivateKeyPEM(credential.PrivateKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	write(certFile, pki.CertificatePEM(credential.Certificate[0]))
	write(keyFile, key)
	trustPEM, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	write(trust, trustPEM)
	socket := filepath.Join(dir, "worker.sock")
	write(settings, []byte("enabled=false\nchannel=\"stable\"\n"))
	write(config, fmt.Appendf(nil, `mode = "node"
socket_path = %q
exit_intent_path = %q
[identity]
node_id = %q
network_id = %q
[tls]
certificate = %q
private_key = %q
ca = %q
[controller]
endpoint = %q
quic_endpoint = %q
service_id = %q
server_name = "127.0.0.1"
poll_interval = "1s"
[tun]
name = "lane-test"
[relay]
server_name = "unused.test"
service_id = %q
[connector]
userspace = true
`, socket, filepath.Join(dir, "worker-exit.json"), node, network, certFile, keyFile, trust, endpoint, quic, service, service))
	if systemd {
		const unit = "lanewayd-rs.service"
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, "systemctl", "stop", unit).Run()
			_ = exec.CommandContext(ctx, "systemctl", "reset-failed", unit).Run()
		})
		if out, err := exec.CommandContext(t.Context(), "systemd-run", "--quiet", "--unit="+unit,
			"--description=Laneway isolated updater activation fixture", "--property=Type=exec",
			"--property=Restart=no", installed, "--config", config).CombinedOutput(); err != nil {
			t.Fatalf("start systemd fixture: %v %s", err, out)
		}
	} else {
		cmd := exec.CommandContext(t.Context(), installed, "--config", config)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	local := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	t.Cleanup(local.CloseIdleConnections)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
		resp, err := local.Get("http://lanewayd/v1/status")
		if err != nil {
			continue
		}
		var state struct {
			Controller struct {
				Until uint64 `json:"configuration_lease_valid_until_unix_seconds"`
			}
		}
		parseErr := json.NewDecoder(resp.Body).Decode(&state)
		resp.Body.Close()
		if resp.StatusCode == 200 && parseErr == nil && state.Controller.Until > uint64(time.Now().Unix()) {
			return installed
		}
	}
	t.Fatal("disposable native node did not gain controller health")
	return ""
}
