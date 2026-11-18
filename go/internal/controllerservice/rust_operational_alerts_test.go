//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
)

func testRustOperationalAlerts(t *testing.T, httpClient *http.Client, cert, key, rootFile string) {
	t.Helper()
	f := newFixture(t, 0, nil)
	_, session, proof, _ := bootstrapAdministratorSessionForHTTPTest(t, f, "alerts-owner", "operational alerts test password")
	ctx, now := t.Context(), time.Now()
	network := f.network.ID
	foreign, err := f.store.CreateNetwork(ctx, "foreign alert network", netip.MustParsePrefix("10.215.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(name string) identity.NodeID {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, network, name, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		node, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return node.ID
	}
	offline, exit, _ := enroll("silent"), enroll("uses-exit"), enroll("never-reported")
	_, certificate, err := pki.IssueNode(f.service.ca, f.service.caKey,
		identity.NodeIdentity{NetworkID: network, NodeID: offline}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AddCertificate(ctx, network, offline, certificate.SerialNumber.Bytes(), certificate.Raw, certificate.NotBefore, certificate.NotAfter); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	root := labCredentials{bearer: testRootBearer}
	owner := labCredentials{session: session, csrf: proof}
	send := labManagementHTTP(t, httpClient)
	base := "/v1/admin/networks/" + network.String()
	path := base + "/alerts"
	otherPath := "/v1/admin/networks/" + foreign.ID.String() + "/alerts"
	start := func() (string, func()) {
		return startRustAdministratorLab(t, f.dbPath, cert, key, rootFile)
	}
	endpoint, stop := start()
	send(endpoint, "GET", path, "", root, 404)
	stop()
	if out, err := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath).CombinedOutput(); err != nil {
		t.Fatalf("migrate for alerts: %v %s", err, out)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA busy_timeout=3000"); err != nil {
		t.Fatal(err)
	}
	execDB := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	setReport := func(node identity.NodeID, observed int64, health string) {
		t.Helper()
		execDB(`INSERT INTO endpoint_status_latest
			(node_id,network_id,observed_at,expires_at,valid_for_seconds,product_version,platform,
			certificate_state,configuration_state,carrier_state,route_state,selected_exit_state,cleanup_failure_count,configuration_epoch)
			VALUES(?,?,?,?,30,'lab','linux','healthy','current','relay_quic','ready',?,0,1)
			ON CONFLICT(node_id) DO UPDATE SET observed_at=excluded.observed_at,expires_at=excluded.expires_at,selected_exit_state=excluded.selected_exit_state`,
			node[:], network[:], observed, observed+30, health)
	}
	setUpdate := func(value string, at int64) {
		t.Helper()
		id, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		plan := map[string]string{"failed": "paused", "running": "canary", "healthy": "complete"}
		execDB(`INSERT INTO fleet_updates VALUES(?,?,'v1.2.3','node','stable',1,1,?,?,?)`,
			id[:], network[:], plan[value], at, at)
		execDB(`INSERT INTO fleet_update_targets(update_id,network_id,node_id,canary,state,updated_at) VALUES(?,?,?,1,?,?)`,
			id[:], network[:], offline[:], value, at)
	}
	setReport(offline, now.Unix()-200, "unavailable")
	setReport(exit, now.Unix(), "unavailable")
	setUpdate("failed", now.Unix()-60)
	setUpdate("running", now.Unix()-30)
	endpoint, stop = start()
	originalEpoch := send(endpoint, "GET", base, "", owner, 200)["configuration_epoch"]
	bot := func(permission string) labCredentials {
		t.Helper()
		principal := send(endpoint, "POST", "/v1/admin/service-principals",
			fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, "alerts-"+permission, permission, network.String()),
			root, 201)["principal_id"].(string)
		token := send(endpoint, "POST", "/v1/admin/service-principals/"+principal+"/tokens",
			fmt.Sprintf(`{"label":"alert lab","expires_at_unix_seconds":%d}`, now.Add(time.Hour).Unix()), root, 201)["access_token"].(string)
		return labCredentials{bearer: token}
	}
	reader, manager := bot("node.read"), bot("node.manage")
	send(endpoint, "GET", path, "", labCredentials{}, 401)
	send(endpoint, "GET", otherPath, "", reader, 403)
	send(endpoint, "GET", path, "", manager, 403)
	await := func(want int) map[string]map[string]any {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			values := send(endpoint, "GET", path, "", reader, 200)["alerts"].([]any)
			if len(values) != want {
				continue
			}
			alerts := make(map[string]map[string]any, len(values))
			resolved := false
			for _, value := range values {
				row := value.(map[string]any)
				n := row["node_id"].(string)
				if (resolved && row["state"] != "resolved") || row["remediation_path"] != "/nodes/"+n ||
					row["network_id"] != network.String() {
					t.Fatalf("incorrect alert scope or order: %#v", values)
				}
				resolved = row["state"] == "resolved"
				alerts[n+"/"+row["kind"].(string)] = row
			}
			return alerts
		}
		t.Fatalf("alert reconciler did not observe %d incidents", want)
		return nil
	}
	offlineKey, credsKey, updateKey := offline.String()+"/node_offline", offline.String()+"/credentials_expiring", offline.String()+"/update_failed"
	exitKey := exit.String() + "/exit_unavailable"
	initial := await(4)
	for _, expected := range []string{offlineKey, credsKey, updateKey, exitKey} {
		if initial[expected]["state"] != "open" || initial[expected]["acknowledged_at"] != nil {
			t.Fatalf("incorrect incident evidence: %#v", initial)
		}
	}
	id := initial[offlineKey]["alert_id"].(string)
	ack := path + "/" + id + "/acknowledge"
	send(endpoint, "POST", otherPath+"/"+id+"/acknowledge", "", root, 404)
	send(endpoint, "POST", ack, "", reader, 403)
	send(endpoint, "POST", ack, "", labCredentials{session: session}, 403)
	send(endpoint, "POST", ack, "", owner, 204)
	send(endpoint, "POST", ack, "", manager, 204)
	if got := await(4)[offlineKey]; got["state"] != "acknowledged" || got["acknowledged_at"] == nil {
		t.Fatalf("acknowledgement not persisted: %#v", got)
	}
	var audits int
	if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE action='alert.acknowledged' AND target_type='operational_alert'").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("acknowledgement audit count %d: %v", audits, err)
	}
	stop()
	setReport(offline, time.Now().Unix(), "ready")
	setReport(exit, now.Unix()-200, "ready") // Old readiness is not evidence of recovery.
	setUpdate("healthy", now.Unix())
	endpoint, stop = start()
	defer stop()
	reloaded := await(5)
	if reloaded[offlineKey]["state"] != "resolved" || reloaded[offlineKey]["alert_id"] != id ||
		reloaded[updateKey]["state"] != "resolved" || reloaded[exitKey]["state"] != "open" {
		t.Fatalf("incorrect state after reconciliation and restart: %#v", reloaded)
	}
	if epoch := send(endpoint, "GET", base, "", owner, 200)["configuration_epoch"]; epoch != originalEpoch {
		t.Fatalf("alerts should not change network authority: %v -> %v", originalEpoch, epoch)
	}
	continuous := false
	for deadline := time.Now().Add(7 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
		var total, disabled int
		if err := db.QueryRow(`SELECT count(*),sum(delivery_state='disabled' AND attempts=0) FROM operational_alert_events`).Scan(&total, &disabled); err != nil {
			t.Fatal(err)
		}
		if total == 8 && disabled == total {
			continuous = true
			break
		}
	}
	if !continuous {
		t.Fatal("disabled webhook outbox did not drain the eight real transitions")
	}
	var payload string
	if err := db.QueryRow(`SELECT payload FROM operational_alert_events WHERE json_extract(payload,'$.alert.state')='acknowledged'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var event struct {
		ID    string         `json:"event_id"`
		Alert map[string]any `json:"alert"`
	}
	if err := json.Unmarshal([]byte(payload), &event); err != nil || event.ID == "" || event.Alert["alert_id"] != id {
		t.Fatalf("durable event omitted its identity: %v", err)
	}
}
