//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
)

func testRustFleetPolicyHistory(t *testing.T, client *http.Client, cert, key, rootFile string) {
	t.Helper()
	f := newFixture(t, 0, nil)
	bootstrapAdministratorSessionForHTTPTest(t, f, "fleet-owner", "fleet fixture owner password")
	ctx := t.Context()
	other, err := f.store.CreateNetwork(ctx, "foreign", netip.MustParsePrefix("10.192.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	seed, epoch, err := f.store.AddACLRule(ctx, f.network.ID, 17, controller.ACLActionDeny, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "Go schema 18 rule")
	if err != nil {
		t.Fatal(err)
	}
	nodeToken, err := f.store.IssueEnrollmentToken(ctx, f.network.ID, "fleet-fixture", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	node, err := f.store.EnrollNode(ctx, nodeToken.Secret, "fleet-fixture", 0)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Network(ctx, f.network.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Stop the Go writer before migrating the disposable database.
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"applied", "already present"} {
		cmd := exec.CommandContext(ctx, os.Getenv("LANEWAY_RUST_CONTROLLER"), "migrate-fleet", f.dbPath)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "fleet schema 19 "+want {
			t.Fatalf("schema migration: %v %s", err, out)
		}
	}
	endpoint, stop := startRustAdministratorLab(t, f.dbPath, cert, key, rootFile)
	defer stop()
	// The fixture writes test triggers while the Rust controller is running.
	db, err := sql.Open("sqlite", f.dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	base := "/v1/admin/networks/" + f.network.ID.String()
	path := base + "/policy-history"
	acl := base + "/acl-rules"
	updated := "/v1/admin/acl-rules/" + seed.ID.String()
	if v := send(endpoint, "GET", base, "", root, 200); v["configuration_epoch"] != float64(before.ConfigurationEpoch) || v["name"] != before.Name {
		t.Fatalf("network changed during migration: %#v", v)
	}
	if v := send(endpoint, "GET", base+"/private-dns", "", root, 200); !strings.Contains(fmt.Sprint(v["records"]), "n-"+node.ID.String()) {
		t.Fatalf("migrated database private DNS omitted the enrolled node: %#v", v)
	}
	flow := fmt.Sprintf(`{"flow":{"source_node_id":%q,"destination_node_id":%q,"protocol":"tcp","destination_port":443}}`, node.ID.String(), node.ID.String())
	if v := send(endpoint, "POST", base+"/policy-preview", flow, root, 200)["current"].(map[string]any); v["configuration_epoch"] != float64(before.ConfigurationEpoch) || v["matched_rule_id"] != seed.ID.String() || v["action"] != "deny" {
		t.Fatalf("preview did not use the migrated policy: %#v", v)
	}
	diagnosticFlow := fmt.Sprintf(`{"source_node_id":%q,"destination_node_id":%q,"protocol":"tcp","destination_port":443}`, node.ID.String(), node.ID.String())
	report := send(endpoint, "POST", base+"/diagnostics", diagnosticFlow, root, 200)
	if decision := report["policy"].(map[string]any); decision["matched_rule_id"] != seed.ID.String() || report["reachability"] != "unknown" {
		t.Fatalf("diagnostics did not use the migrated policy: %#v", report)
	}
	history := func() []any {
		t.Helper()
		v := send(endpoint, "GET", path, "", root, 200)
		if v["scope"] != "manual_acl" {
			t.Fatalf("unexpected policy history: %#v", v)
		}
		return v["revisions"].([]any)
	}
	if len(history()) != 0 {
		t.Fatal("migration invented history")
	}
	change := send(endpoint, "PUT", updated, `{"priority":20,"action":"accept","selector":{"ip_protocol":"IP_PROTOCOL_ANY"},"description":"Rust update","enabled":true}`, root, 200)
	rows := history()
	if len(rows) != 2 {
		t.Fatalf("expected pre/post history: %#v", rows)
	}
	beforeRow, afterRow := rows[1].(map[string]any), rows[0].(map[string]any)
	if beforeRow["revision"] != float64(1) || afterRow["revision"] != float64(2) || beforeRow["configuration_epoch"] != float64(before.ConfigurationEpoch) || afterRow["configuration_epoch"] != change["configuration_epoch"] || float64(epoch) > beforeRow["configuration_epoch"].(float64) {
		t.Fatalf("invalid history order or epochs: %#v", rows)
	}
	if rule := beforeRow["rules"].([]any)[0].(map[string]any); rule["description"] != "Go schema 18 rule" || rule["action"] != "deny" || rule["rule_id"] != seed.ID.String() {
		t.Fatalf("invalid Go checkpoint: %#v", rule)
	}
	if rule := afterRow["rules"].([]any)[0].(map[string]any); rule["description"] != "Rust update" || rule["action"] != "accept" {
		t.Fatalf("invalid Rust checkpoint: %#v", rule)
	}
	if got := send(endpoint, "GET", path+"?limit=1", "", root, 200)["revisions"].([]any); !reflect.DeepEqual(got, rows[:1]) {
		t.Fatalf("limit on policy history not applied: %#v", got)
	}
	restore := func(epoch any) string {
		return fmt.Sprintf(`{"expected_configuration_epoch":%.0f}`, epoch)
	}
	restorePath := path + "/1/restore"
	send(endpoint, "POST", restorePath, restore(beforeRow["configuration_epoch"]), root, 409)
	send(endpoint, "POST", path+"/400/restore", restore(afterRow["configuration_epoch"]), root, 404)
	principal := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"history-reader","permissions":["acl.read"],"network_ids":[%q]}`, f.network.ID.String()), root, 201)["principal_id"].(string)
	token := send(endpoint, "POST", "/v1/admin/service-principals/"+principal+"/tokens", fmt.Sprintf(`{"label":"history","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)
	reader := labCredentials{bearer: token}
	send(endpoint, "GET", path, "", reader, 200)
	send(endpoint, "GET", "/v1/admin/networks/"+other.ID.String()+"/policy-history", "", reader, 403)
	send(endpoint, "POST", restorePath, restore(afterRow["configuration_epoch"]), reader, 403)
	if _, err := db.Exec(`CREATE TRIGGER fail_restore_audit BEFORE INSERT ON audit_events WHEN NEW.action='policy.restore' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	current := send(endpoint, "GET", acl, "", root, 200)
	send(endpoint, "POST", restorePath, restore(afterRow["configuration_epoch"]), root, 500)
	if got := send(endpoint, "GET", acl, "", root, 200); !reflect.DeepEqual(got, current) || !reflect.DeepEqual(history(), rows) {
		t.Fatalf("audit failure left partial policy state: %#v", got)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_restore_audit`); err != nil {
		t.Fatal(err)
	}
	restored := send(endpoint, "POST", restorePath, restore(afterRow["configuration_epoch"]), root, 200)
	restoredRules := send(endpoint, "GET", acl, "", root, 200)["acl_rules"].([]any)
	if len(restoredRules) != 1 {
		t.Fatalf("restored wrong number of rules: %#v", restoredRules)
	}
	if rule := restoredRules[0].(map[string]any); rule["rule_id"] != seed.ID.String() || rule["action"] != "deny" || rule["configuration_epoch"] != restored["configuration_epoch"] {
		t.Fatalf("wrong restored ACL: %#v", rule)
	}
	var audit int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE network_id=? AND action='policy.restore' AND target_id IS NULL`, f.network.ID[:]).Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("policy restore audit: %d %v", audit, err)
	}
	send(endpoint, "DELETE", updated, "", root, 200)
	rows = history()
	if len(rows) != 4 || len(rows[0].(map[string]any)["rules"].([]any)) != 0 {
		t.Fatalf("delete did not capture new empty revision: %#v", rows)
	}
	created := send(endpoint, "POST", acl, `{"priority":5,"action":"deny","selector":{"ip_protocol":"IP_PROTOCOL_ANY"},"description":"Rust create"}`, root, 201)
	rows = history()
	if len(rows) != 5 || rows[0].(map[string]any)["rules"].([]any)[0].(map[string]any)["rule_id"] != created["rule_id"] {
		t.Fatalf("create did not save the new rule: %#v", rows)
	}
}
