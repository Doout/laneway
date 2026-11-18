//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func testRustTrafficRules(t *testing.T, f fixture, client *http.Client, goURL, rustURL string,
	foreign identity.NetworkID, operator, auditor, reader, writer labCredentials, writerID string) {
	t.Helper()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	path := "/v1/admin/networks/" + f.network.ID.String() + "/acl-rules"
	other := "/v1/admin/networks/" + foreign.String() + "/acl-rules"
	rulePath := func(id string) string { return "/v1/admin/acl-rules/" + id }
	compare := func(q string, c labCredentials) map[string]any {
		t.Helper()
		expected := send(goURL, "GET", path+q, "", c, 200)
		actual := send(rustURL, "GET", path+q, "", c, 200)
		if !reflect.DeepEqual(expected, actual) {
			t.Fatalf("ACL inventory: Go=%#v Rust=%#v", expected, actual)
		}
		return actual
	}
	deny := `{"priority":10,"action":"deny","selector":{"ip_protocol":"IP_PROTOCOL_ANY"},"description":"Default block"}`
	send(rustURL, "GET", path, "", reader, 200)
	send(rustURL, "GET", path, "", writer, 403)
	send(rustURL, "GET", other, "", reader, 403)
	send(rustURL, "GET", path+"?limit=1001", "", reader, 400)
	send(rustURL, "GET", "/v1/admin/networks/"+strings.Repeat("e", 32)+"/acl-rules", "", root, 404)
	send(rustURL, "POST", path, deny, auditor, 403)
	send(rustURL, "POST", path, deny, reader, 403)
	send(rustURL, "POST", other, deny, writer, 403)
	send(rustURL, "POST", path, deny, labCredentials{session: operator.session, csrf: "bad"}, 403)
	send(rustURL, "POST", path, deny, labCredentials{}, 401)
	for _, selector := range []string{
		`{}`,
		`{"ip_protocol":"IP_PROTOCOL_UNSPECIFIED"}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","destination_ports":[{"first":22,"last":22}]}`,
		`{"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":22,"last":21}]}`,
		`{"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":22,"last":65536}]}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","destination_prefixes":[{"address":"wKgBAQ==","prefix_length":24}]}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","source_node_ids":["AA=="]}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","source_node_ids":["AAAAAAAAAAAAAAAAAAAAAA=="]}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","destination_prefixes":[null]}`,
		`{"ipProtocol":"IP_PROTOCOL_ANY","ip_protocol":"IP_PROTOCOL_TCP"}`,
		`{"ip_protocol":"IP_PROTOCOL_ANY","unsupported":true}`,
	} {
		send(rustURL, "POST", path, `{"action":"accept","selector":`+selector+`}`, writer, 400)
	}
	send(rustURL, "POST", path, `{"action":"drop","selector":{"ip_protocol":"IP_PROTOCOL_ANY"}}`, writer, 400)
	send(rustURL, "POST", path, fmt.Sprintf(`{"action":"accept","selector":{"ip_protocol":"IP_PROTOCOL_ANY"},"description":%q}`, strings.Repeat("a", 1025)), writer, 400)
	send(rustURL, "POST", path, `{"action":"accept","selector":{"ip_protocol":"IP_PROTOCOL_ANY"},"enabled":false}`, writer, 400)
	foreignRule := send(goURL, "POST", other, deny, root, 201)["rule_id"].(string)
	send(rustURL, "DELETE", rulePath(foreignRule), "", operator, 404)
	send(rustURL, "DELETE", rulePath(foreignRule), "", writer, 404)
	baseline := send(goURL, "POST", path, deny, root, 201)
	source := base64.RawURLEncoding.EncodeToString(f.network.ID[:])
	canonical := base64.StdEncoding.EncodeToString(f.network.ID[:])
	allow := fmt.Sprintf(`{"priority":10,"action":"accept","description":"DNS","selector":{"ipProtocol":17,"sourceNodeIds":[%q,%q],"destinationPrefixes":[{"address":"AAAAAA==","prefixLength":0}],"destinationPorts":[{"first":"53","last":53}]}}`, source, source)
	created := send(rustURL, "POST", path, allow, writer, 201)
	rule := created["rule_id"].(string)
	want := map[string]any{
		"ip_protocol": "IP_PROTOCOL_UDP", "source_node_ids": []any{canonical, canonical},
		"destination_prefixes": []any{map[string]any{"address": "AAAAAA=="}},
		"destination_ports":    []any{map[string]any{"first": float64(53), "last": float64(53)}},
	}
	if !reflect.DeepEqual(created["selector"], want) {
		t.Fatalf("selector was not normalized: %#v", created)
	}
	if created["configuration_epoch"].(float64) != baseline["configuration_epoch"].(float64)+1 {
		t.Fatal("create did not advance epoch")
	}
	rules := compare("", auditor)["acl_rules"].([]any)
	var ties []string
	for _, raw := range rules {
		r := raw.(map[string]any)
		if r["priority"] == float64(10) {
			ties = append(ties, r["rule_id"].(string))
		}
	}
	if len(ties) < 2 || !slices.IsSorted(ties) {
		t.Fatalf("priority ties not sorted by ID: %v", ties)
	}
	if len(compare("?limit=1", reader)["acl_rules"].([]any)) != 1 {
		t.Fatal("list limit ignored")
	}

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	originalEpoch := created["configuration_epoch"].(float64)
	update := `{"priority":5,"action":"deny","selector":{"ip_protocol":"IP_PROTOCOL_UDP","destination_ports":[{"first":53,"last":53}]},"description":"Pause DNS","enabled":false}`
	if _, err = db.Exec("CREATE TRIGGER lab_acl_fail BEFORE INSERT ON audit_events WHEN NEW.action='acl_rule.update' BEGIN SELECT RAISE(ABORT,'lab'); END"); err != nil {
		t.Fatal(err)
	}
	send(rustURL, "PUT", rulePath(rule), update, operator, 500)
	unchanged := compare("", reader)["acl_rules"].([]any)
	for _, value := range unchanged {
		r := value.(map[string]any)
		if r["configuration_epoch"] != originalEpoch || (r["rule_id"] == rule && !reflect.DeepEqual(r, created)) {
			t.Fatal("failed ACL audit did not roll back policy and epoch")
		}
	}
	if _, err = db.Exec("DROP TRIGGER lab_acl_fail"); err != nil {
		t.Fatal(err)
	}
	patched := send(rustURL, "PUT", rulePath(rule), update, operator, 200)
	if patched["configuration_epoch"] != originalEpoch+1 || patched["enabled"] != false || patched["priority"] != float64(5) {
		t.Fatalf("wrong ACL update: %#v", patched)
	}
	compare("", reader)
	gone := send(rustURL, "DELETE", rulePath(rule), "", writer, 200)
	if gone["configuration_epoch"] != originalEpoch+2 {
		t.Fatal("delete did not advance epoch")
	}
	send(rustURL, "DELETE", rulePath(rule), "", writer, 404)
	compare("", reader)
	var count int
	var details string
	if err = db.QueryRow("SELECT count(*) FROM audit_events WHERE actor_id=? AND actor_kind='service_principal' AND target_id=? AND action IN ('acl_rule.create','acl_rule.delete')", mustAccessID(t, writerID), mustAccessID(t, rule)).Scan(&count); err != nil || count != 2 {
		t.Fatalf("ACL audit count=%d err=%v", count, err)
	}
	if err = db.QueryRow("SELECT details_json FROM audit_events WHERE target_id=? AND action='acl_rule.update'", mustAccessID(t, rule)).Scan(&details); err != nil {
		t.Fatal(err)
	}
	var event map[string]bool
	if err = json.Unmarshal([]byte(details), &event); err != nil || !reflect.DeepEqual(event, map[string]bool{"enabled": false}) {
		t.Fatalf("wrong ACL update audit: %s err=%v", details, err)
	}
}
