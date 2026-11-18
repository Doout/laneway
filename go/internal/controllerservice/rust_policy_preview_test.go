//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func testRustPolicyPreview(t *testing.T, f fixture, client *http.Client, endpoint, session, csrf string) {
	t.Helper()
	ctx := t.Context()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	browser := labCredentials{session: session, csrf: csrf}
	network, err := f.store.CreateNetworkDualStack(ctx, "preview", netip.MustParsePrefix("10.194.0.0/24"), netip.MustParsePrefix("fd00:194::/64"))
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/admin/networks/" + network.ID.String()
	path := base + "/policy-preview"
	otherPath := "/v1/admin/networks/" + f.network.ID.String() + "/policy-preview"
	node := func(net identity.NetworkID, name string, user *identity.ID) controller.Node {
		t.Helper()
		token, err := f.store.IssueEnrollmentTokenWithOptions(ctx, net, name, time.Now().Add(time.Hour), controller.EnrollmentTokenOptions{UserID: user})
		if err != nil {
			t.Fatal(err)
		}
		n, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	userID := send(endpoint, "POST", base+"/users", `{"name":"preview-managed"}`, root, 201)["user_id"].(string)
	user, err := identity.ParseID(userID)
	if err != nil {
		t.Fatal(err)
	}
	source, target := node(network.ID, "preview-source", nil), node(network.ID, "preview-target", nil)
	router, managed := node(network.ID, "preview-router", nil), node(network.ID, "preview-managed", &user)
	foreign := node(f.network.ID, "preview-foreign", nil)
	if _, err = f.store.SetNodeCapabilities(ctx, router.ID, protocol.CapabilitySubnetRouterV1); err != nil {
		t.Fatal(err)
	}
	routedIP := "172.31.100.9"
	route, err := f.store.AdvertiseRoute(ctx, router.ID, netip.MustParsePrefix("172.31.100.0/24"), controller.RouteKindSubnet, controller.RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ApproveRoute(ctx, route.ID); err != nil {
		t.Fatal(err)
	}
	allow := send(endpoint, "POST", base+"/acl-rules", `{"priority":10,"action":"accept","selector":{"ip_protocol":"IP_PROTOCOL_TCP","destination_ports":[{"first":443,"last":443}]}}`, root, 201)["rule_id"]
	deny := send(endpoint, "POST", base+"/acl-rules", `{"priority":5,"action":"deny","selector":{"ip_protocol":"IP_PROTOCOL_UDP"}}`, root, 201)["rule_id"]
	bot := func(permission string) labCredentials {
		t.Helper()
		id := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, "preview-"+permission, permission, network.ID.String()), root, 201)["principal_id"].(string)
		return labCredentials{bearer: send(endpoint, "POST", "/v1/admin/service-principals/"+id+"/tokens", fmt.Sprintf(`{"label":"preview","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)}
	}
	reader, writer := bot("acl.read"), bot("acl.manage")
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := func() [3]int64 {
		t.Helper()
		var got [3]int64
		if err := db.QueryRow(`SELECT n.configuration_epoch,(SELECT count(*) FROM audit_events),
			(SELECT sum(last_seen_at) FROM administrator_sessions) FROM networks n WHERE n.id=?`, network.ID[:]).Scan(&got[0], &got[1], &got[2]); err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := state()
	body := func(from controller.Node, to, ip, proto string, port int, proposed ...any) string {
		t.Helper()
		req := map[string]any{"flow": map[string]any{"source_node_id": from.ID.String(), "destination_node_id": to, "destination_ip": ip, "protocol": proto, "destination_port": port}}
		if len(proposed) != 0 {
			req["proposed_rules"] = proposed[0]
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	eval := func(req string, c labCredentials, status int) map[string]any {
		t.Helper()
		return send(endpoint, "POST", path, req, c, status)
	}
	req := body(source, target.ID.String(), "", "TCP", 443, []any{})
	got := eval(req, reader, 200)
	current, proposed := got["current"].(map[string]any), got["proposed"].(map[string]any)
	wantTrace := []any{
		map[string]any{"rule_id": deny, "priority": float64(5), "action": "deny", "matched": false},
		map[string]any{"rule_id": allow, "priority": float64(10), "action": "accept", "matched": true},
	}
	if got["scope"] != "manual_acl_with_current_managed_access" ||
		current["configuration_epoch"] != float64(before[0]) || current["action"] != "accept" || current["matched_rule_id"] != allow ||
		current["default_result"] != false || current["destination_node_id"] != target.ID.String() ||
		current["destination_ip"] != target.IPv4Address.String() || !reflect.DeepEqual(current["trace"], wantTrace) ||
		proposed["configuration_epoch"] != current["configuration_epoch"] || proposed["default_result"] != true || proposed["action"] != "deny" ||
		proposed["matched_rule_id"] != nil || !reflect.DeepEqual(proposed["trace"], []any{}) {
		t.Fatalf("unexpected preview: %#v", got)
	}
	if v := eval(body(source, "", routedIP, "tcp", 443), browser, 200); v["proposed"] != nil ||
		v["current"].(map[string]any)["destination_node_id"] != router.ID.String() {
		t.Fatalf("approved subnet route did not resolve: %#v", v)
	}
	if v := eval(body(source, "", target.IPv6Address.String(), "icmpv6", 0), root, 200)["current"].(map[string]any); v["destination_node_id"] != target.ID.String() || v["default_result"] != true {
		t.Fatalf("IPv6 overlay flow did not resolve: %#v", v)
	}
	eval(req, labCredentials{session: session}, 403)
	eval(req, labCredentials{session: session, csrf: "bogus"}, 403)
	eval(req, writer, 403)
	eval(`{"flow":"bad"}`, writer, 403)
	eval(`{"flow":"bad"}`, reader, 400)
	send(endpoint, "POST", otherPath, req, reader, 403)
	eval(body(foreign, target.ID.String(), "", "tcp", 443), root, 404)
	eval(body(source, foreign.ID.String(), "", "tcp", 443), root, 404)
	eval(body(source, target.ID.String(), routedIP, "tcp", 443), root, 400)
	eval(body(source, "", "172.31.101.9", "tcp", 443), root, 400)
	eval(body(source, "", target.IPv6Address.String(), "icmp", 0), root, 400)
	eval(body(source, target.ID.String(), "", "udp", 0), root, 400)
	eval(body(source, target.ID.String(), "", "icmp", 1), root, 400)
	allowAll := []any{map[string]any{"rule_id": allow, "priority": 0, "action": "accept", "enabled": true, "selector": map[string]any{"ip_protocol": "IP_PROTOCOL_ANY"}}}
	managedReq := body(managed, target.ID.String(), "", "tcp", 443, allowAll)
	restricted := eval(managedReq, reader, 200)
	for _, field := range []string{"current", "proposed"} {
		v := restricted[field].(map[string]any)
		if v["action"] != "deny" || v["default_result"] != false || v["matched_rule_id"] == deny {
			t.Fatalf("manual allow bypassed managed restriction: %#v", restricted)
		}
	}
	if after := state(); after != before {
		t.Fatalf("preview changed database state: before=%v after=%v", before, after)
	}
	send(endpoint, "POST", base+"/access-grants", fmt.Sprintf(`{"subject_kind":"user","subject_id":%q,"target_kind":"node","node_id":%q}`, userID, target.ID.String()), root, 201)
	granted := eval(body(managed, target.ID.String(), "", "tcp", 443, []any{}), reader, 200)
	for _, field := range []string{"current", "proposed"} {
		v := granted[field].(map[string]any)
		if v["action"] != "accept" || v["matched_rule_id"] == allow {
			t.Fatalf("managed grant was not retained: %#v", granted)
		}
	}
	if _, err := f.store.RevokeNode(ctx, target.ID, "preview lab"); err != nil {
		t.Fatal(err)
	}
	eval(req, reader, 400)
}
