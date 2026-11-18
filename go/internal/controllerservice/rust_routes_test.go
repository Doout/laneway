//go:build rustinterop

package controllerservice

import (
	"database/sql"
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

func testRustRouteManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	ctx := t.Context()
	net := f.network.ID
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	bot := func(permission string) labCredentials {
		t.Helper()
		data := fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, permission, permission, net)
		id := send(goURL, "POST", "/v1/admin/service-principals", data, root, 201)["principal_id"].(string)
		data = fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix())
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+id+"/tokens", data, root, 201)["access_token"].(string)}
	}
	web := func(role string) labCredentials {
		t.Helper()
		candidate, err := f.store.AdministratorPasswordCandidate(ctx, "web-"+role)
		if err != nil {
			t.Fatal(err)
		}
		_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(ctx, candidate, controller.AdministratorSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return labCredentials{session: token, csrf: csrf}
	}
	node := func(network identity.NetworkID, name string) identity.NodeID {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, network, name, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		n, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return n.ID
	}
	advertise := func(node identity.NodeID, prefix string, metric uint32, until *time.Time) string {
		t.Helper()
		r, err := f.store.AdvertiseRoute(ctx, node, netip.MustParsePrefix(prefix), controller.RouteKindSubnet, controller.RouteModeNAT, metric, until)
		if err != nil {
			t.Fatal(err)
		}
		return r.ID.String()
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	reader, writer := bot("route.read"), bot("route.manage")
	operator, auditor := web("operator"), web("auditor")
	other, err := f.store.CreateNetwork(ctx, "foreign-route", netip.MustParsePrefix("10.219.0.0/24"))
	must(err)
	router := node(net, "routes-connector")
	otherRouter := node(net, "routes-second")
	foreign := node(other.ID, "routes-foreign")
	_, err = f.store.SetNodeCapabilities(ctx, foreign, protocol.CapabilitySubnetRouterV1)
	must(err)
	foreignRoute := advertise(foreign, "192.0.2.0/24", 4, nil)
	list := "/v1/admin/networks/" + net.String() + "/routes"
	compare := func(path string, auth labCredentials) {
		t.Helper()
		a := send(goURL, "GET", path, "", auth, 200)
		b := send(rustURL, "GET", path, "", auth, 200)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("route list mismatch: Go=%#v Rust=%#v", a, b)
		}
	}
	compare("/v1/admin/networks/"+other.ID.String()+"/routes", root)
	const actions = "/v1/admin/routes/"
	send(rustURL, "GET", list, "", writer, 403)
	send(rustURL, "GET", list+"?limit=0", "", reader, 400)
	send(rustURL, "GET", "/v1/admin/networks/"+other.ID.String()+"/routes", "", reader, 403)
	send(rustURL, "POST", actions+foreignRoute+"/approve", "", operator, 404)
	send(rustURL, "POST", actions+foreignRoute+"/withdraw", "", writer, 404)
	send(rustURL, "DELETE", "/v1/routes/"+foreignRoute, "", root, 401)
	assign := func(node identity.NodeID, prefix string) string {
		return fmt.Sprintf(`{"network_id":%q,"node_id":%q,"prefix":%q,"mode":"nat","metric":22}`, net, node, prefix)
	}
	valid := assign(router, "2001:db8:72::/64")
	for _, cred := range []labCredentials{auditor, reader, {session: operator.session, csrf: "bad"}} {
		send(rustURL, "POST", actions+"assign", valid, cred, 403)
	}
	for _, bad := range []string{"192.0.2.1/24", "0.0.0.0/0", "::ffff:192.0.2.0/120", "126.0.0.0/7", "fe80::/10"} {
		send(rustURL, "POST", actions+"assign", assign(router, bad), operator, 400)
	}
	send(rustURL, "POST", actions+"assign", assign(foreign, "192.0.2.0/24"), operator, 404)

	db, err := sql.Open("sqlite", f.dbPath)
	must(err)
	defer db.Close()
	epoch := func() (out int64) {
		t.Helper()
		must(db.QueryRow("SELECT configuration_epoch FROM networks WHERE id=?", net[:]).Scan(&out))
		return out
	}
	before := epoch()
	_, err = db.Exec("CREATE TRIGGER lab_route_rollback BEFORE INSERT ON audit_events WHEN NEW.action='route.approve' BEGIN SELECT RAISE(ABORT,'lab'); END")
	must(err)
	send(rustURL, "POST", actions+"assign", valid, operator, 500)
	_, err = db.Exec("DROP TRIGGER lab_route_rollback")
	must(err)
	var caps, rows int
	must(db.QueryRow("SELECT enabled_capabilities,(SELECT count(*) FROM routes WHERE node_id=?) FROM nodes WHERE id=?", router[:], router[:]).Scan(&caps, &rows))
	if caps != 0 || rows != 0 || epoch() != before {
		t.Fatal("failed assignment did not roll back the route, capability and epoch")
	}
	got := send(rustURL, "POST", actions+"assign", valid, operator, 201)
	if got["state"] != "approved" || got["prefix"] != "2001:db8:72::/64" || epoch() != before+2 {
		t.Fatalf("unexpected assignment: %#v", got)
	}
	reused := send(rustURL, "POST", actions+"assign", valid, writer, 200)
	if !reflect.DeepEqual(reused, got) || epoch() != before+2 {
		t.Fatal("exact assignment retry did not reuse the record without an epoch change")
	}
	id := got["route_id"].(string)
	send(rustURL, "POST", actions+id+"/approve", "", writer, 409)
	send(rustURL, "POST", actions+"assign", assign(otherRouter, "2001:db8:72::/64"), writer, 409)
	_, err = f.store.SetNodeCapabilities(ctx, otherRouter, protocol.CapabilitySubnetRouterV1)
	must(err)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	alternate := advertise(otherRouter, "2001:db8:72::/64", 22, &expires)
	send(rustURL, "POST", actions+"assign", valid, operator, 409)
	send(rustURL, "POST", actions+alternate+"/approve", "", writer, 409)
	compare(list+"?limit=1", reader)
	compare(list, auditor)
	before = epoch()
	send(rustURL, "POST", actions+id+"/withdraw", "", operator, 200)
	if epoch() != before+1 {
		t.Fatal("approved withdrawal did not advance the epoch")
	}
	send(rustURL, "POST", actions+id+"/withdraw", "", operator, 409)
	send(rustURL, "POST", actions+alternate+"/approve", "", writer, 200)
	pending := advertise(otherRouter, "192.0.2.0/24", 5, nil)
	before = epoch()
	send(rustURL, "POST", actions+pending+"/withdraw", "", writer, 200)
	if epoch() != before {
		t.Fatal("withdrawing an unapproved route changed the epoch")
	}
	compare(list, reader)
}
