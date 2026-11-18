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
	"github.com/Doout/laneway/go/internal/netvalidate"
)

func testRustRelayManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	ctx := t.Context()
	net := f.network.ID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	foreign, err := f.store.CreateNetwork(ctx, "relay-foreign", netip.MustParsePrefix("10.221.0.0/24"))
	must(err)
	node := func(net identity.NetworkID, name string) identity.NodeID {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, net, name, time.Now().Add(time.Hour))
		must(err)
		n, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		must(err)
		return n.ID
	}
	host, foreignHost := node(net, "relay-host"), node(foreign.ID, "relay-host-foreign")
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	bot := func(permission string) labCredentials {
		t.Helper()
		args := fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, permission, permission, net)
		id := send(goURL, "POST", "/v1/admin/service-principals", args, root, 201)["principal_id"].(string)
		args = fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix())
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+id+"/tokens", args, root, 201)["access_token"].(string)}
	}
	web := func(role string) labCredentials {
		t.Helper()
		candidate, err := f.store.AdministratorPasswordCandidate(ctx, "web-"+role)
		must(err)
		_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(ctx, candidate, controller.AdministratorSessionOptions{})
		must(err)
		return labCredentials{session: token, csrf: csrf}
	}
	reader, writer := bot("relay.read"), bot("relay.manage")
	operator, auditor := web("operator"), web("auditor")
	list := "/v1/admin/networks/" + net.String() + "/relays"
	foreignList := "/v1/admin/networks/" + foreign.ID.String() + "/relays"
	register := func(service int, name, endpoint, node string) string {
		return fmt.Sprintf(`{"service_id":"%032x","name":%q,"endpoint":%q,"node_id":%q}`, service, name, endpoint, node)
	}
	update := func(name, endpoint string, enabled bool) string {
		return fmt.Sprintf(`{"name":%q,"endpoint":%q,"enabled":%t}`, name, endpoint, enabled)
	}
	relayPath := func(r map[string]any) string {
		return "/v1/admin/relays/" + r["relay_id"].(string)
	}
	external := relayPath(send(goURL, "POST", foreignList, register(1, "foreign", "relay.foreign:4433", ""), root, 201))
	send(rustURL, "GET", foreignList, "", reader, 403)
	send(rustURL, "GET", list, "", writer, 403)
	send(rustURL, "GET", list+"?limit=1001", "", reader, 400)
	send(rustURL, "POST", external+"/disable", "", operator, 404)
	send(rustURL, "PUT", external, update("other", "relay.foreign:4433", true), writer, 404)
	body := register(2, "primary", "Relay.Example.:04433", host.String())
	send(rustURL, "POST", list, body, auditor, 403)
	send(rustURL, "POST", list, body, reader, 403)
	send(rustURL, "POST", list, body, labCredentials{session: operator.session, csrf: "bad"}, 403)
	send(rustURL, "POST", list, register(2, "primary", "relay.example:4433", foreignHost.String()), operator, 404)
	for _, endpoint := range []string{"[::ffff:192.0.2.1]:4433", "224.0.0.1:4433", "0.0.0.0:4433", "foo..bar:4433", "relay.example:65536"} {
		send(rustURL, "POST", list, register(2, "primary", endpoint, ""), writer, 400)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	must(err)
	defer db.Close()
	epoch := func() uint64 {
		t.Helper()
		n, err := f.store.Network(ctx, net)
		must(err)
		return n.ConfigurationEpoch
	}
	before := epoch()
	_, err = db.Exec("CREATE TRIGGER fail_relay_audit BEFORE INSERT ON audit_events WHEN NEW.action='relay.register' BEGIN SELECT RAISE(ABORT,'lab'); END")
	must(err)
	send(rustURL, "POST", list, body, writer, 500)
	_, err = db.Exec("DROP TRIGGER fail_relay_audit")
	must(err)
	if epoch() != before {
		t.Fatal("failed relay registration changed the epoch")
	}
	added := send(rustURL, "POST", list, body, writer, 201)
	path := relayPath(added)
	if added["endpoint"] != "relay.example:4433" || added["node_id"] != host.String() || added["enabled"] != true || epoch() != before+1 {
		t.Fatalf("unexpected relay registration: %#v", added)
	}
	send(rustURL, "POST", list, register(3, "duplicate-endpoint", "relay.example:4433", ""), writer, 409)
	send(rustURL, "POST", list, register(2, "duplicate-service", "other.example:4433", ""), writer, 409)
	send(rustURL, "POST", list, register(3, "primary", "other.example:4433", ""), writer, 409)
	send(rustURL, "PUT", path, update("primary", "Relay.EXAMPLE.:04433", true), writer, 409)
	changed := send(rustURL, "PUT", path, update("renamed", "[2001:0db8::2]:4433", true), operator, 200)
	if changed["relay_id"] != added["relay_id"] || changed["service_id"] != added["service_id"] ||
		changed["node_id"] != added["node_id"] || changed["endpoint"] != "[2001:db8::2]:4433" || epoch() != before+2 {
		t.Fatalf("unexpected relay update: %#v", changed)
	}
	send(rustURL, "POST", path+"/disable", "", writer, 200)
	send(rustURL, "POST", path+"/disable", "", writer, 409)
	active, err := f.store.ActiveRelays(ctx, net)
	must(err)
	for _, r := range active {
		if r.ID.String() == added["relay_id"] {
			t.Fatal("disabled relay is still published")
		}
	}
	for _, path := range []string{list, list + "?limit=1"} {
		a := send(goURL, "GET", path, "", reader, 200)
		b := send(rustURL, "GET", path, "", auditor, 200)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("relay inventory mismatch: Go=%#v Rust=%#v", a, b)
		}
	}
	standby := relayPath(send(rustURL, "POST", foreignList, register(2, "standby", "standby.foreign:4433", ""), root, 201))
	send(rustURL, "POST", standby+"/disable", "", root, 200)
	for i := 1; i < netvalidate.MaxRelayEndpoints; i++ {
		name := fmt.Sprintf("relay-%d", i)
		send(rustURL, "POST", foreignList, register(i+2, name, name+".foreign:4433", ""), root, 201)
	}
	send(rustURL, "POST", foreignList, register(99, "overflow", "overflow.foreign:4433", ""), root, 400)
	send(rustURL, "PUT", standby, update("standby", "standby.foreign:4433", true), root, 400)
	send(rustURL, "POST", external+"/disable", "", root, 200)
	send(rustURL, "PUT", standby, update("standby", "standby.foreign:4433", true), root, 200)
}
