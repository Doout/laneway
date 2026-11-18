//go:build rustinterop

package controllerservice

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func testRustAccessManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	ctx := t.Context()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	web := func(role string) (labCredentials, string) {
		t.Helper()
		candidate, err := f.store.AdministratorPasswordCandidate(ctx, "web-"+role)
		if err != nil {
			t.Fatal(err)
		}
		ses, tok, csrf, err := f.store.CreateAdministratorSessionAfterPassword(ctx, candidate, controller.AdministratorSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return labCredentials{session: tok, csrf: csrf}, ses.PrincipalID.String()
	}
	operator, operatorID := web("operator")
	auditor, _ := web("auditor")
	readBot := send(goURL, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"access-reader","permissions":["acl.read"],"network_ids":[%q]}`, f.network.ID.String()), root, 201)["principal_id"].(string)
	writeBot := send(goURL, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"access-writer","permissions":["acl.manage"],"network_ids":[%q]}`, f.network.ID.String()), root, 201)["principal_id"].(string)
	token := func(id string) labCredentials {
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+id+"/tokens", fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)}
	}
	reader, writer := token(readBot), token(writeBot)
	other, err := f.store.CreateNetwork(ctx, "foreign-access", netip.MustParsePrefix("10.213.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/admin/networks/" + f.network.ID.String()
	otherPath := "/v1/admin/networks/" + other.ID.String()
	inventory := func(c labCredentials, path string) {
		t.Helper()
		goResult := send(goURL, "GET", path+"/access-subjects", "", c, 200)
		rustResult := send(rustURL, "GET", path+"/access-subjects", "", c, 200)
		if !reflect.DeepEqual(goResult, rustResult) {
			t.Fatalf("access inventory: Go=%#v Rust=%#v", goResult, rustResult)
		}
	}
	inventory(reader, path)
	send(rustURL, "GET", otherPath+"/access-subjects", "", reader, 403)
	send(rustURL, "GET", path+"/access-subjects", "", writer, 403)
	send(rustURL, "POST", path+"/users", `{"name":"denied"}`, auditor, 403)
	send(rustURL, "POST", path+"/users", `{"name":"denied"}`, reader, 403)
	send(rustURL, "POST", otherPath+"/users", `{"name":"denied"}`, operator, 403)
	noCSRF := labCredentials{session: operator.session, csrf: "bad"}
	send(rustURL, "POST", path+"/users", `{"name":"denied"}`, noCSRF, 403)
	send(rustURL, "POST", path+"/users", `{"name":"denied"}`, labCredentials{}, 401)
	send(rustURL, "POST", path+"/users", `{"name":" invalid"}`, root, 400)
	send(rustURL, "POST", path+"/users", `{"name":"extra","extra":true}`, root, 400)

	user := send(rustURL, "POST", path+"/users", `{"name":"operator-device"}`, operator, 201)["user_id"].(string)
	send(rustURL, "POST", path+"/users", `{"name":"operator-device"}`, operator, 409)
	team := send(rustURL, "POST", path+"/teams", `{"name":"release-team"}`, writer, 201)["team_id"].(string)
	foreignUser := send(goURL, "POST", otherPath+"/users", `{"name":"outsider"}`, root, 201)["user_id"].(string)
	foreignTeam := send(goURL, "POST", otherPath+"/teams", `{"name":"outsiders"}`, root, 201)["team_id"].(string)
	send(rustURL, "PATCH", "/v1/admin/users/"+foreignUser, `{"enabled":false}`, operator, 404)
	send(rustURL, "PATCH", "/v1/admin/users/"+foreignUser, `{"enabled":false}`, writer, 404)
	send(rustURL, "PUT", "/v1/admin/teams/"+foreignTeam+"/members/"+user, "", operator, 404)
	send(rustURL, "PUT", "/v1/admin/teams/"+team+"/members/"+foreignUser, "", operator, 400)
	member := "/v1/admin/teams/" + team + "/members/" + user
	first := send(rustURL, "PUT", member, "", operator, 200)["configuration_epoch"]
	second := send(rustURL, "PUT", member, "", operator, 200)["configuration_epoch"]
	if first != second {
		t.Fatal("duplicate membership advanced the epoch")
	}
	inventory(auditor, path)

	node := func(net identity.NetworkID, name string) controller.Node {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, net, name, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		node, err := f.store.EnrollNode(ctx, token.Secret, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	connector := node(f.network.ID, "access-connector")
	foreign := node(other.ID, "foreign-node")
	grantBody := func(kind, id, target, node string) string {
		if node == "" {
			return fmt.Sprintf(`{"subject_kind":%q,"subject_id":%q,"target_kind":%q}`, kind, id, target)
		}
		return fmt.Sprintf(`{"subject_kind":%q,"subject_id":%q,"target_kind":%q,"node_id":%q}`, kind, id, target, node)
	}
	grants := path + "/access-grants"
	send(rustURL, "POST", grants, grantBody("user", foreignUser, "network", ""), writer, 404)
	send(rustURL, "POST", grants, grantBody("user", user, "node", foreign.ID.String()), writer, 404)
	send(rustURL, "POST", grants, grantBody("user", user, "exit", connector.ID.String()), writer, 400)
	if _, err = f.store.SetNodeCapabilities(ctx, connector.ID, protocol.CapabilityExitNodeV1|protocol.CapabilitySubnetRouterV1); err != nil {
		t.Fatal(err)
	}
	exits, err := f.store.AdvertiseRoute(ctx, connector.ID, netip.MustParsePrefix("0.0.0.0/0"), controller.RouteKindExit, controller.RouteModeNAT, 50, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ApproveRoute(ctx, exits.ID); err != nil {
		t.Fatal(err)
	}
	subnet, err := f.store.AdvertiseRoute(ctx, connector.ID, netip.MustParsePrefix("172.24.0.0/16"), controller.RouteKindSubnet, controller.RouteModeNAT, 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ApproveRoute(ctx, subnet.ID); err != nil {
		t.Fatal(err)
	}
	exitGrant := send(rustURL, "POST", grants, grantBody("team", team, "exit", connector.ID.String()), writer, 201)["grant_id"].(string)
	direct := send(rustURL, "POST", grants, grantBody("user", user, "node", connector.ID.String()), operator, 201)["grant_id"].(string)
	send(rustURL, "POST", grants, grantBody("user", user, "node", connector.ID.String()), operator, 409)
	// Use Go to write the named resource and sealed service; verify the full
	// inventory emitted by Rust, not just objects written by its own server.
	resource := send(goURL, "POST", path+"/resources", fmt.Sprintf(`{"name":"private","target_kind":"prefix","route_id":%q,"prefix":"172.24.1.2/32"}`, subnet.ID.String()), root, 201)["resource_id"].(string)
	service := send(goURL, "POST", path+"/services", `{"name":"HTTPS","protocol":"tcp","ports":[{"first":443,"last":445}]}`, root, 201)["service_id"].(string)
	send(goURL, "POST", path+"/resource-access-grants", fmt.Sprintf(`{"subject_kind":"team","subject_id":%q,"resource_id":%q,"service_id":%q}`, team, resource, service), root, 201)
	inventory(reader, path)
	send(rustURL, "PATCH", "/v1/admin/users/"+user, `{"enabled":false}`, operator, 200)
	send(rustURL, "DELETE", "/v1/admin/access-grants/"+direct, "", operator, 200)
	send(rustURL, "DELETE", "/v1/admin/access-grants/"+direct, "", operator, 404)
	send(rustURL, "DELETE", "/v1/admin/access-grants/"+exitGrant, "", writer, 200)
	send(rustURL, "DELETE", member, "", operator, 200)
	inventory(reader, path)

	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	audit := func(key, actor, kind, action string, count int) {
		t.Helper()
		var got int
		err := db.QueryRow("SELECT count(*) FROM audit_events WHERE target_id=? AND actor_id=? AND actor_kind=? AND action=?",
			mustAccessID(t, key), mustAccessID(t, actor), kind, action).Scan(&got)
		if err != nil || got != count {
			t.Fatalf("audit %s: %d want %d err=%v", action, got, count, err)
		}
	}
	audit(user, operatorID, "administrator", "access_user.create", 1)
	audit(team, operatorID, "administrator", "access_team.member", 2)
	audit(team, writeBot, "service_principal", "access_team.create", 1)
	audit(exitGrant, writeBot, "service_principal", "access_grant.delete", 1)
	before, err := f.store.Network(ctx, f.network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TRIGGER lab_access_rollback BEFORE INSERT ON audit_events WHEN NEW.action='access_user.create' BEGIN SELECT RAISE(ABORT,'lab'); END"); err != nil {
		t.Fatal(err)
	}
	send(rustURL, "POST", path+"/users", `{"name":"rollback"}`, writer, 500)
	if _, err = db.Exec("DROP TRIGGER lab_access_rollback"); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.Network(ctx, f.network.ID)
	if err != nil || before.ConfigurationEpoch != after.ConfigurationEpoch {
		t.Fatalf("failed audit advanced epoch: %v", err)
	}
	users := send(rustURL, "GET", path+"/access-subjects", "", reader, 200)["users"]
	if strings.Contains(fmt.Sprint(users), "rollback") {
		t.Fatal("failed audit left a user behind")
	}
}

func mustAccessID(t *testing.T, raw string) []byte {
	t.Helper()
	id, err := identity.ParseID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id[:]
}
