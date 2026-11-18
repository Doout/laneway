//go:build rustinterop

package controllerservice_test

import (
	"database/sql"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/policy"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func checkRustManagedPolicy(t *testing.T, store *controller.Store, db *sql.DB, network identity.NetworkID, source identity.NodeID,
	rust, reference *controllerclient.Client, provision func(string) (identity.NodeID, pki.Material)) {
	t.Helper()
	ctx := t.Context()
	id := func() identity.ID {
		v, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	user, team := id(), id()
	target, _ := provision("managed-connector")
	gateway, _ := provision("managed-exit")
	sibling, _ := provision("managed-sibling")
	targetNode, err := store.Node(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	srcNode, err := store.Node(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SetNodeCapabilities(ctx, target, protocol.CapabilitySubnetRouterV1); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SetNodeCapabilities(ctx, gateway, protocol.CapabilityExitNodeV1); err != nil {
		t.Fatal(err)
	}
	route := func(node identity.NodeID, prefix string, kind controller.RouteKind) controller.Route {
		r, err := store.AdvertiseRoute(ctx, node, netip.MustParsePrefix(prefix), kind, controller.RouteModeNAT, 10, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.ApproveRoute(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		return r
	}
	subnet := route(target, "172.22.0.0/16", controller.RouteKindSubnet)
	_ = route(gateway, "0.0.0.0/0", controller.RouteKindExit)
	global, _, err := store.AddACLRule(ctx, network, 0, controller.ACLActionAccept, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "Global allow")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.AddACLRule(ctx, network, math.MaxUint32, controller.ACLActionAccept, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "Max priority"); err != nil {
		t.Fatal(err)
	}
	type migrationFixture struct {
		q    string
		args []any
	}
	row := func(q string, args ...any) migrationFixture { return migrationFixture{q, args} }
	// Write only schema-valid fixture rows in the temp SQLite DB. The Go
	// reference reads the same committed rows. Mutations bump the epoch just
	// as the administrator APIs do, independently of the compiled policy.
	edit := func(rows ...migrationFixture) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, r := range rows {
			if _, err = tx.ExecContext(ctx, r.q, r.args...); err != nil {
				t.Fatalf("%s: %v", r.q, err)
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE networks SET configuration_epoch=configuration_epoch+1 WHERE id=?", network[:]); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	edit(
		row("INSERT INTO access_users(id,network_id,name,created_at,updated_at) VALUES(?,?,?,unixepoch(),unixepoch())", user[:], network[:], "operator"),
		row("INSERT INTO access_teams(id,network_id,name,created_at,updated_at) VALUES(?,?,?,unixepoch(),unixepoch())", team[:], network[:], "ops"),
		row("INSERT INTO access_team_members(network_id,team_id,user_id,created_at) VALUES(?,?,?,unixepoch())", network[:], team[:], user[:]),
		row("UPDATE nodes SET user_id=? WHERE id IN (?,?)", user[:], source[:], sibling[:]),
	)
	var known uint64
	read := func() (*v1.NodeConfiguration, *policy.Engine) {
		t.Helper()
		got, same, err := rust.Configuration(ctx, known)
		if err != nil || same || got.GetConfigurationEpoch() <= known {
			t.Fatalf("Rust managed snapshot: %v %t %v", got, same, err)
		}
		expected, same, err := reference.Configuration(ctx, 0)
		if err != nil || same {
			t.Fatalf("Go managed snapshot: %v %t %v", expected, same, err)
		}
		expected.ValidUntilUnixSeconds = got.ValidUntilUnixSeconds
		if !proto.Equal(expected, got) {
			t.Fatalf("managed policy mismatch\nGo: %v\nRust: %v", expected.GetPolicy(), got.GetPolicy())
		}
		known = got.ConfigurationEpoch
		engine, err := policy.Compile(got.Policy)
		if err != nil {
			t.Fatal(err)
		}
		return got, engine
	}
	packet := func(dest netip.Addr, port uint16) []byte {
		p := make([]byte, 40)
		p[0], p[9] = 0x45, 6
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		copy(p[12:16], srcNode.IPv4Address.AsSlice())
		copy(p[16:20], dest.AsSlice())
		binary.BigEndian.PutUint16(p[20:22], 49152)
		binary.BigEndian.PutUint16(p[22:24], port)
		p[32] = 0x50
		return p
	}
	expect := func(e *policy.Engine, from, to identity.NodeID, dest netip.Addr, port uint16, rule identity.ID, allow bool) {
		t.Helper()
		got := e.Evaluate(from, to, packet(dest, port))
		if (got.Action == policy.Accept) != allow || (!rule.IsZero() && got.RuleID != rule) {
			t.Fatalf("decision to %s:%d via %s: %+v (want allow=%t rule=%s)", dest, port, to, got, allow, rule)
		}
	}
	cfg, engine := read()
	if len(cfg.ExitPolicy.AuthorizedNodeIds) != 0 || len(cfg.Policy.Rules) != 3 {
		t.Fatalf("unexpected no-grant policy: %v", cfg.Policy)
	}
	expect(engine, source, target, targetNode.IPv4Address, 443, identity.ID{}, false)
	expect(engine, sibling, target, targetNode.IPv4Address, 443, identity.ID{}, false)
	expect(engine, target, source, srcNode.IPv4Address, 443, global.ID, true)

	nodeGrant, exitGrant, networkGrant := id(), id(), id()
	prefixResource, nodeResource, service := id(), id(), id()
	prefixGrant, namedNodeGrant := id(), id()
	host := netip.MustParseAddr("172.22.1.4")
	otherHost := netip.MustParseAddr("172.22.1.5")
	public := netip.MustParseAddr("8.8.8.8")
	edit(
		row("INSERT INTO access_grants(id,network_id,subject_kind,user_id,target_kind,node_id,created_at) VALUES(?,?,'user',?,'node',?,unixepoch())", nodeGrant[:], network[:], user[:], target[:]),
		row("INSERT INTO access_grants(id,network_id,subject_kind,team_id,target_kind,node_id,created_at) VALUES(?,?,'team',?,'exit',?,unixepoch())", exitGrant[:], network[:], team[:], gateway[:]),
		row("INSERT INTO access_resources(id,network_id,name,target_kind,route_id,route_node_id,route_prefix_address,route_prefix_length,prefix_address,prefix_length,created_at,updated_at) VALUES(?,?,'database','prefix',?,?,?,?,?,32,unixepoch(),unixepoch())", prefixResource[:], network[:], subnet.ID[:], target[:], subnet.Prefix.Addr().AsSlice(), subnet.Prefix.Bits(), host.AsSlice()),
		row("INSERT INTO access_resources(id,network_id,name,target_kind,node_id,created_at,updated_at) VALUES(?,?,'sibling','node',?,unixepoch(),unixepoch())", nodeResource[:], network[:], sibling[:]),
		row("INSERT INTO access_services(id,network_id,name,protocol,created_at,updated_at) VALUES(?,?,'https','tcp',unixepoch(),unixepoch())", service[:], network[:]),
		row("INSERT INTO access_service_ports(service_id,first_port,last_port) VALUES(?,443,445),(?,8443,8443)", service[:], service[:]),
		row("UPDATE access_services SET ports_sealed=1 WHERE id=?", service[:]),
		row("INSERT INTO access_resource_grants(id,network_id,subject_kind,user_id,resource_id,service_id,created_at) VALUES(?,?,'user',?,?,?,unixepoch())", prefixGrant[:], network[:], user[:], prefixResource[:], service[:]),
		row("INSERT INTO access_resource_grants(id,network_id,subject_kind,team_id,resource_id,service_id,created_at) VALUES(?,?,'team',?,?,?,unixepoch())", namedNodeGrant[:], network[:], team[:], nodeResource[:], service[:]),
	)
	cfg, engine = read()
	if len(cfg.ExitPolicy.AuthorizedNodeIds) != 1 || string(cfg.ExitPolicy.AuthorizedNodeIds[0]) != string(gateway[:]) {
		t.Fatalf("unexpected approved exits: %v", cfg.ExitPolicy)
	}
	expect(engine, source, target, targetNode.IPv4Address, 22, nodeGrant, true)
	expect(engine, source, target, host, 444, prefixGrant, true)
	expect(engine, source, target, host, 8443, prefixGrant, true)
	expect(engine, source, target, host, 446, identity.ID{}, false)
	expect(engine, source, target, otherHost, 443, identity.ID{}, false)
	expect(engine, source, gateway, public, 443, exitGrant, true)
	siblingNode, err := store.Node(ctx, sibling)
	if err != nil {
		t.Fatal(err)
	}
	expect(engine, source, sibling, siblingNode.IPv4Address, 444, namedNodeGrant, true)
	expect(engine, source, sibling, siblingNode.IPv4Address, 22, identity.ID{}, false)
	malformedService, badGrant := id(), id()
	edit(
		row("INSERT INTO access_services(id,network_id,name,protocol,created_at,updated_at) VALUES(?,?,'unmerged','tcp',unixepoch(),unixepoch())", malformedService[:], network[:]),
		row("INSERT INTO access_service_ports(service_id,first_port,last_port) VALUES(?,443,445),(?,446,449)", malformedService[:], malformedService[:]),
		row("UPDATE access_services SET ports_sealed=1 WHERE id=?", malformedService[:]),
		row("INSERT INTO access_resource_grants(id,network_id,subject_kind,user_id,resource_id,service_id,created_at) VALUES(?,?,'user',?,?,?,unixepoch())", badGrant[:], network[:], user[:], prefixResource[:], malformedService[:]),
	)
	for name, cl := range map[string]*controllerclient.Client{"Go": reference, "Rust": rust} {
		if _, _, err := cl.Configuration(ctx, known); err == nil {
			t.Fatalf("%s served a managed snapshot containing noncanonical service ranges", name)
		}
	}
	edit(row("DELETE FROM access_resource_grants WHERE id=?", badGrant[:]))

	if _, err = store.WithdrawRoute(ctx, subnet.ID, &target); err != nil {
		t.Fatal(err)
	}
	_ = route(target, "172.22.0.0/16", controller.RouteKindSubnet)
	_, engine = read()
	expect(engine, source, target, host, 443, identity.ID{}, false) // replacement has another ID
	edit(row("UPDATE access_services SET enabled=0 WHERE id=?", service[:]))
	_, engine = read()
	expect(engine, source, sibling, siblingNode.IPv4Address, 444, identity.ID{}, false)
	edit(
		row("DELETE FROM access_grants WHERE id=?", exitGrant[:]),
		row("INSERT INTO access_grants(id,network_id,subject_kind,team_id,target_kind,created_at) VALUES(?,?,'team',?,'network',unixepoch())", networkGrant[:], network[:], team[:]),
	)
	cfg, engine = read()
	if len(cfg.ExitPolicy.AuthorizedNodeIds) != 0 {
		t.Fatalf("private network grant authorized an exit")
	}
	expect(engine, source, target, otherHost, 22, networkGrant, true)
	expect(engine, source, gateway, public, 443, identity.ID{}, false)
	edit(row("DELETE FROM access_team_members WHERE team_id=? AND user_id=?", team[:], user[:]))
	_, engine = read()
	expect(engine, source, target, otherHost, 22, identity.ID{}, false)
	expect(engine, source, target, targetNode.IPv4Address, 443, nodeGrant, true)
	edit(row("UPDATE access_users SET enabled=0 WHERE id=?", user[:]))
	_, engine = read()
	expect(engine, source, target, targetNode.IPv4Address, 443, identity.ID{}, false)
	expect(engine, sibling, target, otherHost, 443, identity.ID{}, false)
}
