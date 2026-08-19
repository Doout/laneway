package controller

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAccessUsersTeamsAndGrantsCompileFailClosedPolicy(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "managed-access", "10.84.0.0/24")

	userDecision := administratorRootDecision(t, store, administratorAccessUserCreatePolicy, adminauth.NetworkTarget(network.ID))
	user, _, err := store.AdministratorCreateAccessUser(ctx, userDecision, network.ID, "Sam")
	if err != nil {
		t.Fatal(err)
	}
	teamDecision := administratorRootDecision(t, store, administratorAccessTeamCreatePolicy, adminauth.NetworkTarget(network.ID))
	team, _, err := store.AdministratorCreateAccessTeam(ctx, teamDecision, network.ID, "Engineering")
	if err != nil {
		t.Fatal(err)
	}

	memberDecision := administratorRootDecision(t, store, administratorAccessMemberAddPolicy, adminauth.ObjectTarget(team.ID))
	if _, err := store.AdministratorSetAccessTeamMember(ctx, memberDecision, team.ID, user.ID, true); err != nil {
		t.Fatal(err)
	}

	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "sam-laptop", time.Now().Add(time.Hour), EnrollmentTokenOptions{
		Class: EnrollmentClassDurable, UserID: &user.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.EnrollNode(ctx, token.Secret, "sam-laptop", 0)
	if err != nil {
		t.Fatal(err)
	}
	if source.UserID == nil || *source.UserID != user.ID {
		t.Fatalf("enrolled node user=%v want %s", source.UserID, user.ID)
	}
	target := resourceTestNode(t, store, network.ID, "database", 0)
	exit := resourceTestNode(t, store, network.ID, "egress", protocol.CapabilityExitNodeV1)

	grantDecision := administratorRootDecision(t, store, administratorAccessGrantCreatePolicy, adminauth.NetworkTarget(network.ID))
	nodeGrant, _, err := store.AdministratorCreateAccessGrant(ctx, grantDecision, network.ID, AccessSubjectUser, user.ID, AccessTargetNode, &target.ID)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Managed || len(compiled.Rules) != 2 || len(compiled.AuthorizedExitNodes) != 0 {
		t.Fatalf("node-only policy=%+v", compiled)
	}
	selector := decodeAccessSelector(t, compiled.Rules[0].SelectorJSON)
	if got := selector.GetDestinationNodeIds(); len(got) != 1 || string(got[0]) != string(target.ID[:]) {
		t.Fatalf("node grant destinations=%x want %x", got, target.ID)
	}
	if prefixes := selector.GetDestinationPrefixes(); len(prefixes) == 0 || prefixes[0].GetPrefixLength() != 32 {
		t.Fatalf("node grant prefixes=%v", prefixes)
	}
	if compiled.Rules[1].Action != ACLActionDeny || compiled.Rules[1].Priority != 1 {
		t.Fatalf("missing terminal deny: %+v", compiled.Rules[1])
	}

	networkGrant, _, err := store.AdministratorCreateAccessGrant(ctx, grantDecision, network.ID, AccessSubjectTeam, team.ID, AccessTargetNetwork, nil)
	if err != nil {
		t.Fatal(err)
	}
	exitGrant, _, err := store.AdministratorCreateAccessGrant(ctx, grantDecision, network.ID, AccessSubjectUser, user.ID, AccessTargetExit, &exit.ID)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err = store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Rules) != 4 || len(compiled.AuthorizedExitNodes) != 1 || compiled.AuthorizedExitNodes[0] != exit.ID {
		t.Fatalf("combined policy=%+v", compiled)
	}
	foundDefault := false
	for _, rule := range compiled.Rules[:3] {
		candidate := decodeAccessSelector(t, rule.SelectorJSON)
		for _, prefix := range candidate.GetDestinationPrefixes() {
			if prefix.GetPrefixLength() == 0 {
				foundDefault = true
			}
		}
	}
	if !foundDefault {
		t.Fatal("explicit Exit grant did not compile the default route")
	}

	inventoryDecision := administratorRootDecision(t, store, administratorAccessInventoryPolicy, adminauth.NetworkTarget(network.ID))
	inventory, err := store.AdministratorAccessInventory(ctx, inventoryDecision, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Users) != 1 || len(inventory.Teams) != 1 || len(inventory.Memberships) != 1 || len(inventory.Grants) != 3 {
		t.Fatalf("inventory=%+v", inventory)
	}
	if inventory.Grants[0].ID != nodeGrant.ID && inventory.Grants[1].ID != nodeGrant.ID && inventory.Grants[2].ID != nodeGrant.ID {
		t.Fatalf("node grant %s missing from inventory", nodeGrant.ID)
	}

	deleteDecision := administratorRootDecision(t, store, administratorAccessGrantDeletePolicy, adminauth.ObjectTarget(exitGrant.ID))
	if _, err := store.AdministratorDeleteAccessGrant(ctx, deleteDecision, exitGrant.ID); err != nil {
		t.Fatal(err)
	}
	compiled, err = store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.AuthorizedExitNodes) != 0 {
		t.Fatalf("deleted Exit grant remains authorized: %v", compiled.AuthorizedExitNodes)
	}
	_ = networkGrant
}

func TestNamedResourcesAndServicesCompileDeterministicallyAndFailClosed(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "named-access", "10.87.0.0/24")
	user, _, err := store.AdministratorCreateAccessUser(ctx,
		administratorRootDecision(t, store, administratorAccessUserCreatePolicy, adminauth.NetworkTarget(network.ID)), network.ID, "Casey")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "casey-device", store.now().Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassDurable, UserID: &user.ID})
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.EnrollNode(ctx, token.Secret, "casey-device", 0)
	if err != nil {
		t.Fatal(err)
	}
	target := resourceTestNode(t, store, network.ID, "build-server", 0)
	connector := resourceTestNode(t, store, network.ID, "private-connector", protocol.CapabilitySubnetRouterV1)
	route, err := store.AdvertiseRoute(ctx, connector.ID, netip.MustParsePrefix("10.240.64.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRoute(ctx, route.ID); err != nil {
		t.Fatal(err)
	}

	resourceDecision := administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(network.ID))
	nodeResource, _, err := store.AdministratorCreateAccessResource(ctx, resourceDecision, network.ID, "Build server",
		AccessResourceTargetNode, &target.ID, nil, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	hostPrefix := netip.MustParsePrefix("10.240.64.6/32")
	prefixResource, _, err := store.AdministratorCreateAccessResource(ctx, resourceDecision, network.ID, "Database",
		AccessResourceTargetPrefix, nil, &route.ID, hostPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if prefixResource.RouteNodeID == nil || *prefixResource.RouteNodeID != connector.ID || prefixResource.RoutePrefix != route.Prefix {
		t.Fatalf("pinned route=%+v want node=%s prefix=%s", prefixResource, connector.ID, route.Prefix)
	}
	serviceDecision := administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(network.ID))
	service, _, err := store.AdministratorCreateAccessService(ctx, serviceDecision, network.ID, "Admin HTTPS", AccessServiceTCP,
		[]AccessPortRange{{First: 443, Last: 445}, {First: 440, Last: 442}})
	if err != nil {
		t.Fatal(err)
	}
	if len(service.Ports) != 1 || service.Ports[0] != (AccessPortRange{First: 440, Last: 445}) {
		t.Fatalf("canonical ports=%v want 440-445", service.Ports)
	}
	if _, _, err := store.AdministratorCreateAccessService(ctx, serviceDecision, network.ID, "Invalid ICMP ports", AccessServiceICMP,
		[]AccessPortRange{{First: 8, Last: 8}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ICMP ports error=%v want ErrInvalid", err)
	}
	if _, _, err := store.AdministratorCreateAccessService(ctx, serviceDecision, network.ID, "Missing TCP ports", AccessServiceTCP,
		nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing TCP ports error=%v want ErrInvalid", err)
	}
	tooManyPorts := make([]AccessPortRange, maxAccessServicePortRanges+1)
	for index := range tooManyPorts {
		port := uint16(index + 1)
		tooManyPorts[index] = AccessPortRange{First: port, Last: port}
	}
	if _, _, err := store.AdministratorCreateAccessService(ctx, serviceDecision, network.ID, "Too many ports", AccessServiceTCP,
		tooManyPorts); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many ports error=%v want ErrInvalid", err)
	}

	grantDecision := administratorRootDecision(t, store, administratorAccessResourceGrantCreatePolicy, adminauth.NetworkTarget(network.ID))
	nodeGrant, _, err := store.AdministratorCreateAccessResourceGrant(ctx, grantDecision, network.ID, AccessSubjectUser,
		user.ID, nodeResource.ID, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	prefixGrant, _, err := store.AdministratorCreateAccessResourceGrant(ctx, grantDecision, network.ID, AccessSubjectUser,
		user.ID, prefixResource.ID, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.Managed || len(compiled.Rules) != 3 {
		t.Fatalf("named policy=%+v", compiled)
	}
	selectors := make(map[identity.ID]*lanewayv1.TrafficSelector)
	for _, rule := range compiled.Rules {
		if rule.Action == ACLActionAccept {
			selectors[rule.ID] = decodeAccessSelector(t, rule.SelectorJSON)
		}
	}
	nodeSelector := selectors[nodeGrant.ID]
	if nodeSelector == nil || nodeSelector.GetIpProtocol() != lanewayv1.IpProtocol_IP_PROTOCOL_TCP ||
		len(nodeSelector.GetDestinationPorts()) != 1 || nodeSelector.GetDestinationPorts()[0].GetFirst() != 440 ||
		nodeSelector.GetDestinationPorts()[0].GetLast() != 445 || len(nodeSelector.GetDestinationNodeIds()) != 1 ||
		base64.StdEncoding.EncodeToString(nodeSelector.GetDestinationNodeIds()[0]) != base64.StdEncoding.EncodeToString(target.ID[:]) {
		t.Fatalf("node selector=%+v", nodeSelector)
	}
	prefixSelector := selectors[prefixGrant.ID]
	if prefixSelector == nil || len(prefixSelector.GetDestinationNodeIds()) != 1 ||
		string(prefixSelector.GetDestinationNodeIds()[0]) != string(connector.ID[:]) || len(prefixSelector.GetDestinationPrefixes()) != 1 ||
		prefixSelector.GetDestinationPrefixes()[0].GetPrefixLength() != 32 ||
		string(prefixSelector.GetDestinationPrefixes()[0].GetAddress()) != string(hostPrefix.Addr().AsSlice()) {
		t.Fatalf("prefix selector=%+v", prefixSelector)
	}
	inventory, err := store.AdministratorAccessInventory(ctx,
		administratorRootDecision(t, store, administratorAccessInventoryPolicy, adminauth.NetworkTarget(network.ID)), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Resources) != 2 || len(inventory.Services) != 1 || len(inventory.ResourceGrants) != 2 {
		t.Fatalf("named inventory=%+v", inventory)
	}

	disableResource := administratorRootDecision(t, store, administratorAccessResourceUpdatePolicy, adminauth.ObjectTarget(prefixResource.ID))
	if _, _, err := store.AdministratorSetAccessResourceEnabled(ctx, disableResource, prefixResource.ID, false); err != nil {
		t.Fatal(err)
	}
	compiled, err = store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil || len(compiled.Rules) != 2 || compiled.Rules[0].ID != nodeGrant.ID {
		t.Fatalf("disabled resource policy=%+v err=%v", compiled, err)
	}
	if _, _, err := store.AdministratorSetAccessResourceEnabled(ctx, disableResource, prefixResource.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WithdrawRoute(ctx, route.ID, &connector.ID); err != nil {
		t.Fatal(err)
	}
	compiled, err = store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil || len(compiled.Rules) != 2 || compiled.Rules[0].ID != nodeGrant.ID {
		t.Fatalf("withdrawn route policy=%+v err=%v", compiled, err)
	}
	disableService := administratorRootDecision(t, store, administratorAccessServiceUpdatePolicy, adminauth.ObjectTarget(service.ID))
	if _, _, err := store.AdministratorSetAccessServiceEnabled(ctx, disableService, service.ID, false); err != nil {
		t.Fatal(err)
	}
	compiled, err = store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil || len(compiled.Rules) != 1 || compiled.Rules[0].Action != ACLActionDeny {
		t.Fatalf("disabled service policy=%+v err=%v", compiled, err)
	}
	var audits int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action IN
		('access_resource.create','access_service.create','access_resource_grant.create','access_resource.update','access_service.update')`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 8 {
		t.Fatalf("named access audits=%d want 8", audits)
	}
}

func TestNamedServicePortSelectionRejectsTamperingAndMissingRows(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "sealed-service", "10.88.0.0/24")
	user, _, err := store.AdministratorCreateAccessUser(ctx,
		administratorRootDecision(t, store, administratorAccessUserCreatePolicy, adminauth.NetworkTarget(network.ID)), network.ID, "Jordan")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "jordan-device", store.now().Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassDurable, UserID: &user.ID})
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.EnrollNode(ctx, token.Secret, "jordan-device", 0)
	if err != nil {
		t.Fatal(err)
	}
	target := resourceTestNode(t, store, network.ID, "sealed-target", 0)
	resource, _, err := store.AdministratorCreateAccessResource(ctx,
		administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Sealed target", AccessResourceTargetNode, &target.ID, nil, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := store.AdministratorCreateAccessService(ctx,
		administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "HTTPS", AccessServiceTCP, []AccessPortRange{{First: 443, Last: 443}})
	if err != nil {
		t.Fatal(err)
	}
	temporaryService, _, err := store.AdministratorCreateAccessService(ctx,
		administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Temporary DNS", AccessServiceUDP, []AccessPortRange{{First: 53, Last: 53}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM access_services WHERE id=?`, idBytes(temporaryService.ID)); err != nil {
		t.Fatalf("parent service cascade could not remove sealed ports: %v", err)
	}
	if _, _, err := store.AdministratorCreateAccessResourceGrant(ctx,
		administratorRootDecision(t, store, administratorAccessResourceGrantCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, AccessSubjectUser, user.ID, resource.ID, service.ID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		statement string
	}{
		{name: "insert", statement: `INSERT INTO access_service_ports(service_id,first_port,last_port) VALUES(?,444,444)`},
		{name: "update", statement: `UPDATE access_service_ports SET last_port=444 WHERE service_id=?`},
		{name: "delete", statement: `DELETE FROM access_service_ports WHERE service_id=?`},
		{name: "unseal", statement: `UPDATE access_services SET ports_sealed=0 WHERE id=?`},
	} {
		if _, err := store.db.ExecContext(ctx, test.statement, idBytes(service.ID)); err == nil {
			t.Fatalf("sealed service port %s tamper succeeded", test.name)
		}
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER access_service_ports_immutable_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM access_service_ports WHERE service_id=?`, idBytes(service.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID); err == nil ||
		!strings.Contains(err.Error(), "corrupt named service ports") {
		t.Fatalf("missing service ports error=%v", err)
	}
}

func TestNamedPrefixResourcePinsRouteTargetAgainstRetargeting(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	network := resourceTestNetwork(t, store, "pinned-route", "10.89.0.0/24")
	user, _, err := store.AdministratorCreateAccessUser(ctx,
		administratorRootDecision(t, store, administratorAccessUserCreatePolicy, adminauth.NetworkTarget(network.ID)), network.ID, "Riley")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.IssueEnrollmentTokenWithOptions(ctx, network.ID, "riley-device", store.now().Add(time.Hour),
		EnrollmentTokenOptions{Class: EnrollmentClassDurable, UserID: &user.ID})
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.EnrollNode(ctx, token.Secret, "riley-device", 0)
	if err != nil {
		t.Fatal(err)
	}
	firstConnector := resourceTestNode(t, store, network.ID, "first-connector", protocol.CapabilitySubnetRouterV1)
	secondConnector := resourceTestNode(t, store, network.ID, "second-connector", protocol.CapabilitySubnetRouterV1)
	route, err := store.AdvertiseRoute(ctx, firstConnector.ID, netip.MustParsePrefix("10.241.0.0/24"), RouteKindSubnet, RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRoute(ctx, route.ID); err != nil {
		t.Fatal(err)
	}
	resource, _, err := store.AdministratorCreateAccessResource(ctx,
		administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Pinned database", AccessResourceTargetPrefix, nil, &route.ID, netip.MustParsePrefix("10.241.0.8/32"))
	if err != nil {
		t.Fatal(err)
	}
	service, _, err := store.AdministratorCreateAccessService(ctx,
		administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, "Postgres", AccessServiceTCP, []AccessPortRange{{First: 5432, Last: 5432}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AdministratorCreateAccessResourceGrant(ctx,
		administratorRootDecision(t, store, administratorAccessResourceGrantCreatePolicy, adminauth.NetworkTarget(network.ID)),
		network.ID, AccessSubjectUser, user.ID, resource.ID, service.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE routes SET node_id=? WHERE id=?`, idBytes(secondConnector.ID), idBytes(route.ID)); err == nil {
		t.Fatal("sealed route target was mutable")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER routes_identity_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE routes SET node_id=? WHERE id=?`, idBytes(secondConnector.ID), idBytes(route.ID)); err != nil {
		t.Fatal(err)
	}
	compiled, err := store.ManagedAccessPolicyForNode(ctx, network.ID, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Rules) != 1 || compiled.Rules[0].Action != ACLActionDeny {
		t.Fatalf("retargeted route broadened policy: %+v", compiled)
	}
}

func TestManagedAccessRejectsCrossNetworkAndNonExitTargets(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	first := resourceTestNetwork(t, store, "first-access", "10.85.0.0/24")
	second := resourceTestNetwork(t, store, "second-access", "10.86.0.0/24")
	user, _, err := store.AdministratorCreateAccessUser(ctx,
		administratorRootDecision(t, store, administratorAccessUserCreatePolicy, adminauth.NetworkTarget(first.ID)), first.ID, "Taylor")
	if err != nil {
		t.Fatal(err)
	}
	foreignNode := resourceTestNode(t, store, second.ID, "foreign", 0)
	decision := administratorRootDecision(t, store, administratorAccessGrantCreatePolicy, adminauth.NetworkTarget(first.ID))
	if _, _, err := store.AdministratorCreateAccessGrant(ctx, decision, first.ID, AccessSubjectUser, user.ID, AccessTargetNode, &foreignNode.ID); err == nil {
		t.Fatal("cross-network node grant accepted")
	}
	resourceDecision := administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(first.ID))
	if _, _, err := store.AdministratorCreateAccessResource(ctx, resourceDecision, first.ID, "Foreign node",
		AccessResourceTargetNode, &foreignNode.ID, nil, netip.Prefix{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-network named resource error=%v want ErrNotFound", err)
	}
	foreignResource, _, err := store.AdministratorCreateAccessResource(ctx,
		administratorRootDecision(t, store, administratorAccessResourceCreatePolicy, adminauth.NetworkTarget(second.ID)),
		second.ID, "Foreign resource", AccessResourceTargetNode, &foreignNode.ID, nil, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	foreignService, _, err := store.AdministratorCreateAccessService(ctx,
		administratorRootDecision(t, store, administratorAccessServiceCreatePolicy, adminauth.NetworkTarget(second.ID)),
		second.ID, "Foreign service", AccessServiceTCP, []AccessPortRange{{First: 443, Last: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AdministratorCreateAccessResourceGrant(ctx,
		administratorRootDecision(t, store, administratorAccessResourceGrantCreatePolicy, adminauth.NetworkTarget(first.ID)),
		first.ID, AccessSubjectUser, user.ID, foreignResource.ID, foreignService.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-network named grant error=%v want ErrNotFound", err)
	}
	ordinary := resourceTestNode(t, store, first.ID, "ordinary", 0)
	if _, _, err := store.AdministratorCreateAccessGrant(ctx, decision, first.ID, AccessSubjectUser, user.ID, AccessTargetExit, &ordinary.ID); err == nil {
		t.Fatal("Exit grant without approved Exit route accepted")
	}
}

func decodeAccessSelector(t *testing.T, raw string) *lanewayv1.TrafficSelector {
	t.Helper()
	selector := new(lanewayv1.TrafficSelector)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal([]byte(raw), selector); err != nil {
		t.Fatalf("decode selector %s: %v", raw, err)
	}
	return selector
}
