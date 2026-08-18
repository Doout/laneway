package controller

import (
	"context"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/adminauth"
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
