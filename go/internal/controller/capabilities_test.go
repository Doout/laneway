package controller

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/protocol"
)

func TestNodePolicyCapabilitiesGateAdvertisementAndApproval(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "10.48.0.0/24")
	invalidToken := issueToken(t, store, network.ID, "invalid-capability")
	if _, err := store.EnrollNode(context.Background(), invalidToken.Secret, "invalid-capability", uint64(protocol.CapabilityRelayV1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-policy enrollment capability error = %v", err)
	}
	node, err := store.EnrollNode(context.Background(), issueToken(t, store, network.ID, "gateway").Secret, "gateway", 0)
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("192.168.48.0/24")
	if _, err := store.AdvertiseRoute(context.Background(), node.ID, prefix, RouteKindSubnet, RouteModeNAT, 0, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unauthorized advertisement error = %v", err)
	}
	epoch, err := store.SetNodeCapabilities(context.Background(), node.ID, protocol.CapabilitySubnetRouterV1)
	if err != nil || epoch <= network.ConfigurationEpoch {
		t.Fatalf("SetNodeCapabilities epoch=%d error=%v", epoch, err)
	}
	route, err := store.AdvertiseRoute(context.Background(), node.ID, prefix, RouteKindSubnet, RouteModeNAT, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix("0.0.0.0/0"), RouteKindExit, RouteModeNAT, 0, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unauthorized exit advertisement error = %v", err)
	}
	if _, err := store.SetNodeCapabilities(context.Background(), node.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRoute(context.Background(), route.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval after capability removal error = %v", err)
	}
	if _, err := store.SetNodeCapabilities(context.Background(), node.ID, protocol.CapabilityE2EPacketV1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved capability error = %v", err)
	}

	// A no-op replacement returns the current epoch without creating churn.
	before, err := store.Network(context.Background(), network.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.SetNodeCapabilities(context.Background(), node.ID, 0)
	if err != nil || got != before.ConfigurationEpoch {
		t.Fatalf("no-op epoch=%d want=%d error=%v", got, before.ConfigurationEpoch, err)
	}
}

func TestExitCapabilityBoundInviteCreatesApprovedDefault(t *testing.T) {
	store, _ := openTestStore(t)
	network := createTestNetwork(t, store, "10.51.0.0/24")
	token, err := store.IssueEnrollmentTokenWithOptions(context.Background(), network.ID, "docker-exit", time.Now().Add(time.Hour), EnrollmentTokenOptions{
		Class: EnrollmentClassEphemeral, SessionLifetime: MinEphemeralLifetime, RequestedName: "docker-exit",
		EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1),
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.EnrollNode(context.Background(), token.Secret, "docker-exit", 0)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.Capability(node.EnabledCapabilities) != protocol.CapabilityExitNodeV1 {
		t.Fatalf("capabilities=%d", node.EnabledCapabilities)
	}
	routes, err := store.NetworkRoutes(context.Background(), network.ID, 10)
	if err != nil || len(routes) != 1 {
		t.Fatalf("routes=%+v error=%v", routes, err)
	}
	route := routes[0]
	if route.NodeID != node.ID || route.Prefix.String() != "0.0.0.0/0" || route.Kind != RouteKindExit || route.Mode != RouteModeNAT || route.State != RouteStateApproved || route.ValidUntil == nil || !route.ValidUntil.Equal(*node.LeaseExpiresAt) {
		t.Fatalf("invited exit route=%+v node=%+v", route, node)
	}
}

func TestControllerRejectsSpecialUsePoolsAndAdvertisements(t *testing.T) {
	store, _ := openTestStore(t)
	for _, pool := range []string{"127.0.0.0/24", "169.254.0.0/24", "224.0.0.0/24"} {
		if _, err := store.CreateNetwork(context.Background(), "bad-"+pool, netip.MustParsePrefix(pool)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("pool %s error = %v", pool, err)
		}
	}
	if _, err := store.CreateNetworkDualStack(context.Background(), "bad-v6", netip.MustParsePrefix("10.49.0.0/24"), netip.MustParsePrefix("fe80::/64")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("link-local IPv6 pool error = %v", err)
	}
	network := createTestNetwork(t, store, "10.50.0.0/24")
	node, err := store.EnrollNode(context.Background(), issueToken(t, store, network.ID, "special").Secret, "special", uint64(protocol.CapabilitySubnetRouterV1))
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "fe80::/64", "ff00::/8"} {
		if _, err := store.AdvertiseRoute(context.Background(), node.ID, netip.MustParsePrefix(prefix), RouteKindSubnet, RouteModeRouted, 0, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("prefix %s error = %v", prefix, err)
		}
	}
}
