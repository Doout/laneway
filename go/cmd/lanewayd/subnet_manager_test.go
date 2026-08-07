package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
	"laneway.dev/laneway/internal/subnet"
)

func TestDaemonSubnetManagerReconcilesApprovedSelfOwnedRoutes(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	remote := identity.NodeID(testID(3))
	forwarding := subnet.NewMemoryForwardingManager()
	var relayPrefixes, directPrefixes []netip.Prefix
	manager := &daemonSubnetManager{
		forwarding:           forwarding,
		fixedForwardPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		setRelayPrefixes: func(prefixes []netip.Prefix) error {
			relayPrefixes = append([]netip.Prefix(nil), prefixes...)
			return nil
		},
		setDirectPrefixes: func(prefixes []netip.Prefix) error {
			directPrefixes = append([]netip.Prefix(nil), prefixes...)
			return nil
		},
	}
	configuration := &lanewayv1.NodeConfiguration{EnabledCapabilities: uint64(protocol.CapabilitySubnetRouterV1), Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
		subnetRoute(local.NodeID, "192.168.50.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT),
		subnetRoute(local.NodeID, "10.20.0.0/16", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_ROUTED),
		subnetRoute(remote, "172.16.0.0/16", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT),
	}}}
	if err := manager.Apply(context.Background(), configuration, local); err != nil {
		t.Fatal(err)
	}
	plan, active := forwarding.Snapshot()
	if !active || len(plan.Routes) != 2 || plan.Mode != "" {
		t.Fatalf("forwarding plan = %+v, active=%t", plan, active)
	}
	wantPrefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.168.50.0/24"),
		netip.MustParsePrefix("10.20.0.0/16"),
	}
	if !slices.Equal(relayPrefixes, wantPrefixes) || !slices.Equal(directPrefixes, wantPrefixes) {
		t.Fatalf("relay=%v direct=%v, want %v", relayPrefixes, directPrefixes, wantPrefixes)
	}

	// A withdrawal is represented by the route disappearing from the next
	// complete snapshot and must restore host forwarding immediately.
	if err := manager.Apply(context.Background(), &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{}}, local); err != nil {
		t.Fatal(err)
	}
	if _, active := forwarding.Snapshot(); active {
		t.Fatal("withdrawn subnet routes left forwarding active")
	}
	wantPrefixes = wantPrefixes[:1]
	if !slices.Equal(relayPrefixes, wantPrefixes) || !slices.Equal(directPrefixes, wantPrefixes) {
		t.Fatalf("withdrawal relay=%v direct=%v, want %v", relayPrefixes, directPrefixes, wantPrefixes)
	}
}

func TestApprovedLocalSubnetRoutesRejectsMissingMode(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
		subnetRoute(local.NodeID, "192.168.50.0/24", lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_UNSPECIFIED),
	}}}
	if _, err := approvedLocalSubnetRoutes(configuration, local); err == nil {
		t.Fatal("self-owned subnet route without NAT/routed mode was accepted")
	}
}

func TestExitForwardPrefixRequiresApprovedSelfOwnedGatewayRoute(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	remote := identity.NodeID(testID(3))
	var prefixes []netip.Prefix
	manager := &daemonSubnetManager{serveExit: true, setRelayPrefixes: func(values []netip.Prefix) error {
		prefixes = append([]netip.Prefix(nil), values...)
		return nil
	}}
	remoteOnly := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{exitRoute(remote)}}}
	if err := manager.Apply(context.Background(), remoteOnly, local); err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("remote exit authorized local forwarding: %v", prefixes)
	}
	approved := &lanewayv1.NodeConfiguration{EnabledCapabilities: uint64(protocol.CapabilityExitNodeV1), Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{exitRoute(local.NodeID)}}}
	if err := manager.Apply(context.Background(), approved, local); err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("exit authorized before gateway activation: %v", prefixes)
	}
	if err := manager.PublishApprovedForwardPrefixes(approved, local); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prefixes, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}) {
		t.Fatalf("approved exit prefixes=%v", prefixes)
	}
	if required, err := manager.RequiresIPForwarding(approved, local); err != nil || !required {
		t.Fatalf("requires forwarding=%t err=%v", required, err)
	}
	if err := manager.Apply(context.Background(), &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{}}, local); err != nil {
		t.Fatal(err)
	}
	if err := manager.PublishApprovedForwardPrefixes(&lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{}}, local); err != nil {
		t.Fatal(err)
	}
	if len(prefixes) != 0 {
		t.Fatalf("withdrawn exit retained forwarding authorization: %v", prefixes)
	}
}

func subnetRoute(owner identity.NodeID, prefixText string, mode lanewayv1.RouteAdvertisementMode) *lanewayv1.Route {
	prefix := netip.MustParsePrefix(prefixText)
	routeID := testID(12)
	return &lanewayv1.Route{
		RouteId:     append([]byte(nil), routeID[:]...),
		Destination: &lanewayv1.IpPrefix{Address: prefix.Addr().AsSlice(), PrefixLength: uint32(prefix.Bits())},
		ViaNodeId:   append([]byte(nil), owner[:]...), Kind: lanewayv1.RouteKind_ROUTE_KIND_SUBNET, Mode: mode,
	}
}

func exitRoute(owner identity.NodeID) *lanewayv1.Route {
	routeID := testID(13)
	return &lanewayv1.Route{
		RouteId:     append([]byte(nil), routeID[:]...),
		Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0},
		ViaNodeId:   append([]byte(nil), owner[:]...), Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT,
		Mode: lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT,
	}
}
