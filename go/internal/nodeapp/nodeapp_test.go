package nodeapp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/exitnode"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodeservice"
	"github.com/Doout/laneway/go/internal/pathmanager"
	"github.com/Doout/laneway/go/internal/platform"
	"github.com/Doout/laneway/go/internal/policy"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/Doout/laneway/go/internal/routing"
	"github.com/Doout/laneway/go/internal/wireguard"
	"google.golang.org/protobuf/proto"
)

func TestControllerPacketPolicyAllowsOnlyAuthorizedBidirectionalTraffic(t *testing.T) {
	network, client, connector := testID(1), identity.NodeID(testID(2)), identity.NodeID(testID(3))
	acceptID, denyID := testID(4), testID(5)
	engine, err := policy.Compile(&lanewayv1.PolicySnapshot{
		NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{{
			RuleId: acceptID[:], Priority: 100, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
			Selector: &lanewayv1.TrafficSelector{
				SourceNodeIds:       [][]byte{client[:]},
				DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: []byte{10, 240, 64, 6}, PrefixLength: 32}},
				IpProtocol:          lanewayv1.IpProtocol_IP_PROTOCOL_TCP,
				DestinationPorts:    []*lanewayv1.PortRange{{First: 22, Last: 22}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var table policy.Table
	if err := table.Replace(engine); err != nil {
		t.Fatal(err)
	}
	packet, err := nodeservice.IPv4Packet(netip.MustParseAddr("10.240.64.6"), netip.MustParseAddr("100.96.0.2"), make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	packet[9] = 6
	binary.BigEndian.PutUint16(packet[20:22], 22)
	binary.BigEndian.PutUint16(packet[22:24], 49152)
	if !controllerPacketAllowed(&table, connector, client, packet) {
		t.Fatal("endpoint denied an authorized TCP reply")
	}

	engine, err = policy.Compile(&lanewayv1.PolicySnapshot{
		NetworkId: network[:], DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
		Rules: []*lanewayv1.PolicyRule{
			{RuleId: denyID[:], Priority: 50, Action: lanewayv1.PolicyAction_POLICY_ACTION_DENY, Selector: &lanewayv1.TrafficSelector{
				SourceNodeIds: [][]byte{connector[:]}, DestinationNodeIds: [][]byte{client[:]}, IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY,
			}},
			{RuleId: acceptID[:], Priority: 100, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT, Selector: &lanewayv1.TrafficSelector{
				SourceNodeIds: [][]byte{client[:]}, DestinationPrefixes: []*lanewayv1.IpPrefix{{Address: []byte{10, 240, 64, 6}, PrefixLength: 32}}, IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := table.Replace(engine); err != nil {
		t.Fatal(err)
	}
	if controllerPacketAllowed(&table, connector, client, packet) {
		t.Fatal("endpoint return handling overrode an explicit deny")
	}
}

type diagnosticsPath struct{ name string }

func (p diagnosticsPath) Name() string                    { return p.name }
func (diagnosticsPath) MaxPayload(pathmanager.PeerID) int { return 1200 }
func (diagnosticsPath) Send(context.Context, pathmanager.PeerID, pathmanager.PacketBuffer) error {
	return nil
}
func (diagnosticsPath) Receive(context.Context) (pathmanager.ReceivedPacket, error) {
	return pathmanager.ReceivedPacket{}, context.Canceled
}
func (diagnosticsPath) Health(pathmanager.PeerID) pathmanager.PathHealth {
	return pathmanager.PathHealth{State: pathmanager.HealthHealthy}
}
func (diagnosticsPath) Close() error { return nil }

func TestPathManagerDiagnosticsExposeAutomaticFailover(t *testing.T) {
	manager := pathmanager.MustNew(pathmanager.Config{})
	peer := identity.NodeID(testID(9))
	if err := manager.SetPaths(peer, []pathmanager.Candidate{
		{Kind: pathmanager.PathDirect, Path: diagnosticsPath{name: "direct"}},
		{Kind: pathmanager.PathRelayQUIC, Path: diagnosticsPath{name: "relay-quic"}},
	}); err != nil {
		t.Fatal(err)
	}
	if got := peerPathState(peer, manager, nil); got != "direct" {
		t.Fatalf("initial peer path = %q, want direct", got)
	}
	manager.Observe(peer, pathmanager.PathSample{Path: "direct", HardFailure: true, Reason: "probe timeout"})
	if got := peerPathState(peer, manager, nil); got != "relay-quic" {
		t.Fatalf("failed-over peer path = %q, want relay-quic", got)
	}
	values := map[string]uint64{}
	addPathManagerDiagnostics(values, manager)
	for name, want := range map[string]uint64{
		"path_observations_total": 1, "path_failures_total": 1,
		"path_direct_failures_total": 1, "path_switches_total": 1, "path_peers": 1,
	} {
		if got := values[name]; got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

func TestWireGuardCarrierStatusOverridesRelaySessionStatus(t *testing.T) {
	peer := identity.NodeID(testID(10))
	secure := &fakeNodeWireGuard{carrier: "direct-wireguard", summary: "mixed"}
	if got := peerPathState(peer, nil, nil, secure); got != "direct-wireguard" {
		t.Fatalf("peer carrier=%q", got)
	}
	if got := foregroundPath(identity.NodeID(testID(11)), nil, nil, nil, secure); got != "mixed" {
		t.Fatalf("foreground carrier=%q", got)
	}
}

func TestWireGuardDiagnosticsExposeCarrierFailoverWithoutLabels(t *testing.T) {
	secure := &fakeNodeWireGuard{
		relayMetrics: wireguard.RelayEndpointMetrics{
			PacketsSent: 1, PacketsReceived: 2, PacketsDropped: 3, UnknownSources: 4, UnauthorizedPeers: 5,
		},
		carrierMetrics: wireguard.CarrierMuxMetrics{
			PacketsSent: 6, PacketsReceived: 7, PacketsDropped: 8, PathFailures: 9, PathSwitchRetries: 10,
		},
		carrierPathMetrics: pathmanager.Metrics{Observations: 11, DirectFailures: 12, Switches: 13, Peers: 14},
	}
	values := map[string]uint64{}
	addWireGuardDiagnostics(values, secure)
	for name, want := range map[string]uint64{
		"wireguard_packets_sent_total": 1, "wireguard_packets_received_total": 2,
		"wireguard_packets_dropped_total": 3, "wireguard_unknown_sources_total": 4,
		"wireguard_unauthorized_peers_total": 5, "wireguard_carrier_packets_sent_total": 6,
		"wireguard_carrier_packets_received_total": 7, "wireguard_carrier_packets_dropped_total": 8,
		"wireguard_carrier_path_failures_total": 9, "wireguard_carrier_path_switch_retries_total": 10,
		"wireguard_carrier_observations_total": 11, "wireguard_carrier_direct_failures_total": 12,
		"wireguard_carrier_switches_total": 13, "wireguard_carrier_peers": 14,
	} {
		if got := values[name]; got != want {
			t.Errorf("%s=%d, want %d", name, got, want)
		}
	}
	for name := range values {
		if strings.Contains(name, "peer") && name != "wireguard_carrier_peers" && name != "wireguard_unauthorized_peers_total" {
			t.Fatalf("identity-derived metric name=%q", name)
		}
	}
}

func TestBuildRoutes(t *testing.T) {
	local := identity.NodeIdentity{
		NetworkID: identity.NetworkID(testID(1)),
		NodeID:    identity.NodeID(testID(2)),
	}
	peerID := identity.NodeID(testID(3))
	table, osRoutes, err := buildRoutes(local, []config.AuthorizedPeer{{
		NetworkID: local.NetworkID.String(), NodeID: peerID.String(), Prefixes: []string{"100.96.0.3/32"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	route, ok := table.Lookup(netip.MustParseAddr("100.96.0.3"))
	if !ok || route.NextHop != peerID || len(osRoutes) != 1 {
		t.Fatalf("route lookup = %#v, %v; OS routes %#v", route, ok, osRoutes)
	}
}

func TestNonCancellationErrorPreservesCleanupFailure(t *testing.T) {
	cleanup := errors.New("cleanup failed")
	if err := nonCancellationError(context.Canceled); err != nil {
		t.Fatalf("bare cancellation = %v", err)
	}
	if err := nonCancellationError(errors.Join(context.Canceled, cleanup)); !errors.Is(err, cleanup) || errors.Is(err, context.Canceled) {
		t.Fatalf("filtered joined error = %v", err)
	}
}

func TestBuildSubnetRoute(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peerID := identity.NodeID(testID(3))
	table, osRoutes, err := buildRoutes(local, []config.AuthorizedPeer{{
		NetworkID: local.NetworkID.String(), NodeID: peerID.String(), Prefixes: []string{"192.168.50.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("192.168.50.15")); !ok || route.NextHop != peerID || osRoutes[0].Prefix.Bits() != 24 {
		t.Fatalf("subnet route missing: %#v, %v, %#v", route, ok, osRoutes)
	}
}

func TestTUNPacketAdapter(t *testing.T) {
	tun, err := platform.NewMemoryTUN(platform.TUNConfig{Name: "lane0", MTU: 1200}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	adapter := tunPacketIO{tun}
	packet := []byte{1, 2, 3}
	if err := tun.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, err := adapter.ReadPacket(context.Background(), buffer)
	if err != nil || string(buffer[:n]) != string(packet) {
		t.Fatalf("ReadPacket = %x, %v", buffer[:n], err)
	}
	if err := adapter.WritePacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	received, err := tun.Receive(context.Background())
	if err != nil || string(received) != string(packet) {
		t.Fatalf("Receive = %x, %v", received, err)
	}
}

func TestOverlayAddressValidation(t *testing.T) {
	if _, err := overlayAddresses([]string{"100.96.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	if addresses, err := overlayAddresses([]string{"2001:db8::1/128"}); err != nil || len(addresses) != 1 {
		t.Fatalf("IPv6 overlay addresses = %v, %v", addresses, err)
	}
	if _, err := overlayAddresses([]string{"100.96.0.1/24"}); err == nil {
		t.Fatal("noncanonical address accepted")
	}
}

func TestBuildIPv6Routes(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peerID := identity.NodeID(testID(3))
	table, osRoutes, err := buildRoutes(local, []config.AuthorizedPeer{{
		NetworkID: local.NetworkID.String(), NodeID: peerID.String(), Prefixes: []string{"2001:db8:1::/64"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("2001:db8:1::20")); !ok || route.NextHop != peerID || len(osRoutes) != 1 {
		t.Fatalf("IPv6 route lookup = %#v, %v; OS routes %#v", route, ok, osRoutes)
	}
}

func TestDirectCandidatePolicyFromConfig(t *testing.T) {
	policy := directCandidatePolicy(config.Direct{MaxCandidates: 4, AllowLoopback: true, AllowLinkLocal: true})
	if policy.MaxCandidates != 4 || !policy.AllowLoopback || !policy.AllowLinkLocal {
		t.Fatalf("direct policy = %#v", policy)
	}
}

func TestExitTransportBypassesTrackControllerRelayReplacement(t *testing.T) {
	static := netip.MustParseAddr("192.0.2.1")
	first := netip.MustParseAddr("192.0.2.2")
	second := netip.MustParseAddr("192.0.2.3")
	manager := &daemonExitManagers{staticBypass: []netip.Addr{static}, bypass: []netip.Addr{static}}
	if err := manager.SetControllerRelayEndpoints(context.Background(), []netip.Addr{first}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetControllerRelayEndpoints(context.Background(), []netip.Addr{second}); err != nil {
		t.Fatal(err)
	}
	if want := []netip.Addr{static, second}; !slices.Equal(manager.bypass, want) {
		t.Fatalf("exit transport bypasses = %v, want %v", manager.bypass, want)
	}
}

func TestApplyControllerConfiguration(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	routeID := testID(4)
	ruleID := testID(5)
	configuration := &lanewayv1.NodeConfiguration{
		ConfigurationEpoch: 2,
		Peers: []*lanewayv1.NodePeer{
			{NodeId: local.NodeID[:], Name: "local"},
			{NodeId: peer[:], Name: "peer", OverlayAddresses: [][]byte{{100, 96, 0, 3}}},
		},
		Routes: &lanewayv1.RouteSnapshot{
			NetworkId: local.NetworkID[:], ConfigurationEpoch: 2,
			Routes: []*lanewayv1.Route{{
				RouteId:     routeID[:],
				Destination: &lanewayv1.IpPrefix{Address: []byte{100, 96, 0, 3}, PrefixLength: 32},
				ViaNodeId:   peer[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY,
			}},
		},
		Policy: &lanewayv1.PolicySnapshot{
			NetworkId: local.NetworkID[:], ConfigurationEpoch: 2,
			DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
			Rules: []*lanewayv1.PolicyRule{{
				RuleId: ruleID[:], Priority: 1, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
				Selector: &lanewayv1.TrafficSelector{IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY},
			}},
		},
	}
	table := routing.NewTable(nil)
	routeManager := platform.NewMemoryRouteManager()
	policyTable := new(policy.Table)
	if err := applyControllerConfiguration(context.Background(), configuration, local, table, routeManager,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, policyTable, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); !ok || route.NextHop != peer {
		t.Fatalf("dynamic route = %#v, %t", route, ok)
	}
	if len(routeManager.Routes()) != 1 {
		t.Fatalf("OS routes = %#v", routeManager.Routes())
	}
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3] = 0x45, 0, 20
	copy(packet[12:16], []byte{100, 96, 0, 2})
	copy(packet[16:20], []byte{100, 96, 0, 3})
	if result := policyTable.Evaluate(local.NodeID, peer, packet); result.Action != policy.Accept {
		t.Fatalf("policy result = %#v", result)
	}
	configuration.Policy.DefaultAction = lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT
	if err := applyControllerConfiguration(context.Background(), configuration, local, routing.NewTable(nil),
		platform.NewMemoryRouteManager(), nil, new(policy.Table), nil, nil, nil); err == nil {
		t.Fatal("controller policy with a permissive default was accepted")
	}
}

func TestApplyControllerConfigurationRejectsForeignNetwork(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	foreign := identity.NetworkID(testID(9))
	configuration := &lanewayv1.NodeConfiguration{
		ConfigurationEpoch: 1,
		Routes:             &lanewayv1.RouteSnapshot{NetworkId: foreign[:], ConfigurationEpoch: 1},
		Policy:             &lanewayv1.PolicySnapshot{NetworkId: foreign[:], ConfigurationEpoch: 1, DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY},
	}
	if err := applyControllerConfiguration(context.Background(), configuration, local, routing.NewTable(nil),
		platform.NewMemoryRouteManager(), nil, new(policy.Table), nil, nil, nil); err == nil {
		t.Fatal("foreign network configuration accepted")
	}
}

func TestApplyControllerConfigurationDeduplicatesBackupOSRoutes(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	preferred := identity.NodeID(testID(3))
	backup := identity.NodeID(testID(4))
	configuration := controllerTestConfiguration(local, preferred, uint64(time.Now().Unix()+60))
	configuration.Peers = append(configuration.Peers,
		&lanewayv1.NodePeer{NodeId: backup[:], Name: "backup", OverlayAddresses: [][]byte{{100, 96, 0, 4}}})
	prefix := &lanewayv1.IpPrefix{Address: []byte{192, 0, 2, 0}, PrefixLength: 24}
	preferredRouteID, backupRouteID := testID(20), testID(21)
	configuration.Routes.Routes = append(configuration.Routes.Routes,
		&lanewayv1.Route{RouteId: preferredRouteID[:], Destination: prefix, ViaNodeId: preferred[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_SUBNET, Metric: 10,
			Mode: lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT},
		&lanewayv1.Route{RouteId: backupRouteID[:], Destination: prefix, ViaNodeId: backup[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_SUBNET, Metric: 20,
			Mode: lanewayv1.RouteAdvertisementMode_ROUTE_ADVERTISEMENT_MODE_NAT})
	table := routing.NewTable(nil)
	routeManager := platform.NewMemoryRouteManager()
	if err := applyControllerConfiguration(context.Background(), configuration, local, table, routeManager,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, new(policy.Table), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if route, ok := table.Lookup(netip.MustParseAddr("192.0.2.10")); !ok || route.NextHop != preferred {
		t.Fatalf("backup route selection = %#v, %t", route, ok)
	}
	if got := len(routeManager.Routes()); got != 2 {
		t.Fatalf("OS route count=%d want overlay + one deduplicated subnet", got)
	}
}

func TestControllerOverlayAddressesRequiresAuthoritativeHostRouteAndLease(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	configuration := controllerTestConfiguration(local, identity.NodeID(testID(3)), uint64(time.Now().Unix()+60))
	addresses, err := controllerOverlayAddresses(configuration, local, time.Now())
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParsePrefix("100.96.0.2/32") {
		t.Fatalf("controller addresses = %#v, %v", addresses, err)
	}
	configuration.ValidUntilUnixSeconds = uint64(time.Now().Unix() - 1)
	if _, err := controllerOverlayAddresses(configuration, local, time.Now()); err == nil {
		t.Fatal("expired controller assignment accepted")
	}
	configuration.ValidUntilUnixSeconds = uint64(time.Now().Unix() + 60)
	wrongOwner := identity.NodeID(testID(9))
	configuration.Routes.Routes[0].ViaNodeId = wrongOwner[:]
	if _, err := controllerOverlayAddresses(configuration, local, time.Now()); err == nil {
		t.Fatal("overlay assignment without a self-owned host route accepted")
	}
}

func TestControllerOverlayAddressesEnforcesEphemeralIdentityLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	configuration := controllerTestConfiguration(local, identity.NodeID(testID(3)), uint64(now.Add(time.Minute).Unix()))
	configuration.EnrollmentClass = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
	configuration.IdentityLeaseExpiresAtUnixSeconds = uint64(now.Add(2 * time.Minute).Unix())
	if _, err := controllerOverlayAddresses(configuration, local, now); err != nil {
		t.Fatal(err)
	}
	configuration.ValidUntilUnixSeconds = uint64(now.Add(3 * time.Minute).Unix())
	if _, err := controllerOverlayAddresses(configuration, local, now); err == nil {
		t.Fatal("snapshot extending beyond ephemeral lease accepted")
	}
	configuration.ValidUntilUnixSeconds = uint64(now.Add(time.Minute).Unix())
	configuration.IdentityLeaseExpiresAtUnixSeconds = uint64(now.Unix())
	if _, err := controllerOverlayAddresses(configuration, local, now); err == nil {
		t.Fatal("expired ephemeral identity lease accepted")
	}
	configuration.EnrollmentClass = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
	if _, err := controllerOverlayAddresses(configuration, local, now); err == nil {
		t.Fatal("durable identity with ephemeral lease accepted")
	}
}

func TestEphemeralExitConfigurationRequiresExactLeaseWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	configuration := &lanewayv1.NodeConfiguration{
		EnrollmentClass:                   lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER,
		EnabledCapabilities:               uint64(protocol.CapabilityExitNodeV1),
		IdentityLeaseExpiresAtUnixSeconds: uint64(now.Add(time.Hour).Unix()),
		ValidUntilUnixSeconds:             uint64(now.Add(20 * time.Second).Unix()),
		EphemeralExitLeaseGeneration:      7,
		EphemeralExitSuspectAtUnixSeconds: uint64(now.Add(20 * time.Second).Unix()),
		EphemeralExitRevokeAtUnixSeconds:  uint64(now.Add(60 * time.Second).Unix()),
	}
	if err := validateConfigurationIdentityLease(configuration, now); err != nil {
		t.Fatalf("valid ephemeral Exit lease rejected: %v", err)
	}
	configuration.EphemeralExitRevokeAtUnixSeconds--
	if err := validateConfigurationIdentityLease(configuration, now); err == nil {
		t.Fatal("noncanonical revoke window accepted")
	}
	configuration.EphemeralExitRevokeAtUnixSeconds++
	configuration.ValidUntilUnixSeconds++
	if err := validateConfigurationIdentityLease(configuration, now); err == nil {
		t.Fatal("snapshot beyond suspect boundary accepted")
	}
}

func TestEphemeralExitLeaseRenewalRequiresStableSnapshot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	previous := controllerTestConfiguration(local, peer, uint64(now.Add(20*time.Second).Unix()))
	previous.EnrollmentClass = lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
	previous.EnabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
	previous.IdentityLeaseExpiresAtUnixSeconds = uint64(now.Add(time.Hour).Unix())
	previous.EphemeralExitLeaseGeneration = 7
	previous.EphemeralExitSuspectAtUnixSeconds = uint64(now.Add(20 * time.Second).Unix())
	previous.EphemeralExitRevokeAtUnixSeconds = uint64(now.Add(60 * time.Second).Unix())
	next := proto.Clone(previous).(*lanewayv1.NodeConfiguration)
	next.ValidUntilUnixSeconds = uint64(now.Add(25 * time.Second).Unix())
	next.EphemeralExitSuspectAtUnixSeconds = uint64(now.Add(25 * time.Second).Unix())
	next.EphemeralExitRevokeAtUnixSeconds = uint64(now.Add(65 * time.Second).Unix())
	expected := []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}
	deadline, err := validateEphemeralExitLeaseRenewal(previous, next, local, expected, now.Add(20*time.Second), now)
	if err != nil || !deadline.Equal(now.Add(25*time.Second)) {
		t.Fatalf("valid renewal deadline=%v error=%v", deadline, err)
	}

	changed := proto.Clone(next).(*lanewayv1.NodeConfiguration)
	changed.Routes.Routes[0].Metric++
	if _, err := validateEphemeralExitLeaseRenewal(previous, changed, local, expected, now.Add(20*time.Second), now); err == nil {
		t.Fatal("same-epoch route change accepted as an ephemeral Exit lease renewal")
	}
	changed = proto.Clone(next).(*lanewayv1.NodeConfiguration)
	changed.EphemeralExitLeaseGeneration++
	if _, err := validateEphemeralExitLeaseRenewal(previous, changed, local, expected, now.Add(20*time.Second), now); err == nil {
		t.Fatal("changed ephemeral Exit generation accepted as a renewal")
	}
	changed = proto.Clone(next).(*lanewayv1.NodeConfiguration)
	changed.EphemeralExitSuspectAtUnixSeconds = previous.EphemeralExitSuspectAtUnixSeconds - 1
	changed.EphemeralExitRevokeAtUnixSeconds = previous.EphemeralExitRevokeAtUnixSeconds - 1
	if _, err := validateEphemeralExitLeaseRenewal(previous, changed, local, expected, now.Add(20*time.Second), now); err == nil {
		t.Fatal("backwards ephemeral Exit lease accepted")
	}
}

func TestEphemeralExitSnapshotExpiryDrainsBeforeTerminalRevocation(t *testing.T) {
	gateway := exitnode.NewMemoryGatewayManager()
	if err := gateway.Apply(context.Background(), exitnode.GatewayPlan{Enabled: true, Authorized: true,
		OverlaySources: []netip.Prefix{netip.MustParsePrefix("100.96.0.0/16")}}); err != nil {
		t.Fatal(err)
	}
	managers := &daemonExitManagers{gateway: gateway, gatewayReady: true}
	failCloseControllerSnapshot(context.Background(), &lanewayv1.NodeConfiguration{EphemeralExitLeaseGeneration: 1},
		identity.NodeIdentity{}, nil, nil, nil, nil, nil, nil, managers, nil)
	if !gateway.Draining() || managers.gatewayReady {
		t.Fatalf("suspect Exit draining=%t gatewayReady=%t", gateway.Draining(), managers.gatewayReady)
	}
}

func TestControllerOverlayAddressesAcceptsDualStackAssignment(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	configuration := controllerTestConfiguration(local, identity.NodeID(testID(3)), uint64(time.Now().Unix()+60))
	ipv6 := netip.MustParseAddr("2001:db8::2")
	configuration.OverlayAddresses = append(configuration.OverlayAddresses, ipv6.AsSlice())
	configuration.Routes.Routes = append(configuration.Routes.Routes, &lanewayv1.Route{
		Destination: &lanewayv1.IpPrefix{Address: ipv6.AsSlice(), PrefixLength: 128},
		ViaNodeId:   local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY,
	})
	addresses, err := controllerOverlayAddresses(configuration, local, time.Now())
	if err != nil || len(addresses) != 2 || addresses[1] != netip.MustParsePrefix("2001:db8::2/128") {
		t.Fatalf("dual-stack controller addresses = %v, %v", addresses, err)
	}
}

func TestConfigurationLeaseExpiryFailsClosed(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	initial := controllerTestConfiguration(local, peer, uint64(time.Now().Unix()+1))
	table := routing.NewTable(nil)
	routeManager := platform.NewMemoryRouteManager()
	policyTable := new(policy.Table)
	if err := applyControllerConfiguration(context.Background(), initial, local, table, routeManager,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, policyTable, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); !ok {
		t.Fatal("initial controller route was not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runConfigurationUpdates(ctx, 5*time.Millisecond, blockingConfigurationSource{}, local,
			[]netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}, initial, table, routeManager,
			[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, policyTable, nil, nil, nil)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); !ok && len(routeManager.Routes()) == 0 {
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("updater exit = %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("expired controller snapshot remained active")
}

func TestLeaseExpiryDeniesUserspaceBeforePrivilegedCleanupFailure(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	initial := controllerTestConfiguration(local, peer, uint64(time.Now().Unix()+60))
	table := routing.NewTable(nil)
	policyTable := new(policy.Table)
	memoryRoutes := platform.NewMemoryRouteManager()
	if err := applyControllerConfiguration(context.Background(), initial, local, table, memoryRoutes,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, policyTable, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	forwardAuthorized := true
	subnets := &daemonSubnetManager{setRelayPrefixes: func(prefixes []netip.Prefix) error {
		forwardAuthorized = len(prefixes) != 0
		return nil
	}}
	expired := failClosedNodeConfiguration(initial, local)
	expired.ValidUntilUnixSeconds = uint64(time.Now().Unix() - 1)
	cleanupErr := errors.New("route cleanup failed")
	failingRoutes := cleanupFailureRouteManager{RouteManager: memoryRoutes, err: cleanupErr}
	err := applyControllerConfiguration(context.Background(), expired, local, table, failingRoutes,
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")}, policyTable, subnets, nil, nil)
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("cleanup error = %v", err)
	}
	if _, ok := table.Lookup(netip.MustParseAddr("100.96.0.3")); ok {
		t.Fatal("expired userspace route survived cleanup failure")
	}
	if forwardAuthorized {
		t.Fatal("expired forwarding prefix authorization survived cleanup failure")
	}
	packet := make([]byte, 20)
	packet[0], packet[2], packet[3] = 0x45, 0, 20
	copy(packet[12:16], []byte{100, 96, 0, 2})
	copy(packet[16:20], []byte{100, 96, 0, 3})
	if result := policyTable.Evaluate(local.NodeID, peer, packet); result.Action != policy.Deny {
		t.Fatalf("expired policy result = %#v", result)
	}
}

type cleanupFailureRouteManager struct {
	platform.RouteManager
	err error
}

func (m cleanupFailureRouteManager) Apply(context.Context, platform.RoutePlan) error { return m.err }

type blockingConfigurationSource struct{}

func (blockingConfigurationSource) Configuration(ctx context.Context, _ uint64) (*lanewayv1.NodeConfiguration, bool, error) {
	<-ctx.Done()
	return nil, false, ctx.Err()
}

type oneLeaseConfigurationSource struct {
	lease  *lanewayv1.NodeConfiguration
	calls  chan struct{}
	served bool
}

func (s *oneLeaseConfigurationSource) Configuration(ctx context.Context, _ uint64) (*lanewayv1.NodeConfiguration, bool, error) {
	s.calls <- struct{}{}
	if !s.served {
		s.served = true
		return s.lease, true, nil
	}
	<-ctx.Done()
	return nil, false, ctx.Err()
}

func TestControllerUpdatesRejectNonAdvancingEpochAndShorterLease(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	peer := identity.NodeID(testID(3))
	initialDeadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	initial := controllerTestConfiguration(local, peer, initialDeadline)
	state := new(controllerApplyState)
	table := routing.NewTable(nil)
	routes := platform.NewMemoryRouteManager()
	policies := new(policy.Table)
	if err := applyControllerConfiguration(context.Background(), initial, local, table, routes, nil, policies, nil, nil, nil, state); err != nil {
		t.Fatal(err)
	}
	for _, epoch := range []uint64{initial.ConfigurationEpoch, initial.ConfigurationEpoch - 1} {
		replayed := controllerTestConfiguration(local, peer, uint64(time.Now().Add(3*time.Minute).Unix()))
		replayed.ConfigurationEpoch = epoch
		replayed.Routes.ConfigurationEpoch = epoch
		replayed.Policy.ConfigurationEpoch = epoch
		if err := applyControllerConfiguration(context.Background(), replayed, local, table, routes, nil, policies, nil, nil, nil, state); err == nil {
			t.Fatalf("controller epoch %d accepted after %d", epoch, initial.ConfigurationEpoch)
		}
	}

	lease := &lanewayv1.NodeConfiguration{
		ConfigurationEpoch:    initial.ConfigurationEpoch,
		ValidUntilUnixSeconds: uint64(time.Now().Add(time.Minute).Unix()),
	}
	source := &oneLeaseConfigurationSource{lease: lease, calls: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runConfigurationUpdates(ctx, time.Millisecond, source, local,
			[]netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}, initial, table, routes, nil, policies, nil, nil, nil, state)
	}()
	<-source.calls
	<-source.calls // The next poll begins only after the rejected lease was processed.
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("updater exit = %v", err)
	}
	if got := state.accepted.configuration.GetValidUntilUnixSeconds(); got != initialDeadline {
		t.Fatalf("shorter lease changed accepted deadline to %d, want %d", got, initialDeadline)
	}
}

func controllerTestConfiguration(local identity.NodeIdentity, peer identity.NodeID, validUntil uint64) *lanewayv1.NodeConfiguration {
	epoch := uint64(2)
	localRouteID, peerRouteID := testID(10), testID(11)
	ruleID := testID(9)
	return &lanewayv1.NodeConfiguration{
		ConfigurationEpoch: epoch, OverlayAddresses: [][]byte{{100, 96, 0, 2}}, ValidUntilUnixSeconds: validUntil,
		Peers: []*lanewayv1.NodePeer{
			{NodeId: local.NodeID[:], Name: "local", OverlayAddresses: [][]byte{{100, 96, 0, 2}}},
			{NodeId: peer[:], Name: "peer", OverlayAddresses: [][]byte{{100, 96, 0, 3}}},
		},
		Routes: &lanewayv1.RouteSnapshot{NetworkId: local.NetworkID[:], ConfigurationEpoch: epoch, Routes: []*lanewayv1.Route{
			{RouteId: localRouteID[:], Destination: &lanewayv1.IpPrefix{Address: []byte{100, 96, 0, 2}, PrefixLength: 32}, ViaNodeId: local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
			{RouteId: peerRouteID[:], Destination: &lanewayv1.IpPrefix{Address: []byte{100, 96, 0, 3}, PrefixLength: 32}, ViaNodeId: peer[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
		}},
		Policy: &lanewayv1.PolicySnapshot{NetworkId: local.NetworkID[:], ConfigurationEpoch: epoch,
			DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY,
			Rules: []*lanewayv1.PolicyRule{{
				RuleId: ruleID[:], Priority: 1, Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
				Selector: &lanewayv1.TrafficSelector{IpProtocol: lanewayv1.IpProtocol_IP_PROTOCOL_ANY},
			}}},
	}
}

func TestDaemonExitManagersAuthorizationAndSelection(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	routes := exitnode.NewMemoryRouteManager()
	dns := exitnode.NewMemoryDNSManager()
	client, err := exitnode.NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	gateway := exitnode.NewMemoryGatewayManager()
	routeTable := routing.NewTable(nil)
	managers := &daemonExitManagers{
		client: client, gateway: gateway, selected: selected, local: local,
		failureMode: exitnode.FailureModeClosed, enabled: true,
		bypass: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		routeTable: routeTable, pathHealthy: func(identity.NodeID) bool { return true },
	}
	otherExit := identity.NodeID(testID(5))
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
		{Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0}, ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT, Metric: 100},
		{Destination: &lanewayv1.IpPrefix{Address: netip.MustParseAddr("::").AsSlice(), PrefixLength: 0}, ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT, Metric: 100},
		{Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0}, ViaNodeId: otherExit[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT},
		{Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0}, ViaNodeId: local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT, Metric: 10},
		{Destination: &lanewayv1.IpPrefix{Address: []byte{100, 96, 0, 0}, PrefixLength: 24}, ViaNodeId: local.NodeID[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_OVERLAY},
	}}}
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if status := managers.Status(); !status.Enabled || !status.Authorized || status.SelectedNodeID != selected.String() || !status.ForwardingReady || !status.NATReady {
		t.Fatalf("exit status = %#v", status)
	}
	if _, active := routes.Snapshot(); !active {
		t.Fatal("exit routes were not activated")
	}
	if plan, active := gateway.Snapshot(); !active || len(plan.OverlaySources) != 1 {
		t.Fatalf("gateway = %#v, %t", plan, active)
	}
	if route, ok := routeTable.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || route.NextHop != selected {
		t.Fatalf("selected exit route = %#v, %t", route, ok)
	}
	if route, ok := routeTable.Lookup(netip.MustParseAddr("2001:4860:4860::8888")); !ok || route.NextHop != selected {
		t.Fatalf("selected IPv6 exit route = %#v, %t", route, ok)
	}
	if err := managers.SetSelection(context.Background(), true, otherExit); err != nil {
		t.Fatal(err)
	}
	if route, ok := routeTable.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || route.NextHop != otherExit {
		t.Fatalf("switched exit route = %#v, %t", route, ok)
	}
	unauthorized := identity.NodeID(testID(4))
	if err := managers.SetSelection(context.Background(), true, unauthorized); err != nil {
		t.Fatal(err)
	}
	if status := managers.Status(); status.Authorized {
		t.Fatalf("unauthorized exit status = %#v", status)
	}
	if _, active := routes.Snapshot(); active {
		t.Fatal("unauthorized exit routes remained active")
	}
	if _, ok := routeTable.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("unauthorized exit remained in dataplane routing table")
	}
}

func TestGatewayActivationFailureNeverAuthorizesExitForwarding(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	gatewayErr := errors.New("gateway activation failed")
	exitManagers := &daemonExitManagers{
		gateway:    failingGatewayManager{err: gatewayErr},
		local:      local,
		routeTable: routing.NewTable(nil),
	}
	var published [][]netip.Prefix
	subnets := &daemonSubnetManager{
		serveExit: true,
		setRelayPrefixes: func(prefixes []netip.Prefix) error {
			published = append(published, append([]netip.Prefix(nil), prefixes...))
			return nil
		},
	}
	configuration := controllerTestConfiguration(local, identity.NodeID(testID(3)), uint64(time.Now().Unix()+60))
	configuration.EnabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
	configuration.Routes.Routes = append(configuration.Routes.Routes, exitRoute(local.NodeID))
	err := applyControllerConfiguration(context.Background(), configuration, local, exitManagers.routeTable,
		platform.NewMemoryRouteManager(), nil, new(policy.Table), subnets, nil, exitManagers)
	if !errors.Is(err, gatewayErr) {
		t.Fatalf("activation error = %v", err)
	}
	defaultPrefix := netip.MustParsePrefix("0.0.0.0/0")
	for _, prefixes := range published {
		if slices.Contains(prefixes, defaultPrefix) {
			t.Fatalf("exit forwarding authorized despite failed gateway activation: %v", published)
		}
	}
}

type failingGatewayManager struct{ err error }

func (m failingGatewayManager) Apply(context.Context, exitnode.GatewayPlan) error { return m.err }
func (failingGatewayManager) Drain(context.Context) error                         { return nil }
func (failingGatewayManager) Restore(context.Context) error                       { return nil }
func (failingGatewayManager) Close() error                                        { return nil }

func TestDaemonExitManagersFailOpenTracksPathHealth(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	routes := exitnode.NewMemoryRouteManager()
	dns := exitnode.NewMemoryDNSManager()
	client, err := exitnode.NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	healthy := true
	managers := &daemonExitManagers{
		client: client, selected: selected, local: local, enabled: true,
		failureMode: exitnode.FailureModeOpen,
		bypass:      []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		dns:         []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		routeTable:  routing.NewTable(nil),
		pathHealthy: func(identity.NodeID) bool { return healthy },
	}
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{{
		Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0},
		ViaNodeId:   selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT,
	}}}}
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if _, active := routes.Snapshot(); !active {
		t.Fatal("healthy fail-open exit did not install routes")
	}
	healthy = false
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if _, active := routes.Snapshot(); active {
		t.Fatal("fail-open exit routes remained after path failure")
	}
	if _, active := dns.Snapshot(); active {
		t.Fatal("fail-open DNS remained after path failure")
	}
	healthy = true
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if _, active := routes.Snapshot(); !active {
		t.Fatal("recovered exit path did not restore routes")
	}
}

func TestDaemonExitManagersReconcilesDirectEndpointBypass(t *testing.T) {
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	routes := exitnode.NewMemoryRouteManager()
	client, err := exitnode.NewClientManager(routes, exitnode.NewMemoryDNSManager(), 0)
	if err != nil {
		t.Fatal(err)
	}
	static := netip.MustParseAddr("203.0.113.1")
	managers := &daemonExitManagers{
		client: client, selected: selected, local: local, enabled: true,
		failureMode: exitnode.FailureModeClosed, staticBypass: []netip.Addr{static}, bypass: []netip.Addr{static},
		dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, routeTable: routing.NewTable(nil),
		pathHealthy: func(identity.NodeID) bool { return true },
	}
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{{
		Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0},
		ViaNodeId:   selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT,
	}}}}
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	direct := netip.MustParseAddr("198.51.100.44")
	if err := managers.SetDirectPathEndpoints(context.Background(), []netip.Addr{direct, direct}); err != nil {
		t.Fatal(err)
	}
	plan, active := routes.Snapshot()
	if !active || !slices.Contains(plan.TransportBypass, static) || !slices.Contains(plan.TransportBypass, direct) || len(plan.TransportBypass) != 2 {
		t.Fatalf("active direct bypass plan = %#v, %t", plan, active)
	}
	if err := managers.SetDirectPathEndpoints(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	plan, active = routes.Snapshot()
	if !active || !slices.Equal(plan.TransportBypass, []netip.Addr{static}) {
		t.Fatalf("restored static bypass plan = %#v, %t", plan, active)
	}
}

func testID(last byte) identity.ID {
	var id identity.ID
	id[len(id)-1] = last
	return id
}
