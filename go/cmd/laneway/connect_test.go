package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/identity"
	"google.golang.org/protobuf/proto"
)

func TestConnectRejectsUnsafeOrAmbiguousFlagsBeforePrompt(t *testing.T) {
	for _, args := range [][]string{
		{"lane.example.com", "--ephemeral", "--remembered"},
		{"lane.example.com", "--dns", "1.1.1.1"},
		{"lane.example.com", "--failure-mode", "invalid", "--exit", "gateway"},
		{"lane.example.com", "--route", "0.0.0.0/0"},
	} {
		if err := runConnect(args); err == nil {
			t.Fatalf("accepted unsafe arguments %v", args)
		}
	}
}

func TestConnectPrefixListMakesTemporaryOwnershipExplicit(t *testing.T) {
	if got := connectPrefixList(nil); got != "none" {
		t.Fatalf("empty prefix list = %q", got)
	}
	if got := connectPrefixList([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00::/64")}); got != "10.20.0.0/16,fd00::/64" {
		t.Fatalf("prefix list = %q", got)
	}
}

func TestRuntimeCredentialsHaveNoFilesystemName(t *testing.T) {
	directory := t.TempDir()
	credentials := new(runtimeCredentialFiles)
	path, err := credentials.add(directory, "secret", []byte("sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "sensitive" {
		t.Fatalf("read descriptor path: contents=%q err=%v", contents, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("credential left a directory entry: entries=%v err=%v", entries, err)
	}
	if err := credentials.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Fatal("credential descriptor remained readable after close")
	}
}

func TestConnectConfigurationFilterIsExactAndFailClosed(t *testing.T) {
	local := connectTestNodeID(t, "101112131415161718191a1b1c1d1e1f")
	peer := connectTestNodeID(t, "202122232425262728292a2b2c2d2e2f")
	exit := connectTestNodeID(t, "303132333435363738393a3b3c3d3e3f")
	wanted := netip.MustParsePrefix("10.20.0.0/16")
	configuration := &lanewayv1.NodeConfiguration{
		Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_OVERLAY, "100.96.0.2/32", peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_SUBNET, wanted.String(), peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_SUBNET, "10.30.0.0/16", peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_EXIT, "0.0.0.0/0", exit),
		}},
		ExitPolicy: &lanewayv1.ExitNodePolicy{AuthorizedNodeIds: [][]byte{append([]byte(nil), exit[:]...)}},
	}
	filter := connectConfigurationFilter([]netip.Prefix{wanted}, exit, local)
	filtered, err := filter(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.GetRoutes().GetRoutes()) != 3 {
		t.Fatalf("filtered routes=%v", filtered.GetRoutes().GetRoutes())
	}
	for _, route := range filtered.GetRoutes().GetRoutes() {
		prefix, err := connectProtoPrefix(route.GetDestination())
		if err != nil {
			t.Fatal(err)
		}
		if prefix == netip.MustParsePrefix("10.30.0.0/16") {
			t.Fatal("unrequested subnet route survived filtering")
		}
	}
	if len(configuration.GetRoutes().GetRoutes()) != 4 {
		t.Fatal("filter mutated the authenticated source snapshot")
	}
	missing := connectConfigurationFilter([]netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}, identity.NodeID{}, local)
	if _, err := missing(configuration); err == nil || !strings.Contains(err.Error(), "no longer controller-authorized") {
		t.Fatalf("missing route error=%v", err)
	}
	withdrawn := proto.Clone(configuration).(*lanewayv1.NodeConfiguration)
	withdrawn.ExitPolicy = &lanewayv1.ExitNodePolicy{}
	if _, err := filter(withdrawn); err == nil || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("withdrawn exit error=%v", err)
	}
	if got, err := resolveConnectExit(configuration, exit.String(), local); err != nil || got != exit {
		t.Fatalf("resolve exit=%s err=%v", got, err)
	}
}

func TestRememberedConnectDerivesOnlyAuthorizedPrivatePrefixes(t *testing.T) {
	local := connectTestNodeID(t, "101112131415161718191a1b1c1d1e1f")
	peer := connectTestNodeID(t, "202122232425262728292a2b2c2d2e2f")
	exit := connectTestNodeID(t, "303132333435363738393a3b3c3d3e3f")
	configuration := &lanewayv1.NodeConfiguration{
		OverlayAddresses: [][]byte{netip.MustParseAddr("100.96.0.10").AsSlice()},
		Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_OVERLAY, "100.96.0.2/32", peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_SUBNET, "10.20.0.0/16", peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_SUBNET, "10.30.0.0/16", peer),
			connectTestRoute(lanewayv1.RouteKind_ROUTE_KIND_EXIT, "0.0.0.0/0", exit),
		}},
		Policy: &lanewayv1.PolicySnapshot{DefaultAction: lanewayv1.PolicyAction_POLICY_ACTION_DENY, Rules: []*lanewayv1.PolicyRule{{
			Action: lanewayv1.PolicyAction_POLICY_ACTION_ACCEPT,
			Selector: &lanewayv1.TrafficSelector{
				SourceNodeIds:       [][]byte{append([]byte(nil), local[:]...)},
				DestinationNodeIds:  [][]byte{append([]byte(nil), peer[:]...)},
				DestinationPrefixes: []*lanewayv1.IpPrefix{connectTestProtoPrefix("10.20.4.0/24")},
			},
		}}},
		ExitPolicy: &lanewayv1.ExitNodePolicy{AuthorizedNodeIds: [][]byte{append([]byte(nil), exit[:]...)}},
	}
	filtered, err := connectAuthorizedConfigurationFilter(identity.NodeID{}, local)(configuration)
	if err != nil {
		t.Fatal(err)
	}
	subnets := connectSubnetPrefixes(filtered)
	if len(subnets) != 1 || subnets[0] != netip.MustParsePrefix("10.20.4.0/24") {
		t.Fatalf("derived subnet routes=%v", subnets)
	}
	for _, route := range filtered.GetRoutes().GetRoutes() {
		prefix, err := connectProtoPrefix(route.GetDestination())
		if err != nil {
			t.Fatal(err)
		}
		if prefix.Bits() == 0 {
			t.Fatal("remembered split routing automatically selected a default route")
		}
	}
	if len(configuration.GetRoutes().GetRoutes()) != 4 {
		t.Fatal("authorized filter mutated the controller snapshot")
	}
}

func connectTestNodeID(t *testing.T, value string) identity.NodeID {
	t.Helper()
	parsed, err := identity.ParseNodeID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func connectTestRoute(kind lanewayv1.RouteKind, prefix string, via identity.NodeID) *lanewayv1.Route {
	return &lanewayv1.Route{
		Destination: connectTestProtoPrefix(prefix),
		ViaNodeId:   append([]byte(nil), via[:]...), Kind: kind,
	}
}

func connectTestProtoPrefix(value string) *lanewayv1.IpPrefix {
	parsed := netip.MustParsePrefix(value)
	return &lanewayv1.IpPrefix{Address: append([]byte(nil), parsed.Addr().AsSlice()...), PrefixLength: uint32(parsed.Bits())}
}

func TestConnectTokenFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "code")
	if err := os.WriteFile(path, []byte("secret-code\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := connectEnrollmentCode(path); err == nil {
		t.Fatal("group-readable enrollment code accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := connectEnrollmentCode(path)
	if err != nil || !bytes.Equal([]byte(code), []byte("secret-code")) {
		t.Fatalf("code=%q err=%v", code, err)
	}
}
