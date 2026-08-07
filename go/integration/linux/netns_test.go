//go:build linux

// Package linux_test contains opt-in tests that mutate real Linux network
// namespace state. Run them through integration/linux-netns.sh; ordinary
// `go test ./...` skips them without requiring privileges.
package linux_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/platform"
	"laneway.dev/laneway/internal/subnet"
)

const privilegedGate = "LANEWAY_PRIVILEGED_INTEGRATION"

func requirePrivileged(t *testing.T) {
	t.Helper()
	if os.Getenv(privilegedGate) != "1" {
		t.Skip("set LANEWAY_RUN_PRIVILEGED=1 and use integration/linux-netns.sh")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged integration test must run as root inside a disposable network namespace")
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %q: %v: %s", name, args, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func tryRun(name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, name, args...).Run()
}

func addDummy(t *testing.T, name string) {
	t.Helper()
	run(t, "ip", "link", "add", name, "type", "dummy")
	run(t, "ip", "link", "set", name, "up")
	t.Cleanup(func() { tryRun("ip", "link", "delete", name) })
}

func TestTUNAndOverlayRouteLifecycle(t *testing.T) {
	requirePrivileged(t)
	ctx := context.Background()
	tun, err := platform.OpenTUN(ctx, platform.TUNConfig{
		Name: "laneit0", MTU: 1280,
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.127.0.1/32"),
			netip.MustParsePrefix("fd42:127::1/128"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output := run(t, "ip", "-4", "-o", "address", "show", "dev", "laneit0"); !strings.Contains(output, "100.127.0.1/32") {
		t.Fatalf("TUN address is absent: %s", output)
	}
	if output := run(t, "ip", "-6", "-o", "address", "show", "dev", "laneit0"); !strings.Contains(output, "fd42:127::1/128") {
		t.Fatalf("IPv6 TUN address is absent: %s", output)
	}
	if output := run(t, "ip", "-o", "link", "show", "dev", "laneit0"); !strings.Contains(output, "mtu 1280") {
		t.Fatalf("TUN MTU is absent: %s", output)
	}

	routes, err := platform.NewRouteManager(platform.RouteManagerConfig{InterfaceName: tun.Name(), Protocol: 249})
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.Apply(ctx, platform.RoutePlan{Routes: []platform.Route{
		{Prefix: netip.MustParsePrefix("10.77.0.0/16")},
		{Prefix: netip.MustParsePrefix("fd42:77::/64")},
	}}); err != nil {
		t.Fatal(err)
	}
	if output := run(t, "ip", "-4", "route", "show", "exact", "10.77.0.0/16"); !strings.Contains(output, "dev laneit0") {
		t.Fatalf("overlay route is absent: %s", output)
	}
	if output := run(t, "ip", "-6", "route", "show", "exact", "fd42:77::/64"); !strings.Contains(output, "dev laneit0") {
		t.Fatalf("IPv6 overlay route is absent: %s", output)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	if output := run(t, "ip", "-4", "route", "show", "exact", "10.77.0.0/16"); output != "" {
		t.Fatalf("owned overlay route survived close: %s", output)
	}
	if output := run(t, "ip", "-6", "route", "show", "exact", "fd42:77::/64"); output != "" {
		t.Fatalf("owned IPv6 overlay route survived close: %s", output)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "show", "dev", "laneit0").Run(); err == nil {
		t.Fatal("non-persistent TUN survived close")
	}
}

func TestTUNReadBlocksUntilItsContextExpires(t *testing.T) {
	requirePrivileged(t)
	tun, err := platform.OpenTUN(context.Background(), platform.TUNConfig{
		Name: "laneit1", MTU: 1200,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.127.0.2/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := tun.Read(ctx, make([]byte, 1200)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("idle real TUN read error=%v, want context deadline", err)
	}
}

func TestSubnetNATAndRoutedReconciliation(t *testing.T) {
	requirePrivileged(t)
	addDummy(t, "lanesub0")
	addDummy(t, "wansub0")
	const table = "laneway_it"
	tryRun("nft", "delete", "table", "inet", table)
	t.Cleanup(func() { tryRun("nft", "delete", "table", "inet", table) })
	priorForwarding := run(t, "sysctl", "-n", "net.ipv4.ip_forward")
	t.Cleanup(func() { tryRun("sysctl", "-w", "net.ipv4.ip_forward="+priorForwarding) })

	manager, err := subnet.NewForwardingManager(subnet.ForwardingManagerConfig{
		InputInterface: "lanesub0", OutputInterface: "wansub0", TableName: table,
	})
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("10.88.0.0/16")
	if err := manager.Apply(context.Background(), subnet.ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix}, Mode: subnet.ModeNAT,
	}); err != nil {
		t.Fatal(err)
	}
	natRules := run(t, "nft", "list", "table", "inet", table)
	for _, want := range []string{"10.88.0.0/16", "laneway-masquerade", "masquerade"} {
		if !strings.Contains(natRules, want) {
			t.Fatalf("NAT ruleset lacks %q:\n%s", want, natRules)
		}
	}
	if err := manager.Apply(context.Background(), subnet.ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{prefix}, Mode: subnet.ModeRouted,
	}); err != nil {
		t.Fatal(err)
	}
	routedRules := run(t, "nft", "list", "table", "inet", table)
	if strings.Contains(routedRules, "masquerade") {
		t.Fatalf("routed mode retained NAT:\n%s", routedRules)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("nft", "list", "table", "inet", table).Run(); err == nil {
		t.Fatal("owned nftables table survived close")
	}
	if got := run(t, "sysctl", "-n", "net.ipv4.ip_forward"); got != priorForwarding {
		t.Fatalf("ip_forward=%s, want restored %s", got, priorForwarding)
	}
}

type resolverState struct {
	servers      []string
	domains      []string
	defaultRoute string
}

type fakeResolver struct {
	mu             sync.Mutex
	state          resolverState
	failDomainOnce bool
}

func (r *fakeResolver) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name != "fake-resolvectl" || len(args) < 2 {
		return nil, fmt.Errorf("unexpected resolver command %s %q", name, args)
	}
	property := args[0]
	if len(args) == 2 && property != "revert" {
		var values []string
		switch property {
		case "dns":
			values = r.state.servers
		case "domain":
			values = r.state.domains
		case "default-route":
			if r.state.defaultRoute != "" {
				values = []string{r.state.defaultRoute}
			}
		default:
			return nil, fmt.Errorf("unexpected resolver property %q", property)
		}
		return []byte("Link 7 (laneexit0): " + strings.Join(values, " ") + "\n"), nil
	}
	switch property {
	case "revert":
		r.state = resolverState{}
	case "dns":
		r.state.servers = append([]string(nil), args[2:]...)
	case "domain":
		if r.failDomainOnce && len(args) > 2 && args[2] == "~." {
			r.failDomainOnce = false
			return []byte("injected failure"), errors.New("injected resolver failure")
		}
		r.state.domains = append([]string(nil), args[2:]...)
	case "default-route":
		r.state.defaultRoute = args[2]
	default:
		return nil, fmt.Errorf("unexpected resolver operation %q", property)
	}
	return nil, nil
}

func (r *fakeResolver) snapshot() resolverState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return resolverState{
		servers: append([]string(nil), r.state.servers...), domains: append([]string(nil), r.state.domains...),
		defaultRoute: r.state.defaultRoute,
	}
}

func TestExitSplitDefaultAndDNSRollback(t *testing.T) {
	requirePrivileged(t)
	addDummy(t, "laneexit0")
	addDummy(t, "wanexit0")
	run(t, "ip", "address", "add", "192.0.2.2/24", "dev", "wanexit0")
	run(t, "ip", "route", "add", "default", "dev", "wanexit0")
	defer tryRun("ip", "route", "delete", "default", "dev", "wanexit0")

	priorDNS := resolverState{servers: []string{"192.0.2.53"}, domains: []string{"corp.example"}, defaultRoute: "no"}
	resolver := &fakeResolver{state: priorDNS}
	client := newExitClient(t, resolver)
	plan := exitnode.ClientPlan{
		Enabled: true, Authorized: true, FailureMode: exitnode.FailureModeClosed, PathAvailable: true,
		ExitPrefixes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		TransportBypass: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
		LocalLANBypass:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		DNSServers:      []netip.Addr{netip.MustParseAddr("10.42.0.53")},
	}
	if err := client.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if output := run(t, "ip", "-4", "route", "show", "table", "51820", "exact", prefix); !strings.Contains(output, "dev laneexit0") {
			t.Fatalf("split default %s is absent: %s", prefix, output)
		}
	}
	if output := run(t, "ip", "-4", "rule", "show", "priority", "11000"); !strings.Contains(output, "lookup 51820") {
		t.Fatalf("exit policy rule is absent: %s", output)
	}
	applied := resolver.snapshot()
	if strings.Join(applied.servers, ",") != "10.42.0.53" || strings.Join(applied.domains, ",") != "~." || applied.defaultRoute != "yes" {
		t.Fatalf("tunnel DNS was not applied: %+v", applied)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	assertExitRestored(t, resolver, priorDNS)

	rollbackResolver := &fakeResolver{state: priorDNS, failDomainOnce: true}
	rollbackClient := newExitClient(t, rollbackResolver)
	if err := rollbackClient.Apply(context.Background(), plan); err == nil {
		t.Fatal("injected DNS failure did not fail exit activation")
	}
	assertExitRestored(t, rollbackResolver, priorDNS)
	if err := rollbackClient.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExitDynamicDirectBypassPreventsTunnelRecursion(t *testing.T) {
	requirePrivileged(t)
	addDummy(t, "lanedirect0")
	addDummy(t, "wandirect0")
	run(t, "ip", "address", "add", "198.51.100.2/24", "dev", "wandirect0")
	run(t, "ip", "route", "add", "203.0.113.9/32", "dev", "wandirect0")
	routes, err := exitnode.NewRouteManager(exitnode.RouteManagerConfig{
		InterfaceName: "lanedirect0", Table: 51821, RulePriority: 11001, Protocol: 247,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = routes.Close()
		tryRun("ip", "-4", "rule", "del", "priority", "11001", "lookup", "51821")
		tryRun("ip", "-4", "route", "flush", "table", "51821")
	})
	plan := exitnode.RoutePlan{
		TunnelPrefixes:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
		TransportBypass: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}
	if err := routes.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	directEndpoint := netip.MustParseAddr("198.51.100.44")
	plan.TransportBypass = append(plan.TransportBypass, directEndpoint)
	if err := routes.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if output := run(t, "ip", "-4", "route", "show", "table", "51821", "exact", directEndpoint.String()+"/32"); !strings.Contains(output, "dev wandirect0") {
		t.Fatalf("direct endpoint lacks native policy-table bypass: %s", output)
	}
	if output := run(t, "ip", "-4", "route", "get", directEndpoint.String()); !strings.Contains(output, "dev wandirect0") || strings.Contains(output, "dev lanedirect0") {
		t.Fatalf("direct endpoint recursively entered tunnel: %s", output)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
}

func newExitClient(t *testing.T, resolver *fakeResolver) *exitnode.ClientManager {
	t.Helper()
	routes, err := exitnode.NewRouteManager(exitnode.RouteManagerConfig{InterfaceName: "laneexit0", Protocol: 248})
	if err != nil {
		t.Fatal(err)
	}
	dns, err := exitnode.NewDNSManager(exitnode.DNSManagerConfig{InterfaceName: "laneexit0", ResolveCommand: "fake-resolvectl", Runner: resolver})
	if err != nil {
		t.Fatal(err)
	}
	client, err := exitnode.NewClientManager(routes, dns, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func assertExitRestored(t *testing.T, resolver *fakeResolver, prior resolverState) {
	t.Helper()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if output := run(t, "ip", "-4", "route", "show", "table", "51820", "exact", prefix); output != "" {
			t.Fatalf("split default %s survived rollback: %s", prefix, output)
		}
	}
	if output := run(t, "ip", "-4", "rule", "show", "priority", "11000"); output != "" {
		t.Fatalf("exit policy rule survived rollback: %s", output)
	}
	got := resolver.snapshot()
	if strings.Join(got.servers, ",") != strings.Join(prior.servers, ",") ||
		strings.Join(got.domains, ",") != strings.Join(prior.domains, ",") || got.defaultRoute != prior.defaultRoute {
		t.Fatalf("DNS state=%+v, want restored %+v", got, prior)
	}
}

func TestCrashResidueIsFailClosedAndRecoverable(t *testing.T) {
	requirePrivileged(t)
	addDummy(t, "lanecr0")
	addDummy(t, "wancr0")
	run(t, "ip", "address", "add", "192.0.2.2/24", "dev", "wancr0")
	run(t, "ip", "route", "add", "203.0.113.9/32", "dev", "wancr0")
	const table = "laneway_crash"
	const exitTable = "laneway_exit_crash"
	tryRun("nft", "delete", "table", "inet", table)
	tryRun("nft", "delete", "table", "inet", exitTable)
	priorForwarding := run(t, "sysctl", "-n", "net.ipv4.ip_forward")
	t.Cleanup(func() {
		tryRun("ip", "-4", "rule", "del", "priority", "11000", "lookup", "51820")
		tryRun("ip", "-4", "route", "flush", "table", "51820")
		tryRun("nft", "delete", "table", "inet", table)
		tryRun("nft", "delete", "table", "inet", exitTable)
		tryRun("sysctl", "-w", "net.ipv4.ip_forward="+priorForwarding)
	})

	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestPrivilegedCrashHelper$", "-test.v")
	command.Env = append(os.Environ(), "LANEWAY_CRASH_HELPER=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("crash helper exited cleanly:\n%s", output)
	}
	if err := exec.Command("nft", "list", "table", "inet", table).Run(); err != nil {
		t.Fatalf("crash did not leave an ownership-marked table: %v\n%s", err, output)
	}
	if err := exec.Command("nft", "list", "table", "inet", exitTable).Run(); err != nil {
		t.Fatalf("crash did not leave an ownership-marked exit table: %v\n%s", err, output)
	}
	if err := exec.Command("ip", "link", "show", "dev", "lanecrash0").Run(); err == nil {
		t.Fatal("TUN file-descriptor cleanup failed after process crash")
	}
	if output := run(t, "ip", "-4", "rule", "show", "priority", "11000"); !strings.Contains(output, "lookup 51820") {
		t.Fatalf("crash did not leave owned exit policy rule: %s", output)
	}

	manager, err := subnet.NewForwardingManager(subnet.ForwardingManagerConfig{
		InputInterface: "lanecr0", OutputInterface: "wancr0", TableName: table,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), subnet.ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}, Mode: subnet.ModeNAT,
	}); err != nil {
		t.Fatalf("restart did not reclaim exact crash residue: %v", err)
	}
	gateway, err := exitnode.NewGatewayManager(exitnode.GatewayManagerConfig{
		InputInterface: "lanecr0", OutputInterface: "wancr0", TableName: exitTable,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Apply(context.Background(), exitnode.GatewayPlan{
		Enabled: true, Authorized: true, OverlaySources: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	}); err != nil {
		t.Fatalf("restart did not reclaim exact exit crash residue: %v", err)
	}
	routes, err := exitnode.NewRouteManager(exitnode.RouteManagerConfig{InterfaceName: "lanecr0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.Apply(context.Background(), exitnode.RoutePlan{
		TunnelPrefixes:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
		TransportBypass: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}); err != nil {
		t.Fatalf("restart did not reclaim exact exit policy residue: %v", err)
	}
	if err := exec.Command("nft", "list", "table", "inet", table).Run(); err != nil {
		t.Fatalf("restarted manager did not install replacement table: %v", err)
	}
	if err := exec.Command("nft", "list", "table", "inet", exitTable).Run(); err != nil {
		t.Fatalf("restarted gateway did not install replacement exit table: %v", err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	if err := routes.Close(); err != nil {
		t.Fatal(err)
	}
	if output := run(t, "ip", "-4", "rule", "show", "priority", "11000"); output != "" {
		t.Fatalf("replacement exit policy rule survived Close: %s", output)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("nft", "list", "table", "inet", table).Run(); err == nil {
		t.Fatal("replacement nftables table survived Close")
	}
	if err := exec.Command("nft", "list", "table", "inet", exitTable).Run(); err == nil {
		t.Fatal("replacement exit nftables table survived Close")
	}
	if got := run(t, "sysctl", "-n", "net.ipv4.ip_forward"); got != priorForwarding {
		t.Fatalf("forwarding after crash recovery=%s, want original %s", got, priorForwarding)
	}
}

func TestPrivilegedCrashHelper(t *testing.T) {
	if os.Getenv("LANEWAY_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	manager, err := subnet.NewForwardingManager(subnet.ForwardingManagerConfig{
		InputInterface: "lanecr0", OutputInterface: "wancr0", TableName: "laneway_crash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), subnet.ForwardingPlan{
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")}, Mode: subnet.ModeNAT,
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := exitnode.NewGatewayManager(exitnode.GatewayManagerConfig{
		InputInterface: "lanecr0", OutputInterface: "wancr0", TableName: "laneway_exit_crash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Apply(context.Background(), exitnode.GatewayPlan{
		Enabled: true, Authorized: true, OverlaySources: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/16")},
	}); err != nil {
		t.Fatal(err)
	}
	routes, err := exitnode.NewRouteManager(exitnode.RouteManagerConfig{InterfaceName: "lanecr0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.Apply(context.Background(), exitnode.RoutePlan{
		TunnelPrefixes:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")},
		TransportBypass: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.OpenTUN(context.Background(), platform.TUNConfig{
		Name: "lanecrash0", MTU: 1200, Addresses: []netip.Prefix{netip.MustParsePrefix("100.127.9.1/32")},
	}); err != nil {
		t.Fatal(err)
	}
	os.Exit(23)
}
