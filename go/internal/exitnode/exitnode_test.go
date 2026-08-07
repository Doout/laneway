package exitnode

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func validClientPlan() ClientPlan {
	return ClientPlan{
		Enabled: true, Authorized: true, FailureMode: FailureModeOpen, PathAvailable: true,
		ExitPrefixes:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		TransportBypass: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
		LocalLANBypass:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		DNSServers:      []netip.Addr{netip.MustParseAddr("10.42.0.53")},
	}
}

func TestClientRequiresExplicitSafeOptIn(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ClientPlan)
		want   error
	}{
		{"authorization", func(p *ClientPlan) { p.Authorized = false }, ErrUnauthorized},
		{"failure mode", func(p *ClientPlan) { p.FailureMode = FailureModeUnspecified }, ErrInvalid},
		{"transport bypass", func(p *ClientPlan) { p.TransportBypass = nil }, ErrInvalid},
		{"exit families", func(p *ClientPlan) { p.ExitPrefixes = nil }, ErrInvalid},
		{"non-default exit", func(p *ClientPlan) { p.ExitPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")} }, ErrInvalid},
		{"default local bypass", func(p *ClientPlan) { p.LocalLANBypass = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }, ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validClientPlan()
			tt.mutate(&p)
			_, _, err := normalizeClientPlan(p)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
	// Disabled is always a no-op, regardless of stale subordinate fields.
	if _, effective, err := normalizeClientPlan(ClientPlan{}); err != nil || effective {
		t.Fatalf("disabled plan: effective=%v err=%v", effective, err)
	}
}

func TestClientMayPreserveNativeDNS(t *testing.T) {
	routes, dns := NewMemoryRouteManager(), NewMemoryDNSManager()
	manager, err := NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	plan := validClientPlan()
	plan.DNSServers = nil
	if err := manager.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, active := routes.Snapshot(); !active {
		t.Fatal("exit routes were not applied")
	}
	if servers, active := dns.Snapshot(); active || len(servers) != 0 {
		t.Fatalf("native DNS was changed: servers=%v active=%v", servers, active)
	}
}

func TestClientAppliesDualStackSplitDefaults(t *testing.T) {
	routes, dns := NewMemoryRouteManager(), NewMemoryDNSManager()
	m, err := NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := validClientPlan()
	p.ExitPrefixes = append(p.ExitPrefixes, netip.MustParsePrefix("::/0"))
	p.DNSServers = append(p.DNSServers, netip.MustParseAddr("2001:db8::53"))
	if err := m.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	plan, active := routes.Snapshot()
	want := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
	}
	if !active || !slices.Equal(plan.TunnelPrefixes, want) {
		t.Fatalf("dual-stack tunnel routes = %v, active=%v", plan.TunnelPrefixes, active)
	}
}

func TestClientAppliesSplitDefaultsBypassAndDNS(t *testing.T) {
	routes, dns := NewMemoryRouteManager(), NewMemoryDNSManager()
	m, err := NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := validClientPlan()
	p.TransportBypass = append(p.TransportBypass, netip.MustParseAddr("203.0.113.9"))
	if err := m.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	routePlan, active := routes.Snapshot()
	if !active {
		t.Fatal("routes inactive")
	}
	if len(routePlan.TunnelPrefixes) != 2 || routePlan.TunnelPrefixes[0].String() != "0.0.0.0/1" || routePlan.TunnelPrefixes[1].String() != "128.0.0.0/1" {
		t.Fatalf("tunnel routes = %v", routePlan.TunnelPrefixes)
	}
	if len(routePlan.TransportBypass) != 1 {
		t.Fatalf("bypasses not normalized: %v", routePlan.TransportBypass)
	}
	servers, dnsActive := dns.Snapshot()
	if !dnsActive || len(servers) != 1 || servers[0].String() != "10.42.0.53" {
		t.Fatalf("DNS=%v active=%v", servers, dnsActive)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, active := routes.Snapshot(); active {
		t.Fatal("routes survived close")
	}
}

func TestFailureModesDoNotChangeSilently(t *testing.T) {
	for _, tt := range []struct {
		mode       FailureMode
		wantActive bool
	}{{FailureModeOpen, false}, {FailureModeClosed, true}} {
		routes, dns := NewMemoryRouteManager(), NewMemoryDNSManager()
		m, _ := NewClientManager(routes, dns, 0)
		p := validClientPlan()
		p.PathAvailable = false
		p.FailureMode = tt.mode
		if err := m.Apply(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		_, active := routes.Snapshot()
		if active != tt.wantActive {
			t.Fatalf("mode %v active=%v want %v", tt.mode, active, tt.wantActive)
		}
	}
}

func TestDNSFailureRollsBackRoutes(t *testing.T) {
	routes, dns := NewMemoryRouteManager(), NewMemoryDNSManager()
	dns.ApplyError = errors.New("injected DNS failure")
	m, _ := NewClientManager(routes, dns, 0)
	if err := m.Apply(context.Background(), validClientPlan()); err == nil {
		t.Fatal("expected failure")
	}
	if _, active := routes.Snapshot(); active {
		t.Fatal("route state was not rolled back")
	}
}

func TestMemoryManagersCloseAndCancellation(t *testing.T) {
	routes, dns, gateway := NewMemoryRouteManager(), NewMemoryDNSManager(), NewMemoryGatewayManager()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(routes.Restore(ctx), context.Canceled) || !errors.Is(dns.Restore(ctx), context.Canceled) || !errors.Is(gateway.Restore(ctx), context.Canceled) {
		t.Fatal("cancellation not propagated")
	}
	_ = routes.Close()
	_ = dns.Close()
	_ = gateway.Close()
	if !errors.Is(routes.Restore(context.Background()), ErrClosed) || !errors.Is(dns.Restore(context.Background()), ErrClosed) || !errors.Is(gateway.Restore(context.Background()), ErrClosed) {
		t.Fatal("closed error not stable")
	}
}

func TestGatewayPlanAuthorization(t *testing.T) {
	p := GatewayPlan{Enabled: true, OverlaySources: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")}}
	if _, _, err := normalizeGatewayPlan(p); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error=%v", err)
	}
	p.Authorized = true
	g := NewMemoryGatewayManager()
	if err := g.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	snapshot, active := g.Snapshot()
	if !active || len(snapshot.OverlaySources) != 1 {
		t.Fatalf("snapshot=%+v active=%v", snapshot, active)
	}
	if err := g.Apply(context.Background(), GatewayPlan{}); err != nil {
		t.Fatal(err)
	}
	if _, active := g.Snapshot(); active {
		t.Fatal("disabled gateway active")
	}
}
