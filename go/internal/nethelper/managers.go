package nethelper

import (
	"context"
	"net/netip"
	"time"

	"github.com/Doout/laneway/go/internal/exitnode"
	"github.com/Doout/laneway/go/internal/platform"
)

const managerCloseTimeout = 5 * time.Second

// RouteManager returns an unprivileged adapter for the helper-owned overlay
// route manager. Closing the adapter restores its route set but deliberately
// keeps the shared helper session alive for exit and DNS cleanup.
func (s *Session) RouteManager() platform.RouteManager { return helperRouteManager{s: s} }

// ExitRouteManager returns an adapter for the helper's fixed exit routing
// table and rule priority.
func (s *Session) ExitRouteManager() exitnode.RouteManager { return helperExitRouteManager{s: s} }

// DNSManager returns an adapter for per-link systemd-resolved state. It is
// used only when the caller explicitly supplies DNS servers.
func (s *Session) DNSManager() exitnode.DNSManager { return helperDNSManager{s: s} }

type helperRouteManager struct{ s *Session }

func (m helperRouteManager) Apply(ctx context.Context, plan platform.RoutePlan) error {
	wire := RoutePlan{Routes: make([]Route, 0, len(plan.Routes)), Bypasses: make([]string, 0, len(plan.TransportBypass))}
	for _, route := range plan.Routes {
		wire.Routes = append(wire.Routes, Route{Prefix: route.Prefix.String(), Metric: route.Metric})
	}
	for _, address := range plan.TransportBypass {
		wire.Bypasses = append(wire.Bypasses, address.String())
	}
	return m.s.ApplyRoutes(ctx, wire)
}

func (m helperRouteManager) Restore(ctx context.Context) error {
	return m.s.ApplyRoutes(ctx, RoutePlan{})
}

func (m helperRouteManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), managerCloseTimeout)
	defer cancel()
	return m.Restore(ctx)
}

type helperExitRouteManager struct{ s *Session }

func (m helperExitRouteManager) Apply(ctx context.Context, plan exitnode.RoutePlan) error {
	wire := ExitRoutePlan{
		TunnelPrefixes:  make([]string, 0, len(plan.TunnelPrefixes)),
		TransportBypass: make([]string, 0, len(plan.TransportBypass)),
		LocalLANBypass:  make([]string, 0, len(plan.LocalLANBypass)),
	}
	for _, prefix := range plan.TunnelPrefixes {
		wire.TunnelPrefixes = append(wire.TunnelPrefixes, prefix.String())
	}
	for _, address := range plan.TransportBypass {
		wire.TransportBypass = append(wire.TransportBypass, address.String())
	}
	for _, prefix := range plan.LocalLANBypass {
		wire.LocalLANBypass = append(wire.LocalLANBypass, prefix.String())
	}
	return m.s.ApplyExitRoutes(ctx, wire)
}

func (m helperExitRouteManager) Restore(ctx context.Context) error {
	return m.s.RestoreExitRoutes(ctx)
}

func (m helperExitRouteManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), managerCloseTimeout)
	defer cancel()
	return m.Restore(ctx)
}

type helperDNSManager struct{ s *Session }

func (m helperDNSManager) Apply(ctx context.Context, servers []netip.Addr) error {
	plan := DNSPlan{Servers: make([]string, 0, len(servers))}
	for _, address := range servers {
		plan.Servers = append(plan.Servers, address.String())
	}
	return m.s.ApplyDNS(ctx, plan)
}

func (m helperDNSManager) Restore(ctx context.Context) error { return m.s.RestoreDNS(ctx) }

func (m helperDNSManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), managerCloseTimeout)
	defer cancel()
	return m.Restore(ctx)
}
