//go:build darwin

package exitnode

import (
	"context"
	"net/netip"
)

type darwinUnsupportedRoutes struct{}

func (darwinUnsupportedRoutes) Apply(context.Context, RoutePlan) error { return ErrUnsupported }
func (darwinUnsupportedRoutes) Restore(context.Context) error          { return nil }
func (darwinUnsupportedRoutes) Close() error                           { return nil }

type darwinUnsupportedDNS struct{}

func (darwinUnsupportedDNS) Apply(context.Context, []netip.Addr) error { return ErrUnsupported }
func (darwinUnsupportedDNS) Restore(context.Context) error             { return nil }
func (darwinUnsupportedDNS) Close() error                              { return nil }

func NewRouteManager(config RouteManagerConfig) (RouteManager, error) {
	if _, err := normalizeRouteConfig(config); err != nil {
		return nil, err
	}
	return darwinUnsupportedRoutes{}, nil
}

func NewDNSManager(config DNSManagerConfig) (DNSManager, error) {
	if _, err := normalizeDNSConfig(config); err != nil {
		return nil, err
	}
	return darwinUnsupportedDNS{}, nil
}

func NewGatewayManager(GatewayManagerConfig) (GatewayManager, error) {
	return nil, ErrUnsupported
}
