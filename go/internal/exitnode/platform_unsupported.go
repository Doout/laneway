//go:build !linux

package exitnode

func NewRouteManager(RouteManagerConfig) (RouteManager, error)       { return nil, ErrUnsupported }
func NewDNSManager(DNSManagerConfig) (DNSManager, error)             { return nil, ErrUnsupported }
func NewGatewayManager(GatewayManagerConfig) (GatewayManager, error) { return nil, ErrUnsupported }
