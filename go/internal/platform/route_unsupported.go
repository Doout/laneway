//go:build !linux

package platform

func NewRouteManager(RouteManagerConfig) (RouteManager, error) {
	return nil, ErrUnsupported
}
