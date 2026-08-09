//go:build !linux && !darwin

package platform

func NewRouteManager(RouteManagerConfig) (RouteManager, error) {
	return nil, ErrUnsupported
}
