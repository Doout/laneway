//go:build !linux

package subnet

func NewForwardingManager(ForwardingManagerConfig) (ForwardingManager, error) {
	return nil, ErrUnsupported
}
