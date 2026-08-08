//go:build !linux

package wireguard

func NewFirewallManager(FirewallConfig) (FirewallManager, error) { return nil, ErrUnsupported }
