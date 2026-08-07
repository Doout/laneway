// Package endpointpin resolves a transport endpoint once and returns a
// numeric dial target. Callers can install a bypass for Endpoint.Address and
// know that reconnects cannot silently follow later DNS answers outside it.
package endpointpin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"

	"laneway.dev/laneway/internal/netvalidate"
)

var ErrInvalidEndpoint = errors.New("endpoint pin: invalid endpoint")

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Options struct {
	Resolver Resolver
	// IPv4Only is required by callers whose bypass route implementation only
	// supports IPv4 host routes.
	IPv4Only bool
}

type Endpoint struct {
	Original    string
	DialAddress string
	Address     netip.Addr
}

// HostPort pins a host:port transport endpoint to one numeric address.
func HostPort(ctx context.Context, address string, options Options) (Endpoint, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return Endpoint{}, fmt.Errorf("%w: expected host:port", ErrInvalidEndpoint)
	}
	selected, err := resolve(ctx, host, options)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Original: address, DialAddress: net.JoinHostPort(selected.String(), port), Address: selected}, nil
}

// HostPorts pins a host:port transport endpoint to every usable numeric DNS
// answer under the caller-supplied bound. Numeric endpoints return exactly one
// result. DNS answers are canonicalized, sorted, and deduplicated so resolver
// order cannot affect the returned target set.
func HostPorts(ctx context.Context, address string, options Options, maxAnswers int) ([]Endpoint, error) {
	if maxAnswers <= 0 {
		return nil, fmt.Errorf("%w: address limit must be positive", ErrInvalidEndpoint)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("%w: expected host:port", ErrInvalidEndpoint)
	}
	selected, err := resolveAll(ctx, host, options, maxAnswers)
	if err != nil {
		return nil, err
	}
	endpoints := make([]Endpoint, 0, len(selected))
	for _, candidate := range selected {
		endpoints = append(endpoints, Endpoint{
			Original: address, DialAddress: net.JoinHostPort(candidate.String(), port), Address: candidate,
		})
	}
	return endpoints, nil
}

// HTTPS pins an HTTPS origin while retaining the original URL. The original
// hostname remains available to HTTP Host, SNI, and certificate verification;
// only the underlying TCP dial target is numeric.
func HTTPS(ctx context.Context, endpoint string, options Options) (Endpoint, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return Endpoint{}, fmt.Errorf("%w: expected HTTPS origin", ErrInvalidEndpoint)
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	selected, err := resolve(ctx, parsed.Hostname(), options)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{Original: endpoint, DialAddress: net.JoinHostPort(selected.String(), port), Address: selected}, nil
}

func resolve(ctx context.Context, host string, options Options) (netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if usable(parsed, options.IPv4Only) {
			return parsed, nil
		}
		return netip.Addr{}, fmt.Errorf("%w: unusable address %q", ErrInvalidEndpoint, host)
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolved, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("endpoint pin: resolve %q: %w", host, err)
	}
	for _, candidate := range resolved {
		candidate = candidate.Unmap()
		if usable(candidate, options.IPv4Only) {
			return candidate, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %q resolved to no usable addresses", ErrInvalidEndpoint, host)
}

func resolveAll(ctx context.Context, host string, options Options, maxAnswers int) ([]netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if usable(parsed, options.IPv4Only) {
			return []netip.Addr{parsed}, nil
		}
		return nil, fmt.Errorf("%w: unusable address %q", ErrInvalidEndpoint, host)
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolved, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("endpoint pin: resolve %q: %w", host, err)
	}
	if len(resolved) > maxAnswers {
		return nil, fmt.Errorf("%w: %q resolved outside the 1..=%d answer bound", ErrInvalidEndpoint, host, maxAnswers)
	}
	unique := make(map[netip.Addr]struct{}, len(resolved))
	selected := make([]netip.Addr, 0, len(resolved))
	for _, candidate := range resolved {
		candidate = candidate.Unmap()
		if !usable(candidate, options.IPv4Only) {
			continue
		}
		if _, exists := unique[candidate]; exists {
			continue
		}
		unique[candidate] = struct{}{}
		selected = append(selected, candidate)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%w: %q resolved to no usable addresses", ErrInvalidEndpoint, host)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Compare(selected[j]) < 0 })
	return selected, nil
}

func usable(address netip.Addr, ipv4Only bool) bool {
	return netvalidate.UsableRelayAddress(address) &&
		(!ipv4Only || address.Is4())
}
