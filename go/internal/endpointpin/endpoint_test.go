package endpointpin

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type rotatingResolver struct {
	answers [][]netip.Addr
	calls   int
}

func (r *rotatingResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" || host != "relay.example" {
		return nil, errors.New("unexpected lookup")
	}
	answer := r.answers[r.calls%len(r.answers)]
	r.calls++
	return append([]netip.Addr(nil), answer...), nil
}

func TestHostPortPinsOneDNSAnswer(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("203.0.113.10")},
		{netip.MustParseAddr("203.0.113.11")},
	}}
	endpoint, err := HostPort(context.Background(), "relay.example:9443", Options{Resolver: resolver, IPv4Only: true})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.DialAddress != "203.0.113.10:9443" || endpoint.Address != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("pinned endpoint = %+v", endpoint)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want one", resolver.calls)
	}
	// A later DNS rotation cannot mutate the already returned dial target.
	_, _ = resolver.LookupNetIP(context.Background(), "ip", "relay.example")
	if endpoint.DialAddress != "203.0.113.10:9443" {
		t.Fatalf("DNS rotation changed pinned endpoint to %q", endpoint.DialAddress)
	}
}

func TestHTTPSPreservesOriginAndPinsDefaultPort(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{{netip.MustParseAddr("2001:db8::10")}}}
	endpoint, err := HTTPS(context.Background(), "https://relay.example", Options{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Original != "https://relay.example" || endpoint.DialAddress != "[2001:db8::10]:443" {
		t.Fatalf("pinned endpoint = %+v", endpoint)
	}
}

func TestIPv4OnlySkipsIPv6AndRejectsNoBypassCandidate(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{{
		netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("203.0.113.12"),
	}}}
	endpoint, err := HTTPS(context.Background(), "https://relay.example:8443", Options{Resolver: resolver, IPv4Only: true})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Address != netip.MustParseAddr("203.0.113.12") || endpoint.DialAddress != "203.0.113.12:8443" {
		t.Fatalf("pinned endpoint = %+v", endpoint)
	}

	resolver = &rotatingResolver{answers: [][]netip.Addr{{netip.MustParseAddr("2001:db8::10")}}}
	if _, err := HostPort(context.Background(), "relay.example:9443", Options{Resolver: resolver, IPv4Only: true}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("IPv6-only lookup error = %v, want ErrInvalidEndpoint", err)
	}
}

func TestHostPortsReturnsCanonicalSortedUniqueAnswers(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{{
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("203.0.113.12"),
		netip.MustParseAddr("::ffff:203.0.113.12"),
		netip.MustParseAddr("203.0.113.10"),
	}}}
	endpoints, err := HostPorts(context.Background(), "relay.example:9443", Options{Resolver: resolver}, 16)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.10:9443", "203.0.113.12:9443", "[2001:db8::10]:9443"}
	if len(endpoints) != len(want) {
		t.Fatalf("pinned endpoints = %+v", endpoints)
	}
	for i := range want {
		if endpoints[i].DialAddress != want[i] {
			t.Fatalf("pinned endpoint %d = %q, want %q", i, endpoints[i].DialAddress, want[i])
		}
	}
}

func TestHostPortsFiltersUnusableAddressClasses(t *testing.T) {
	resolver := &rotatingResolver{answers: [][]netip.Addr{{
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("::"),
		netip.MustParseAddr("ff02::1"), netip.MustParseAddr("192.0.2.10"),
	}}}
	endpoints, err := HostPorts(context.Background(), "relay.example:9443", Options{Resolver: resolver}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].DialAddress != "192.0.2.10:9443" {
		t.Fatalf("filtered endpoints = %+v", endpoints)
	}
}

func TestHostPortsRejectsAnswerOverflow(t *testing.T) {
	answers := make([]netip.Addr, 17)
	for i := range answers {
		answers[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
	}
	resolver := &rotatingResolver{answers: [][]netip.Addr{answers}}
	if _, err := HostPorts(context.Background(), "relay.example:9443", Options{Resolver: resolver}, 16); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("overflow error = %v, want ErrInvalidEndpoint", err)
	}
}

func TestRejectsInvalidEndpoints(t *testing.T) {
	for _, endpoint := range []string{"relay.example", ":9443", "relay.example:"} {
		if _, err := HostPort(context.Background(), endpoint, Options{}); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("HostPort(%q) error = %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"http://relay.example", "https://relay.example/path", "https://user@relay.example"} {
		if _, err := HTTPS(context.Background(), endpoint, Options{}); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("HTTPS(%q) error = %v", endpoint, err)
		}
	}
}
