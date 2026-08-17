package routing

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func node(last byte) identity.NodeID {
	var id identity.NodeID
	id[15] = last
	return id
}

func route(prefix string, metric uint32, next byte, handle uint32) Route {
	return Route{Prefix: netip.MustParsePrefix(prefix), Metric: metric, NextHop: node(next), RouteHandle: handle}
}

func TestLongestPrefixAndMetric(t *testing.T) {
	routes := []Route{
		route("0.0.0.0/0", 100, 1, 1),
		route("192.168.50.0/24", 50, 2, 2),
		route("192.168.50.0/24", 10, 3, 3),
		route("192.168.50.20/32", 100, 4, 4),
	}
	table := NewTable(MustSnapshot(routes))
	for _, test := range []struct {
		addr   string
		handle uint32
	}{
		{"8.8.8.8", 1},
		{"192.168.50.30", 3},
		{"192.168.50.20", 4},
	} {
		got, ok := table.Lookup(netip.MustParseAddr(test.addr))
		if !ok || got.RouteHandle != test.handle {
			t.Fatalf("lookup %s = %#v, %v", test.addr, got, ok)
		}
	}
}

func TestRejectsTieAndRoutesIPv6(t *testing.T) {
	if _, err := NewSnapshot([]Route{
		route("2001:db8::/32", 10, 9, 1),
		route("2001:db8::/32", 10, 2, 99),
	}); !errors.Is(err, ErrAmbiguousRoute) {
		t.Fatalf("tie error = %v", err)
	}
	s := MustSnapshot([]Route{
		route("2001:db8::/32", 10, 2, 99),
		route("2001:db8:1::/48", 50, 8, 3),
	})
	if got, ok := s.Lookup(netip.MustParseAddr("2001:db8:2::1")); !ok || got.NextHop != node(2) {
		t.Fatalf("tie result %#v, %v", got, ok)
	}
	if got, ok := s.Lookup(netip.MustParseAddr("2001:db8:1::1")); !ok || got.RouteHandle != 3 {
		t.Fatalf("long prefix result %#v, %v", got, ok)
	}
}

func TestSnapshotValidationAndImmutability(t *testing.T) {
	for _, prefix := range []netip.Prefix{
		{},
		netip.MustParsePrefix("192.168.1.1/24"),
		netip.PrefixFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 128),
	} {
		if _, err := NewSnapshot([]Route{{Prefix: prefix}}); !errors.Is(err, ErrInvalidPrefix) {
			t.Fatalf("prefix %v: %v", prefix, err)
		}
	}
	in := []Route{route("10.0.0.0/8", 1, 1, 7)}
	s := MustSnapshot(in)
	in[0].RouteHandle = 99
	copyOut := s.Routes()
	copyOut[0].RouteHandle = 100
	got, _ := s.Lookup(netip.MustParseAddr("10.1.2.3"))
	if got.RouteHandle != 7 {
		t.Fatalf("snapshot mutated: %#v", got)
	}
}

func TestAtomicReplaceConcurrentReaders(t *testing.T) {
	a := MustSnapshot([]Route{route("10.0.0.0/8", 0, 1, 1)})
	b := MustSnapshot([]Route{route("10.0.0.0/8", 0, 2, 2)})
	table := NewTable(a)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3"))
				if !ok || (got.RouteHandle != 1 && got.RouteHandle != 2) {
					t.Errorf("partial snapshot: %#v", got)
					return
				}
			}
		}()
	}
	for range 1000 {
		table.Replace(b)
		table.Replace(a)
	}
	wg.Wait()
}

func FuzzSnapshotLookup(f *testing.F) {
	f.Add([]byte{10, 1, 2, 3}, uint8(8))
	f.Fuzz(func(t *testing.T, octets []byte, bits uint8) {
		if len(octets) != 4 {
			return
		}
		bits %= 33
		addr := netip.AddrFrom4([4]byte{octets[0], octets[1], octets[2], octets[3]})
		prefix := netip.PrefixFrom(addr, int(bits)).Masked()
		s, err := NewSnapshot([]Route{{Prefix: prefix, RouteHandle: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Lookup(addr); !ok {
			t.Fatalf("%v did not match %v", addr, prefix)
		}
	})
}
