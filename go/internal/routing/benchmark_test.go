package routing

import (
	"net/netip"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func BenchmarkLookup4096Routes(b *testing.B) {
	routes := make([]Route, 4096)
	for i := range routes {
		address := netip.AddrFrom4([4]byte{100, 96, byte(i >> 8), byte(i)})
		var node identity.NodeID
		node[14], node[15] = byte(i>>8), byte(i+1)
		routes[i] = Route{Prefix: netip.PrefixFrom(address, 32), NextHop: node}
	}
	snapshot, err := NewSnapshot(routes)
	if err != nil {
		b.Fatal(err)
	}
	target := netip.MustParseAddr("100.96.15.255")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, ok := snapshot.Lookup(target); !ok {
			b.Fatal("route not found")
		}
	}
}
