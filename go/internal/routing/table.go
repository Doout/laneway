// Package routing provides lock-free longest-prefix lookups over immutable
// routing snapshots.
package routing

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"

	"laneway.dev/laneway/internal/identity"
)

var (
	ErrInvalidPrefix  = errors.New("invalid route prefix")
	ErrAmbiguousRoute = errors.New("ambiguous equal-prefix equal-metric routes")
)

type Route struct {
	Prefix      netip.Prefix
	NextHop     identity.NodeID
	RouteHandle uint32
	Metric      uint32
}

type Snapshot struct {
	routes []Route
	v4     [33]map[netip.Addr]Route
	v6     [129]map[netip.Addr]Route
}

func NewSnapshot(routes []Route) (*Snapshot, error) {
	s := &Snapshot{routes: make([]Route, 0, len(routes))}
	ties := make(map[struct {
		prefix netip.Prefix
		metric uint32
	}]struct{}, len(routes))
	for _, route := range routes {
		prefix := route.Prefix
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("%w: %v", ErrInvalidPrefix, prefix)
		}
		route.Prefix = prefix
		tie := struct {
			prefix netip.Prefix
			metric uint32
		}{prefix: prefix, metric: route.Metric}
		if _, exists := ties[tie]; exists {
			return nil, fmt.Errorf("%w: %s metric %d", ErrAmbiguousRoute, prefix, route.Metric)
		}
		ties[tie] = struct{}{}
		s.routes = append(s.routes, route)
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			if s.v4[bits] == nil {
				s.v4[bits] = make(map[netip.Addr]Route)
			}
			installBest(s.v4[bits], prefix.Addr(), route)
		} else {
			if s.v6[bits] == nil {
				s.v6[bits] = make(map[netip.Addr]Route)
			}
			installBest(s.v6[bits], prefix.Addr(), route)
		}
	}
	sort.Slice(s.routes, func(i, j int) bool {
		ai, aj := s.routes[i].Prefix, s.routes[j].Prefix
		if ai.Addr().Compare(aj.Addr()) != 0 {
			return ai.Addr().Compare(aj.Addr()) < 0
		}
		if ai.Bits() != aj.Bits() {
			return ai.Bits() < aj.Bits()
		}
		return routeLess(s.routes[i], s.routes[j])
	})
	return s, nil
}

func installBest(index map[netip.Addr]Route, addr netip.Addr, candidate Route) {
	current, exists := index[addr]
	if !exists || routeLess(candidate, current) {
		index[addr] = candidate
	}
}

// routeLess makes equal-prefix selection deterministic: lower metric wins,
// then the lexicographically lower next-hop ID, then the lower route handle.
func routeLess(a, b Route) bool {
	if a.Metric != b.Metric {
		return a.Metric < b.Metric
	}
	if cmp := bytes.Compare(a.NextHop[:], b.NextHop[:]); cmp != 0 {
		return cmp < 0
	}
	return a.RouteHandle < b.RouteHandle
}

func MustSnapshot(routes []Route) *Snapshot {
	s, err := NewSnapshot(routes)
	if err != nil {
		panic(err)
	}
	return s
}

// Routes returns a defensive copy, preserving snapshot immutability.
func (s *Snapshot) Routes() []Route {
	if s == nil {
		return nil
	}
	return append([]Route(nil), s.routes...)
}

func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.routes)
}

func (s *Snapshot) Lookup(addr netip.Addr) (Route, bool) {
	if s == nil || !addr.IsValid() || addr.Is4In6() {
		return Route{}, false
	}
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			if routes := s.v4[bits]; routes != nil {
				key := netip.PrefixFrom(addr, bits).Masked().Addr()
				if route, ok := routes[key]; ok {
					return route, true
				}
			}
		}
		return Route{}, false
	}
	for bits := 128; bits >= 0; bits-- {
		if routes := s.v6[bits]; routes != nil {
			key := netip.PrefixFrom(addr, bits).Masked().Addr()
			if route, ok := routes[key]; ok {
				return route, true
			}
		}
	}
	return Route{}, false
}

var emptySnapshot = MustSnapshot(nil)

// Table atomically publishes whole snapshots. Lookup takes no locks and sees
// either the complete old snapshot or the complete new one.
type Table struct {
	current atomic.Pointer[Snapshot]
}

func NewTable(initial *Snapshot) *Table {
	t := &Table{}
	t.Replace(initial)
	return t
}

func (t *Table) Lookup(addr netip.Addr) (Route, bool) {
	s := t.current.Load()
	if s == nil {
		s = emptySnapshot
	}
	return s.Lookup(addr)
}

func (t *Table) Replace(snapshot *Snapshot) {
	if snapshot == nil {
		snapshot = emptySnapshot
	}
	t.current.Store(snapshot)
}

func (t *Table) Snapshot() *Snapshot {
	s := t.current.Load()
	if s == nil {
		return emptySnapshot
	}
	return s
}
