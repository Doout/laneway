package subnet

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizePlanDefaultsSortsAndDeduplicates(t *testing.T) {
	plan, err := normalizePlan(ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.2.0/24"),
		netip.MustParsePrefix("10.2.0.0/16"),
		netip.MustParsePrefix("192.168.2.0/24"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != ModeNAT {
		t.Fatalf("mode = %q, want %q", plan.Mode, ModeNAT)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("192.168.2.0/24")}
	if len(plan.AuthorizedPrefixes) != len(want) {
		t.Fatalf("prefixes = %v", plan.AuthorizedPrefixes)
	}
	for i := range want {
		if plan.AuthorizedPrefixes[i] != want[i] {
			t.Fatalf("prefixes = %v, want %v", plan.AuthorizedPrefixes, want)
		}
	}
}

func TestNormalizePlanRejectsUnauthorizedShapes(t *testing.T) {
	tests := []ForwardingPlan{
		{Mode: "bridge", AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}},
		{AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("::/0")}},
		{AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}},
	}
	for _, test := range tests {
		if _, err := normalizePlan(test); !errors.Is(err, ErrInvalid) {
			t.Errorf("normalizePlan(%+v) error = %v", test, err)
		}
	}
}

func TestNormalizePlanAcceptsIPv6(t *testing.T) {
	plan, err := normalizePlan(ForwardingPlan{Routes: []ForwardingRoute{{
		Prefix: netip.MustParsePrefix("2001:db8:50::/64"), Mode: ModeNAT,
	}}})
	if err != nil || len(plan.Routes) != 1 || !plan.Routes[0].Prefix.Addr().Is6() {
		t.Fatalf("IPv6 forwarding plan = %+v, %v", plan, err)
	}
}

func TestNormalizePlanPreservesPerPrefixModes(t *testing.T) {
	plan, err := normalizePlan(ForwardingPlan{Routes: []ForwardingRoute{
		{Prefix: netip.MustParsePrefix("192.168.2.0/24"), Mode: ModeRouted},
		{Prefix: netip.MustParsePrefix("10.2.0.0/16"), Mode: ModeNAT},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != "" || len(plan.Routes) != 2 || plan.Routes[0].Mode != ModeNAT || plan.Routes[1].Mode != ModeRouted {
		t.Fatalf("normalized mixed plan = %+v", plan)
	}
}

func TestMemoryForwardingManagerLifecycle(t *testing.T) {
	m := NewMemoryForwardingManager()
	input := ForwardingPlan{AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := m.Apply(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.AuthorizedPrefixes[0] = netip.MustParsePrefix("192.168.0.0/16")
	got, enabled := m.Snapshot()
	if !enabled || got.Mode != ModeNAT || got.AuthorizedPrefixes[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("snapshot = %+v, enabled %v", got, enabled)
	}
	if err := m.Apply(context.Background(), ForwardingPlan{}); err != nil {
		t.Fatal(err)
	}
	_, enabled = m.Snapshot()
	if enabled {
		t.Fatal("empty plan did not disable forwarding")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(context.Background(), ForwardingPlan{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Apply after Close error = %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("idempotent Close = %v", err)
	}
}
