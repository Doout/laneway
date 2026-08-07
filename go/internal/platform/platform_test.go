package platform

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

func TestNormalizeTUNConfig(t *testing.T) {
	config, err := normalizeTUNConfig(TUNConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != DefaultTUNName || config.MTU != DefaultMTU {
		t.Fatalf("unexpected defaults: %+v", config)
	}
	for _, config := range []TUNConfig{
		{Name: "bad/name", MTU: 1280},
		{Name: "name-that-is-too-long", MTU: 1280},
		{Name: "lane0", MTU: MinMTU - 1},
		{Name: "lane0", MTU: MaxMTU + 1},
		{Addresses: []netip.Prefix{netip.MustParsePrefix("100.96.0.0/24")}},
		{MTU: 1200, Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}},
		{MTU: 1280, Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}},
		{Addresses: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}},
		{Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.96.0.1/32"),
			netip.MustParsePrefix("100.96.0.1/32"),
		}},
	} {
		if _, err := normalizeTUNConfig(config); !errors.Is(err, ErrInvalidTUN) {
			t.Fatalf("normalizeTUNConfig(%+v) error = %v", config, err)
		}
	}
	dual, err := normalizeTUNConfig(TUNConfig{MTU: 1280, Addresses: []netip.Prefix{
		netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("2001:db8::1/128"),
	}})
	if err != nil || len(dual.Addresses) != 2 {
		t.Fatalf("dual-stack TUN config = %+v, %v", dual, err)
	}
}

func TestNormalizePlanValidationAndBypass(t *testing.T) {
	bypass := netip.MustParseAddr("100.96.0.2")
	plan := RoutePlan{
		Routes: []Route{
			{Prefix: netip.MustParsePrefix("100.96.0.1/32"), Metric: 10},
			{Prefix: netip.MustParsePrefix("100.96.0.2/32"), Metric: 20},
		},
		TransportBypass: []netip.Addr{bypass},
	}
	desired, err := normalizePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 1 || desired["100.96.0.1/32"].Metric != 10 {
		t.Fatalf("unexpected filtered plan: %+v", desired)
	}

	invalid := []RoutePlan{
		{Routes: []Route{{Prefix: netip.MustParsePrefix("100.96.0.1/24")}}},
		{Routes: []Route{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}},
		{Routes: []Route{{Prefix: netip.MustParsePrefix("::/0")}}},
		{Routes: []Route{{Prefix: netip.Prefix{}}}},
		{Routes: []Route{
			{Prefix: netip.MustParsePrefix("100.96.0.1/32"), Metric: 1},
			{Prefix: netip.MustParsePrefix("100.96.0.1/32"), Metric: 2},
		}},
		{TransportBypass: []netip.Addr{netip.IPv4Unspecified()}},
	}
	for _, plan := range invalid {
		if _, err := normalizePlan(plan); !errors.Is(err, ErrInvalidRoute) {
			t.Fatalf("normalizePlan(%+v) error = %v", plan, err)
		}
	}
}

func TestNormalizePlanAcceptsIPv6AndFamilySpecificBypass(t *testing.T) {
	v6 := netip.MustParsePrefix("2001:db8::1/128")
	desired, err := normalizePlan(RoutePlan{
		Routes:          []Route{{Prefix: v6}, {Prefix: netip.MustParsePrefix("100.96.0.1/32")}},
		TransportBypass: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := desired[v6.String()]; exists || len(desired) != 1 {
		t.Fatalf("family-specific bypass result = %#v", desired)
	}
}

func TestNormalizePlanAcceptsSubnetPrefix(t *testing.T) {
	desired, err := normalizePlan(RoutePlan{Routes: []Route{{
		Prefix: netip.MustParsePrefix("192.168.50.0/24"), Metric: 10,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := desired["192.168.50.0/24"]; !ok {
		t.Fatalf("subnet route missing: %#v", desired)
	}
}

func TestMemoryTUNPacketFlowCancellationAndClose(t *testing.T) {
	address := netip.MustParsePrefix("100.96.0.1/32")
	tun, err := NewMemoryTUN(TUNConfig{Name: "test0", MTU: 1280, Addresses: []netip.Prefix{address}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	addresses := tun.Addresses()
	if len(addresses) != 1 || addresses[0] != address {
		t.Fatalf("Addresses = %v", addresses)
	}
	addresses[0] = netip.MustParsePrefix("100.96.0.2/32")
	if tun.Addresses()[0] != address {
		t.Fatal("Addresses returned a mutable internal slice")
	}
	packet := []byte{0x45, 0, 0, 20}
	if err := tun.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	packet[0] = 0
	buffer := make([]byte, 32)
	n, err := tun.Read(context.Background(), buffer)
	if err != nil || n != 4 || buffer[0] != 0x45 {
		t.Fatalf("Read = (%d, %v), packet %x", n, err, buffer[:n])
	}
	if _, err := tun.Write(context.Background(), []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	received, err := tun.Receive(context.Background())
	if err != nil || string(received) != "\x01\x02\x03" {
		t.Fatalf("Receive = (%x, %v)", received, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tun.Read(ctx, buffer); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Read error = %v", err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := tun.Read(context.Background(), buffer); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Read error = %v", err)
	}
}

func TestMemoryTUNBoundsAndBlockingWrite(t *testing.T) {
	tun, err := NewMemoryTUN(TUNConfig{MTU: 1280}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if _, err := tun.Write(context.Background(), make([]byte, 1281)); !errors.Is(err, ErrInvalidTUN) {
		t.Fatalf("oversize Write error = %v", err)
	}
	if err := tun.Inject(context.Background(), []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := tun.Read(context.Background(), make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short Read error = %v", err)
	}
	if _, err := tun.Write(context.Background(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := tun.Write(ctx, []byte{2}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Write error = %v", err)
	}
}

func TestMemoryRouteManager(t *testing.T) {
	manager := NewMemoryRouteManager()
	first := Route{Prefix: netip.MustParsePrefix("100.96.0.1/32"), Metric: 10}
	second := Route{Prefix: netip.MustParsePrefix("100.96.0.2/32"), Metric: 20}
	if err := manager.Apply(context.Background(), RoutePlan{Routes: []Route{second, first}}); err != nil {
		t.Fatal(err)
	}
	if got := manager.Routes(); len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("Routes = %+v", got)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Apply(cancelled, RoutePlan{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Apply error = %v", err)
	}
	if len(manager.Routes()) != 2 {
		t.Fatal("cancelled apply changed routes")
	}
	if err := manager.Restore(context.Background()); err != nil || len(manager.Routes()) != 0 {
		t.Fatalf("Restore = %v, routes %+v", err, manager.Routes())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), RoutePlan{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Apply error = %v", err)
	}
}
