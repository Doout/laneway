package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

func testRegistry(t testing.TB, mutate func(*Config)) *Registry {
	t.Helper()
	config := Config{
		MaxSessions:           64,
		MaxHandlesPerSession:  64,
		OutboundQueueCapacity: 16,
		MaxPacketPayload:      1500,
		DuplicatePolicy:       RejectDuplicate,
		QueuePolicy:           DropNewest,
	}
	if mutate != nil {
		mutate(&config)
	}
	r, err := NewRegistry(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func networkID(last byte) identity.NetworkID {
	var id identity.NetworkID
	id[len(id)-1] = last
	return id
}

func nodeID(last byte) identity.NodeID {
	var id identity.NodeID
	id[len(id)-1] = last
	return id
}

func register(t testing.TB, r *Registry, network, node byte, prefixes ...string) *Session {
	t.Helper()
	parsed := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		parsed[i] = netip.MustParsePrefix(prefix)
	}
	s, err := r.Register(SessionConfig{
		Identity:           identity.NodeIdentity{NetworkID: networkID(network), NodeID: nodeID(node)},
		AuthorizedPrefixes: parsed,
		AllowIPv6:          true,
		AllowE2E:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func wireGuardFrame(t testing.TB, handle uint32) []byte {
	t.Helper()
	payload := make([]byte, 148)
	payload[0] = 1
	frame, err := protocol.EncodeWireGuardPacket(nil, handle, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func ipv4Frame(t testing.TB, handle uint32, source, destination string, extra int) []byte {
	t.Helper()
	payload := make([]byte, 20+extra)
	payload[0] = 0x45
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
	payload[8] = 64
	payload[9] = 17
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()
	copy(payload[12:16], src[:])
	copy(payload[16:20], dst[:])
	frame, err := protocol.EncodePacket(nil, protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: handle,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func ipv6Frame(t *testing.T, handle uint32, source, destination string, extra int) []byte {
	t.Helper()
	payload := make([]byte, 40+extra)
	payload[0] = 0x60
	binary.BigEndian.PutUint16(payload[4:6], uint16(extra))
	payload[6] = 17
	payload[7] = 64
	src := netip.MustParseAddr(source).As16()
	dst := netip.MustParseAddr(destination).As16()
	copy(payload[8:24], src[:])
	copy(payload[24:40], dst[:])
	frame, err := protocol.EncodePacket(nil, protocol.PacketHeader{
		Version: protocol.PacketVersion1, RouteHandle: handle,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestNewRegistryRejectsUnboundedOrUnknownPolicies(t *testing.T) {
	valid := Config{MaxSessions: 1, MaxHandlesPerSession: 1, OutboundQueueCapacity: 1, MaxPacketPayload: 1200}
	tests := []Config{
		{},
		func() Config { c := valid; c.MaxSessions = 0; return c }(),
		func() Config { c := valid; c.MaxHandlesPerSession = 0; return c }(),
		func() Config { c := valid; c.OutboundQueueCapacity = 0; return c }(),
		func() Config { c := valid; c.MaxPacketPayload = protocol.MaxPacketPayload + 1; return c }(),
		func() Config { c := valid; c.DuplicatePolicy = 99; return c }(),
		func() Config { c := valid; c.QueuePolicy = 99; return c }(),
	}
	for i, config := range tests {
		if _, err := NewRegistry(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
}

func TestRegisterValidationAndLimits(t *testing.T) {
	r := testRegistry(t, func(c *Config) { c.MaxSessions = 1 })
	if _, err := r.Register(SessionConfig{}); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("zero identity: %v", err)
	}
	if _, err := r.Register(SessionConfig{
		Identity:           identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	}); !errors.Is(err, ErrInvalidPrefix) {
		t.Fatalf("noncanonical prefix: %v", err)
	}
	first := register(t, r, 1, 1, "10.0.0.1/32")
	if first.MaxPacketPayload() != 1500 || first.QueueCapacity() != 16 {
		t.Fatalf("unexpected limits: payload=%d queue=%d", first.MaxPacketPayload(), first.QueueCapacity())
	}
	if _, err := r.Register(SessionConfig{
		Identity: identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(2)},
	}); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("session limit: %v", err)
	}
	if got, ok := r.Lookup(networkID(1), nodeID(1)); !ok || got != first {
		t.Fatalf("lookup returned %p, %v", got, ok)
	}
}

func TestDuplicatePoliciesAndStaleCleanup(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		r := testRegistry(t, nil)
		original := register(t, r, 1, 1, "10.0.0.1/32")
		if _, err := r.Register(SessionConfig{
			Identity: identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)},
		}); !errors.Is(err, ErrDuplicateSession) {
			t.Fatalf("duplicate: %v", err)
		}
		if got, ok := r.Lookup(networkID(1), nodeID(1)); !ok || got != original {
			t.Fatal("duplicate rejection replaced original")
		}
		if r.Metrics().DuplicateRejected != 1 {
			t.Fatal("duplicate metric not incremented")
		}
	})

	t.Run("replace", func(t *testing.T) {
		r := testRegistry(t, func(c *Config) { c.DuplicatePolicy = ReplaceDuplicate })
		old := register(t, r, 1, 1, "10.0.0.1/32")
		peer := register(t, r, 1, 2, "10.0.0.2/32")
		if _, err := r.BindPeers(old, peer); err != nil {
			t.Fatal(err)
		}
		replacement, err := r.Register(SessionConfig{
			Identity:           identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)},
			AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		})
		if err != nil {
			t.Fatal(err)
		}
		if r.Unregister(old) {
			t.Fatal("stale unregister removed or claimed replacement")
		}
		if got, ok := r.Lookup(networkID(1), nodeID(1)); !ok || got != replacement {
			t.Fatal("replacement is not current")
		}
		select {
		case <-old.Done():
		default:
			t.Fatal("replaced session was not closed")
		}
		if r.Metrics().Bindings != 0 {
			t.Fatal("replacement did not clean old peer bindings")
		}
	})
}

func TestBindForwardAndRewriteIPv4AndIPv6(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.1/32", "2001:db8::1/128")
	b := register(t, r, 1, 2, "10.0.0.2/32", "2001:db8::2/128")
	pair, err := r.BindPeers(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if pair.First.Handle == 0 || pair.Second.Handle == 0 {
		t.Fatal("zero handle allocated")
	}
	again, err := r.BindPeers(a, b)
	if err != nil || again.First.Handle != pair.First.Handle || again.Second.Handle != pair.Second.Handle {
		t.Fatalf("binding is not idempotent: %#v, %v", again, err)
	}

	inputs := [][]byte{
		ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 8),
		ipv6Frame(t, pair.First.Handle, "2001:db8::1", "2001:db8::2", 8),
	}
	for _, input := range inputs {
		original := append([]byte(nil), input...)
		if err := r.Forward(a, input); err != nil {
			t.Fatal(err)
		}
		if string(input) != string(original) {
			t.Fatal("Forward mutated caller frame")
		}
		out, err := b.Dequeue(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		header, payload, err := protocol.DecodePacket(out)
		if err != nil {
			t.Fatal(err)
		}
		if header.RouteHandle != pair.Second.Handle {
			t.Fatalf("got rewritten handle %d, want %d", header.RouteHandle, pair.Second.Handle)
		}
		if string(payload) != string(input[protocol.PacketHeaderSize:]) {
			t.Fatal("payload changed while forwarding")
		}
	}
	metrics := r.Metrics()
	if metrics.ForwardedPackets != 2 || metrics.Bindings != 2 || metrics.QueuedPackets != 0 {
		t.Fatalf("unexpected metrics: %#v", metrics)
	}
}

func TestForwardRejectsIPv6UnlessBothSessionsNegotiatedIt(t *testing.T) {
	r := testRegistry(t, nil)
	prefixesA := []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")}
	prefixesB := []netip.Prefix{netip.MustParsePrefix("2001:db8::2/128")}
	a, err := r.Register(SessionConfig{Identity: identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)}, AuthorizedPrefixes: prefixesA, AllowIPv6: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Register(SessionConfig{Identity: identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(2)}, AuthorizedPrefixes: prefixesB})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := r.BindPeers(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Forward(a, ipv6Frame(t, pair.First.Handle, "2001:db8::1", "2001:db8::2", 8)); !errors.Is(err, ErrCapabilityNotNegotiated) {
		t.Fatalf("Forward error = %v, want ErrCapabilityNotNegotiated", err)
	}
	if got := r.Metrics().DroppedCapability; got != 1 {
		t.Fatalf("capability drops = %d, want 1", got)
	}
}

func TestForwardOpaqueWireGuardPreservesCiphertextAndRequiresCapability(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, err := r.BindPeers(a, b)
	if err != nil {
		t.Fatal(err)
	}
	input := wireGuardFrame(t, pair.First.Handle)
	if err := r.Forward(a, input); err != nil {
		t.Fatal(err)
	}
	out, err := b.Dequeue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := protocol.DecodeFrame(out)
	if err != nil || header.Flags != protocol.PacketFlagE2EEncrypted || header.RouteHandle != pair.Second.Handle {
		t.Fatalf("forwarded header=%+v error=%v", header, err)
	}
	if string(payload) != string(input[protocol.PacketHeaderSize:]) {
		t.Fatal("relay changed opaque WireGuard ciphertext")
	}

	withoutCapability, err := r.Register(SessionConfig{
		Identity:           identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(3)},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.3/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	secondPair, err := r.BindPeers(a, withoutCapability)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Forward(a, wireGuardFrame(t, secondPair.First.Handle)); !errors.Is(err, ErrCapabilityNotNegotiated) {
		t.Fatalf("capability error = %v", err)
	}
}

func TestCrossNetworkIsolation(t *testing.T) {
	r := testRegistry(t, nil)
	n1a := register(t, r, 1, 1, "10.1.0.1/32")
	n1b := register(t, r, 1, 2, "10.1.0.2/32")
	n2a := register(t, r, 2, 1, "10.2.0.1/32")
	n2b := register(t, r, 2, 2, "10.2.0.2/32")
	if _, err := r.BindPeers(n1a, n2b); !errors.Is(err, ErrCrossNetwork) {
		t.Fatalf("cross-network bind: %v", err)
	}
	pair1, _ := r.BindPeers(n1a, n1b)
	pair2, _ := r.BindPeers(n2a, n2b)
	if pair1.First.Handle != pair2.First.Handle {
		t.Fatal("test requires equal session-local handles")
	}
	// A handle collision in another network cannot affect resolution. This
	// packet still targets n1b and is rejected for its n2b destination.
	err := r.Forward(n1a, ipv4Frame(t, pair1.First.Handle, "10.1.0.1", "10.2.0.2", 0))
	if !errors.Is(err, ErrDestinationUnauthorized) {
		t.Fatalf("cross-network destination: %v", err)
	}
	if n2b.QueueLen() != 0 {
		t.Fatal("packet escaped into another network")
	}
}

func TestSpoofAndMalformedRejection(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.0/24")
	b := register(t, r, 1, 2, "10.0.1.0/24")
	pair, _ := r.BindPeers(a, b)
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"source", ipv4Frame(t, pair.First.Handle, "10.9.0.1", "10.0.1.2", 0), ErrSourceUnauthorized},
		{"destination", ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.9.0.2", 0), ErrDestinationUnauthorized},
		{"unknown handle", ipv4Frame(t, 999, "10.0.0.1", "10.0.1.2", 0), ErrUnknownHandle},
		{"malformed", []byte{0x10}, protocol.ErrShortPacket},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := r.Forward(a, test.frame); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	if b.QueueLen() != 0 {
		t.Fatal("invalid packet was queued")
	}
	m := r.Metrics()
	if m.DroppedSource != 1 || m.DroppedDestination != 1 || m.DroppedUnknownHandle != 1 || m.DroppedMalformed != 1 {
		t.Fatalf("reason metrics: %#v", m)
	}
}

func TestPayloadLimitAndHandleLimit(t *testing.T) {
	r := testRegistry(t, func(c *Config) { c.MaxHandlesPerSession = 1 })
	a, err := r.Register(SessionConfig{
		Identity:           identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(1)},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		MaxPacketPayload:   20,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := register(t, r, 1, 2, "10.0.0.2/32")
	c := register(t, r, 1, 3, "10.0.0.3/32")
	pair, _ := r.BindPeers(a, b)
	if pair.First.MaxPacketPayload != 20 || pair.Second.MaxPacketPayload != 20 {
		t.Fatalf("binding limit not negotiated: %#v", pair)
	}
	if _, err := r.BindPeers(a, c); !errors.Is(err, ErrHandleLimit) {
		t.Fatalf("handle limit: %v", err)
	}
	if err := r.Forward(a, ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 1)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("payload limit: %v", err)
	}
	if r.Metrics().DroppedTooLarge != 1 {
		t.Fatal("payload drop not counted")
	}
}

func TestReleaseAndDisconnectCleanup(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, b)
	if err := r.Release(b, pair.Second.Handle); err != nil {
		t.Fatal(err)
	}
	if err := r.Forward(a, ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 0)); !errors.Is(err, ErrNoReturnHandle) {
		t.Fatalf("missing reverse handle: %v", err)
	}
	if err := r.Release(b, pair.Second.Handle); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("double release: %v", err)
	}
	oldSecondHandle := pair.Second.Handle
	pair, _ = r.BindPeers(a, b)
	if pair.Second.Handle == oldSecondHandle {
		t.Fatal("released handle was reused in a live session")
	}
	if err := r.Forward(a, ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 0)); err != nil {
		t.Fatal(err)
	}
	if !r.Unregister(b) {
		t.Fatal("unregister failed")
	}
	if r.Unregister(b) {
		t.Fatal("second unregister succeeded")
	}
	if err := r.Forward(a, ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 0)); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("stale handle after disconnect: %v", err)
	}
	if _, _, err := b.TryDequeue(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("closed dequeue: %v", err)
	}
	m := r.Metrics()
	if m.Sessions != 1 || m.Bindings != 0 || m.QueuedPackets != 0 || m.DroppedDisconnect != 1 {
		t.Fatalf("cleanup metrics: %#v", m)
	}
}

func TestRegistryCloseCleansAllStateAndRejectsRegister(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	if _, err := r.BindPeers(a, b); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if got := r.Metrics(); got.Sessions != 0 || got.Bindings != 0 {
		t.Fatalf("state after close: %#v", got)
	}
	if _, err := r.Register(SessionConfig{
		Identity: identity.NodeIdentity{NetworkID: networkID(1), NodeID: nodeID(3)},
	}); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("register after close: %v", err)
	}
	for _, session := range []*Session{a, b} {
		select {
		case <-session.Done():
		default:
			t.Fatal("session remained open after registry close")
		}
	}
}

func TestDisconnectCleansPeerAfterOneWayRelease(t *testing.T) {
	r := testRegistry(t, nil)
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, b)
	if err := r.Release(a, pair.First.Handle); err != nil {
		t.Fatal(err)
	}
	if got := r.Metrics().Bindings; got != 1 {
		t.Fatalf("bindings after one-way release = %d, want 1", got)
	}
	if !r.Unregister(a) {
		t.Fatal("unregister failed")
	}
	if got := r.Metrics().Bindings; got != 0 {
		t.Fatalf("stale peer binding after disconnect: %d", got)
	}
	if err := r.Forward(b, ipv4Frame(t, pair.Second.Handle, "10.0.0.2", "10.0.0.1", 0)); !errors.Is(err, ErrUnknownHandle) {
		t.Fatalf("stale peer handle: %v", err)
	}
}

func TestQueueExhaustionDropsNewestAndPreservesFIFO(t *testing.T) {
	r := testRegistry(t, func(c *Config) { c.OutboundQueueCapacity = 2 })
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, b)
	first := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 1)
	second := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 2)
	third := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 3)
	for _, frame := range [][]byte{first, second} {
		if err := r.Forward(a, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Forward(a, third); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
	for _, wantLen := range []int{len(first), len(second)} {
		got, ok, err := b.TryDequeue()
		if err != nil || !ok || len(got) != wantLen {
			t.Fatalf("dequeue len=%d ok=%v err=%v, want len=%d", len(got), ok, err, wantLen)
		}
	}
	if _, ok, err := b.TryDequeue(); err != nil || ok {
		t.Fatalf("queue not empty: ok=%v err=%v", ok, err)
	}
	m := r.Metrics()
	if m.ForwardedPackets != 2 || m.DroppedQueueFull != 1 {
		t.Fatalf("queue metrics: %#v", m)
	}
}

func TestForwardAndLeasedDequeueReuseQueuedFrameBuffer(t *testing.T) {
	r := testRegistry(t, func(c *Config) { c.OutboundQueueCapacity = 1 })
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, b)
	frame := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 1200-20)
	forwardAndRelease := func() bool {
		if err := r.Forward(a, frame); err != nil {
			return false
		}
		buffer, err := b.DequeueBuffer(context.Background())
		if err != nil || len(buffer.Bytes()) != len(frame) {
			return false
		}
		buffer.Release()
		return true
	}
	if !forwardAndRelease() {
		t.Fatal("warm forward failed")
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		if !forwardAndRelease() {
			t.Fatal("forward failed")
		}
	}); allocations != 0 {
		t.Fatalf("warm forward + leased dequeue allocations = %v, want zero", allocations)
	}
}

func BenchmarkForwardLeasedQueue(b *testing.B) {
	r := testRegistry(b, func(c *Config) { c.OutboundQueueCapacity = 1 })
	a := register(b, r, 1, 1, "10.0.0.1/32")
	recipient := register(b, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, recipient)
	frame := ipv4Frame(b, pair.First.Handle, "10.0.0.1", "10.0.0.2", 1200-20)
	_ = r.Forward(a, frame)
	warm, _ := recipient.DequeueBuffer(context.Background())
	warm.Release()
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for range b.N {
		_ = r.Forward(a, frame)
		buffer, _ := recipient.DequeueBuffer(context.Background())
		buffer.Release()
	}
}

func TestForwardDoesNotAcquireRegistryControlLock(t *testing.T) {
	r := testRegistry(t, nil)
	sender := register(t, r, 1, 1, "10.0.0.1/32")
	recipient := register(t, r, 1, 2, "10.0.0.2/32")
	pair, err := r.BindPeers(sender, recipient)
	if err != nil {
		t.Fatal(err)
	}
	frame := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 0)

	// Holding the process-wide control lock must not stall packet lookup or
	// enqueue. Forward reads only the sender's immutable atomic snapshot.
	r.mu.Lock()
	result := make(chan error, 1)
	go func() { result <- r.Forward(sender, frame) }()
	select {
	case err := <-result:
		if err != nil {
			r.mu.Unlock()
			t.Fatalf("Forward while control lock held: %v", err)
		}
	case <-time.After(time.Second):
		r.mu.Unlock()
		t.Fatal("Forward blocked on the registry control lock")
	}
	r.mu.Unlock()

	buffer, err := recipient.DequeueBuffer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buffer.Release()
}

func TestDequeueCancellationAndDisconnectWake(t *testing.T) {
	r := testRegistry(t, nil)
	s := register(t, r, 1, 1, "10.0.0.1/32")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Dequeue(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := s.Dequeue(context.Background())
		result <- err
	}()
	r.Unregister(s)
	select {
	case err := <-result:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("disconnect: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect did not wake Dequeue")
	}
}

func TestConcurrentRegisterBindAndForward(t *testing.T) {
	const pairs = 24
	r := testRegistry(t, func(c *Config) {
		c.MaxSessions = pairs * 2
		c.OutboundQueueCapacity = 4
	})
	start := make(chan struct{})
	errs := make(chan error, pairs)
	var wg sync.WaitGroup
	for i := 0; i < pairs; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			network := byte(i + 1)
			a, err := r.Register(SessionConfig{
				Identity:           identity.NodeIdentity{NetworkID: networkID(network), NodeID: nodeID(1)},
				AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
			})
			if err != nil {
				errs <- err
				return
			}
			b, err := r.Register(SessionConfig{
				Identity:           identity.NodeIdentity{NetworkID: networkID(network), NodeID: nodeID(2)},
				AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			})
			if err != nil {
				errs <- err
				return
			}
			binding, err := r.BindPeers(a, b)
			if err != nil {
				errs <- err
				return
			}
			if err := r.Forward(a, ipv4Frame(t, binding.First.Handle, "10.0.0.1", "10.0.0.2", i)); err != nil {
				errs <- err
				return
			}
			out, err := b.Dequeue(context.Background())
			if err != nil {
				errs <- err
				return
			}
			header, _, err := protocol.DecodePacket(out)
			if err != nil || header.RouteHandle != binding.Second.Handle {
				errs <- errors.New("incorrect concurrent forwarding result")
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	m := r.Metrics()
	if m.Sessions != pairs*2 || m.Bindings != pairs*2 || m.ForwardedPackets != pairs {
		t.Fatalf("concurrent metrics: %#v", m)
	}
}

func TestConcurrentForwardAndDisconnect(t *testing.T) {
	r := testRegistry(t, func(c *Config) { c.OutboundQueueCapacity = 2048 })
	a := register(t, r, 1, 1, "10.0.0.1/32")
	b := register(t, r, 1, 2, "10.0.0.2/32")
	pair, _ := r.BindPeers(a, b)
	frame := ipv4Frame(t, pair.First.Handle, "10.0.0.1", "10.0.0.2", 0)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				err := r.Forward(a, frame)
				if err != nil && !errors.Is(err, ErrUnknownHandle) && !errors.Is(err, ErrSessionClosed) {
					t.Errorf("unexpected forward error: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	r.Unregister(b)
	wg.Wait()
	if m := r.Metrics(); m.Sessions != 1 || m.Bindings != 0 || m.QueuedPackets != 0 {
		t.Fatalf("post-race cleanup: %#v", m)
	}
}
