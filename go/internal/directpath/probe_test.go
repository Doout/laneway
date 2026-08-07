package directpath

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"laneway.dev/laneway/internal/identity"
)

func TestProbePacketStrictCodec(t *testing.T) {
	local := testNode(t, "101112131415161718191a1b1c1d1e1f")
	peer := testNode(t, "202122232425262728292a2b2c2d2e2f")
	var token ProbeToken
	token[0] = 1
	wire, err := (ProbePacket{Token: token, Sender: peer, Recipient: local}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProbePacket(wire, local, peer, token)
	if err != nil || parsed.Sender != peer || parsed.Recipient != local {
		t.Fatalf("parsed = %#v, %v", parsed, err)
	}
	for _, malformed := range [][]byte{nil, wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		if _, err := ParseProbePacket(malformed, local, peer, token); !errors.Is(err, ErrInvalidProbe) {
			t.Fatalf("malformed error = %v", err)
		}
	}
	wrong := append([]byte(nil), wire...)
	wrong[6]++
	if _, err := ParseProbePacket(wrong, local, peer, token); !errors.Is(err, ErrInvalidProbe) {
		t.Fatalf("wrong token error = %v", err)
	}
}

func FuzzParseProbePacket(f *testing.F) {
	local, err := identity.ParseNodeID("101112131415161718191a1b1c1d1e1f")
	if err != nil {
		f.Fatal(err)
	}
	peer, err := identity.ParseNodeID("202122232425262728292a2b2c2d2e2f")
	if err != nil {
		f.Fatal(err)
	}
	var token ProbeToken
	token[0] = 1
	valid, err := (ProbePacket{Token: token, Sender: peer, Recipient: local}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _ = ParseProbePacket(wire, local, peer, token)
	})
}

func TestProbeScheduleIsDeterministicAndSimultaneousByRound(t *testing.T) {
	node := testNode(t, "101112131415161718191a1b1c1d1e1f")
	start := time.Unix(100, 0)
	a := Candidate{NodeID: node, Address: netip.MustParseAddrPort("10.0.0.2:2"), Priority: 2}
	b := Candidate{NodeID: node, Address: netip.MustParseAddrPort("10.0.0.1:1"), Priority: 1}
	schedule, err := ProbeSchedule([]Candidate{a, b}, start, 2, 50*time.Millisecond, CandidatePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(schedule) != 4 || schedule[0].Candidate != b || schedule[1].Candidate != a || schedule[0].At != schedule[1].At || schedule[2].At != schedule[3].At || schedule[2].At.Sub(schedule[0].At) != 50*time.Millisecond {
		t.Fatalf("schedule = %#v", schedule)
	}
	again, _ := ProbeSchedule([]Candidate{a, b}, start, 2, 50*time.Millisecond, CandidatePolicy{})
	if !reflect.DeepEqual(schedule, again) {
		t.Fatal("schedule not deterministic")
	}
}

type recordingWriter struct{ addresses []string }

func (w *recordingWriter) WriteTo(_ []byte, address net.Addr) (int, error) {
	w.addresses = append(w.addresses, address.String())
	return probePacketSize, nil
}

func TestSendProbeScheduleUsesOneWaitPerRoundAndHonorsCancel(t *testing.T) {
	local := testNode(t, "101112131415161718191a1b1c1d1e1f")
	peer := testNode(t, "202122232425262728292a2b2c2d2e2f")
	start := time.Unix(100, 0)
	candidates := []Candidate{
		{NodeID: peer, Address: netip.MustParseAddrPort("10.0.0.2:2"), Priority: 2},
		{NodeID: peer, Address: netip.MustParseAddrPort("10.0.0.1:1"), Priority: 1},
	}
	schedule, _ := ProbeSchedule(candidates, start, 2, time.Second, CandidatePolicy{})
	var token ProbeToken
	token[0] = 1
	writer := &recordingWriter{}
	current := start.Add(-time.Second)
	var waits []time.Duration
	wait := func(_ context.Context, duration time.Duration) error {
		waits = append(waits, duration)
		current = current.Add(duration)
		return nil
	}
	if err := SendProbeSchedule(context.Background(), writer, local, peer, token, schedule, func() time.Time { return current }, wait); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(waits, []time.Duration{time.Second, time.Second}) {
		t.Fatalf("waits = %v", waits)
	}
	if want := []string{"10.0.0.1:1", "10.0.0.2:2", "10.0.0.1:1", "10.0.0.2:2"}; !reflect.DeepEqual(writer.addresses, want) {
		t.Fatalf("addresses = %v", writer.addresses)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SendProbeSchedule(canceled, writer, local, peer, token, schedule, time.Now, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
}
