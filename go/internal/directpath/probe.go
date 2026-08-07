package directpath

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"laneway.dev/laneway/internal/identity"
)

const (
	probePacketSize           = 54
	probeVersion         byte = 1
	probeRequest         byte = 1
	probeResponse        byte = 2
	DefaultProbeAttempts      = 3
	MaxProbeAttempts          = 8
)

var (
	// The high two bits are zero so quic-go demultiplexes this as a non-QUIC
	// packet on the shared UDP socket.
	probeMagic      = [4]byte{0x0c, 'W', 'H', 'P'}
	ErrInvalidProbe = errors.New("directpath: invalid UDP probe")
)

type ProbeToken [16]byte

func NewProbeToken() (ProbeToken, error) {
	var token ProbeToken
	if _, err := rand.Read(token[:]); err != nil {
		return ProbeToken{}, fmt.Errorf("directpath: generate probe token: %w", err)
	}
	if token == (ProbeToken{}) {
		return NewProbeToken()
	}
	return token, nil
}

type ProbePacket struct {
	Response  bool
	Token     ProbeToken
	Sender    identity.NodeID
	Recipient identity.NodeID
}

func (p ProbePacket) MarshalBinary() ([]byte, error) {
	if p.Token == (ProbeToken{}) || p.Sender.IsZero() || p.Recipient.IsZero() || p.Sender == p.Recipient {
		return nil, ErrInvalidProbe
	}
	out := make([]byte, probePacketSize)
	copy(out[:4], probeMagic[:])
	out[4] = probeVersion
	out[5] = probeRequest
	if p.Response {
		out[5] = probeResponse
	}
	copy(out[6:22], p.Token[:])
	copy(out[22:38], p.Sender[:])
	copy(out[38:54], p.Recipient[:])
	return out, nil
}

func ParseProbePacket(data []byte, local identity.NodeID, expectedPeer identity.NodeID, token ProbeToken) (ProbePacket, error) {
	if len(data) != probePacketSize || !bytes.Equal(data[:4], probeMagic[:]) || data[4] != probeVersion || (data[5] != probeRequest && data[5] != probeResponse) {
		return ProbePacket{}, ErrInvalidProbe
	}
	var packet ProbePacket
	packet.Response = data[5] == probeResponse
	copy(packet.Token[:], data[6:22])
	copy(packet.Sender[:], data[22:38])
	copy(packet.Recipient[:], data[38:54])
	if packet.Token == (ProbeToken{}) || packet.Sender.IsZero() || packet.Recipient.IsZero() || packet.Sender == packet.Recipient || (!local.IsZero() && packet.Recipient != local) || (!expectedPeer.IsZero() && packet.Sender != expectedPeer) || (token != ProbeToken{} && packet.Token != token) {
		return ProbePacket{}, ErrInvalidProbe
	}
	return packet, nil
}

type ProbeAttempt struct {
	Candidate Candidate
	Attempt   int
	At        time.Time
}

// ProbeSchedule returns stable, priority-ordered simultaneous rounds. Nodes
// given the same rendezvous start time independently produce the same cadence.
func ProbeSchedule(candidates []Candidate, start time.Time, attempts int, interval time.Duration, policy CandidatePolicy) ([]ProbeAttempt, error) {
	if attempts == 0 {
		attempts = DefaultProbeAttempts
	}
	if attempts < 1 || attempts > MaxProbeAttempts || interval <= 0 || start.IsZero() {
		return nil, ErrInvalidProbe
	}
	validated, err := ValidateCandidates(candidates, identity.NodeID{}, policy)
	if err != nil {
		return nil, err
	}
	result := make([]ProbeAttempt, 0, len(validated)*attempts)
	for round := range attempts {
		at := start.Add(time.Duration(round) * interval)
		for _, candidate := range validated {
			result = append(result, ProbeAttempt{Candidate: candidate, Attempt: round + 1, At: at})
		}
	}
	return result, nil
}

type ProbeWriter interface {
	WriteTo([]byte, net.Addr) (int, error)
}

type WaitFunc func(context.Context, time.Duration) error

func waitContext(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SendProbeSchedule emits each round at its shared scheduled time. A failed
// candidate does not stop probes to other candidates, preserving relay fallback.
func SendProbeSchedule(ctx context.Context, writer ProbeWriter, local, peer identity.NodeID, token ProbeToken, schedule []ProbeAttempt, now func() time.Time, wait WaitFunc) error {
	if writer == nil || local.IsZero() || peer.IsZero() || local == peer || token == (ProbeToken{}) {
		return ErrInvalidProbe
	}
	if len(schedule) == 0 || len(schedule) > AbsoluteMaxCandidates*MaxProbeAttempts {
		return ErrInvalidProbe
	}
	permissiveAddressPolicy := CandidatePolicy{MaxCandidates: AbsoluteMaxCandidates, AllowLoopback: true, AllowLinkLocal: true}
	for _, attempt := range schedule {
		if attempt.Attempt < 1 || attempt.Attempt > MaxProbeAttempts || attempt.At.IsZero() || permissiveAddressPolicy.Validate(attempt.Candidate, peer) != nil {
			return ErrInvalidProbe
		}
	}
	if now == nil {
		now = time.Now
	}
	if wait == nil {
		wait = waitContext
	}
	packet, err := (ProbePacket{Token: token, Sender: local, Recipient: peer}).MarshalBinary()
	if err != nil {
		return err
	}
	schedule = append([]ProbeAttempt(nil), schedule...)
	sort.SliceStable(schedule, func(i, j int) bool { return schedule[i].At.Before(schedule[j].At) })
	var allErrors []error
	for i := 0; i < len(schedule); {
		at := schedule[i].At
		if err := wait(ctx, at.Sub(now())); err != nil {
			return err
		}
		end := i
		for end < len(schedule) && schedule[end].At.Equal(at) {
			end++
		}
		for _, attempt := range schedule[i:end] {
			addr := net.UDPAddrFromAddrPort(attempt.Candidate.Address)
			if _, err := writer.WriteTo(packet, addr); err != nil {
				allErrors = append(allErrors, err)
			}
		}
		i = end
	}
	return errors.Join(allErrors...)
}

func addrPort(address net.Addr) (netip.AddrPort, bool) {
	udp, ok := address.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udp.AddrPort(), true
}
