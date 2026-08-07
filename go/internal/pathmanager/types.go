// Package pathmanager selects a transport path for each Laneway peer.
package pathmanager

import (
	"context"
	"time"

	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/packetbuffer"
)

// PeerID is the authenticated node identity used by routing and transport.
type PeerID = identity.NodeID

// PacketBuffer is an IP packet owned by the caller for the duration of Send.
type PacketBuffer []byte

// ReceivedPacket identifies the authenticated sender of a received packet.
type ReceivedPacket struct {
	Peer   PeerID
	Packet PacketBuffer
	// Buffer is non-nil when Packet aliases a pooled carrier buffer. Consumers
	// must call Release on every path, including validation and policy drops.
	Buffer *packetbuffer.Buffer
}

func (p *ReceivedPacket) Release() {
	if p == nil || p.Buffer == nil {
		return
	}
	p.Buffer.Release()
	p.Buffer = nil
	p.Packet = nil
}

type HealthState uint8

const (
	HealthUnknown HealthState = iota
	HealthHealthy
	HealthProbing
	HealthFailed
)

func (s HealthState) String() string {
	switch s {
	case HealthHealthy:
		return "healthy"
	case HealthProbing:
		return "probing"
	case HealthFailed:
		return "failed"
	default:
		return "unknown"
	}
}

type PathHealth struct {
	State         HealthState
	Latency       time.Duration
	Loss          float64
	FailureReason string
}

// PacketPath is the transport-agnostic packet interface from the architecture.
type PacketPath interface {
	Name() string
	MaxPayload(PeerID) int
	Send(context.Context, PeerID, PacketBuffer) error
	Receive(context.Context) (ReceivedPacket, error)
	Health(PeerID) PathHealth
	Close() error
}

// PathManager is the selection interface consumed by the packet pump.
type PathManager interface {
	BestPath(PeerID) PacketPath
	Observe(PeerID, PathSample)
	MarkFailed(PeerID, string)
}

// PathKind is the coarse path preference. Lower values are preferred.
type PathKind uint8

const (
	PathDirect PathKind = iota + 1
	PathRelayQUIC
	PathTCPFallback
)

// Short aliases are useful in candidate declarations while the Path-prefixed
// names remain unambiguous at call sites that dot-import nothing.
const (
	Direct      = PathDirect
	RelayQUIC   = PathRelayQUIC
	TCPFallback = PathTCPFallback
)

func (k PathKind) String() string {
	switch k {
	case PathDirect:
		return "direct"
	case PathRelayQUIC:
		return "relay-quic"
	case PathTCPFallback:
		return "tcp-fallback"
	default:
		return "unknown"
	}
}

func (k PathKind) valid() bool { return k >= PathDirect && k <= PathTCPFallback }

type Candidate struct {
	Kind PathKind
	Path PacketPath
}

// PathSample is one bounded health observation. Path names are scoped to a
// peer. Lost samples do not contribute a latency measurement. HardFailure
// bypasses the ordinary consecutive-loss threshold.
type PathSample struct {
	Path        string
	Latency     time.Duration
	Lost        bool
	HardFailure bool
	Reason      string
	ObservedAt  time.Time
}

type Clock interface{ Now() time.Time }

type Config struct {
	Clock Clock
	// EWMAAlpha is the weight of the newest sample, in (0,1].
	EWMAAlpha   float64
	LossPenalty time.Duration
	// Hysteresis is the required score improvement between paths of one kind.
	Hysteresis        time.Duration
	MinStableTime     time.Duration
	FailureThreshold  uint32
	RecoverySamples   uint32
	ObservationWindow int
}

type PathMetrics struct {
	Name                string
	Kind                PathKind
	State               HealthState
	LatencyEWMA         time.Duration
	LossEWMA            float64
	Samples             uint64
	ConsecutiveFailures uint32
	RecoverySuccesses   uint32
	FailureReason       string
	LastObserved        time.Time
	Selected            bool
	Observations        []PathSample
}

type PeerMetrics struct {
	Peer        PeerID
	Selected    string
	Candidate   string
	StableSince time.Time
	Paths       []PathMetrics
}

type Metrics struct {
	Observations   uint64
	HardFailures   uint64
	DirectFailures uint64
	Switches       uint64
	Peers          int
}
