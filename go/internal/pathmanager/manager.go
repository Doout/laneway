package pathmanager

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultEWMAAlpha         = 0.2
	DefaultLossPenalty       = 500 * time.Millisecond
	DefaultHysteresis        = 10 * time.Millisecond
	DefaultMinStableTime     = 5 * time.Second
	DefaultFailureThreshold  = 3
	DefaultRecoverySamples   = 3
	DefaultObservationWindow = 32
)

var (
	ErrInvalidConfig    = errors.New("pathmanager: invalid configuration")
	ErrInvalidCandidate = errors.New("pathmanager: invalid candidate")
)

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

type pathState struct {
	kind                                   PathKind
	path                                   PacketPath
	state                                  HealthState
	latency, loss                          float64
	hasLatency                             bool
	samples                                uint64
	consecutiveFailures, recoverySuccesses uint32
	failureReason                          string
	lastObserved                           time.Time
	observations                           []PathSample
	observationNext                        int
}

type peerState struct {
	paths               map[string]*pathState
	selected, candidate string
	stableSince         time.Time
}

// Manager serializes health updates and publishes immutable read snapshots.
// BestPath takes no lock and allocates no memory.
type Manager struct {
	mu      sync.Mutex
	config  Config
	peers   map[PeerID]*peerState
	metrics Metrics
	current atomic.Pointer[Snapshot]
}

var _ PathManager = (*Manager)(nil)

func New(config Config) (*Manager, error) {
	if config.Clock == nil {
		config.Clock = wallClock{}
	}
	if config.EWMAAlpha == 0 {
		config.EWMAAlpha = DefaultEWMAAlpha
	}
	if config.LossPenalty == 0 {
		config.LossPenalty = DefaultLossPenalty
	}
	if config.Hysteresis == 0 {
		config.Hysteresis = DefaultHysteresis
	}
	if config.MinStableTime == 0 {
		config.MinStableTime = DefaultMinStableTime
	}
	if config.FailureThreshold == 0 {
		config.FailureThreshold = DefaultFailureThreshold
	}
	if config.RecoverySamples == 0 {
		config.RecoverySamples = DefaultRecoverySamples
	}
	if config.ObservationWindow == 0 {
		config.ObservationWindow = DefaultObservationWindow
	}
	if math.IsNaN(config.EWMAAlpha) || math.IsInf(config.EWMAAlpha, 0) || config.EWMAAlpha <= 0 || config.EWMAAlpha > 1 ||
		config.LossPenalty < 0 || config.Hysteresis < 0 || config.MinStableTime < 0 || config.ObservationWindow < 1 {
		return nil, fmt.Errorf("%w: alpha=%g loss_penalty=%s hysteresis=%s stable=%s window=%d", ErrInvalidConfig,
			config.EWMAAlpha, config.LossPenalty, config.Hysteresis, config.MinStableTime, config.ObservationWindow)
	}
	m := &Manager{config: config, peers: make(map[PeerID]*peerState)}
	m.current.Store(emptySnapshot)
	return m, nil
}

func MustNew(config Config) *Manager {
	m, err := New(config)
	if err != nil {
		panic(err)
	}
	return m
}

// SetPaths atomically replaces a peer's candidates. Health is retained when a
// candidate still has the same name, kind, and transport object.
func (m *Manager) SetPaths(peer PeerID, candidates []Candidate) error {
	if m == nil {
		return fmt.Errorf("%w: nil manager", ErrInvalidConfig)
	}
	next := make(map[string]*pathState, len(candidates))
	for _, candidate := range candidates {
		if candidate.Path == nil || !candidate.Kind.valid() || candidate.Path.Name() == "" {
			return fmt.Errorf("%w: kind=%s", ErrInvalidCandidate, candidate.Kind)
		}
		name := candidate.Path.Name()
		if _, ok := next[name]; ok {
			return fmt.Errorf("%w: duplicate path %q", ErrInvalidCandidate, name)
		}
		next[name] = &pathState{kind: candidate.Kind, path: candidate.Path, state: HealthHealthy}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.peers[peer]
	if state == nil {
		state = &peerState{}
		m.peers[peer] = state
	}
	for name, replacement := range next {
		if old := state.paths[name]; old != nil && samePath(old.path, replacement.path) && old.kind == replacement.kind {
			next[name] = old
		}
	}
	state.paths = next
	if _, exists := next[state.selected]; !exists {
		state.selected, state.candidate, state.stableSince = "", "", time.Time{}
	}
	m.reselectLocked(state, m.config.Clock.Now(), true)
	m.publishLocked()
	return nil
}

func (m *Manager) AddPath(peer PeerID, kind PathKind, path PacketPath) error {
	if m == nil || path == nil || !kind.valid() || path.Name() == "" {
		return ErrInvalidCandidate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.peers[peer]
	if state == nil {
		state = &peerState{paths: make(map[string]*pathState)}
		m.peers[peer] = state
	}
	if old := state.paths[path.Name()]; old == nil || !samePath(old.path, path) || old.kind != kind {
		state.paths[path.Name()] = &pathState{kind: kind, path: path, state: HealthHealthy}
	}
	m.reselectLocked(state, m.config.Clock.Now(), false)
	m.publishLocked()
	return nil
}

// Interface equality panics when the dynamic implementation is not
// comparable. Such implementations are legal (for example, a named slice with
// pointer-free methods), so treat them as replacements instead.
func samePath(a, b PacketPath) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	aValue, bValue := reflect.ValueOf(a), reflect.ValueOf(b)
	return aValue.Type() == bValue.Type() && aValue.Comparable() && aValue.Interface() == bValue.Interface()
}

// RemovePath does not close the transport.
func (m *Manager) RemovePath(peer PeerID, name string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.peers[peer]
	if state == nil || state.paths[name] == nil {
		return false
	}
	delete(state.paths, name)
	force := state.selected == name
	if force {
		state.selected = ""
	}
	m.reselectLocked(state, m.config.Clock.Now(), force)
	if len(state.paths) == 0 {
		delete(m.peers, peer)
	}
	m.publishLocked()
	return true
}

func (m *Manager) BestPath(peer PeerID) PacketPath {
	if m == nil {
		return nil
	}
	snapshot := m.current.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot.best[peer]
}

func (m *Manager) Observe(peer PeerID, sample PathSample) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.peers[peer]
	if state == nil {
		return
	}
	path := state.paths[sample.Path]
	if path == nil {
		return
	}
	now := sample.ObservedAt
	if now.IsZero() {
		now = m.config.Clock.Now()
	}
	sample.ObservedAt = now
	path.addObservation(sample, m.config.ObservationWindow)
	path.samples++
	path.lastObserved = now
	alpha := m.config.EWMAAlpha
	lossValue := 0.0
	if sample.Lost || sample.HardFailure {
		lossValue = 1
	}
	if path.samples == 1 {
		path.loss = lossValue
	} else {
		path.loss = alpha*lossValue + (1-alpha)*path.loss
	}
	if !sample.Lost && !sample.HardFailure && sample.Latency >= 0 {
		if !path.hasLatency {
			path.latency = float64(sample.Latency)
			path.hasLatency = true
		} else {
			path.latency = alpha*float64(sample.Latency) + (1-alpha)*path.latency
		}
	}
	m.metrics.Observations++
	force := false
	if sample.HardFailure {
		force = m.failLocked(state, path, sample.Path, sample.Reason)
	} else if sample.Lost {
		path.consecutiveFailures++
		path.recoverySuccesses = 0
		if path.state == HealthProbing || path.consecutiveFailures >= m.config.FailureThreshold {
			force = m.failLocked(state, path, sample.Path, sample.Reason)
		}
	} else {
		path.consecutiveFailures = 0
		switch path.state {
		case HealthFailed:
			path.state, path.recoverySuccesses, path.failureReason = HealthProbing, 1, ""
		case HealthProbing:
			path.recoverySuccesses++
		default:
			path.state = HealthHealthy
		}
		if path.state == HealthProbing && path.recoverySuccesses >= m.config.RecoverySamples {
			path.state, path.recoverySuccesses = HealthHealthy, m.config.RecoverySamples
		}
	}
	m.reselectLocked(state, now, force)
	m.publishLocked()
}

func (m *Manager) MarkFailed(peer PeerID, name string) {
	m.MarkFailedReason(peer, name, "marked failed")
}

func (m *Manager) MarkFailedReason(peer PeerID, name, reason string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.peers[peer]
	if state == nil || state.paths[name] == nil {
		return false
	}
	force := m.failLocked(state, state.paths[name], name, reason)
	m.reselectLocked(state, m.config.Clock.Now(), force)
	m.publishLocked()
	return true
}

func (m *Manager) failLocked(peer *peerState, path *pathState, name, reason string) bool {
	if path.state != HealthFailed {
		m.metrics.HardFailures++
		if path.kind == PathDirect {
			m.metrics.DirectFailures++
		}
	}
	path.state, path.failureReason = HealthFailed, reason
	path.recoverySuccesses, path.consecutiveFailures = 0, m.config.FailureThreshold
	if peer.candidate == name {
		peer.candidate, peer.stableSince = "", time.Time{}
	}
	return peer.selected == name
}

func (p *pathState) addObservation(sample PathSample, limit int) {
	if len(p.observations) < limit {
		p.observations = append(p.observations, sample)
		return
	}
	p.observations[p.observationNext] = sample
	p.observationNext = (p.observationNext + 1) % limit
}

func (m *Manager) reselectLocked(peer *peerState, now time.Time, force bool) {
	best := m.bestHealthyLocked(peer)
	if peer.selected == "" || peer.paths[peer.selected] == nil || peer.paths[peer.selected].state != HealthHealthy {
		force = true
	}
	if best == "" {
		if force && peer.selected != "" {
			peer.selected = ""
			m.metrics.Switches++
		}
		peer.candidate, peer.stableSince = "", time.Time{}
		return
	}
	if force {
		if peer.selected != best {
			if peer.selected != "" {
				m.metrics.Switches++
			}
			peer.selected = best
		}
		peer.candidate, peer.stableSince = "", time.Time{}
		return
	}
	if best == peer.selected || !m.preferredLocked(peer.paths[best], peer.paths[peer.selected]) {
		peer.candidate, peer.stableSince = "", time.Time{}
		return
	}
	// Path kind is an explicit security/transport preference, not a latency
	// estimate. An authenticated healthier carrier of a better kind is promoted
	// immediately; stability and hysteresis remain for choices within one kind.
	if peer.paths[best].kind < peer.paths[peer.selected].kind {
		peer.selected, peer.candidate, peer.stableSince = best, "", time.Time{}
		m.metrics.Switches++
		return
	}
	if peer.candidate != best {
		peer.candidate, peer.stableSince = best, now
		return
	}
	if now.Sub(peer.stableSince) >= m.config.MinStableTime {
		peer.selected, peer.candidate, peer.stableSince = best, "", time.Time{}
		m.metrics.Switches++
	}
}

func (m *Manager) bestHealthyLocked(peer *peerState) string {
	best := ""
	for name, path := range peer.paths {
		if path.state != HealthHealthy {
			continue
		}
		if best == "" || m.lessLocked(name, path, best, peer.paths[best]) {
			best = name
		}
	}
	return best
}

func (m *Manager) lessLocked(aName string, a *pathState, bName string, b *pathState) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	aScore, bScore := m.score(a), m.score(b)
	if aScore != bScore {
		return aScore < bScore
	}
	return aName < bName
}

func (m *Manager) preferredLocked(candidate, current *pathState) bool {
	if candidate == nil || current == nil {
		return candidate != nil
	}
	if candidate.kind != current.kind {
		return candidate.kind < current.kind
	}
	return m.score(candidate)+float64(m.config.Hysteresis) < m.score(current)
}

func (m *Manager) score(path *pathState) float64 {
	latency := path.latency
	if !path.hasLatency {
		latency = float64(m.config.LossPenalty)
	}
	return latency + path.loss*float64(m.config.LossPenalty)
}

func (m *Manager) publishLocked() {
	snapshot := &Snapshot{best: make(map[PeerID]PacketPath, len(m.peers)), peers: make(map[PeerID]PeerMetrics, len(m.peers))}
	for peerID, peer := range m.peers {
		view := PeerMetrics{Peer: peerID, Selected: peer.selected, Candidate: peer.candidate, StableSince: peer.stableSince, Paths: make([]PathMetrics, 0, len(peer.paths))}
		for name, path := range peer.paths {
			observations := make([]PathSample, len(path.observations))
			if len(path.observations) < m.config.ObservationWindow || path.observationNext == 0 {
				copy(observations, path.observations)
			} else {
				n := copy(observations, path.observations[path.observationNext:])
				copy(observations[n:], path.observations[:path.observationNext])
			}
			view.Paths = append(view.Paths, PathMetrics{Name: name, Kind: path.kind, State: path.state,
				LatencyEWMA: time.Duration(path.latency), LossEWMA: path.loss, Samples: path.samples,
				ConsecutiveFailures: path.consecutiveFailures, RecoverySuccesses: path.recoverySuccesses,
				FailureReason: path.failureReason, LastObserved: path.lastObserved, Selected: name == peer.selected, Observations: observations})
		}
		sort.Slice(view.Paths, func(i, j int) bool {
			if view.Paths[i].Kind != view.Paths[j].Kind {
				return view.Paths[i].Kind < view.Paths[j].Kind
			}
			return view.Paths[i].Name < view.Paths[j].Name
		})
		snapshot.peers[peerID] = view
		if selected := peer.paths[peer.selected]; selected != nil && selected.state == HealthHealthy {
			snapshot.best[peerID] = selected.path
		}
	}
	m.metrics.Peers = len(m.peers)
	snapshot.metrics = m.metrics
	m.current.Store(snapshot)
}
