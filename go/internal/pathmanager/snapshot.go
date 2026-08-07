package pathmanager

// Snapshot is immutable. Its maps are not exposed and slice accessors copy.
type Snapshot struct {
	best    map[PeerID]PacketPath
	peers   map[PeerID]PeerMetrics
	metrics Metrics
}

var emptySnapshot = &Snapshot{best: map[PeerID]PacketPath{}, peers: map[PeerID]PeerMetrics{}}

func (m *Manager) Snapshot() *Snapshot {
	if m == nil {
		return emptySnapshot
	}
	snapshot := m.current.Load()
	if snapshot == nil {
		return emptySnapshot
	}
	return snapshot
}

func (s *Snapshot) BestPath(peer PeerID) PacketPath {
	if s == nil {
		return nil
	}
	return s.best[peer]
}

func (s *Snapshot) Peer(peer PeerID) (PeerMetrics, bool) {
	if s == nil {
		return PeerMetrics{}, false
	}
	view, ok := s.peers[peer]
	if !ok {
		return PeerMetrics{}, false
	}
	view.Paths = clonePathMetrics(view.Paths)
	return view, true
}

func (s *Snapshot) Metrics() Metrics {
	if s == nil {
		return Metrics{}
	}
	return s.metrics
}

func clonePathMetrics(paths []PathMetrics) []PathMetrics {
	copyPaths := make([]PathMetrics, len(paths))
	copy(copyPaths, paths)
	for i := range copyPaths {
		copyPaths[i].Observations = append([]PathSample(nil), copyPaths[i].Observations...)
	}
	return copyPaths
}
