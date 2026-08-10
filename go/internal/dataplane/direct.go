package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/directpath"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pathmanager"
	"laneway.dev/laneway/internal/routing"
)

const DefaultMaxCandidatePeers = 4096

var (
	ErrCandidateUnauthorized = errors.New("dataplane: direct candidate is not authorized")
	ErrCandidateLimit        = errors.New("dataplane: direct candidate peer limit reached")
)

type CandidateSink interface {
	HandleCandidate(context.Context, *lanewayv1.EndpointCandidate) error
}

type PeerAuthorizer interface {
	AuthorizeDirectPeer(identity.NodeID) bool
}

type CandidateAuthority interface {
	CandidateExchangeEnabled() bool
	CandidateExchangeMaxCandidates() int
	CandidateExchangeTTL() time.Duration
}

// DirectPathAttacher is the authenticated path boundary used by the direct
// rendezvous controller. Both the plaintext IP dataplane and the opaque
// WireGuard carrier selector implement it.
type DirectPathAttacher interface {
	Attach(identity.NodeID, pathmanager.PathKind, pathmanager.PacketPath) error
	Detach(identity.NodeID, string) bool
}

type PeerAuthorizerFunc func(identity.NodeID) bool

func (f PeerAuthorizerFunc) AuthorizeDirectPeer(peer identity.NodeID) bool { return f(peer) }

type DirectConfig struct {
	Local              identity.NodeIdentity
	Endpoint           *directpath.Endpoint
	Paths              DirectPathAttacher
	Authorizer         PeerAuthorizer
	CandidateAuthority CandidateAuthority
	CandidatePolicy    directpath.CandidatePolicy
	CandidateTTL       time.Duration
	MaxCandidatePeers  int
	ProbeAttempts      int
	ProbeInterval      time.Duration
	ProbeTimeout       time.Duration
	DialOptions        directpath.DialOptions
	ReportFailure      func(error)
}

type storedCandidates struct {
	candidates []directpath.Candidate
	expiresAt  time.Time
}

type probeRequest struct {
	peer  identity.NodeID
	token directpath.ProbeToken
	start time.Time
}

// DirectController consumes authenticated relay candidate messages, coordinates
// simultaneous probes, and attaches established direct sessions to Engine.
type DirectController struct {
	config   DirectConfig
	mu       sync.Mutex
	peers    map[identity.NodeID]storedCandidates
	requests chan probeRequest
	pathMu   sync.Mutex
	active   map[identity.NodeID]*directpath.Path
}

func NewDirectController(config DirectConfig) (*DirectController, error) {
	if err := config.Local.Validate(); err != nil || config.Endpoint == nil || config.Paths == nil || config.Authorizer == nil {
		return nil, ErrInvalidConfiguration
	}
	if config.Endpoint.LocalIdentity() != config.Local {
		return nil, ErrInvalidConfiguration
	}
	if config.CandidateTTL == 0 {
		config.CandidateTTL = directpath.DefaultCandidateTTL
	}
	if config.CandidateTTL < time.Second || config.CandidateTTL > 10*time.Minute {
		return nil, ErrInvalidConfiguration
	}
	if config.MaxCandidatePeers == 0 {
		config.MaxCandidatePeers = DefaultMaxCandidatePeers
	}
	if config.MaxCandidatePeers < 1 || config.MaxCandidatePeers > 65536 {
		return nil, ErrInvalidConfiguration
	}
	if config.ProbeAttempts == 0 {
		config.ProbeAttempts = directpath.DefaultProbeAttempts
	}
	if config.ProbeAttempts < 1 || config.ProbeAttempts > directpath.MaxProbeAttempts {
		return nil, ErrInvalidConfiguration
	}
	if config.ProbeInterval == 0 {
		config.ProbeInterval = 200 * time.Millisecond
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = 3 * time.Second
	}
	if config.ProbeInterval <= 0 || config.ProbeInterval > time.Second || config.ProbeTimeout <= 0 || config.ProbeTimeout > 30*time.Second {
		return nil, ErrInvalidConfiguration
	}
	return &DirectController{
		config: config, peers: make(map[identity.NodeID]storedCandidates),
		requests: make(chan probeRequest, config.MaxCandidatePeers), active: make(map[identity.NodeID]*directpath.Path),
	}, nil
}

func (c *DirectController) HandleCandidate(_ context.Context, message *lanewayv1.EndpointCandidate) error {
	policy, ttl := c.config.CandidatePolicy, c.config.CandidateTTL
	if authority := c.config.CandidateAuthority; authority != nil {
		if !authority.CandidateExchangeEnabled() {
			return ErrCandidateUnauthorized
		}
		maximum := authority.CandidateExchangeMaxCandidates()
		if maximum < 1 {
			return ErrCandidateUnauthorized
		}
		if maximum < policy.MaxCandidates {
			policy.MaxCandidates = maximum
		}
		if controllerTTL := authority.CandidateExchangeTTL(); controllerTTL > 0 && controllerTTL < ttl {
			ttl = controllerTTL
		}
	}
	if message == nil || len(message.GetNodeId()) != identity.IDSize {
		return directpath.ErrInvalidCandidate
	}
	var peer identity.NodeID
	copy(peer[:], message.GetNodeId())
	if peer.IsZero() || peer == c.config.Local.NodeID || !c.config.Authorizer.AuthorizeDirectPeer(peer) {
		return ErrCandidateUnauthorized
	}
	candidate, err := directpath.CandidateFromProto(message, peer, policy)
	if err != nil {
		return err
	}
	now := time.Now()
	var request *probeRequest
	tokenBytes, startValue := message.GetRendezvousToken(), message.GetProbeStartUnixNano()
	if len(tokenBytes) != 0 || startValue != 0 {
		if len(tokenBytes) != identity.IDSize || startValue == 0 || startValue > math.MaxInt64 {
			return directpath.ErrInvalidProbe
		}
		var token directpath.ProbeToken
		copy(token[:], tokenBytes)
		start := time.Unix(0, int64(startValue))
		if token == (directpath.ProbeToken{}) || start.Before(now.Add(-ttl)) || start.After(now.Add(min(ttl, 30*time.Second))) {
			return directpath.ErrInvalidProbe
		}
		request = &probeRequest{peer: peer, token: token, start: start}
	}
	c.mu.Lock()
	for existingPeer, record := range c.peers {
		if !now.Before(record.expiresAt) {
			delete(c.peers, existingPeer)
		}
	}
	record, exists := c.peers[peer]
	if !exists && len(c.peers) >= c.config.MaxCandidatePeers {
		c.mu.Unlock()
		return ErrCandidateLimit
	}
	replaced := false
	for i := range record.candidates {
		if record.candidates[i].Address == candidate.Address {
			record.candidates[i] = candidate
			replaced = true
			break
		}
	}
	if !replaced {
		record.candidates = append(record.candidates, candidate)
	}
	validated, err := directpath.ValidateCandidates(record.candidates, peer, policy)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	record.candidates = validated
	record.expiresAt = now.Add(ttl)
	c.peers[peer] = record
	c.mu.Unlock()
	if request != nil {
		// Periodic rendezvous refreshes the NAT mapping and direct session. Keep
		// the current authenticated path carrying traffic while that happens;
		// replaceDirect performs the swap only after the new QUIC session has
		// authenticated. A genuinely stale path is still removed by its receive
		// loop when QUIC keepalive declares the connection failed.
		select {
		case c.requests <- *request:
		default:
			return ErrCandidateLimit
		}
	}
	return nil
}

func (c *DirectController) Candidates(peer identity.NodeID, now time.Time) []directpath.Candidate {
	if now.IsZero() {
		now = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.peers[peer]
	if !ok || !now.Before(record.expiresAt) {
		delete(c.peers, peer)
		return nil
	}
	return append([]directpath.Candidate(nil), record.candidates...)
}

// ProbeAndConnect participates in a relay-coordinated probe window. Both peers
// call this with the same token and start time. The lower NodeID dials after a
// probe succeeds; the other side is attached by Run's accept loop.
func (c *DirectController) ProbeAndConnect(ctx context.Context, peer identity.NodeID, token directpath.ProbeToken, start time.Time) error {
	if peer.IsZero() || peer == c.config.Local.NodeID || !c.config.Authorizer.AuthorizeDirectPeer(peer) {
		return ErrCandidateUnauthorized
	}
	candidates := c.Candidates(peer, time.Now())
	if len(candidates) == 0 {
		return directpath.ErrInvalidCandidate
	}
	schedule, err := directpath.ProbeSchedule(candidates, start, c.config.ProbeAttempts, c.config.ProbeInterval, c.config.CandidatePolicy)
	if err != nil {
		return err
	}
	reservation, err := c.config.Endpoint.ReservePathEndpoints(candidates)
	if err != nil {
		return err
	}
	releaseNow := true
	defer func() {
		if releaseNow {
			_ = reservation.Release()
		}
	}()
	probeContext, cancel := context.WithTimeout(ctx, c.config.ProbeTimeout)
	defer cancel()
	sendResult := make(chan error, 1)
	go func() {
		sendResult <- directpath.SendProbeSchedule(probeContext, c.config.Endpoint.ProbeWriter(), c.config.Local.NodeID, peer, token, schedule, nil, nil)
	}()
	source, readErr := c.config.Endpoint.ReadProbe(probeContext, peer, token, candidates)
	if readErr != nil {
		cancel()
		<-sendResult
		return readErr
	}
	// Receiving either an authenticated request or response proves that the
	// advertised endpoint is reachable. Prefer it for the bounded QUIC dial.
	for i := range candidates {
		if candidates[i].Address == source {
			candidates[0], candidates[i] = candidates[i], candidates[0]
			break
		}
	}
	if bytes.Compare(c.config.Local.NodeID[:], peer[:]) < 0 {
		path, dialErr := c.config.Endpoint.DialCandidates(ctx, candidates, identity.NodeIdentity{NetworkID: c.config.Local.NetworkID, NodeID: peer}, c.config.DialOptions)
		cancel()
		<-sendResult
		if dialErr != nil {
			return dialErr
		}
		if err := c.replaceDirect(peer, path); err != nil {
			_ = path.Close()
			return err
		}
		return nil
	}
	cancel()
	<-sendResult
	// The accepting side must retain its native bypass while the deterministic
	// dialer completes QUIC after the probe response. Keep a bounded grace
	// reservation; an authenticated accepted path takes over ownership before
	// this expires.
	releaseNow = false
	releaseReservationAfter(reservation, c.config.ProbeTimeout+12*time.Second)
	return nil
}

func releaseReservationAfter(reservation *directpath.EndpointReservation, delay time.Duration) {
	if reservation == nil {
		return
	}
	if delay <= 0 || delay > time.Minute {
		delay = 15 * time.Second
	}
	time.AfterFunc(delay, func() {
		// A failed removal leaves a safe native bypass. Retry briefly so a
		// transient route-manager reconciliation error does not make it stale.
		for attempt := 0; attempt < 3; attempt++ {
			if reservation.Release() == nil {
				return
			}
			time.Sleep(time.Second)
		}
	})
}

// Run accepts authenticated direct sessions and serializes bounded rendezvous
// attempts. Direct failures do not terminate the relay-backed dataplane.
func (c *DirectController) Run(ctx context.Context) error {
	acceptResult := make(chan error, 1)
	go func() { acceptResult <- c.acceptLoop(ctx) }()
	for {
		select {
		case <-ctx.Done():
			<-acceptResult
			return ctx.Err()
		case err := <-acceptResult:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case request := <-c.requests:
			if err := c.ProbeAndConnect(ctx, request.peer, request.token, request.start); err != nil && c.config.ReportFailure != nil {
				c.config.ReportFailure(err)
			}
		}
	}
}

func (c *DirectController) acceptLoop(ctx context.Context) error {
	for {
		path, err := c.config.Endpoint.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		peer := path.PeerIdentity()
		if !c.config.Authorizer.AuthorizeDirectPeer(peer) {
			_ = path.Close()
			continue
		}
		if err := c.replaceDirect(peer, path); err != nil {
			_ = path.Close()
			if !errors.Is(err, ErrPathNameConflict) {
				return fmt.Errorf("dataplane: attach accepted direct path: %w", err)
			}
		}
	}
}

func (c *DirectController) replaceDirect(peer identity.NodeID, path *directpath.Path) error {
	if path == nil {
		return ErrInvalidConfiguration
	}
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	if previous := c.active[peer]; previous != nil && previous != path {
		c.config.Paths.Detach(peer, previous.Name())
		_ = previous.Close()
	}
	if err := c.config.Paths.Attach(peer, pathmanager.PathDirect, path); err != nil {
		return err
	}
	c.active[peer] = path
	return nil
}

func (c *DirectController) detachDirect(peer identity.NodeID) {
	c.pathMu.Lock()
	defer c.pathMu.Unlock()
	path := c.active[peer]
	if path == nil {
		return
	}
	delete(c.active, peer)
	c.config.Paths.Detach(peer, path.Name())
	_ = path.Close()
}

// RouteAuthorizer permits only peers currently named as a route next hop.
type RouteAuthorizer struct{ Routes *routing.Table }

func (a RouteAuthorizer) AuthorizeDirectPeer(peer identity.NodeID) bool {
	if a.Routes == nil || peer.IsZero() {
		return false
	}
	for _, route := range a.Routes.Snapshot().Routes() {
		if route.NextHop == peer {
			return true
		}
	}
	return false
}

var _ CandidateSink = (*DirectController)(nil)
var _ PeerAuthorizer = RouteAuthorizer{}
