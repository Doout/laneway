package directpath

import (
	"fmt"
	"sync"
	"time"

	"laneway.dev/laneway/internal/identity"
)

type rendezvousKey struct {
	network identity.NetworkID
	node    identity.NodeID
}

type candidateRecord struct {
	candidates []Candidate
	expiresAt  time.Time
}

// Rendezvous is a bounded in-memory candidate exchange. Publish and Lookup
// accept only identities authenticated by the surrounding control transport.
// Networks are separate namespaces, including when they share a CA or relay.
type Rendezvous struct {
	mu      sync.RWMutex
	policy  CandidatePolicy
	ttl     time.Duration
	records map[rendezvousKey]candidateRecord
}

func NewRendezvous(policy CandidatePolicy, ttl time.Duration) (*Rendezvous, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = DefaultCandidateTTL
	}
	if ttl < time.Second || ttl > 10*time.Minute {
		return nil, fmt.Errorf("%w: candidate TTL must be in [1s,10m]", ErrInvalidCandidate)
	}
	return &Rendezvous{policy: policy, ttl: ttl, records: make(map[rendezvousKey]candidateRecord)}, nil
}

func authenticatedNode(auth identity.AuthenticatedIdentity) (identity.NodeIdentity, error) {
	if err := auth.Validate(); err != nil || auth.Role != identity.IdentityRoleNode {
		return identity.NodeIdentity{}, ErrUnauthorizedPeer
	}
	node, ok := auth.NodeIdentity()
	if !ok {
		return identity.NodeIdentity{}, ErrUnauthorizedPeer
	}
	return node, nil
}

// Publish replaces a node's candidate set. The node_id inside every candidate
// must equal the certificate identity, preventing candidate injection for a peer.
func (r *Rendezvous) Publish(auth identity.AuthenticatedIdentity, candidates []Candidate, now time.Time) error {
	node, err := authenticatedNode(auth)
	if err != nil {
		return err
	}
	validated, err := ValidateCandidates(candidates, node.NodeID, r.policy)
	if err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := rendezvousKey{network: node.NetworkID, node: node.NodeID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(validated) == 0 {
		delete(r.records, key)
		return nil
	}
	r.records[key] = candidateRecord{candidates: validated, expiresAt: now.Add(r.ttl)}
	return nil
}

// Lookup returns only candidates in the requester's authenticated network.
// Callers should additionally apply ACL policy before invoking Lookup.
func (r *Rendezvous) Lookup(requester identity.AuthenticatedIdentity, peer identity.NodeID, now time.Time) ([]Candidate, error) {
	node, err := authenticatedNode(requester)
	if err != nil || peer.IsZero() || peer == node.NodeID {
		return nil, ErrUnauthorizedPeer
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := rendezvousKey{network: node.NetworkID, node: peer}
	r.mu.RLock()
	record, exists := r.records[key]
	r.mu.RUnlock()
	if !exists || !now.Before(record.expiresAt) {
		if exists {
			r.mu.Lock()
			if current, ok := r.records[key]; ok && !now.Before(current.expiresAt) {
				delete(r.records, key)
			}
			r.mu.Unlock()
		}
		return nil, nil
	}
	return append([]Candidate(nil), record.candidates...), nil
}

func (r *Rendezvous) Remove(auth identity.AuthenticatedIdentity) error {
	node, err := authenticatedNode(auth)
	if err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.records, rendezvousKey{network: node.NetworkID, node: node.NodeID})
	r.mu.Unlock()
	return nil
}
