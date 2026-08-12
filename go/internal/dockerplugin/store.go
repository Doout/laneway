package dockerplugin

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Network struct {
	ID          string               `json:"id"`
	Bridge      string               `json:"bridge"`
	Table       int                  `json:"table"`
	Subnet      netip.Prefix         `json:"subnet"`
	Gateway     netip.Addr           `json:"gateway"`
	Policy      Policy               `json:"policy"`
	BypassCIDRs []netip.Prefix       `json:"bypass_cidrs,omitempty"`
	Phase       string               `json:"phase"`
	CreatedAt   time.Time            `json:"created_at"`
	Endpoints   map[string]*Endpoint `json:"endpoints,omitempty"`
}

type Endpoint struct {
	ID       string     `json:"id"`
	Address  netip.Addr `json:"address,omitempty"`
	HostVeth string     `json:"host_veth,omitempty"`
	PeerVeth string     `json:"peer_veth,omitempty"`
	Sandbox  string     `json:"sandbox,omitempty"`
	Joined   bool       `json:"joined,omitempty"`
}

type stateFile struct {
	Version  int                 `json:"version"`
	Networks map[string]*Network `json:"networks"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state stateFile
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, state: stateFile{Version: 1, Networks: make(map[string]*Network)}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: state must be a private regular file", ErrConflict)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dockerplugin: read state: %w", err)
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("dockerplugin: decode state: %w", err)
	}
	if s.state.Version != 1 || s.state.Networks == nil {
		return nil, fmt.Errorf("%w: unsupported state file", ErrConflict)
	}
	return s, nil
}

func (s *Store) Snapshot() map[string]*Network {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneNetworks(s.state.Networks)
}

func (s *Store) Update(mutator func(map[string]*Network) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneNetworks(s.state.Networks)
	if err := mutator(next); err != nil {
		return err
	}
	state := stateFile{Version: 1, Networks: next}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	temporary := s.path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0600); err == nil {
		_, err = file.Write(append(data, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return err
	}
	s.state = state
	return nil
}

func cloneNetworks(source map[string]*Network) map[string]*Network {
	result := make(map[string]*Network, len(source))
	for id, network := range source {
		copyNetwork := *network
		copyNetwork.BypassCIDRs = append([]netip.Prefix(nil), network.BypassCIDRs...)
		copyNetwork.Policy.EgressCIDRs = append([]netip.Prefix(nil), network.Policy.EgressCIDRs...)
		copyNetwork.Policy.IngressSources = append([]netip.Prefix(nil), network.Policy.IngressSources...)
		copyNetwork.Policy.DNS = append([]netip.Addr(nil), network.Policy.DNS...)
		copyNetwork.Endpoints = make(map[string]*Endpoint, len(network.Endpoints))
		for endpointID, endpoint := range network.Endpoints {
			copyEndpoint := *endpoint
			copyNetwork.Endpoints[endpointID] = &copyEndpoint
		}
		result[id] = &copyNetwork
	}
	return result
}
