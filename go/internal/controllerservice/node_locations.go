package controllerservice

import (
	"log"
	"net/http"
	"net/netip"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodelocation"
)

type LocationResolver interface {
	Lookup(netip.Addr) (*nodelocation.Location, error)
}

func (s *Service) observeNodeLocation(r *http.Request, caller identity.NodeIdentity) {
	// Do not trust forwarded headers or client-supplied addresses. A proxied
	// private/loopback source stays unknown rather than locating the proxy.
	var location *nodelocation.Location
	address := ""
	if remote, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && nodelocation.PublicIP(remote.Addr()) {
		address = remote.Addr().Unmap().String()
		if s.locationResolver != nil {
			location, err = s.locationResolver.Lookup(remote.Addr())
		}
		if err != nil {
			location = nil
		} // Optional enrichment must not fail status reporting.
	}
	if err := s.store.RecordNodeLocation(r.Context(), caller, location, s.now(), address); err != nil {
		log.Printf("record node presence failed: %v", err)
	}
}

func (s *Service) readNodeLocations(w http.ResponseWriter, r *http.Request) {
	networkID, err := parseNetworkPath(r)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	limit, err := queryLimit(r, 100)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.NetworkTarget(networkID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	values, err := s.store.AdministratorNodeLocations(r.Context(), decision, networkID, limit)
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	provider := ""
	if attributed, ok := s.locationResolver.(interface{ Provider() string }); ok {
		provider = attributed.Provider()
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"node_locations": values, "automatic_enabled": s.locationResolver != nil, "location_provider": provider})
}

func (s *Service) setNodeLocation(w http.ResponseWriter, r *http.Request) {
	nodeID, err := parseIDPath(r, "node_id")
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.ObjectTarget(nodeID))
	if err != nil {
		s.writeError(w, err, false)
		return
	}
	var location *nodelocation.Location
	if r.Method == http.MethodPut {
		// Pointer fields distinguish a real coordinate at zero from missing input.
		var body struct {
			Label     string   `json:"label"`
			Latitude  *float64 `json:"latitude"`
			Longitude *float64 `json:"longitude"`
		}
		if err := s.decodeJSON(w, r, &body); err != nil {
			s.writeError(w, err, false)
			return
		}
		if body.Latitude == nil || body.Longitude == nil {
			s.writeError(w, malformed("latitude and longitude are required"), false)
			return
		}
		location = &nodelocation.Location{Label: body.Label, Latitude: *body.Latitude, Longitude: *body.Longitude}
	}
	if err := s.store.AdministratorSetNodeLocation(r.Context(), decision, identity.NodeID(nodeID), location); err != nil {
		s.writeError(w, err, false)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
