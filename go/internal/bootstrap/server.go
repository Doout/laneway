package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

type RelaySource interface {
	ActiveRelays(context.Context, identity.NetworkID) ([]controller.Relay, error)
}

type ServerOptions struct {
	Relays               RelaySource
	NetworkID            identity.NetworkID
	ControllerEndpoint   string
	ControllerQUIC       string
	ControllerServerName string
	ControllerServiceID  identity.ID
	CAPEM                string
	Artifacts            []Artifact
	Now                  func() time.Time
	DocumentLifetime     time.Duration
}

type Server struct {
	relays               RelaySource
	networkID            identity.NetworkID
	controllerEndpoint   string
	controllerQUIC       string
	controllerServerName string
	controllerServiceID  identity.ID
	caPEM                string
	artifacts            []Artifact
	now                  func() time.Time
	lifetime             time.Duration
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.Relays == nil || options.NetworkID.IsZero() || options.ControllerServiceID.IsZero() {
		return nil, errors.New("bootstrap: server requires relay source and controller identity pins")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.DocumentLifetime == 0 {
		options.DocumentLifetime = 5 * time.Minute
	}
	if options.DocumentLifetime <= 0 || options.DocumentLifetime > MaxDocumentLifetime {
		return nil, errors.New("bootstrap: document lifetime is invalid")
	}
	server := &Server{
		relays: options.Relays, networkID: options.NetworkID,
		controllerEndpoint: options.ControllerEndpoint, controllerQUIC: options.ControllerQUIC,
		controllerServerName: options.ControllerServerName, controllerServiceID: options.ControllerServiceID,
		caPEM: options.CAPEM, artifacts: slices.Clone(options.Artifacts), now: options.Now, lifetime: options.DocumentLifetime,
	}
	// Validate the static portion at startup. A placeholder relay is used only
	// for structural validation; live relay data is validated on every request.
	now := server.now().UTC().Truncate(time.Second)
	probe := server.baseMetadata(now)
	probe.Relays = []Relay{{Name: "startup-validation", Endpoint: "127.0.0.1:1", ServiceID: options.ControllerServiceID.String()}}
	if err := probe.Validate(now); err != nil {
		return nil, err
	}
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) baseMetadata(now time.Time) Metadata {
	return Metadata{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Unix(),
		ValidUntil:    now.Add(s.lifetime).Unix(),
		NetworkID:     s.networkID.String(),
		Controller: Controller{
			EnrollmentEndpoint: s.controllerEndpoint,
			QUICEndpoint:       s.controllerQUIC,
			ServerName:         s.controllerServerName,
			ServiceID:          s.controllerServiceID.String(),
		},
		Trust: Trust{CAPEM: s.caPEM},
		Protocol: Protocol{
			ControlMajor: protocol.ProtocolMajor1,
			ControlMinor: 0,
			Packet:       []uint32{uint32(protocol.PacketVersion1)},
			Capabilities: uint64(protocol.KnownCapabilities),
		},
		Artifacts: slices.Clone(s.artifacts),
	}
}

func (s *Server) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if request.Method != http.MethodGet || request.URL.Path != WellKnownPath || request.URL.RawQuery != "" {
		http.NotFound(writer, request)
		return
	}
	now := s.now().UTC().Truncate(time.Second)
	values, err := s.relays.ActiveRelays(request.Context(), s.networkID)
	if err != nil {
		http.Error(writer, "bootstrap metadata temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	metadata := s.baseMetadata(now)
	metadata.Relays = make([]Relay, 0, len(values))
	for _, relay := range values {
		metadata.Relays = append(metadata.Relays, Relay{Name: relay.Name, Endpoint: relay.Endpoint, ServiceID: relay.ServiceID.String()})
	}
	if err := metadata.Validate(now); err != nil {
		http.Error(writer, "bootstrap metadata temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(metadata); err != nil {
		return
	}
}
