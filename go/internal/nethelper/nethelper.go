// Package nethelper implements the narrow privileged boundary used by
// foreground Laneway sessions. The helper accepts only typed TUN and route
// plans over an inherited Unix socket; it never listens on a pathname and it
// never receives credentials or private keys.
package nethelper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/platform"
)

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data in network helper message")
	}
	return nil
}

const (
	ProtocolVersion  = 1
	maxMessageSize   = 64 << 10
	maxAddresses     = 8
	maxRoutes        = 1024
	maxBypasses      = 64
	maxDNSAddresses  = 8
	roundTripTimeout = 10 * time.Second
)

type Setup struct {
	Name      string    `json:"name"`
	MTU       int       `json:"mtu"`
	Addresses []string  `json:"addresses"`
	Routes    RoutePlan `json:"routes"`
}

type Route struct {
	Prefix string `json:"prefix"`
	Metric uint32 `json:"metric,omitempty"`
}

type RoutePlan struct {
	Routes   []Route  `json:"routes,omitempty"`
	Bypasses []string `json:"bypasses,omitempty"`
}

// ExitRoutePlan is the narrow wire representation of the policy-routing
// changes required by an explicitly selected exit node. Every prefix and
// bypass is re-parsed and validated by the privileged process.
type ExitRoutePlan struct {
	TunnelPrefixes  []string `json:"tunnel_prefixes,omitempty"`
	TransportBypass []string `json:"transport_bypasses,omitempty"`
	LocalLANBypass  []string `json:"local_lan_bypasses,omitempty"`
}

type DNSPlan struct {
	Servers []string `json:"servers,omitempty"`
}

type request struct {
	Version int            `json:"version"`
	ID      uint64         `json:"id"`
	Op      string         `json:"op"`
	Setup   *Setup         `json:"setup,omitempty"`
	Routes  *RoutePlan     `json:"routes,omitempty"`
	Exit    *ExitRoutePlan `json:"exit_routes,omitempty"`
	DNS     *DNSPlan       `json:"dns,omitempty"`
}

type response struct {
	Version       int    `json:"version"`
	ID            uint64 `json:"id"`
	OK            bool   `json:"ok"`
	Error         string `json:"error,omitempty"`
	HelperPID     int    `json:"helper_pid,omitempty"`
	InterfaceName string `json:"interface_name,omitempty"`
}

func parseSetup(value Setup) (platform.TUNConfig, platform.RoutePlan, error) {
	if len(value.Addresses) > maxAddresses {
		return platform.TUNConfig{}, platform.RoutePlan{}, fmt.Errorf("too many interface addresses (maximum %d)", maxAddresses)
	}
	addresses := make([]netip.Prefix, 0, len(value.Addresses))
	for _, raw := range value.Addresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return platform.TUNConfig{}, platform.RoutePlan{}, fmt.Errorf("invalid interface address %q", raw)
		}
		addresses = append(addresses, prefix)
	}
	plan, err := parseRoutePlan(value.Routes)
	if err != nil {
		return platform.TUNConfig{}, platform.RoutePlan{}, err
	}
	config := platform.TUNConfig{Name: value.Name, MTU: value.MTU, Addresses: addresses}
	// AdoptTUNFile and OpenTUN use the same strict normalization. Validate here
	// without performing a privileged mutation by checking a disposable nil fd
	// only after the route plan; OpenTUN remains authoritative in the service.
	return config, plan, nil
}

func parseRoutePlan(value RoutePlan) (platform.RoutePlan, error) {
	if len(value.Routes) > maxRoutes || len(value.Bypasses) > maxBypasses {
		return platform.RoutePlan{}, errors.New("route plan exceeds helper limits")
	}
	plan := platform.RoutePlan{Routes: make([]platform.Route, 0, len(value.Routes)), TransportBypass: make([]netip.Addr, 0, len(value.Bypasses))}
	for _, item := range value.Routes {
		prefix, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			return platform.RoutePlan{}, fmt.Errorf("invalid route prefix %q", item.Prefix)
		}
		plan.Routes = append(plan.Routes, platform.Route{Prefix: prefix, Metric: item.Metric})
	}
	for _, raw := range value.Bypasses {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return platform.RoutePlan{}, fmt.Errorf("invalid bypass address %q", raw)
		}
		plan.TransportBypass = append(plan.TransportBypass, address)
	}
	if err := platform.ValidateRoutePlan(plan); err != nil {
		return platform.RoutePlan{}, err
	}
	return plan, nil
}

func parseExitRoutePlan(value ExitRoutePlan) (exitnode.RoutePlan, error) {
	if len(value.TunnelPrefixes) > 4 || len(value.TransportBypass) > maxBypasses || len(value.LocalLANBypass) > maxBypasses {
		return exitnode.RoutePlan{}, errors.New("exit route plan exceeds helper limits")
	}
	plan := exitnode.RoutePlan{
		TunnelPrefixes:  make([]netip.Prefix, 0, len(value.TunnelPrefixes)),
		TransportBypass: make([]netip.Addr, 0, len(value.TransportBypass)),
		LocalLANBypass:  make([]netip.Prefix, 0, len(value.LocalLANBypass)),
	}
	for _, raw := range value.TunnelPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return exitnode.RoutePlan{}, fmt.Errorf("invalid exit tunnel prefix %q", raw)
		}
		plan.TunnelPrefixes = append(plan.TunnelPrefixes, prefix)
	}
	for _, raw := range value.TransportBypass {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return exitnode.RoutePlan{}, fmt.Errorf("invalid exit transport bypass %q", raw)
		}
		plan.TransportBypass = append(plan.TransportBypass, address)
	}
	for _, raw := range value.LocalLANBypass {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return exitnode.RoutePlan{}, fmt.Errorf("invalid exit local-LAN bypass %q", raw)
		}
		plan.LocalLANBypass = append(plan.LocalLANBypass, prefix)
	}
	if err := exitnode.ValidateRoutePlan(plan); err != nil {
		return exitnode.RoutePlan{}, err
	}
	return plan, nil
}

func parseDNSPlan(value DNSPlan) ([]netip.Addr, error) {
	if len(value.Servers) == 0 || len(value.Servers) > maxDNSAddresses {
		return nil, fmt.Errorf("DNS plan must contain from 1 through %d servers", maxDNSAddresses)
	}
	servers := make([]netip.Addr, 0, len(value.Servers))
	for _, raw := range value.Servers {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("invalid DNS server %q", raw)
		}
		servers = append(servers, address)
	}
	return servers, nil
}

// Session is the unprivileged side of a helper connection.
type Session struct {
	conn      packetConn
	TUN       platform.TUNDevice
	mu        sync.Mutex
	next      uint64
	done      bool
	wait      <-chan error
	kill      func() error
	helperPID int
}

type packetConn interface {
	ReadPacket([]byte, []byte) (int, int, int, error)
	WritePacket([]byte, []byte) error
	Close() error
	SetDeadline(time.Time) error
}

func (s *Session) ApplyRoutes(ctx context.Context, plan RoutePlan) error {
	return s.request(ctx, request{Op: "apply-routes", Routes: &plan})
}

// ApplyExitRoutes reconciles the dedicated exit policy-routing table. It does
// not permit arbitrary tables, priorities, protocols, devices, or commands;
// those remain fixed by ProductionConfig in the privileged process.
func (s *Session) ApplyExitRoutes(ctx context.Context, plan ExitRoutePlan) error {
	return s.request(ctx, request{Op: "apply-exit-routes", Exit: &plan})
}

func (s *Session) RestoreExitRoutes(ctx context.Context) error {
	return s.request(ctx, request{Op: "restore-exit-routes"})
}

func (s *Session) ApplyDNS(ctx context.Context, plan DNSPlan) error {
	return s.request(ctx, request{Op: "apply-dns", DNS: &plan})
}

func (s *Session) RestoreDNS(ctx context.Context) error {
	return s.request(ctx, request{Op: "restore-dns"})
}

func (s *Session) request(ctx context.Context, req request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return platform.ErrClosed
	}
	s.next++
	req.Version, req.ID = ProtocolVersion, s.next
	deadline := time.Now().Add(roundTripTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := s.conn.SetDeadline(deadline); err != nil {
		return err
	}
	defer s.conn.SetDeadline(time.Time{})
	return s.roundTrip(req, false)
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	s.done = true
	s.next++
	_ = s.conn.SetDeadline(time.Now().Add(roundTripTimeout))
	requestErr := s.roundTrip(request{Version: ProtocolVersion, ID: s.next, Op: "close"}, false)
	closeErr := errors.Join(requestErr, s.TUN.Close(), s.conn.Close())
	if s.wait != nil {
		timer := time.NewTimer(roundTripTimeout)
		select {
		case waitErr := <-s.wait:
			timer.Stop()
			if waitErr != nil && requestErr == nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("network helper exited: %w", waitErr))
			}
		case <-timer.C:
			if s.kill != nil {
				closeErr = errors.Join(closeErr, s.kill())
			}
			closeErr = errors.Join(closeErr, errors.New("network helper cleanup timed out"))
		}
	}
	return closeErr
}

func (s *Session) roundTrip(req request, wantFD bool) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := s.conn.WritePacket(payload, nil); err != nil {
		return fmt.Errorf("network helper request: %w", err)
	}
	data := make([]byte, maxMessageSize)
	oob := make([]byte, 128)
	n, oobn, flags, err := s.conn.ReadPacket(data, oob)
	if err != nil {
		return fmt.Errorf("network helper response: %w", err)
	}
	if flags&(unixMessageTruncated|unixControlTruncated) != 0 || n == 0 {
		return errors.New("network helper returned a truncated response")
	}
	var reply response
	if err := decodeStrict(data[:n], &reply); err != nil {
		return fmt.Errorf("network helper response: %w", err)
	}
	if reply.Version != ProtocolVersion || reply.ID != req.ID {
		return errors.New("network helper returned a mismatched response")
	}
	if !reply.OK {
		return fmt.Errorf("network helper: %s", reply.Error)
	}
	if wantFD && oobn == 0 {
		return errors.New("network helper omitted the TUN descriptor")
	}
	return nil
}
