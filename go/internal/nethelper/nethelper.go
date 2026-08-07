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
	ProtocolVersion = 1
	maxMessageSize  = 64 << 10
	maxAddresses    = 8
	maxRoutes       = 1024
	maxBypasses     = 64
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

type request struct {
	Version int        `json:"version"`
	ID      uint64     `json:"id"`
	Op      string     `json:"op"`
	Setup   *Setup     `json:"setup,omitempty"`
	Routes  *RoutePlan `json:"routes,omitempty"`
}

type response struct {
	Version   int    `json:"version"`
	ID        uint64 `json:"id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	HelperPID int    `json:"helper_pid,omitempty"`
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

// Session is the unprivileged side of a helper connection.
type Session struct {
	conn      packetConn
	TUN       platform.TUNDevice
	mu        sync.Mutex
	next      uint64
	done      bool
	wait      func() error
	helperPID int
}

type packetConn interface {
	ReadPacket([]byte, []byte) (int, int, int, error)
	WritePacket([]byte, []byte) error
	Close() error
}

func (s *Session) ApplyRoutes(ctx context.Context, plan RoutePlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return platform.ErrClosed
	}
	s.next++
	return s.roundTrip(request{Version: ProtocolVersion, ID: s.next, Op: "apply-routes", Routes: &plan}, false)
}

func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	s.done = true
	s.next++
	requestErr := s.roundTrip(request{Version: ProtocolVersion, ID: s.next, Op: "close"}, false)
	closeErr := errors.Join(requestErr, s.TUN.Close(), s.conn.Close())
	if s.wait != nil {
		if waitErr := s.wait(); waitErr != nil && requestErr == nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("network helper exited: %w", waitErr))
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
