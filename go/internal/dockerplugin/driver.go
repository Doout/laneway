package dockerplugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

type Backend interface {
	ApplyNetwork(context.Context, *Network, Authorization) error
	RemoveNetwork(context.Context, *Network, Authorization) error
	Join(context.Context, *Network, *Endpoint) error
	Leave(context.Context, *Network, *Endpoint) error
}

type AuthorizationSource interface {
	Current(context.Context) (Authorization, error)
}

type FileAuthorizationSource struct{ Path string }

func (s FileAuthorizationSource) Current(_ context.Context) (Authorization, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		return Authorization{}, fmt.Errorf("dockerplugin: inspect controller authorization: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return Authorization{}, fmt.Errorf("%w: controller authorization must be a private regular file", ErrConflict)
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return Authorization{}, fmt.Errorf("dockerplugin: read controller authorization: %w", err)
	}
	var result Authorization
	if err := json.Unmarshal(data, &result); err != nil {
		return Authorization{}, fmt.Errorf("dockerplugin: decode controller authorization: %w", err)
	}
	if result.Epoch == 0 || result.ValidUntil.IsZero() {
		return Authorization{}, fmt.Errorf("%w: incomplete controller authorization snapshot", ErrUnauthorized)
	}
	return result, nil
}

type Driver struct {
	mu             sync.Mutex
	store          *Store
	backend        Backend
	authorizations AuthorizationSource
	now            func() time.Time
	version        string
}

type DriverOptions struct {
	Store          *Store
	Backend        Backend
	Authorizations AuthorizationSource
	Now            func() time.Time
	Version        string
}

func NewDriver(options DriverOptions) (*Driver, error) {
	if options.Store == nil || options.Backend == nil {
		return nil, fmt.Errorf("%w: store and backend are required", ErrInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Driver{store: options.Store, backend: options.Backend, authorizations: options.Authorizations, now: options.Now, version: options.Version}, nil
}

// Reconcile validates and recreates owned network-level state. Endpoint veths
// are not guessed after a crash: Docker's idempotent Join retry recreates them.
func (d *Driver) Reconcile(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	networks := d.store.Snapshot()
	for id, network := range networks {
		if network.Phase != "active" {
			_ = d.backend.RemoveNetwork(ctx, network, Authorization{})
			if err := d.store.Update(func(values map[string]*Network) error { delete(values, id); return nil }); err != nil {
				return err
			}
			continue
		}
		auth, err := d.authorization(ctx, network)
		if err != nil {
			return fmt.Errorf("reconcile network %s: %w", id, err)
		}
		if err := d.backend.ApplyNetwork(ctx, network, auth); err != nil {
			return fmt.Errorf("reconcile network %s: %w", id, err)
		}
	}
	return nil
}

func (d *Driver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/Plugin.Activate", d.activate)
	mux.HandleFunc("/NetworkDriver.GetCapabilities", d.capabilities)
	mux.HandleFunc("/NetworkDriver.CreateNetwork", d.createNetwork)
	mux.HandleFunc("/NetworkDriver.DeleteNetwork", d.deleteNetwork)
	mux.HandleFunc("/NetworkDriver.CreateEndpoint", d.createEndpoint)
	mux.HandleFunc("/NetworkDriver.DeleteEndpoint", d.deleteEndpoint)
	mux.HandleFunc("/NetworkDriver.EndpointOperInfo", d.endpointInfo)
	mux.HandleFunc("/NetworkDriver.Join", d.join)
	mux.HandleFunc("/NetworkDriver.Leave", d.leave)
	mux.HandleFunc("/NetworkDriver.DiscoverNew", emptyOK)
	mux.HandleFunc("/NetworkDriver.DiscoverDelete", emptyOK)
	mux.HandleFunc("/NetworkDriver.AllocateNetwork", unsupported)
	mux.HandleFunc("/NetworkDriver.FreeNetwork", unsupported)
	mux.HandleFunc("/status", d.status)
	return methodGuard(mux)
}

func methodGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.URL.Path != "/status" {
			writeError(w, http.StatusMethodNotAllowed, errors.New("POST required"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
func emptyOK(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]any{}) }
func unsupported(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"Err": "global-scope and Swarm networking are not supported"})
}
func (d *Driver) activate(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"Implements": []string{"NetworkDriver"}})
}
func (d *Driver) capabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"Scope": "local", "ConnectivityScope": "local"})
}

type ipamData struct {
	Pool         string `json:"Pool"`
	Gateway      string `json:"Gateway"`
	AddressSpace string `json:"AddressSpace"`
}
type createNetworkRequest struct {
	NetworkID string         `json:"NetworkID"`
	IPv4Data  []ipamData     `json:"IPv4Data"`
	IPv6Data  []ipamData     `json:"IPv6Data"`
	Options   map[string]any `json:"Options"`
}
type networkRequest struct {
	NetworkID string `json:"NetworkID"`
}
type endpointRequest struct {
	NetworkID  string `json:"NetworkID"`
	EndpointID string `json:"EndpointID"`
	Interface  *struct {
		Address     string `json:"Address"`
		AddressIPv6 string `json:"AddressIPv6"`
		MacAddress  string `json:"MacAddress"`
	} `json:"Interface"`
	Options map[string]any `json:"Options"`
}
type joinRequest struct {
	NetworkID  string         `json:"NetworkID"`
	EndpointID string         `json:"EndpointID"`
	SandboxKey string         `json:"SandboxKey"`
	Options    map[string]any `json:"Options"`
}

func (d *Driver) createNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if req.NetworkID == "" || len(req.IPv4Data) != 1 {
		writeDriverError(w, fmt.Errorf("%w: exactly one IPv4 pool is required", ErrInvalid))
		return
	}
	if len(req.IPv6Data) != 0 {
		writeDriverError(w, fmt.Errorf("%w: IPv6 fails closed in this release", ErrInvalid))
		return
	}
	subnet, err := netip.ParsePrefix(req.IPv4Data[0].Pool)
	if err != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() || subnet.Bits() > 30 {
		writeDriverError(w, fmt.Errorf("%w: invalid IPv4 pool", ErrInvalid))
		return
	}
	gatewayText := strings.Split(req.IPv4Data[0].Gateway, "/")[0]
	gateway, err := netip.ParseAddr(gatewayText)
	if err != nil || !isUsableIPv4(subnet, gateway) {
		writeDriverError(w, fmt.Errorf("%w: invalid IPv4 gateway", ErrInvalid))
		return
	}
	policy, err := ParsePolicy(req.Options)
	if err != nil {
		writeDriverError(w, err)
		return
	}
	name, table := networkNames(req.NetworkID)
	network := &Network{ID: req.NetworkID, Bridge: name, Table: table, Subnet: subnet, Gateway: gateway, Policy: policy, Phase: "creating", CreatedAt: d.now().UTC(), Endpoints: make(map[string]*Endpoint)}
	for id, existing := range d.store.Snapshot() {
		if id == req.NetworkID {
			if sameNetwork(existing, network) {
				writeJSON(w, map[string]any{})
				return
			}
			writeDriverError(w, fmt.Errorf("%w: network ID already has different configuration", ErrConflict))
			return
		}
		if existing.Subnet.Overlaps(subnet) {
			writeDriverError(w, fmt.Errorf("%w: subnet overlaps managed network %s", ErrConflict, id))
			return
		}
		if existing.Table == table || existing.Bridge == name {
			writeDriverError(w, fmt.Errorf("%w: derived Linux ownership identifier collision", ErrConflict))
			return
		}
	}
	auth, err := d.authorization(r.Context(), network)
	if err != nil {
		writeDriverError(w, err)
		return
	}
	network.BypassCIDRs = append([]netip.Prefix(nil), auth.BypassCIDRs...)
	if err := validateNetworkPolicy(network); err != nil {
		writeDriverError(w, err)
		return
	}
	if err := d.store.Update(func(values map[string]*Network) error { values[network.ID] = network; return nil }); err != nil {
		writeDriverError(w, err)
		return
	}
	if err := d.backend.ApplyNetwork(r.Context(), network, auth); err != nil {
		_ = d.backend.RemoveNetwork(context.Background(), network, auth)
		_ = d.store.Update(func(values map[string]*Network) error { delete(values, network.ID); return nil })
		writeDriverError(w, err)
		return
	}
	if err := d.store.Update(func(values map[string]*Network) error { values[network.ID].Phase = "active"; return nil }); err != nil {
		writeDriverError(w, err)
		return
	}
	writeJSON(w, map[string]any{})
}

func (d *Driver) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	var req networkRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	network := d.store.Snapshot()[req.NetworkID]
	if network == nil {
		writeJSON(w, map[string]any{})
		return
	}
	if len(network.Endpoints) > 0 {
		writeDriverError(w, fmt.Errorf("%w: network still has endpoints", ErrConflict))
		return
	}
	auth, _ := d.authorization(r.Context(), network)
	if err := d.backend.RemoveNetwork(r.Context(), network, auth); err != nil {
		writeDriverError(w, err)
		return
	}
	if err := d.store.Update(func(values map[string]*Network) error { delete(values, req.NetworkID); return nil }); err != nil {
		writeDriverError(w, err)
		return
	}
	writeJSON(w, map[string]any{})
}

func (d *Driver) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	networks := d.store.Snapshot()
	network := networks[req.NetworkID]
	if network == nil {
		writeDriverError(w, ErrNotFound)
		return
	}
	if existing := network.Endpoints[req.EndpointID]; existing != nil {
		writeJSON(w, map[string]any{})
		return
	}
	if req.Interface == nil || req.Interface.AddressIPv6 != "" {
		writeDriverError(w, fmt.Errorf("%w: one IPv4 endpoint address is required", ErrInvalid))
		return
	}
	prefix, err := netip.ParsePrefix(req.Interface.Address)
	if err != nil || !prefix.Addr().Is4() || !isUsableIPv4(network.Subnet, prefix.Addr()) || prefix.Addr() == network.Gateway {
		writeDriverError(w, fmt.Errorf("%w: endpoint address is outside its network", ErrInvalid))
		return
	}
	for _, endpoint := range network.Endpoints {
		if endpoint.Address == prefix.Addr() {
			writeDriverError(w, fmt.Errorf("%w: endpoint address is already in use", ErrConflict))
			return
		}
	}
	endpoint := &Endpoint{ID: req.EndpointID, Address: prefix.Addr()}
	if err := d.store.Update(func(values map[string]*Network) error {
		values[req.NetworkID].Endpoints[req.EndpointID] = endpoint
		return nil
	}); err != nil {
		writeDriverError(w, err)
		return
	}
	writeJSON(w, map[string]any{})
}

func (d *Driver) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	network := d.store.Snapshot()[req.NetworkID]
	if network == nil || network.Endpoints[req.EndpointID] == nil {
		writeJSON(w, map[string]any{})
		return
	}
	endpoint := network.Endpoints[req.EndpointID]
	if endpoint.Joined {
		if err := d.backend.Leave(r.Context(), network, endpoint); err != nil {
			writeDriverError(w, err)
			return
		}
	}
	if err := d.store.Update(func(values map[string]*Network) error {
		delete(values[req.NetworkID].Endpoints, req.EndpointID)
		return nil
	}); err != nil {
		writeDriverError(w, err)
		return
	}
	writeJSON(w, map[string]any{})
}

func (d *Driver) join(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	network := d.store.Snapshot()[req.NetworkID]
	if network == nil || network.Endpoints[req.EndpointID] == nil {
		writeDriverError(w, ErrNotFound)
		return
	}
	endpoint := network.Endpoints[req.EndpointID]
	if !endpoint.Joined {
		endpoint.HostVeth, endpoint.PeerVeth = endpointNames(req.EndpointID)
		endpoint.Sandbox = req.SandboxKey
		if err := d.backend.Join(r.Context(), network, endpoint); err != nil {
			writeDriverError(w, err)
			return
		}
		endpoint.Joined = true
		if err := d.store.Update(func(values map[string]*Network) error {
			values[req.NetworkID].Endpoints[req.EndpointID] = endpoint
			return nil
		}); err != nil {
			writeDriverError(w, err)
			return
		}
	}
	response := map[string]any{"InterfaceName": map[string]string{"SrcName": endpoint.PeerVeth, "DstPrefix": "eth"}, "Gateway": network.Gateway.String()}
	if len(network.Policy.DNS) > 0 {
		values := make([]string, len(network.Policy.DNS))
		for i, v := range network.Policy.DNS {
			values[i] = v.String()
		}
		response["StaticRoutes"] = []any{}
		response["DisableGatewayService"] = true
		response["DNSNameserver"] = values
	}
	writeJSON(w, response)
}

func (d *Driver) leave(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if !decode(w, r, &req) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	network := d.store.Snapshot()[req.NetworkID]
	if network == nil || network.Endpoints[req.EndpointID] == nil {
		writeJSON(w, map[string]any{})
		return
	}
	endpoint := network.Endpoints[req.EndpointID]
	if endpoint.Joined {
		if err := d.backend.Leave(r.Context(), network, endpoint); err != nil {
			writeDriverError(w, err)
			return
		}
		endpoint.Joined = false
		endpoint.HostVeth = ""
		endpoint.PeerVeth = ""
		endpoint.Sandbox = ""
		if err := d.store.Update(func(values map[string]*Network) error {
			values[req.NetworkID].Endpoints[req.EndpointID] = endpoint
			return nil
		}); err != nil {
			writeDriverError(w, err)
			return
		}
	}
	writeJSON(w, map[string]any{})
}

func (d *Driver) endpointInfo(w http.ResponseWriter, r *http.Request) {
	var req endpointRequest
	if !decode(w, r, &req) {
		return
	}
	network := d.store.Snapshot()[req.NetworkID]
	if network == nil || network.Endpoints[req.EndpointID] == nil {
		writeDriverError(w, ErrNotFound)
		return
	}
	endpoint := network.Endpoints[req.EndpointID]
	writeJSON(w, map[string]any{"Value": map[string]any{"address": endpoint.Address.String(), "joined": endpoint.Joined, "policy": network.Policy.Egress}})
}

func (d *Driver) status(w http.ResponseWriter, r *http.Request) {
	networks := d.store.Snapshot()
	endpoints := 0
	policies := make(map[EgressPolicy]int)
	ready := true
	diagnostics := make(map[string]string)
	for _, network := range networks {
		endpoints += len(network.Endpoints)
		policies[network.Policy.Egress]++
		if _, err := d.authorization(r.Context(), network); err != nil {
			ready = false
			diagnostics[network.ID] = err.Error()
		}
	}
	writeJSON(w, map[string]any{"version": d.version, "ready": ready, "networks": len(networks), "endpoints": endpoints, "policies": policies, "diagnostics": diagnostics})
}

func (d *Driver) authorization(ctx context.Context, network *Network) (Authorization, error) {
	needs := network.Policy.Egress != EgressDirect || network.Policy.Ingress == IngressAllow
	if !needs {
		return Authorization{}, nil
	}
	if d.authorizations == nil {
		return Authorization{}, fmt.Errorf("%w: no controller snapshot source configured", ErrUnauthorized)
	}
	auth, err := d.authorizations.Current(ctx)
	if err != nil {
		return Authorization{}, err
	}
	if err := auth.Authorize(d.now(), network.Subnet, network.Policy); err != nil {
		return Authorization{}, err
	}
	return auth, nil
}
func networkNames(id string) (string, int) {
	sum := sha256.Sum256([]byte(id))
	return "lwbr" + hex.EncodeToString(sum[:5]), 20000 + int(uint16(sum[5])<<8|uint16(sum[6]))%10000
}
func endpointNames(id string) (string, string) {
	sum := sha256.Sum256([]byte(id))
	suffix := hex.EncodeToString(sum[:5])
	return "lwh" + suffix, "lwc" + suffix
}
func sameNetwork(a, b *Network) bool {
	return a.Subnet == b.Subnet && a.Gateway == b.Gateway && a.Bridge == b.Bridge && a.Table == b.Table && fmt.Sprint(a.Policy) == fmt.Sprint(b.Policy)
}

func validateNetworkPolicy(network *Network) error {
	for _, prefix := range append(append([]netip.Prefix(nil), network.Policy.EgressCIDRs...), network.Policy.IngressSources...) {
		if network.Subnet.Overlaps(prefix) {
			return fmt.Errorf("%w: policy prefix %s overlaps container subnet %s", ErrInvalid, prefix, network.Subnet)
		}
	}
	for _, prefix := range network.BypassCIDRs {
		if !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() == 0 || network.Subnet.Overlaps(prefix) {
			return fmt.Errorf("%w: unsafe controller bypass prefix %s", ErrUnauthorized, prefix)
		}
	}
	return nil
}

func isUsableIPv4(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || !prefix.Contains(address) || prefix.Bits() > 30 {
		return false
	}
	baseBytes, addressBytes := prefix.Masked().Addr().As4(), address.As4()
	base := uint32(baseBytes[0])<<24 | uint32(baseBytes[1])<<16 | uint32(baseBytes[2])<<8 | uint32(baseBytes[3])
	value := uint32(addressBytes[0])<<24 | uint32(addressBytes[1])<<16 | uint32(addressBytes[2])<<8 | uint32(addressBytes[3])
	hostMask := uint32(1)<<(32-prefix.Bits()) - 1
	return value != base && value != base|hostMask
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(value); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, value any) { _ = json.NewEncoder(w).Encode(value) }
func writeError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"Err": err.Error()})
}
func writeDriverError(w http.ResponseWriter, err error) {
	writeJSON(w, map[string]string{"Err": err.Error()})
}
