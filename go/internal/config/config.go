// Package config loads and validates laneway.toml without applying any host
// networking changes. All paths and prefixes are resolved before a daemon
// starts so partial startup cannot leave routes behind.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"laneway.dev/laneway/internal/netvalidate"
	"laneway.dev/laneway/internal/protocol"

	"github.com/pelletier/go-toml/v2"

	"laneway.dev/laneway/internal/identity"
)

const MaxFileSize = 1 << 20

type Mode string

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

const (
	ModeNode       Mode = "node"
	ModeRelay      Mode = "relay"
	ModeController Mode = "controller"
)

type Config struct {
	Mode        Mode             `toml:"mode"`
	StateDir    string           `toml:"state_dir"`
	SocketPath  string           `toml:"socket_path"`
	TLS         TLS              `toml:"tls"`
	Node        Node             `toml:"node"`
	Relay       Relay            `toml:"relay"`
	Controller  Controller       `toml:"controller"`
	Bootstrap   Bootstrap        `toml:"bootstrap"`
	PublicHTTPS PublicHTTPS      `toml:"public_https"`
	Routing     Routing          `toml:"routing"`
	Connector   Connector        `toml:"connector"`
	Exit        Exit             `toml:"exit"`
	TCPFallback TCPFallback      `toml:"tcp_fallback"`
	Direct      Direct           `toml:"direct"`
	WireGuard   WireGuard        `toml:"wireguard"`
	Peers       []AuthorizedPeer `toml:"peers"`
}

type TLS struct {
	CertificateFile string `toml:"certificate"`
	PrivateKeyFile  string `toml:"private_key"`
	CAFile          string `toml:"ca"`
	ServerName      string `toml:"server_name"`
}

type Node struct {
	Name             string   `toml:"name"`
	RelayAddress     string   `toml:"relay_address"`
	RelayNetworkID   string   `toml:"relay_network_id"`
	RelayServiceID   string   `toml:"relay_service_id"`
	OverlayAddresses []string `toml:"overlay_addresses"`
	ReconnectMin     Duration `toml:"reconnect_min"`
	ReconnectMax     Duration `toml:"reconnect_max"`
}

type Relay struct {
	Listen                  string   `toml:"listen"`
	QueueDepth              int      `toml:"queue_depth"`
	PacketRateBitsPerSecond uint64   `toml:"packet_rate_bits_per_second"`
	PacketBurstBytes        int      `toml:"packet_burst_bytes"`
	HandshakeTimeout        Duration `toml:"handshake_timeout"`
	IdleTimeout             Duration `toml:"idle_timeout"`
}

// TCPFallback configures the fallback-only TLS/TCP relay carrier. Address is
// used in node mode and Listen in relay mode. An empty mode-specific endpoint
// disables the carrier without weakening QUIC validation.
type TCPFallback struct {
	Address           string   `toml:"address"`
	Listen            string   `toml:"listen"`
	HandshakeTimeout  Duration `toml:"handshake_timeout"`
	WriteTimeout      Duration `toml:"write_timeout"`
	IdleTimeout       Duration `toml:"idle_timeout"`
	KeepAlivePeriod   Duration `toml:"keepalive_period"`
	QUICProbeInterval Duration `toml:"quic_probe_interval"`
	QueueDepth        int      `toml:"queue_depth"`
}

// Direct enables authenticated peer QUIC and relay-coordinated UDP probing.
// The relay connection shares this UDP listener to preserve its observed NAT
// mapping. Loopback is disabled by default and intended only for local tests.
type Direct struct {
	Enabled            bool     `toml:"enabled"`
	Listen             string   `toml:"listen"`
	CandidateTTL       Duration `toml:"candidate_ttl"`
	ProbeInterval      Duration `toml:"probe_interval"`
	ProbeTimeout       Duration `toml:"probe_timeout"`
	RendezvousInterval Duration `toml:"rendezvous_interval"`
	MaxCandidates      int      `toml:"max_candidates"`
	AllowLoopback      bool     `toml:"allow_loopback"`
	AllowLinkLocal     bool     `toml:"allow_link_local"`
}

// WireGuard identifies the stable end-to-end encrypted overlay device. The
// private key file contains exactly 32 raw bytes and must remain host-local.
type WireGuard struct {
	Enabled        bool   `toml:"enabled"`
	PrivateKeyFile string `toml:"private_key"`
	InterfaceName  string `toml:"interface"`
	ListenPort     uint16 `toml:"listen_port"`
	MTU            int    `toml:"mtu"`
}

type Controller struct {
	Listen           string `toml:"listen"`
	QUICListen       string `toml:"quic_listen"`
	Endpoint         string `toml:"endpoint"`
	QUICEndpoint     string `toml:"quic_endpoint"`
	ServerName       string `toml:"server_name"`
	NetworkID        string `toml:"network_id"`
	ServiceID        string `toml:"service_id"`
	DatabaseFile     string `toml:"database"`
	CAPrivateKeyFile string `toml:"ca_private_key"`
	// IssuerCertificateFile is an issuer-first PEM CA bundle. It may differ
	// from tls.ca so the controller can hold an intermediate key while nodes
	// trust only the offline root. Empty preserves direct-root deployments.
	IssuerCertificateFile string   `toml:"issuer_certificate"`
	AdminTokenFile        string   `toml:"admin_token_file"`
	LeafValidity          Duration `toml:"leaf_validity"`
	PollInterval          Duration `toml:"poll_interval"`
}

// Bootstrap configures a dedicated public-Web-PKI HTTPS listener. It serves
// non-secret discovery data only; the private controller API keeps its
// Laneway-CA service certificate and identity pin.
type Bootstrap struct {
	Listen                 string              `toml:"listen"`
	CertificateFile        string              `toml:"certificate"`
	PrivateKeyFile         string              `toml:"private_key"`
	NetworkID              string              `toml:"network_id"`
	ControllerEndpoint     string              `toml:"controller_endpoint"`
	ControllerQUICEndpoint string              `toml:"controller_quic_endpoint"`
	ControllerServerName   string              `toml:"controller_server_name"`
	Artifacts              []BootstrapArtifact `toml:"artifacts"`
}

// PublicHTTPS enables Web-PKI HTTPS on a relay's existing TCP fallback
// listener. TLS ALPN keeps ordinary HTTPS and Laneway fallback isolated while
// sharing one externally reachable port.
type PublicHTTPS struct {
	ServerName string `toml:"server_name"`
	CacheDir   string `toml:"cache_dir"`
}

type BootstrapArtifact struct {
	OS        string `toml:"os"`
	Arch      string `toml:"arch"`
	URL       string `toml:"url"`
	SHA256    string `toml:"sha256"`
	SizeBytes int64  `toml:"size_bytes"`
}

type Routing struct {
	Advertise       []string `toml:"advertise"`
	NAT             bool     `toml:"nat"`
	OutputInterface string   `toml:"output_interface"`
}

// Connector selects the unprivileged userspace TCP/UDP forwarding dataplane.
// It is mutually exclusive with native host routing and full packet Exit mode.
type Connector struct {
	Userspace bool `toml:"userspace"`
}

type Exit struct {
	Enabled          bool     `toml:"enabled"`
	Serve            bool     `toml:"serve"`
	SelectedNodeID   string   `toml:"selected_node_id"`
	FailureMode      string   `toml:"failure_mode"`
	DNSServers       []string `toml:"dns_servers"`
	LocalLANBypasses []string `toml:"local_lan_bypasses"`
	// LeaseGeneration is present only in a RAM-backed ephemeral Exit runtime.
	// It binds controller heartbeats to one run and must never be persisted.
	LeaseGeneration uint64 `toml:"lease_generation"`
}

type AuthorizedPeer struct {
	NetworkID string `toml:"network_id"`
	NodeID    string `toml:"node_id"`
	// Name is an optional operator-facing selector. It is never used for
	// transport authentication, which remains certificate/NodeID-bound.
	Name     string   `toml:"name"`
	Prefixes []string `toml:"prefixes"`
}

func Defaults() Config {
	return Config{
		StateDir:   "/var/lib/laneway",
		SocketPath: "/run/laneway/lanewayd.sock",
		Node: Node{
			ReconnectMin: Duration(time.Second),
			ReconnectMax: Duration(30 * time.Second),
		},
		Relay: Relay{
			Listen:           ":4433",
			QueueDepth:       256,
			HandshakeTimeout: Duration(10 * time.Second),
			IdleTimeout:      Duration(45 * time.Second),
		},
		TCPFallback: TCPFallback{
			HandshakeTimeout:  Duration(10 * time.Second),
			WriteTimeout:      Duration(10 * time.Second),
			IdleTimeout:       Duration(45 * time.Second),
			KeepAlivePeriod:   Duration(15 * time.Second),
			QUICProbeInterval: Duration(30 * time.Second),
			QueueDepth:        128,
		},
		Direct: Direct{
			Listen: ":0", CandidateTTL: Duration(2 * time.Minute), ProbeInterval: Duration(200 * time.Millisecond),
			ProbeTimeout: Duration(3 * time.Second), RendezvousInterval: Duration(30 * time.Second), MaxCandidates: 8,
		},
		WireGuard: WireGuard{InterfaceName: "lane0", MTU: 1280},
		Controller: Controller{
			Listen: "127.0.0.1:8080", LeafValidity: Duration(30 * 24 * time.Hour), PollInterval: Duration(30 * time.Second),
		},
		Routing: Routing{NAT: true},
		Exit:    Exit{},
	}
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer f.Close()
	return Decode(io.LimitReader(f, MaxFileSize+1))
}

func Decode(r io.Reader) (Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(data) > MaxFileSize {
		return Config{}, fmt.Errorf("configuration exceeds %d bytes", MaxFileSize)
	}
	cfg := Defaults()
	decoder := toml.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	// Node configurations opt into the managed direct-path default unless the
	// operator explicitly sets direct.enabled=false. Other actor modes retain
	// a disabled direct section because they do not own a node dataplane.
	var document map[string]any
	if err := toml.Unmarshal(data, &document); err != nil {
		return Config{}, fmt.Errorf("decode configuration shape: %w", err)
	}
	direct, _ := document["direct"].(map[string]any)
	if cfg.Mode == ModeNode {
		if _, specified := direct["enabled"]; !specified {
			cfg.Direct.Enabled = true
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Mode != ModeNode && c.Mode != ModeRelay && c.Mode != ModeController {
		return fmt.Errorf("mode must be %q, %q, or %q", ModeNode, ModeRelay, ModeController)
	}
	if c.StateDir == "" || c.SocketPath == "" {
		return errors.New("state_dir and socket_path are required")
	}
	if c.TLS.CertificateFile == "" || c.TLS.PrivateKeyFile == "" || c.TLS.CAFile == "" {
		return errors.New("tls.certificate, tls.private_key, and tls.ca are required")
	}
	if c.Node.ReconnectMin <= 0 || c.Node.ReconnectMax < c.Node.ReconnectMin {
		return errors.New("node reconnect bounds are invalid")
	}
	if c.Relay.QueueDepth < 1 || c.Relay.QueueDepth > 65536 {
		return errors.New("relay.queue_depth must be between 1 and 65536")
	}
	if (c.Relay.PacketRateBitsPerSecond == 0) != (c.Relay.PacketBurstBytes == 0) ||
		c.Relay.PacketRateBitsPerSecond > 1_000_000_000_000 || c.Relay.PacketBurstBytes < 0 || c.Relay.PacketBurstBytes > 64<<20 ||
		(c.Relay.PacketRateBitsPerSecond != 0 && c.Relay.PacketBurstBytes < protocol.PacketHeaderSize+1280) {
		return errors.New("relay packet limiter requires rate and burst together, rate <= 1Tbps, and burst from 1285 bytes through 64MiB")
	}
	if c.Relay.HandshakeTimeout <= 0 || c.Relay.IdleTimeout <= 0 {
		return errors.New("relay timeout values must be positive")
	}
	if c.TCPFallback.HandshakeTimeout <= 0 || c.TCPFallback.WriteTimeout <= 0 || c.TCPFallback.IdleTimeout <= 0 ||
		c.TCPFallback.KeepAlivePeriod <= 0 || c.TCPFallback.KeepAlivePeriod >= c.TCPFallback.IdleTimeout ||
		c.TCPFallback.QUICProbeInterval < Duration(time.Second) || c.TCPFallback.QUICProbeInterval > Duration(5*time.Minute) {
		return errors.New("tcp_fallback timeouts are invalid; keepalive_period must be shorter than idle_timeout and quic_probe_interval in [1s,5m]")
	}
	if c.TCPFallback.QueueDepth < 1 || c.TCPFallback.QueueDepth > 4096 {
		return errors.New("tcp_fallback.queue_depth must be between 1 and 4096")
	}
	if c.Direct.CandidateTTL <= 0 || c.Direct.CandidateTTL > Duration(10*time.Minute) ||
		c.Direct.ProbeInterval <= 0 || c.Direct.ProbeInterval > Duration(time.Second) ||
		c.Direct.ProbeTimeout <= 0 || c.Direct.ProbeTimeout > Duration(30*time.Second) ||
		c.Direct.RendezvousInterval < Duration(time.Second) || c.Direct.RendezvousInterval > Duration(5*time.Minute) ||
		c.Direct.MaxCandidates < 1 || c.Direct.MaxCandidates > 32 {
		return errors.New("direct candidate, probe, and timeout bounds are invalid")
	}
	switch c.Mode {
	case ModeNode:
		if c.Node.RelayAddress == "" {
			return errors.New("node.relay_address is required in node mode")
		}
		if _, err := identity.ParseNetworkID(c.Node.RelayNetworkID); err != nil {
			return fmt.Errorf("node.relay_network_id: %w", err)
		}
		if _, err := identity.ParseID(c.Node.RelayServiceID); err != nil {
			return fmt.Errorf("node.relay_service_id: %w", err)
		}
		if len(c.Node.OverlayAddresses) == 0 && c.Controller.Endpoint == "" {
			return errors.New("at least one node.overlay_addresses entry is required without a controller")
		}
		if c.Controller.Endpoint != "" && (c.Controller.PollInterval <= 0 || c.Controller.QUICEndpoint == "") {
			return errors.New("controller.quic_endpoint and a positive controller.poll_interval are required when controller.endpoint is configured")
		}
		if c.Controller.Endpoint != "" && len(c.Peers) != 0 {
			return errors.New("static peers and controller.endpoint are mutually exclusive in node mode")
		}
		if c.Controller.Endpoint != "" && len(c.Node.OverlayAddresses) != 0 {
			return errors.New("static node.overlay_addresses and controller.endpoint are mutually exclusive")
		}
		if c.TCPFallback.Listen != "" {
			return errors.New("tcp_fallback.listen is only valid in relay mode")
		}
		if c.Direct.Enabled && c.Direct.Listen == "" {
			return errors.New("direct.listen is required when direct connectivity is enabled")
		}
		if c.WireGuard.Enabled && (c.WireGuard.PrivateKeyFile == "" || c.WireGuard.InterfaceName == "" || c.WireGuard.MTU != 1280) {
			return errors.New("wireguard.private_key, interface, and MTU 1280 are required when WireGuard is enabled")
		}
		if c.Connector.Userspace && (c.WireGuard.Enabled || c.Routing.OutputInterface != "" || len(c.Routing.Advertise) != 0 || c.Exit.Enabled || c.Exit.Serve) {
			return errors.New("userspace Connector mode cannot use WireGuard, native routing, or full packet Exit mode")
		}
	case ModeRelay:
		if c.Direct.Enabled || c.WireGuard.Enabled {
			return errors.New("direct connectivity and WireGuard are only valid in node mode")
		}
		if c.Relay.Listen == "" {
			return errors.New("relay.listen is required in relay mode")
		}
		if c.Controller.Endpoint != "" {
			if c.Controller.PollInterval <= 0 || c.Controller.QUICEndpoint == "" {
				return errors.New("controller.quic_endpoint and a positive controller.poll_interval are required when controller.endpoint is configured")
			}
			if len(c.Peers) != 0 {
				return errors.New("static peers and controller.endpoint are mutually exclusive in relay mode")
			}
		} else if len(c.Peers) == 0 {
			return errors.New("at least one static peer or controller.endpoint is required in relay mode")
		}
		if c.TCPFallback.Address != "" {
			return errors.New("tcp_fallback.address is only valid in node mode")
		}
		if (c.PublicHTTPS.ServerName == "") != (c.PublicHTTPS.CacheDir == "") {
			return errors.New("public_https requires server_name and cache_dir together")
		}
		if c.PublicHTTPS.ServerName != "" {
			if c.TCPFallback.Listen == "" || c.Controller.Endpoint == "" {
				return errors.New("public_https requires tcp_fallback.listen and controller.endpoint")
			}
			if err := validateBootstrapDNSName(c.PublicHTTPS.ServerName); err != nil {
				return fmt.Errorf("public_https.server_name: %w", err)
			}
			if !filepath.IsAbs(c.PublicHTTPS.CacheDir) || filepath.Clean(c.PublicHTTPS.CacheDir) != c.PublicHTTPS.CacheDir {
				return errors.New("public_https.cache_dir must be a clean absolute path")
			}
		}
	case ModeController:
		if c.Direct.Enabled || c.WireGuard.Enabled {
			return errors.New("direct connectivity and WireGuard are only valid in node mode")
		}
		if c.Controller.Listen == "" || c.Controller.QUICListen == "" || c.Controller.DatabaseFile == "" || c.Controller.CAPrivateKeyFile == "" || c.Controller.AdminTokenFile == "" {
			return errors.New("controller.listen, controller.quic_listen, controller.database, controller.ca_private_key, and controller.admin_token_file are required in controller mode")
		}
		if c.Controller.LeafValidity <= 0 {
			return errors.New("controller.leaf_validity must be positive")
		}
		if c.TCPFallback.Address != "" || c.TCPFallback.Listen != "" {
			return errors.New("tcp_fallback endpoints are not valid in controller mode")
		}
		if err := validateBootstrap(c.Bootstrap); err != nil {
			return err
		}
	}
	if c.Mode != ModeController && bootstrapConfigured(c.Bootstrap) {
		return errors.New("bootstrap listener is valid only in controller mode")
	}
	if c.Mode != ModeRelay && (c.PublicHTTPS.ServerName != "" || c.PublicHTTPS.CacheDir != "") {
		return errors.New("public_https is valid only in relay mode")
	}
	if c.Mode != ModeNode && c.Connector.Userspace {
		return errors.New("userspace Connector mode is valid only in node mode")
	}
	if c.Controller.Endpoint != "" {
		if _, err := identity.ParseNetworkID(c.Controller.NetworkID); err != nil {
			return fmt.Errorf("controller.network_id: %w", err)
		}
		if _, err := identity.ParseID(c.Controller.ServiceID); err != nil {
			return fmt.Errorf("controller.service_id: %w", err)
		}
	}
	if (len(c.Routing.Advertise) != 0 || c.Exit.Serve) && c.Routing.OutputInterface == "" {
		return errors.New("routing.output_interface is required for subnet or exit gateway forwarding")
	}
	if c.Exit.Enabled {
		if c.Controller.Endpoint == "" {
			return errors.New("controller.endpoint is required when an exit node is selected")
		}
		selected, err := identity.ParseNodeID(c.Exit.SelectedNodeID)
		if err != nil {
			return fmt.Errorf("exit.selected_node_id: %w", err)
		}
		if selected.IsZero() {
			return errors.New("exit.selected_node_id must be nonzero")
		}
		if c.Exit.FailureMode != "open" && c.Exit.FailureMode != "closed" {
			return errors.New("exit.failure_mode must be explicitly set to open or closed")
		}
	}
	if c.Exit.Serve && c.Controller.Endpoint == "" {
		return errors.New("controller.endpoint is required when serving as an exit node")
	}
	if c.Exit.LeaseGeneration != 0 {
		if !c.Exit.Serve || c.Exit.Enabled || c.Exit.FailureMode != "closed" ||
			c.Controller.Endpoint == "" || c.Controller.PollInterval > Duration(10*time.Second) {
			return errors.New("an ephemeral Exit lease requires serve-only fail-closed mode and a controller poll interval no greater than 10s")
		}
	}
	for _, value := range c.Exit.DNSServers {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return fmt.Errorf("exit DNS server %q is not a unicast IP address", value)
		}
	}
	for _, value := range c.Exit.LocalLANBypasses {
		prefix, err := canonicalPrefix(value)
		if err != nil || netvalidate.RoutablePrefix(prefix, false) != nil {
			return fmt.Errorf("exit local LAN bypass %q is not a canonical non-default IP prefix", value)
		}
	}
	for _, prefix := range c.Node.OverlayAddresses {
		if _, err := canonicalPrefix(prefix); err != nil {
			return err
		}
	}
	for _, value := range c.Routing.Advertise {
		prefix, err := canonicalPrefix(value)
		if err != nil || netvalidate.RoutablePrefix(prefix, false) != nil {
			return fmt.Errorf("advertised prefix %q is not a canonical routable non-default prefix", value)
		}
	}
	for i, peer := range c.Peers {
		if _, err := identity.ParseNetworkID(peer.NetworkID); err != nil {
			return fmt.Errorf("peers[%d].network_id: %w", i, err)
		}
		if _, err := identity.ParseNodeID(peer.NodeID); err != nil {
			return fmt.Errorf("peers[%d].node_id: %w", i, err)
		}
		if peer.Name != strings.TrimSpace(peer.Name) || len(peer.Name) > 253 || strings.IndexByte(peer.Name, 0) >= 0 {
			return fmt.Errorf("peers[%d].name must be empty or a trimmed name of at most 253 bytes", i)
		}
		if len(peer.Prefixes) == 0 {
			return fmt.Errorf("peers[%d].prefixes is empty", i)
		}
		for _, prefix := range peer.Prefixes {
			parsed, err := canonicalPrefix(prefix)
			if err != nil || netvalidate.RoutablePrefix(parsed, false) != nil {
				return fmt.Errorf("peers[%d] prefix %q is not a canonical routable non-default prefix", i, prefix)
			}
		}
	}
	return nil
}

func bootstrapConfigured(value Bootstrap) bool {
	return value.Listen != "" || value.CertificateFile != "" || value.PrivateKeyFile != "" || value.NetworkID != "" ||
		value.ControllerEndpoint != "" || value.ControllerQUICEndpoint != "" || value.ControllerServerName != "" || len(value.Artifacts) != 0
}

func validateBootstrap(value Bootstrap) error {
	if !bootstrapConfigured(value) {
		return nil
	}
	if value.NetworkID == "" ||
		value.ControllerEndpoint == "" || value.ControllerQUICEndpoint == "" || value.ControllerServerName == "" {
		return errors.New("bootstrap requires network_id, controller_endpoint, controller_quic_endpoint, and controller_server_name")
	}
	if value.Listen != "" && (value.CertificateFile == "" || value.PrivateKeyFile == "") {
		return errors.New("bootstrap listener requires certificate and private_key")
	}
	if value.Listen == "" && (value.CertificateFile != "" || value.PrivateKeyFile != "") {
		return errors.New("bootstrap certificate and private_key require listen")
	}
	if _, err := identity.ParseNetworkID(value.NetworkID); err != nil {
		return fmt.Errorf("bootstrap.network_id: %w", err)
	}
	parsed, err := url.Parse(value.ControllerEndpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("bootstrap.controller_endpoint must be an HTTPS origin")
	}
	if _, err := netvalidate.CanonicalHostPort(value.ControllerQUICEndpoint); err != nil {
		return errors.New("bootstrap.controller_quic_endpoint must be a canonical host:port")
	}
	if err := validateBootstrapDNSName(value.ControllerServerName); err != nil {
		return fmt.Errorf("bootstrap.controller_server_name: %w", err)
	}
	platforms := make(map[string]struct{}, len(value.Artifacts))
	for i, artifact := range value.Artifacts {
		if (artifact.OS != "linux" && artifact.OS != "darwin") || (artifact.Arch != "amd64" && artifact.Arch != "arm64") {
			return fmt.Errorf("bootstrap.artifacts[%d] must target linux or darwin on amd64 or arm64", i)
		}
		artifactURL, err := url.Parse(artifact.URL)
		if err != nil || artifactURL.Scheme != "https" || artifactURL.Host == "" || artifactURL.User != nil || artifactURL.Fragment != "" {
			return fmt.Errorf("bootstrap.artifacts[%d].url must be HTTPS without credentials or fragment", i)
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != sha256.Size || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
			return fmt.Errorf("bootstrap.artifacts[%d].sha256 must be canonical lowercase SHA-256", i)
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > 512<<20 {
			return fmt.Errorf("bootstrap.artifacts[%d].size_bytes is invalid", i)
		}
		key := artifact.OS + "/" + artifact.Arch
		if _, exists := platforms[key]; exists {
			return fmt.Errorf("bootstrap.artifacts[%d] duplicates platform %s", i, key)
		}
		platforms[key] = struct{}{}
	}
	return nil
}

func validateBootstrapDNSName(value string) error {
	if value == "" || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil || len(value) > 253 {
		return errors.New("must be a canonical lowercase DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("must be a canonical lowercase DNS name")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("must be a canonical lowercase DNS name")
			}
		}
	}
	return nil
}

func canonicalPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("prefix %q is invalid or noncanonical", value)
	}
	return prefix, nil
}
