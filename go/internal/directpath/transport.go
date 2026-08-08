package directpath

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/revocation"
	relaytransport "laneway.dev/laneway/internal/transport"
)

const (
	ALPN                                              = "laneway-peer/1"
	WireGuardALPN                                     = "laneway-peer-wg/1"
	DefaultMaxPacketPayload                           = 1280
	identityPrefaceSize                               = 37
	DefaultDialAttempts                               = 2
	MaxDialAttempts                                   = 8
	peerCloseCode           quic.ApplicationErrorCode = 0
	peerProtocolCode        quic.ApplicationErrorCode = 0x200
)

var (
	ErrInvalidConfiguration = errors.New("directpath: invalid configuration")
	ErrPeerIdentity         = errors.New("directpath: peer identity validation failed")
	ErrPacketTooLarge       = errors.New("directpath: packet exceeds direct path limit")
	ErrWrongPeer            = errors.New("directpath: path used for a different peer")
)

type Credentials struct {
	Roots       *x509.CertPool
	Certificate tls.Certificate
	Revocations *revocation.Set
}

type Config struct {
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	KeepAlive        time.Duration
	MaxPacketPayload int
	CandidatePolicy  CandidatePolicy
	PayloadMode      PayloadMode
}

type PayloadMode uint8

const (
	PayloadIP PayloadMode = iota
	PayloadWireGuard
)

// DialOptions bounds a direct-path attempt. Exhaustion is a normal outcome:
// callers retain their relay path and may retry after fresh rendezvous data.
type DialOptions struct {
	Attempts       int
	AttemptTimeout time.Duration
	RetryDelay     time.Duration
}

func (o DialOptions) normalized(handshakeTimeout time.Duration) (DialOptions, error) {
	if o.Attempts == 0 {
		o.Attempts = DefaultDialAttempts
	}
	if o.AttemptTimeout == 0 {
		o.AttemptTimeout = handshakeTimeout
	}
	if o.RetryDelay == 0 {
		o.RetryDelay = 100 * time.Millisecond
	}
	if o.Attempts < 1 || o.Attempts > MaxDialAttempts || o.AttemptTimeout <= 0 || o.AttemptTimeout > 30*time.Second || o.RetryDelay < 0 || o.RetryDelay > 5*time.Second {
		return DialOptions{}, ErrInvalidConfiguration
	}
	return o, nil
}

func (c Config) normalized() (Config, error) {
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.KeepAlive == 0 {
		c.KeepAlive = 10 * time.Second
	}
	if c.MaxPacketPayload == 0 {
		c.MaxPacketPayload = DefaultMaxPacketPayload
	}
	var err error
	c.CandidatePolicy, err = c.CandidatePolicy.normalized()
	if err != nil {
		return Config{}, err
	}
	if c.HandshakeTimeout <= 0 || c.IdleTimeout <= 0 || c.KeepAlive <= 0 || c.KeepAlive >= c.IdleTimeout || c.MaxPacketPayload < 576 || c.MaxPacketPayload > 65535 ||
		(c.PayloadMode != PayloadIP && c.PayloadMode != PayloadWireGuard) {
		return Config{}, ErrInvalidConfiguration
	}
	return c, nil
}

func (c Config) alpn() string {
	if c.PayloadMode == PayloadWireGuard {
		return WireGuardALPN
	}
	return ALPN
}

func (c Config) quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  c.HandshakeTimeout,
		MaxIdleTimeout:        c.IdleTimeout,
		KeepAlivePeriod:       c.KeepAlive,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		Allow0RTT:             false,
		EnableDatagrams:       true,
	}
}

// Endpoint owns one UDP socket shared by UDP hole-punch probes, accepted QUIC
// connections, and outbound QUIC dials. Sharing is necessary to preserve the
// endpoint mapping created by the probes.
type Endpoint struct {
	local       identity.NodeIdentity
	credentials Credentials
	config      Config
	transport   *quic.Transport
	listener    *quic.Listener
	closeOnce   sync.Once
	closeErr    error
	pathsMu     sync.Mutex
	paths       map[*Path]trackedPath
	reserved    map[netip.Addr]uint32
	pathHandler func([]netip.Addr) error
	unsubscribe func()
}

type trackedPath struct {
	serial   []byte
	endpoint netip.Addr
}

func NewEndpoint(packetConn net.PacketConn, local identity.NodeIdentity, credentials Credentials, config Config) (*Endpoint, error) {
	if packetConn == nil || credentials.Roots == nil || len(credentials.Certificate.Certificate) == 0 {
		return nil, ErrInvalidConfiguration
	}
	if err := local.Validate(); err != nil {
		return nil, fmt.Errorf("%w: local identity: %w", ErrInvalidConfiguration, err)
	}
	config, err := config.normalized()
	if err != nil {
		return nil, err
	}
	leaf := credentials.Certificate.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(credentials.Certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("%w: parse local certificate: %w", ErrInvalidConfiguration, err)
		}
		credentials.Certificate.Leaf = leaf
	}
	auth, err := identity.AuthenticatedIdentityFromCertificate(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: local certificate: %w", ErrInvalidConfiguration, err)
	}
	certNode, ok := auth.NodeIdentity()
	if !ok || certNode != local {
		return nil, fmt.Errorf("%w: local certificate identity mismatch", ErrInvalidConfiguration)
	}
	intermediates := x509.NewCertPool()
	for _, der := range credentials.Certificate.Certificate[1:] {
		certificate, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: parse local certificate chain: %w", ErrInvalidConfiguration, parseErr)
		}
		intermediates.AddCert(certificate)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if _, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: credentials.Roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); verifyErr != nil {
			return nil, fmt.Errorf("%w: local certificate chain or key usage: %w", ErrInvalidConfiguration, verifyErr)
		}
	}
	endpoint := &Endpoint{local: local, credentials: credentials, config: config, transport: &quic.Transport{Conn: packetConn}, paths: make(map[*Path]trackedPath), reserved: make(map[netip.Addr]uint32)}
	listener, err := endpoint.transport.Listen(endpoint.serverTLSConfig(), endpoint.config.quicConfig())
	if err != nil {
		_ = endpoint.transport.Close()
		return nil, fmt.Errorf("directpath: listen: %w", err)
	}
	endpoint.listener = listener
	// quic-go intentionally drops non-QUIC packets until the application first
	// requests one. Arm its bounded queue synchronously so a probe arriving
	// immediately after endpoint publication is not lost to goroutine timing.
	armContext, cancelArm := context.WithCancel(context.Background())
	cancelArm()
	probeBuffer := make([]byte, probePacketSize+1)
	if _, _, armErr := endpoint.transport.ReadNonQUICPacket(armContext, probeBuffer); armErr != nil && !errors.Is(armErr, context.Canceled) {
		_ = listener.Close()
		_ = endpoint.transport.Close()
		return nil, fmt.Errorf("directpath: arm probe queue: %w", armErr)
	}
	if credentials.Revocations != nil {
		endpoint.unsubscribe = credentials.Revocations.Subscribe(endpoint.closeRevokedPaths)
	}
	return endpoint, nil
}

// EndpointReservation pins candidate endpoints to the native routing table
// before probes or a direct QUIC handshake are sent. Release is transactional:
// on a routing error the reservation remains active and may be retried.
type EndpointReservation struct {
	endpoint  *Endpoint
	addresses []netip.Addr
	mu        sync.Mutex
	released  bool
}

func (r *EndpointReservation) Release() error {
	if r == nil || r.endpoint == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil
	}
	e := r.endpoint
	e.pathsMu.Lock()
	for _, address := range r.addresses {
		if count := e.reserved[address]; count > 1 {
			e.reserved[address] = count - 1
		} else {
			delete(e.reserved, address)
		}
	}
	handler, addresses := e.pathHandler, e.pathAddressesLocked()
	e.pathsMu.Unlock()
	if handler != nil {
		if err := handler(addresses); err != nil {
			e.pathsMu.Lock()
			for _, address := range r.addresses {
				e.reserved[address]++
			}
			e.pathsMu.Unlock()
			return fmt.Errorf("directpath: release endpoint bypass reservation: %w", err)
		}
	}
	r.released = true
	return nil
}

// ReservePathEndpoints installs native bypasses before any packet is sent to
// the candidates. This is required when an exit policy rule is already active:
// installing a bypass only after authentication would make the handshake
// recurse into lane0.
func (e *Endpoint) ReservePathEndpoints(candidates []Candidate) (*EndpointReservation, error) {
	if e == nil || len(candidates) == 0 || len(candidates) > e.config.CandidatePolicy.MaxCandidates {
		return nil, ErrInvalidCandidate
	}
	unique := make(map[netip.Addr]struct{}, len(candidates))
	addresses := make([]netip.Addr, 0, len(candidates))
	for _, candidate := range candidates {
		if err := e.config.CandidatePolicy.Validate(candidate, candidate.NodeID); err != nil {
			return nil, err
		}
		address := candidate.Address.Addr().Unmap()
		if _, exists := unique[address]; exists {
			continue
		}
		unique[address] = struct{}{}
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	e.pathsMu.Lock()
	for _, address := range addresses {
		e.reserved[address]++
	}
	handler, desired := e.pathHandler, e.pathAddressesLocked()
	e.pathsMu.Unlock()
	if handler != nil {
		if err := handler(desired); err != nil {
			e.pathsMu.Lock()
			for _, address := range addresses {
				if count := e.reserved[address]; count > 1 {
					e.reserved[address] = count - 1
				} else {
					delete(e.reserved, address)
				}
			}
			e.pathsMu.Unlock()
			return nil, fmt.Errorf("directpath: reserve candidate endpoint bypass: %w", err)
		}
	}
	return &EndpointReservation{endpoint: e, addresses: addresses}, nil
}

func (e *Endpoint) Addr() net.Addr                       { return e.listener.Addr() }
func (e *Endpoint) LocalIdentity() identity.NodeIdentity { return e.local }

// SetPathEndpointHandler installs the single host-routing observer for active,
// authenticated direct paths. The observer is called synchronously before a
// new path is returned to the dataplane, so an exit client can install native
// host-route bypasses before that path becomes eligible for packet selection.
func (e *Endpoint) SetPathEndpointHandler(handler func([]netip.Addr) error) error {
	if e == nil || handler == nil {
		return ErrInvalidConfiguration
	}
	e.pathsMu.Lock()
	if e.pathHandler != nil {
		e.pathsMu.Unlock()
		return fmt.Errorf("%w: direct path endpoint handler already configured", ErrInvalidConfiguration)
	}
	e.pathHandler = handler
	addresses := e.pathAddressesLocked()
	e.pathsMu.Unlock()
	if err := handler(addresses); err != nil {
		e.pathsMu.Lock()
		if len(e.paths) == 0 {
			e.pathHandler = nil
		}
		e.pathsMu.Unlock()
		return fmt.Errorf("directpath: initialize path endpoint handler: %w", err)
	}
	return nil
}

// DialRelay establishes laneway-relay/1 on the endpoint's UDP socket so the
// relay observes the same mapping later used for probes and peer QUIC.
func (e *Endpoint) DialRelay(ctx context.Context, address string, tlsConfig *tls.Config, config *relaytransport.Config) (*relaytransport.Conn, error) {
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("directpath: resolve relay: %w", err)
	}
	return relaytransport.DialOnTransport(ctx, e.transport, remote, tlsConfig, config)
}

func (e *Endpoint) serverTLSConfig() *tls.Config {
	config := &tls.Config{
		Certificates: []tls.Certificate{e.credentials.Certificate},
		ClientCAs:    e.credentials.Roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{e.config.alpn()},
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		_, err := verifyPeer(state, e.credentials.Roots, e.local.NetworkID, identity.NodeID{}, x509.ExtKeyUsageClientAuth, e.config.alpn())
		if err == nil && e.credentials.Revocations != nil {
			err = e.credentials.Revocations.CheckCertificate(state.PeerCertificates[0])
		}
		return err
	}
	return config
}

func (e *Endpoint) clientTLSConfig(expected identity.NodeIdentity) *tls.Config {
	config := &tls.Config{
		Certificates:       []tls.Certificate{e.credentials.Certificate},
		RootCAs:            e.credentials.Roots,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{e.config.alpn()},
		InsecureSkipVerify: true, // Verified against the CA and exact node identity below.
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		_, err := verifyPeer(state, e.credentials.Roots, expected.NetworkID, expected.NodeID, x509.ExtKeyUsageServerAuth, e.config.alpn())
		if err == nil && e.credentials.Revocations != nil {
			err = e.credentials.Revocations.CheckCertificate(state.PeerCertificates[0])
		}
		return err
	}
	return config
}

func verifyPeer(state tls.ConnectionState, roots *x509.CertPool, network identity.NetworkID, expectedNode identity.NodeID, usage x509.ExtKeyUsage, alpn string) (identity.NodeIdentity, error) {
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != alpn || len(state.PeerCertificates) == 0 {
		return identity.NodeIdentity{}, fmt.Errorf("%w: TLS version, ALPN, or certificate", ErrPeerIdentity)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return identity.NodeIdentity{}, fmt.Errorf("%w: certificate chain: %w", ErrPeerIdentity, err)
	}
	auth, err := identity.AuthenticatedIdentityFromCertificate(state.PeerCertificates[0])
	if err != nil || auth.Role != identity.IdentityRoleNode {
		return identity.NodeIdentity{}, fmt.Errorf("%w: certificate is not a node: %w", ErrPeerIdentity, err)
	}
	peer, _ := auth.NodeIdentity()
	if peer.NetworkID != network || (!expectedNode.IsZero() && peer.NodeID != expectedNode) {
		return identity.NodeIdentity{}, fmt.Errorf("%w: wrong network or node", ErrPeerIdentity)
	}
	return peer, nil
}

func validateQUIC(conn *quic.Conn, roots *x509.CertPool, network identity.NetworkID, expected identity.NodeID, usage x509.ExtKeyUsage, alpn string) (identity.NodeIdentity, error) {
	state := conn.ConnectionState()
	if state.Used0RTT || !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return identity.NodeIdentity{}, fmt.Errorf("%w: 0-RTT or missing datagram negotiation", ErrPeerIdentity)
	}
	return verifyPeer(state.TLS, roots, network, expected, usage, alpn)
}

func (e *Endpoint) Dial(ctx context.Context, candidate Candidate, expected identity.NodeIdentity) (*Path, error) {
	if expected.NetworkID != e.local.NetworkID || expected.NodeID == e.local.NodeID {
		return nil, ErrUnauthorizedPeer
	}
	if err := e.config.CandidatePolicy.Validate(candidate, expected.NodeID); err != nil {
		return nil, err
	}
	remote := net.UDPAddrFromAddrPort(candidate.Address)
	started := time.Now()
	conn, err := e.transport.Dial(ctx, remote, e.clientTLSConfig(expected), e.config.quicConfig())
	if err != nil {
		return nil, fmt.Errorf("directpath: dial %s: %w", candidate.Address, err)
	}
	peer, err := validateQUIC(conn, e.credentials.Roots, expected.NetworkID, expected.NodeID, x509.ExtKeyUsageServerAuth, e.config.alpn())
	if err != nil {
		_ = conn.CloseWithError(peerProtocolCode, "peer identity rejected")
		return nil, err
	}
	if err := dialIdentityBinding(ctx, conn, e.local, peer); err != nil {
		_ = conn.CloseWithError(peerProtocolCode, "identity binding rejected")
		return nil, err
	}
	path := newAuthenticatedPath(conn, peer.NodeID, e.config.MaxPacketPayload, e.config.PayloadMode, candidate.Address, time.Since(started))
	if err := e.trackPath(path, conn.ConnectionState().TLS.PeerCertificates[0]); err != nil {
		_ = path.Close()
		return nil, err
	}
	return path, nil
}

// DialCandidates tries validated endpoints in priority order for a bounded
// number of rounds. It changes no relay or path-manager state on failure.
func (e *Endpoint) DialCandidates(ctx context.Context, candidates []Candidate, expected identity.NodeIdentity, options DialOptions) (*Path, error) {
	if expected.NetworkID != e.local.NetworkID || expected.NodeID == e.local.NodeID {
		return nil, ErrUnauthorizedPeer
	}
	validated, err := ValidateCandidates(candidates, expected.NodeID, e.config.CandidatePolicy)
	if err != nil {
		return nil, err
	}
	if len(validated) == 0 {
		return nil, ErrInvalidCandidate
	}
	options, err = options.normalized(e.config.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	var failures []error
	for attempt := 0; attempt < options.Attempts; attempt++ {
		for _, candidate := range validated {
			if err := ctx.Err(); err != nil {
				return nil, errors.Join(err, errors.Join(failures...))
			}
			attemptCtx, cancel := context.WithTimeout(ctx, options.AttemptTimeout)
			path, dialErr := e.Dial(attemptCtx, candidate, expected)
			cancel()
			if dialErr == nil {
				return path, nil
			}
			failures = append(failures, dialErr)
		}
		if attempt+1 < options.Attempts {
			if err := waitContext(ctx, options.RetryDelay); err != nil {
				return nil, errors.Join(err, errors.Join(failures...))
			}
		}
	}
	return nil, fmt.Errorf("directpath: all direct candidates failed: %w", errors.Join(failures...))
}

func (e *Endpoint) Accept(ctx context.Context) (*Path, error) {
	conn, err := e.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	peer, err := validateQUIC(conn, e.credentials.Roots, e.local.NetworkID, identity.NodeID{}, x509.ExtKeyUsageClientAuth, e.config.alpn())
	if err != nil {
		_ = conn.CloseWithError(peerProtocolCode, "peer identity rejected")
		return nil, err
	}
	if err := acceptIdentityBinding(ctx, conn, e.local, peer); err != nil {
		_ = conn.CloseWithError(peerProtocolCode, "identity binding rejected")
		return nil, err
	}
	remote, _ := addrPort(conn.RemoteAddr())
	path := newAuthenticatedPath(conn, peer.NodeID, e.config.MaxPacketPayload, e.config.PayloadMode, remote, 0)
	if err := e.trackPath(path, conn.ConnectionState().TLS.PeerCertificates[0]); err != nil {
		_ = path.Close()
		return nil, err
	}
	return path, nil
}

func (e *Endpoint) trackPath(path *Path, certificate *x509.Certificate) error {
	if path == nil || certificate == nil || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return fmt.Errorf("%w: peer certificate serial", ErrPeerIdentity)
	}
	serial := certificate.SerialNumber.Bytes()
	if e.credentials.Revocations != nil && e.credentials.Revocations.IsRevoked(serial) {
		return fmt.Errorf("%w: peer certificate is revoked", ErrPeerIdentity)
	}
	e.pathsMu.Lock()
	e.paths[path] = trackedPath{serial: append([]byte(nil), serial...), endpoint: path.remote.Addr().Unmap()}
	path.onClose = func() error {
		e.pathsMu.Lock()
		delete(e.paths, path)
		handler, addresses := e.pathHandler, e.pathAddressesLocked()
		e.pathsMu.Unlock()
		if handler != nil {
			return handler(addresses)
		}
		return nil
	}
	handler, addresses := e.pathHandler, e.pathAddressesLocked()
	e.pathsMu.Unlock()
	if handler != nil {
		if err := handler(addresses); err != nil {
			e.pathsMu.Lock()
			delete(e.paths, path)
			path.onClose = nil
			e.pathsMu.Unlock()
			return fmt.Errorf("directpath: install path endpoint bypass: %w", err)
		}
	}
	return nil
}

func (e *Endpoint) pathAddressesLocked() []netip.Addr {
	unique := make(map[netip.Addr]struct{}, len(e.paths)+len(e.reserved))
	for _, path := range e.paths {
		if path.endpoint.IsValid() && !path.endpoint.IsUnspecified() {
			unique[path.endpoint] = struct{}{}
		}
	}
	for endpoint := range e.reserved {
		unique[endpoint] = struct{}{}
	}
	addresses := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return addresses
}

func (e *Endpoint) closeRevokedPaths() {
	if e == nil || e.credentials.Revocations == nil {
		return
	}
	e.pathsMu.Lock()
	paths := make([]*Path, 0)
	for path, tracked := range e.paths {
		if e.credentials.Revocations.IsRevoked(tracked.serial) {
			paths = append(paths, path)
		}
	}
	e.pathsMu.Unlock()
	for _, path := range paths {
		_ = path.Close()
	}
}

func identityPreface(node identity.NodeIdentity) []byte {
	preface := make([]byte, identityPrefaceSize)
	copy(preface[:4], []byte{'L', 'W', 'P', 'D'})
	preface[4] = 1
	copy(preface[5:21], node.NetworkID[:])
	copy(preface[21:37], node.NodeID[:])
	return preface
}

func validateIdentityPreface(preface []byte, expected identity.NodeIdentity) error {
	if len(preface) != identityPrefaceSize || string(preface[:4]) != "LWPD" || preface[4] != 1 || !equalIDBytes(preface[5:21], expected.NetworkID[:]) || !equalIDBytes(preface[21:37], expected.NodeID[:]) {
		return fmt.Errorf("%w: connection identity binding", ErrPeerIdentity)
	}
	return nil
}

func equalIDBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

func setStreamDeadline(ctx context.Context, stream *quic.Stream) func() {
	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}
	}
	_ = stream.SetDeadline(deadline)
	return func() { _ = stream.SetDeadline(time.Time{}) }
}

func dialIdentityBinding(ctx context.Context, conn *quic.Conn, local, peer identity.NodeIdentity) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("directpath: open identity stream: %w", err)
	}
	defer stream.Close()
	defer setStreamDeadline(ctx, stream)()
	if err := writeFull(stream, identityPreface(local)); err != nil {
		return fmt.Errorf("directpath: write identity binding: %w", err)
	}
	response := make([]byte, identityPrefaceSize)
	if _, err := io.ReadFull(stream, response); err != nil {
		return fmt.Errorf("directpath: read identity binding: %w", err)
	}
	return validateIdentityPreface(response, peer)
}

func acceptIdentityBinding(ctx context.Context, conn *quic.Conn, local, peer identity.NodeIdentity) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("directpath: accept identity stream: %w", err)
	}
	defer stream.Close()
	defer setStreamDeadline(ctx, stream)()
	request := make([]byte, identityPrefaceSize)
	if _, err := io.ReadFull(stream, request); err != nil {
		return fmt.Errorf("directpath: read identity binding: %w", err)
	}
	if err := validateIdentityPreface(request, peer); err != nil {
		return err
	}
	if err := writeFull(stream, identityPreface(local)); err != nil {
		return fmt.Errorf("directpath: write identity binding: %w", err)
	}
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

// ReadProbe reads one non-QUIC probe from the shared socket and validates both
// rendezvous token and source endpoint before optionally sending the response.
func (e *Endpoint) ReadProbe(ctx context.Context, peer identity.NodeID, token ProbeToken, candidates []Candidate) (netip.AddrPort, error) {
	validated, err := ValidateCandidates(candidates, peer, e.config.CandidatePolicy)
	if err != nil {
		return netip.AddrPort{}, err
	}
	allowed := make(map[netip.AddrPort]struct{}, len(validated))
	for _, candidate := range validated {
		allowed[candidate.Address] = struct{}{}
	}
	buffer := make([]byte, probePacketSize+1)
	n, source, err := e.transport.ReadNonQUICPacket(ctx, buffer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	sourceAddress, ok := addrPort(source)
	if !ok {
		return netip.AddrPort{}, ErrInvalidProbe
	}
	// quic-go may report IPv4 sources from a shared UDP socket as IPv4-mapped
	// IPv6 addresses. Candidate validation intentionally accepts only canonical
	// addresses, so canonicalize the observed source before the fail-closed
	// endpoint membership check.
	sourceAddress = unmapAddrPort(sourceAddress)
	if _, ok := allowed[sourceAddress]; !ok {
		return netip.AddrPort{}, ErrInvalidProbe
	}
	packet, err := ParseProbePacket(buffer[:n], e.local.NodeID, peer, token)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !packet.Response {
		response, _ := (ProbePacket{Response: true, Token: token, Sender: e.local.NodeID, Recipient: peer}).MarshalBinary()
		if _, err := e.transport.WriteTo(response, source); err != nil {
			return netip.AddrPort{}, err
		}
	}
	return sourceAddress, nil
}

func unmapAddrPort(address netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
}

func (e *Endpoint) ProbeWriter() ProbeWriter { return e.transport }

func (e *Endpoint) Close() error {
	e.closeOnce.Do(func() {
		if e.unsubscribe != nil {
			e.unsubscribe()
		}
		e.closeErr = errors.Join(e.listener.Close(), e.transport.Close())
	})
	return e.closeErr
}
