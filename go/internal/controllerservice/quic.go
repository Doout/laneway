package controllerservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/protocol"
)

const (
	// ControllerALPN is the stable-v1 reliable controller stream protocol.
	ControllerALPN           = "laneway-control/1"
	controllerSchemaVersion  = 1
	controllerRequestTimeout = 15 * time.Second
	maxControllerConnections = 256
)

// QUICServer exposes authenticated controller operations over bounded,
// reliable QUIC request/response streams. Enrollment is intentionally absent:
// a joining node has no certificate with which to authenticate mTLS.
type QUICServer struct {
	service     *Service
	handler     http.Handler
	listener    *quic.Listener
	local       identity.AuthenticatedIdentity
	connections chan struct{}
}

// ListenQUIC opens the production controller UDP listener. The supplied TLS
// configuration is cloned and tightened to TLS 1.3, exact ALPN, mandatory
// client certificates, and disabled early data.
func (s *Service) ListenQUIC(address string, tlsConfig *tls.Config) (*QUICServer, error) {
	return s.ListenQUICWithMiddleware(address, tlsConfig, nil)
}

// ListenQUICWithMiddleware is equivalent to ListenQUIC and applies optional
// HTTP-compatible instrumentation around the shared bounded service handler.
// Authorization still occurs inside Service after QUIC mTLS authentication.
func (s *Service) ListenQUICWithMiddleware(address string, tlsConfig *tls.Config, middleware func(http.Handler) http.Handler) (*QUICServer, error) {
	if s == nil || tlsConfig == nil || len(tlsConfig.Certificates) == 0 || tlsConfig.ClientCAs == nil {
		return nil, errors.New("controller QUIC: service certificate and client CA pool are required")
	}
	certificate := tlsConfig.Certificates[0].Leaf
	if certificate == nil && len(tlsConfig.Certificates[0].Certificate) != 0 {
		var err error
		certificate, err = x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("controller QUIC: parse local certificate: %w", err)
		}
	}
	local, err := identity.AuthenticatedIdentityFromCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("controller QUIC: local identity: %w", err)
	}
	if err := local.RequireRole(identity.IdentityRoleController); err != nil {
		return nil, fmt.Errorf("controller QUIC: %w", err)
	}
	config := tlsConfig.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.NextProtos = []string{ControllerALPN}
	config.ClientAuth = tls.RequireAndVerifyClientCert
	listener, err := quic.ListenAddr(address, config, &quic.Config{
		HandshakeIdleTimeout:  10 * time.Second,
		MaxIdleTimeout:        60 * time.Second,
		KeepAlivePeriod:       20 * time.Second,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       false,
		Allow0RTT:             false,
	})
	if err != nil {
		return nil, fmt.Errorf("controller QUIC: listen: %w", err)
	}
	handler := s.Handler()
	if middleware != nil {
		handler = middleware(handler)
	}
	return &QUICServer{service: s, handler: handler, listener: listener, local: local, connections: make(chan struct{}, maxControllerConnections)}, nil
}

func (s *QUICServer) Addr() net.Addr { return s.listener.Addr() }
func (s *QUICServer) Close() error   { return s.listener.Close() }

// Serve accepts a bounded number of connections. Requests on each connection
// are deliberately processed one-at-a-time, preserving application ordering
// even though QUIC itself can multiplex streams.
func (s *QUICServer) Serve(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("controller QUIC: accept: %w", err)
		}
		select {
		case s.connections <- struct{}{}:
			go func() {
				defer func() { <-s.connections }()
				s.serveConnection(ctx, conn)
			}()
		default:
			_ = conn.CloseWithError(0x101, "controller connection capacity exhausted")
		}
	}
}

func (s *QUICServer) serveConnection(ctx context.Context, conn *quic.Conn) {
	state := conn.ConnectionState().TLS
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		_ = conn.CloseWithError(0x102, "verified client certificate required")
		return
	}
	peer, err := identity.AuthenticatedIdentityFromCertificate(state.VerifiedChains[0][0])
	if err != nil || peer.NetworkID != s.local.NetworkID || (peer.Role != identity.IdentityRoleNode && peer.Role != identity.IdentityRoleRelay) {
		_ = conn.CloseWithError(0x102, "client identity is outside controller network or role")
		return
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		deadline := time.Now().Add(controllerRequestTimeout)
		_ = stream.SetReadDeadline(deadline)
		_ = stream.SetWriteDeadline(deadline)
		if err := s.handleStream(ctx, stream, &state, peer); err != nil {
			stream.CancelRead(0x103)
			stream.CancelWrite(0x103)
			_ = conn.CloseWithError(0x103, "invalid controller request")
			return
		}
		_ = stream.Close()
	}
}

func (s *QUICServer) handleStream(ctx context.Context, stream io.ReadWriter, state *tls.ConnectionState, peer identity.AuthenticatedIdentity) error {
	if len(state.PeerCertificates) == 0 || !s.service.certificateCurrentlyValid(state.PeerCertificates[0]) {
		return errors.New("client certificate is outside its validity interval")
	}
	payload, err := protocol.ReadControlFrame(stream, protocol.DefaultMaxControlFrame)
	if err != nil {
		return err
	}
	// Consume the request FIN before returning the response. Reading exactly the
	// framed payload leaves the receive half open at the application layer when
	// the FIN arrives separately. With MaxIncomingStreams=1 that can retain the
	// peer's stream credit and eventually deadlock an otherwise serialized,
	// persistent controller connection. Trailing bytes are never valid.
	var trailing [1]byte
	if n, readErr := stream.Read(trailing[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		if readErr == nil {
			readErr = errors.New("trailing request bytes")
		}
		return fmt.Errorf("finish controller request stream: %w", readErr)
	}
	request := new(lanewayv1.ControllerEnvelope)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, request); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if request.GetSchemaVersion() != controllerSchemaVersion || request.GetRequestId() == 0 {
		return errors.New("invalid controller schema version or request ID")
	}
	path, body, requiredRole, responseKind, err := controllerOperation(request)
	if err != nil {
		return err
	}
	if peer.Role != requiredRole {
		return errors.New("controller operation is not permitted for client certificate role")
	}
	requestContext, cancel := context.WithTimeout(ctx, controllerRequestTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestContext, http.MethodPost, "https://controller.invalid"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/x-protobuf")
	httpRequest.TLS = state
	recorder := httptest.NewRecorder()
	s.handler.ServeHTTP(recorder, httpRequest)
	response, err := controllerResponse(request.GetRequestId(), responseKind, recorder.Result())
	if err != nil {
		return err
	}
	if lease := response.GetConfigurationLease(); lease != nil {
		switch body := request.GetBody().(type) {
		case *lanewayv1.ControllerEnvelope_ConfigurationRequest:
			lease.ConfigurationEpoch = body.ConfigurationRequest.GetKnownConfigurationEpoch()
		case *lanewayv1.ControllerEnvelope_RelayConfigurationRequest:
			lease.ConfigurationEpoch = body.RelayConfigurationRequest.GetKnownConfigurationEpoch()
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
	if err != nil {
		return err
	}
	return protocol.WriteControlFrame(stream, encoded, protocol.DefaultMaxControlFrame)
}

type quicResponseKind uint8

const (
	responseNodeConfiguration quicResponseKind = iota + 1
	responseRelayConfiguration
	responseRenewal
)

func controllerOperation(envelope *lanewayv1.ControllerEnvelope) (string, []byte, identity.IdentityRole, quicResponseKind, error) {
	var path string
	var message proto.Message
	var role identity.IdentityRole
	var responseKind quicResponseKind
	switch body := envelope.GetBody().(type) {
	case *lanewayv1.ControllerEnvelope_ConfigurationRequest:
		path, message, role, responseKind = "/v1/configuration", body.ConfigurationRequest, identity.IdentityRoleNode, responseNodeConfiguration
	case *lanewayv1.ControllerEnvelope_RelayConfigurationRequest:
		path, message, role, responseKind = "/v1/relay/configuration", body.RelayConfigurationRequest, identity.IdentityRoleRelay, responseRelayConfiguration
	case *lanewayv1.ControllerEnvelope_RenewalRequest:
		path, message, role, responseKind = "/v1/renew", body.RenewalRequest, identity.IdentityRoleNode, responseRenewal
	default:
		return "", nil, "", 0, errors.New("unsupported controller QUIC operation")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	return path, encoded, role, responseKind, err
}

func controllerResponse(requestID uint64, responseKind quicResponseKind, response *http.Response) (*lanewayv1.ControllerEnvelope, error) {
	defer response.Body.Close()
	envelope := &lanewayv1.ControllerEnvelope{SchemaVersion: controllerSchemaVersion, RequestId: requestID}
	if response.StatusCode == http.StatusNotModified {
		deadline, err := strconv.ParseUint(response.Header.Get(SnapshotValidityHeader), 10, 64)
		if err != nil || deadline == 0 {
			return nil, errors.New("controller conditional response omitted a valid lease deadline")
		}
		envelope.Body = &lanewayv1.ControllerEnvelope_ConfigurationLease{ConfigurationLease: &lanewayv1.ConfigurationLease{ValidUntilUnixSeconds: deadline}}
		return envelope, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(protocol.DefaultMaxControlFrame)+1))
	if err != nil || len(body) > int(protocol.DefaultMaxControlFrame) {
		return nil, errors.New("controller response exceeds bounded QUIC envelope")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		protocolError := new(lanewayv1.ProtocolError)
		if proto.Unmarshal(body, protocolError) != nil {
			protocolError = &lanewayv1.ProtocolError{Detail: http.StatusText(response.StatusCode)}
		}
		envelope.Body = &lanewayv1.ControllerEnvelope_Error{Error: protocolError}
		return envelope, nil
	}
	contentType := response.Header.Get("Content-Type")
	if contentType != "application/x-protobuf" {
		return nil, fmt.Errorf("unexpected controller response content type %q", contentType)
	}
	switch responseKind {
	case responseNodeConfiguration:
		value := new(lanewayv1.NodeConfiguration)
		if err := proto.Unmarshal(body, value); err == nil && value.ConfigurationEpoch != 0 && value.Routes != nil {
			envelope.Body = &lanewayv1.ControllerEnvelope_NodeConfiguration{NodeConfiguration: value}
			return envelope, nil
		}
	case responseRelayConfiguration:
		value := new(lanewayv1.RelayConfiguration)
		if err := proto.Unmarshal(body, value); err == nil && value.ConfigurationEpoch != 0 && len(value.NetworkId) != 0 {
			envelope.Body = &lanewayv1.ControllerEnvelope_RelayConfiguration{RelayConfiguration: value}
			return envelope, nil
		}
	case responseRenewal:
		value := new(lanewayv1.RenewalResponse)
		if err := proto.Unmarshal(body, value); err == nil && value.CertificateChain != nil {
			envelope.Body = &lanewayv1.ControllerEnvelope_RenewalResponse{RenewalResponse: value}
			return envelope, nil
		}
	}
	return nil, errors.New("invalid successful controller response")
}
