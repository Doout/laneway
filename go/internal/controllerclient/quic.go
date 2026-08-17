package controllerclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controllerservice"
	"github.com/Doout/laneway/go/internal/protocol"
	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"
)

const controllerSchemaVersion = 1

type quicControllerClient struct {
	address                 string
	tls                     *tls.Config
	timeout                 time.Duration
	mu                      sync.Mutex
	conn                    *quic.Conn
	requestID               atomic.Uint64
	ephemeralExitGeneration uint64
}

func newQUICControllerClient(address, dialAddress string, tlsConfig *tls.Config, timeout time.Duration, ephemeralExitGeneration uint64) (*quicControllerClient, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("controller client: QUIC endpoint must be host:port")
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, errors.New("controller client: QUIC endpoint has an invalid port")
	}
	if dialAddress != "" {
		if err := validatePinnedDialAddress(dialAddress); err != nil {
			return nil, fmt.Errorf("controller client: QUIC %w", err)
		}
		address = dialAddress
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{controllerservice.ControllerALPN}
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	return &quicControllerClient{address: address, tls: config, timeout: timeout, ephemeralExitGeneration: ephemeralExitGeneration}, nil
}

func (c *quicControllerClient) renew(ctx context.Context, csr, wireGuardPublicKey []byte) (*lanewayv1.RenewalResponse, error) {
	request := &lanewayv1.ControllerEnvelope{Body: &lanewayv1.ControllerEnvelope_RenewalRequest{RenewalRequest: &lanewayv1.RenewalRequest{Pkcs10CsrDer: csr, WireguardPublicKey: append([]byte(nil), wireGuardPublicKey...)}}}
	response, err := c.request(ctx, request)
	if err != nil {
		return nil, err
	}
	value := response.GetRenewalResponse()
	if value == nil || value.CertificateChain == nil {
		return nil, errors.New("controller QUIC: renewal response is incomplete")
	}
	return value, nil
}

func (c *quicControllerClient) configuration(ctx context.Context, known uint64) (*lanewayv1.NodeConfiguration, bool, error) {
	request := &lanewayv1.ControllerEnvelope{Body: &lanewayv1.ControllerEnvelope_ConfigurationRequest{ConfigurationRequest: &lanewayv1.ConfigurationRequest{
		KnownConfigurationEpoch: known, EphemeralExitLeaseGeneration: c.ephemeralExitGeneration,
	}}}
	response, err := c.request(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if lease := response.GetConfigurationLease(); lease != nil {
		if lease.ConfigurationEpoch != known || lease.ValidUntilUnixSeconds == 0 {
			return nil, false, errors.New("controller QUIC: configuration lease omitted deadline")
		}
		if c.ephemeralExitGeneration != 0 && (lease.GetEphemeralExitLeaseGeneration() != c.ephemeralExitGeneration ||
			lease.GetEphemeralExitSuspectAtUnixSeconds() == 0 || lease.GetEphemeralExitRevokeAtUnixSeconds() == 0) {
			return nil, false, errors.New("controller QUIC: ephemeral Exit lease metadata is incomplete")
		}
		return &lanewayv1.NodeConfiguration{ConfigurationEpoch: known, ValidUntilUnixSeconds: lease.ValidUntilUnixSeconds}, true, nil
	}
	value := response.GetNodeConfiguration()
	if value == nil {
		return nil, false, errors.New("controller QUIC: expected node configuration")
	}
	if c.ephemeralExitGeneration != 0 && value.GetEphemeralExitLeaseGeneration() != c.ephemeralExitGeneration {
		return nil, false, errors.New("controller QUIC: ephemeral Exit lease generation changed")
	}
	return value, false, nil
}

func (c *quicControllerClient) relayConfiguration(ctx context.Context, known uint64) (*lanewayv1.RelayConfiguration, bool, error) {
	request := &lanewayv1.ControllerEnvelope{Body: &lanewayv1.ControllerEnvelope_RelayConfigurationRequest{RelayConfigurationRequest: &lanewayv1.RelayConfigurationRequest{KnownConfigurationEpoch: known}}}
	response, err := c.request(ctx, request)
	if err != nil {
		return nil, false, err
	}
	if lease := response.GetConfigurationLease(); lease != nil {
		if lease.ConfigurationEpoch != known || lease.ValidUntilUnixSeconds == 0 {
			return nil, false, errors.New("controller QUIC: relay configuration lease omitted deadline")
		}
		return &lanewayv1.RelayConfiguration{ConfigurationEpoch: known, ValidUntilUnixSeconds: lease.ValidUntilUnixSeconds}, true, nil
	}
	value := response.GetRelayConfiguration()
	if value == nil {
		return nil, false, errors.New("controller QUIC: expected relay configuration")
	}
	return value, false, nil
}

func (c *quicControllerClient) request(ctx context.Context, envelope *lanewayv1.ControllerEnvelope) (*lanewayv1.ControllerEnvelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if c.conn == nil {
		conn, err := quic.DialAddr(requestCtx, c.address, c.tls.Clone(), &quic.Config{
			HandshakeIdleTimeout: min(c.timeout, 10*time.Second), MaxIdleTimeout: 60 * time.Second,
			KeepAlivePeriod: 20 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: -1,
			EnableDatagrams: false, Allow0RTT: false,
		})
		if err != nil {
			return nil, fmt.Errorf("controller QUIC: dial: %w", err)
		}
		c.conn = conn
	}
	stream, err := c.conn.OpenStreamSync(requestCtx)
	if err != nil {
		c.discardConnection()
		return nil, fmt.Errorf("controller QUIC: open request stream: %w", err)
	}
	if deadline, ok := requestCtx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	requestID := c.requestID.Add(1)
	if requestID == 0 {
		requestID = c.requestID.Add(1)
	}
	envelope.SchemaVersion, envelope.RequestId = controllerSchemaVersion, requestID
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err == nil {
		err = protocol.WriteControlFrame(stream, encoded, protocol.DefaultMaxControlFrame)
	}
	if err == nil {
		err = stream.Close()
	}
	var payload []byte
	if err == nil {
		payload, err = protocol.ReadControlFrame(stream, protocol.DefaultMaxControlFrame)
	}
	if err != nil {
		stream.CancelRead(0x103)
		c.discardConnection()
		return nil, fmt.Errorf("controller QUIC: exchange: %w", err)
	}
	// Consume the response FIN explicitly. Reading exactly the framed payload
	// is not sufficient to release QUIC stream credit if the FIN arrives in a
	// later packet; a fast polling loop could otherwise block opening its next
	// request despite having no concurrent application request.
	var trailing [1]byte
	if n, readErr := stream.Read(trailing[:]); n != 0 || !errors.Is(readErr, io.EOF) {
		c.discardConnection()
		if readErr == nil {
			readErr = errors.New("trailing response bytes")
		}
		return nil, fmt.Errorf("controller QUIC: finish response stream: %w", readErr)
	}
	response := new(lanewayv1.ControllerEnvelope)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, response); err != nil {
		c.discardConnection()
		return nil, fmt.Errorf("controller QUIC: decode response: %w", err)
	}
	if response.SchemaVersion != controllerSchemaVersion || response.RequestId != requestID || response.Body == nil {
		c.discardConnection()
		return nil, errors.New("controller QUIC: response schema or request ID mismatch")
	}
	if protocolError := response.GetError(); protocolError != nil {
		if protocolError.Code == lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED ||
			protocolError.Code == lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
			c.discardConnection()
		}
		return nil, fmt.Errorf("controller QUIC: %s (code %s, retryable=%t)", protocolError.Detail, protocolError.Code, protocolError.Retryable)
	}
	return response, nil
}

func (c *quicControllerClient) discardConnection() {
	if c.conn != nil {
		_ = c.conn.CloseWithError(0, "reconnect")
		c.conn = nil
	}
}

func (c *quicControllerClient) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.CloseWithError(0, "client closed")
		c.conn = nil
	}
}
