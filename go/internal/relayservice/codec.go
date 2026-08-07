package relayservice

import (
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/protocol"
)

const relaySchemaVersion uint32 = 1

var (
	ErrMalformedRelayEnvelope = errors.New("relay service: malformed relay envelope")
	ErrUnexpectedSequence     = errors.New("relay service: unexpected relay sequence")
	ErrUnexpectedRelayMessage = errors.New("relay service: unexpected relay message")
)

// relayCodec deliberately has sequence state separate from ControlEnvelope.
// The first RelayEnvelope in each direction starts at one.
type relayCodec struct {
	framer  protocol.ControlFramer
	inNext  uint64
	outNext uint64
}

func newRelayCodec(maxPayload uint32) *relayCodec {
	return &relayCodec{
		framer: protocol.ControlFramer{MaxPayload: maxPayload},
		inNext: 1, outNext: 1,
	}
}

func (c *relayCodec) read(r io.Reader) (*lanewayv1.RelayEnvelope, error) {
	payload, err := c.framer.Read(r)
	if err != nil {
		return nil, fmt.Errorf("read relay frame: %w", err)
	}
	envelope := new(lanewayv1.RelayEnvelope)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, envelope); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedRelayEnvelope, err)
	}
	if envelope.GetSchemaVersion() != relaySchemaVersion {
		return nil, fmt.Errorf("%w: schema version %d", ErrMalformedRelayEnvelope, envelope.GetSchemaVersion())
	}
	if envelope.GetSequence() != c.inNext {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedSequence, envelope.GetSequence(), c.inNext)
	}
	if !validRelayBody(envelope) {
		return nil, fmt.Errorf("%w: missing or nil body", ErrMalformedRelayEnvelope)
	}
	if c.inNext == ^uint64(0) {
		return nil, fmt.Errorf("%w: sequence exhausted", ErrUnexpectedSequence)
	}
	c.inNext++
	return envelope, nil
}

func (c *relayCodec) write(w io.Writer, body proto.Message) error {
	if c.outNext == 0 {
		return fmt.Errorf("%w: outbound sequence exhausted", ErrUnexpectedSequence)
	}
	envelope := &lanewayv1.RelayEnvelope{SchemaVersion: relaySchemaVersion, Sequence: c.outNext}
	switch message := body.(type) {
	case *lanewayv1.RelayRegister:
		envelope.Body = &lanewayv1.RelayEnvelope_Register{Register: message}
	case *lanewayv1.RouteHandleBinding:
		envelope.Body = &lanewayv1.RelayEnvelope_RouteHandleBinding{RouteHandleBinding: message}
	case *lanewayv1.RouteHandleRelease:
		envelope.Body = &lanewayv1.RelayEnvelope_RouteHandleRelease{RouteHandleRelease: message}
	case *lanewayv1.EndpointCandidate:
		envelope.Body = &lanewayv1.RelayEnvelope_EndpointCandidate{EndpointCandidate: message}
	case *lanewayv1.ProtocolError:
		envelope.Body = &lanewayv1.RelayEnvelope_Error{Error: message}
	default:
		return fmt.Errorf("%w: outbound %T", ErrUnexpectedRelayMessage, body)
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal relay envelope: %w", err)
	}
	if err := c.framer.Write(w, payload); err != nil {
		return fmt.Errorf("write relay frame: %w", err)
	}
	if c.outNext == ^uint64(0) {
		c.outNext = 0
	} else {
		c.outNext++
	}
	return nil
}

func validRelayBody(envelope *lanewayv1.RelayEnvelope) bool {
	switch body := envelope.GetBody().(type) {
	case *lanewayv1.RelayEnvelope_Register:
		return body.Register != nil
	case *lanewayv1.RelayEnvelope_RouteHandleBinding:
		return body.RouteHandleBinding != nil
	case *lanewayv1.RelayEnvelope_RouteHandleRelease:
		return body.RouteHandleRelease != nil
	case *lanewayv1.RelayEnvelope_EndpointCandidate:
		return body.EndpointCandidate != nil
	case *lanewayv1.RelayEnvelope_Error:
		return body.Error != nil
	default:
		return false
	}
}
