package agent

import (
	"errors"
	"fmt"
	"io"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

const ControlSchemaVersion = uint32(1)

// BodyType identifies a ControlEnvelope oneof member without exposing the
// generated package's private oneof interface.
type BodyType uint8

const (
	BodyUnknown BodyType = iota
	BodyHello
	BodyWelcome
	BodyPing
	BodyPong
	BodyError
	BodyConfigurationAck
	BodyDisconnect
)

func (t BodyType) String() string {
	switch t {
	case BodyHello:
		return "Hello"
	case BodyWelcome:
		return "Welcome"
	case BodyPing:
		return "Ping"
	case BodyPong:
		return "Pong"
	case BodyError:
		return "ProtocolError"
	case BodyConfigurationAck:
		return "ConfigurationAck"
	case BodyDisconnect:
		return "Disconnect"
	default:
		return "unknown"
	}
}

// EnvelopeBody returns the body type and rejects a set oneof wrapper whose
// message pointer is nil.
func EnvelopeBody(env *lanewayv1.ControlEnvelope) (BodyType, error) {
	if env == nil {
		return BodyUnknown, malformed(ErrInvalidEnvelope, "nil envelope")
	}
	switch body := env.GetBody().(type) {
	case *lanewayv1.ControlEnvelope_Hello:
		if body.Hello != nil {
			return BodyHello, nil
		}
	case *lanewayv1.ControlEnvelope_Welcome:
		if body.Welcome != nil {
			return BodyWelcome, nil
		}
	case *lanewayv1.ControlEnvelope_Ping:
		if body.Ping != nil {
			return BodyPing, nil
		}
	case *lanewayv1.ControlEnvelope_Pong:
		if body.Pong != nil {
			return BodyPong, nil
		}
	case *lanewayv1.ControlEnvelope_Error:
		if body.Error != nil {
			return BodyError, nil
		}
	case *lanewayv1.ControlEnvelope_ConfigurationAck:
		if body.ConfigurationAck != nil {
			return BodyConfigurationAck, nil
		}
	case *lanewayv1.ControlEnvelope_Disconnect:
		if body.Disconnect != nil {
			return BodyDisconnect, nil
		}
	case nil:
		return BodyUnknown, malformed(ErrInvalidEnvelope, "envelope body is missing")
	}
	return BodyUnknown, malformed(ErrInvalidEnvelope, "envelope body is nil or unknown")
}

func bodyAllowed(got BodyType, allowed []BodyType) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, want := range allowed {
		if got == want {
			return true
		}
	}
	return false
}

// SequenceValidator validates schema, body type, and the exact next inbound
// sequence. Its zero value expects sequence 1. It advances only on success.
type SequenceValidator struct {
	next      uint64
	started   bool
	exhausted bool
}

func (s *SequenceValidator) Next() uint64 {
	if s == nil || s.exhausted {
		return 0
	}
	if !s.started {
		return 1
	}
	return s.next
}

func (s *SequenceValidator) Validate(env *lanewayv1.ControlEnvelope, allowed ...BodyType) error {
	if s == nil {
		return malformed(ErrUnexpectedSequence, "nil sequence validator")
	}
	if s.exhausted {
		return malformed(ErrUnexpectedSequence, "sequence space exhausted")
	}
	if env == nil {
		return malformed(ErrInvalidEnvelope, "nil envelope")
	}
	if env.GetSchemaVersion() != ControlSchemaVersion {
		return unsupported(ErrUnsupportedVersion, "schema version %d, supported %d", env.GetSchemaVersion(), ControlSchemaVersion)
	}
	want := s.Next()
	if env.GetSequence() != want {
		return malformed(ErrUnexpectedSequence, "sequence %d, expected %d", env.GetSequence(), want)
	}
	body, err := EnvelopeBody(env)
	if err != nil {
		return err
	}
	if !bodyAllowed(body, allowed) {
		return malformed(ErrUnexpectedMessage, "received %s", body)
	}
	if want == ^uint64(0) {
		s.exhausted = true
	} else {
		s.next = want + 1
		s.started = true
	}
	return nil
}

// SequenceGenerator creates correctly-versioned outbound envelopes. Its zero
// value emits sequence 1 first.
type SequenceGenerator struct {
	next      uint64
	started   bool
	exhausted bool
}

func (s *SequenceGenerator) Next(body proto.Message) (*lanewayv1.ControlEnvelope, error) {
	if s == nil || s.exhausted {
		return nil, malformed(ErrUnexpectedSequence, "outbound sequence space exhausted")
	}
	sequence := uint64(1)
	if s.started {
		sequence = s.next
	}
	env := &lanewayv1.ControlEnvelope{SchemaVersion: ControlSchemaVersion, Sequence: sequence}
	switch message := body.(type) {
	case *lanewayv1.Hello:
		env.Body = &lanewayv1.ControlEnvelope_Hello{Hello: message}
	case *lanewayv1.Welcome:
		env.Body = &lanewayv1.ControlEnvelope_Welcome{Welcome: message}
	case *lanewayv1.Ping:
		env.Body = &lanewayv1.ControlEnvelope_Ping{Ping: message}
	case *lanewayv1.Pong:
		env.Body = &lanewayv1.ControlEnvelope_Pong{Pong: message}
	case *lanewayv1.ProtocolError:
		env.Body = &lanewayv1.ControlEnvelope_Error{Error: message}
	case *lanewayv1.ConfigurationAck:
		env.Body = &lanewayv1.ControlEnvelope_ConfigurationAck{ConfigurationAck: message}
	case *lanewayv1.Disconnect:
		env.Body = &lanewayv1.ControlEnvelope_Disconnect{Disconnect: message}
	default:
		return nil, malformed(ErrUnexpectedMessage, "unsupported outbound body %T", body)
	}
	if _, err := EnvelopeBody(env); err != nil {
		return nil, err
	}
	if sequence == ^uint64(0) {
		s.exhausted = true
	} else {
		s.next = sequence + 1
		s.started = true
	}
	return env, nil
}

// ControlCodec couples protobuf encoding with the bounded Phase 1 frame
// format. A zero MaxPayload selects protocol.DefaultMaxControlFrame.
type ControlCodec struct {
	Framer protocol.ControlFramer
}

func (c ControlCodec) Read(r io.Reader, sequence *SequenceValidator, allowed ...BodyType) (*lanewayv1.ControlEnvelope, error) {
	payload, err := c.Framer.Read(r)
	if err != nil {
		if errors.Is(err, protocol.ErrInvalidControlLimit) {
			return nil, fmt.Errorf("control codec configuration: %w", err)
		}
		return nil, malformed(ErrMalformed, "read control frame: %v", err)
	}
	env := new(lanewayv1.ControlEnvelope)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, env); err != nil {
		return nil, malformed(ErrMalformed, "decode control envelope: %v", err)
	}
	if err := sequence.Validate(env, allowed...); err != nil {
		return nil, err
	}
	return env, nil
}

func (c ControlCodec) Write(w io.Writer, sequence *SequenceGenerator, body proto.Message) (*lanewayv1.ControlEnvelope, error) {
	env, err := sequence.Next(body)
	if err != nil {
		return nil, err
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(env)
	if err != nil {
		return nil, malformed(ErrMalformed, "encode control envelope: %v", err)
	}
	if err := c.Framer.Write(w, payload); err != nil {
		return nil, fmt.Errorf("write control frame: %w", err)
	}
	return env, nil
}
