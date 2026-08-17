package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/protocol"
)

func TestSequenceValidation(t *testing.T) {
	var generator SequenceGenerator
	first, err := generator.Next(&lanewayv1.Ping{Nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := generator.Next(&lanewayv1.Pong{Nonce: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != 2 || first.SchemaVersion != 1 {
		t.Fatalf("sequences = %d, %d", first.Sequence, second.Sequence)
	}
	var validator SequenceValidator
	if err := validator.Validate(first, BodyPing); err != nil {
		t.Fatal(err)
	}
	if validator.Next() != 2 {
		t.Fatalf("next = %d", validator.Next())
	}
	if err := validator.Validate(second, BodyPong); err != nil {
		t.Fatal(err)
	}
}

func TestSequenceRejectsEnvelopeInvariantsWithoutAdvancing(t *testing.T) {
	valid := func() *lanewayv1.ControlEnvelope {
		return &lanewayv1.ControlEnvelope{
			SchemaVersion: 1,
			Sequence:      1,
			Body:          &lanewayv1.ControlEnvelope_Ping{Ping: &lanewayv1.Ping{}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*lanewayv1.ControlEnvelope)
		want   error
	}{
		{"schema zero", func(e *lanewayv1.ControlEnvelope) { e.SchemaVersion = 0 }, ErrUnsupportedVersion},
		{"sequence zero", func(e *lanewayv1.ControlEnvelope) { e.Sequence = 0 }, ErrUnexpectedSequence},
		{"sequence skipped", func(e *lanewayv1.ControlEnvelope) { e.Sequence = 2 }, ErrUnexpectedSequence},
		{"missing body", func(e *lanewayv1.ControlEnvelope) { e.Body = nil }, ErrInvalidEnvelope},
		{"nil body", func(e *lanewayv1.ControlEnvelope) { e.Body = &lanewayv1.ControlEnvelope_Ping{} }, ErrInvalidEnvelope},
		{"wrong type", func(e *lanewayv1.ControlEnvelope) { e.Body = &lanewayv1.ControlEnvelope_Pong{Pong: &lanewayv1.Pong{}} }, ErrUnexpectedMessage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var validator SequenceValidator
			envelope := valid()
			tt.mutate(envelope)
			if err := validator.Validate(envelope, BodyPing); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if validator.Next() != 1 {
				t.Fatalf("validator advanced to %d after rejection", validator.Next())
			}
		})
	}
}

func TestControlCodecRoundTripAndLimit(t *testing.T) {
	codec := ControlCodec{}
	var wire bytes.Buffer
	var outbound SequenceGenerator
	written, err := codec.Write(&wire, &outbound, &lanewayv1.Ping{Nonce: 42})
	if err != nil {
		t.Fatal(err)
	}
	var inbound SequenceValidator
	read, err := codec.Read(&wire, &inbound, BodyPing)
	if err != nil {
		t.Fatal(err)
	}
	if read.GetPing().GetNonce() != 42 || written.Sequence != read.Sequence {
		t.Fatalf("written=%v read=%v", written, read)
	}

	var oversized bytes.Buffer
	_ = binary.Write(&oversized, binary.BigEndian, uint32(1025))
	oversized.Write(make([]byte, 1025))
	limited := ControlCodec{Framer: protocolFramer(1024)}
	if _, err := limited.Read(&oversized, &SequenceValidator{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize error = %v", err)
	}
}

// protocolFramer keeps the test's framing intent readable without exporting a
// second codec constructor.
func protocolFramer(max uint32) protocol.ControlFramer {
	return protocol.ControlFramer{MaxPayload: max}
}

func TestControlCodecMalformedProtobuf(t *testing.T) {
	var wire bytes.Buffer
	_ = binary.Write(&wire, binary.BigEndian, uint32(1))
	wire.WriteByte(0xff)
	if _, err := (ControlCodec{}).Read(&wire, &SequenceValidator{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed protobuf error = %v", err)
	}
}

func TestRemoteErrorValidation(t *testing.T) {
	for _, input := range []*lanewayv1.ProtocolError{
		nil,
		{},
		{Code: lanewayv1.ErrorCode(99)},
	} {
		if err := RemoteError(input); !errors.Is(err, ErrMalformed) {
			t.Fatalf("RemoteError(%v) = %v", input, err)
		}
	}
}

func FuzzControlCodecRead(f *testing.F) {
	f.Add([]byte{0x08, 0x01, 0x10, 0x01, 0x62, 0x00})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			return
		}
		var wire bytes.Buffer
		_ = binary.Write(&wire, binary.BigEndian, uint32(len(payload)))
		wire.Write(payload)
		_, _ = (ControlCodec{Framer: protocolFramer(4096)}).Read(&wire, &SequenceValidator{})
	})
}
