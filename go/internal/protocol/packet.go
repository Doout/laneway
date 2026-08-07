// Package protocol contains Laneway's language-independent wire framing and
// feature negotiation primitives.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	PacketHeaderSize = 5
	PacketVersion1   = uint8(1)
	MaxPacketPayload = 65575
)

type PacketFlags uint8

const MaxPacketFlags PacketFlags = 0

var (
	ErrShortPacket        = errors.New("laneway packet is shorter than its header")
	ErrUnsupportedVersion = errors.New("unsupported Laneway packet version")
	ErrInvalidPacketFlags = errors.New("invalid Laneway packet flags")
	ErrInvalidRouteHandle = errors.New("invalid Laneway route handle")
	ErrPacketTooLarge     = errors.New("Laneway packet payload is too large")
	ErrInvalidIPPacket    = errors.New("invalid IP packet in Laneway frame")
)

// PacketHeader is the fixed five-byte dataplane header. Version and Flags each
// occupy a nibble of the first byte; RouteHandle is big-endian.
type PacketHeader struct {
	Version     uint8
	Flags       PacketFlags
	RouteHandle uint32
}

func (h PacketHeader) validate() error {
	if h.Version != PacketVersion1 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.Version)
	}
	if h.Flags != 0 {
		return fmt.Errorf("%w: %#x", ErrInvalidPacketFlags, h.Flags)
	}
	if h.RouteHandle == 0 {
		return ErrInvalidRouteHandle
	}
	return nil
}

func EncodePacketHeader(dst []byte, h PacketHeader) error {
	if len(dst) < PacketHeaderSize {
		return ErrShortPacket
	}
	if err := h.validate(); err != nil {
		return err
	}
	dst[0] = h.Version<<4 | byte(h.Flags)
	binary.BigEndian.PutUint32(dst[1:PacketHeaderSize], h.RouteHandle)
	return nil
}

func DecodePacketHeader(src []byte) (PacketHeader, error) {
	if len(src) < PacketHeaderSize {
		return PacketHeader{}, ErrShortPacket
	}
	h := PacketHeader{
		Version:     src[0] >> 4,
		Flags:       PacketFlags(src[0] & 0x0f),
		RouteHandle: binary.BigEndian.Uint32(src[1:PacketHeaderSize]),
	}
	if err := h.validate(); err != nil {
		return PacketHeader{}, err
	}
	return h, nil
}

// EncodePacket appends a framed packet to dst. Callers may reuse dst to avoid
// allocating on the dataplane fast path.
func EncodePacket(dst []byte, h PacketHeader, payload []byte) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if len(payload) > MaxPacketPayload {
		return nil, ErrPacketTooLarge
	}
	if err := ValidateIPPayload(payload); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, make([]byte, PacketHeaderSize)...)
	if err := EncodePacketHeader(dst[start:], h); err != nil {
		return dst[:start], err
	}
	dst = append(dst, payload...)
	return dst, nil
}

// DecodePacket returns a view into src for the payload; it does not allocate.
func DecodePacket(src []byte) (PacketHeader, []byte, error) {
	if len(src) <= PacketHeaderSize {
		return PacketHeader{}, nil, ErrShortPacket
	}
	h, err := DecodePacketHeader(src)
	if err != nil {
		return PacketHeader{}, nil, err
	}
	if len(src)-PacketHeaderSize > MaxPacketPayload {
		return PacketHeader{}, nil, ErrPacketTooLarge
	}
	payload := src[PacketHeaderSize:]
	if err := ValidateIPPayload(payload); err != nil {
		return PacketHeader{}, nil, err
	}
	return h, payload, nil
}

// ValidateIPPayload verifies the structural lengths required before a relay
// forwards a complete IPv4 or IPv6 packet. Source/destination authorization and
// the negotiated IPv6 capability are contextual checks performed by callers.
func ValidateIPPayload(payload []byte) error {
	if len(payload) == 0 {
		return ErrShortPacket
	}
	switch payload[0] >> 4 {
	case 4:
		if len(payload) < 20 {
			return ErrShortPacket
		}
		headerLen := int(payload[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(payload[2:4]))
		if headerLen < 20 || headerLen > len(payload) || totalLen < headerLen || totalLen != len(payload) {
			return ErrInvalidIPPacket
		}
	case 6:
		if len(payload) < 40 {
			return ErrShortPacket
		}
		payloadLen := int(binary.BigEndian.Uint16(payload[4:6]))
		if payloadLen+40 != len(payload) {
			return ErrInvalidIPPacket
		}
	default:
		return ErrInvalidIPPacket
	}
	return nil
}
