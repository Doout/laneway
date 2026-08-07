package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ControlLengthSize       = 4
	DefaultMaxControlFrame  = uint32(1 << 20)
	absoluteMaxControlFrame = DefaultMaxControlFrame
)

var (
	ErrControlFrameTooLarge = errors.New("Laneway control frame exceeds maximum")
	ErrEmptyControlFrame    = errors.New("Laneway control frame is empty")
	ErrInvalidControlLimit  = errors.New("invalid Laneway control frame limit")
)

func validControlLimit(max uint32) error {
	if max == 0 || max > absoluteMaxControlFrame {
		return fmt.Errorf("%w: %d", ErrInvalidControlLimit, max)
	}
	return nil
}

func WriteControlFrame(w io.Writer, payload []byte, max uint32) error {
	if err := validControlLimit(max); err != nil {
		return err
	}
	if uint64(len(payload)) > uint64(max) {
		return fmt.Errorf("%w: length %d, maximum %d", ErrControlFrameTooLarge, len(payload), max)
	}
	if len(payload) == 0 {
		return ErrEmptyControlFrame
	}
	var header [ControlLengthSize]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return fmt.Errorf("write control frame length: %w", err)
	}
	if err := writeFull(w, payload); err != nil {
		return fmt.Errorf("write control frame payload: %w", err)
	}
	return nil
}

func ReadControlFrame(r io.Reader, max uint32) ([]byte, error) {
	if err := validControlLimit(max); err != nil {
		return nil, err
	}
	var header [ControlLengthSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read control frame length: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return nil, ErrEmptyControlFrame
	}
	if size > max {
		return nil, fmt.Errorf("%w: length %d, maximum %d", ErrControlFrameTooLarge, size, max)
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read control frame payload: %w", err)
	}
	return payload, nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type ControlFramer struct {
	MaxPayload uint32
}

func (f ControlFramer) limit() uint32 {
	if f.MaxPayload == 0 {
		return DefaultMaxControlFrame
	}
	return f.MaxPayload
}

func (f ControlFramer) Read(r io.Reader) ([]byte, error) {
	return ReadControlFrame(r, f.limit())
}

func (f ControlFramer) Write(w io.Writer, payload []byte) error {
	return WriteControlFrame(w, payload, f.limit())
}
