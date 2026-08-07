package tcpfallback

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// ControlStream adapts Session control records to io.ReadWriter. One reader
// and one writer may use it concurrently, matching net.Conn stream semantics.
type ControlStream struct {
	session *Session

	readMu sync.Mutex
	read   []byte

	writeMu      sync.Mutex
	writeHeader  [4]byte
	writeHeaderN int
	writePayload []byte
	writeExpect  int

	deadlineMu    sync.RWMutex
	writeDeadline time.Time
}

var _ io.ReadWriter = (*ControlStream)(nil)

func (s *ControlStream) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.read) == 0 {
		payload, err := s.session.ReadControl(context.Background())
		if err != nil {
			return 0, err
		}
		s.read = make([]byte, 4+len(payload))
		binary.BigEndian.PutUint32(s.read[:4], uint32(len(payload)))
		copy(s.read[4:], payload)
	}
	n := copy(dst, s.read)
	s.read = s.read[n:]
	return n, nil
}

func (s *ControlStream) Write(payload []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	original := len(payload)
	for len(payload) != 0 {
		if s.writeHeaderN < len(s.writeHeader) {
			n := copy(s.writeHeader[s.writeHeaderN:], payload)
			s.writeHeaderN += n
			payload = payload[n:]
			if s.writeHeaderN != len(s.writeHeader) {
				continue
			}
			s.writeExpect = int(binary.BigEndian.Uint32(s.writeHeader[:]))
			if s.writeExpect == 0 || s.writeExpect > s.session.config.maxControl {
				s.resetWrite()
				return original - len(payload), fmt.Errorf("%w: inner control length", ErrProtocol)
			}
			s.writePayload = make([]byte, 0, s.writeExpect)
		}
		n := min(s.writeExpect-len(s.writePayload), len(payload))
		s.writePayload = append(s.writePayload, payload[:n]...)
		payload = payload[n:]
		if len(s.writePayload) != s.writeExpect {
			continue
		}
		frame := s.writePayload
		s.resetWrite()
		if err := s.writeControl(frame); err != nil {
			return original - len(payload), err
		}
	}
	return original, nil
}

func (s *ControlStream) writeControl(payload []byte) error {
	s.deadlineMu.RLock()
	deadline := s.writeDeadline
	s.deadlineMu.RUnlock()
	ctx := context.Background()
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	if err := s.session.WriteControl(ctx, payload); err != nil {
		return err
	}
	return nil
}

func (s *ControlStream) resetWrite() {
	s.writeHeaderN = 0
	s.writeExpect = 0
	s.writePayload = nil
}

func (s *ControlStream) SetWriteDeadline(deadline time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = deadline
	s.deadlineMu.Unlock()
	return nil
}
