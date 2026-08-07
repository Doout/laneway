package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type oneByteWriter struct{ bytes.Buffer }

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func TestControlFrameRoundTripPartialIO(t *testing.T) {
	w := &oneByteWriter{}
	payload := []byte("hello")
	if err := WriteControlFrame(w, payload, 16); err != nil {
		t.Fatal(err)
	}
	if got := w.Bytes(); !bytes.Equal(got, []byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("wire frame %x", got)
	}
	got, err := ReadControlFrame(io.LimitReader(bytes.NewReader(w.Bytes()), int64(w.Len())), 16)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %q: %v", got, err)
	}
}

func TestControlFrameBoundsAndTruncation(t *testing.T) {
	if err := WriteControlFrame(io.Discard, []byte("123"), 2); !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("write oversize: %v", err)
	}
	for _, max := range []uint32{0, absoluteMaxControlFrame + 1} {
		if _, err := ReadControlFrame(bytes.NewReader(nil), max); !errors.Is(err, ErrInvalidControlLimit) {
			t.Fatalf("limit %d: %v", max, err)
		}
	}
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], 100)
	if _, err := ReadControlFrame(bytes.NewReader(oversized[:]), 10); !errors.Is(err, ErrControlFrameTooLarge) {
		t.Fatalf("read oversize: %v", err)
	}
	if _, err := ReadControlFrame(bytes.NewReader([]byte{0, 0}), 10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short header: %v", err)
	}
	if _, err := ReadControlFrame(bytes.NewReader([]byte{0, 0, 0, 2, 1}), 10); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short payload: %v", err)
	}
}

func TestControlFramerDefaultAndEmpty(t *testing.T) {
	var buf bytes.Buffer
	f := ControlFramer{}
	if err := f.Write(&buf, nil); !errors.Is(err, ErrEmptyControlFrame) {
		t.Fatalf("empty write: %v", err)
	}
	if _, err := f.Read(bytes.NewReader([]byte{0, 0, 0, 0})); !errors.Is(err, ErrEmptyControlFrame) {
		t.Fatalf("empty read: %v", err)
	}
}

func FuzzControlFrame(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte("x"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 || len(payload) > 1<<20 {
			return
		}
		var buf bytes.Buffer
		if err := WriteControlFrame(&buf, payload, 1<<20); err != nil {
			t.Fatal(err)
		}
		got, err := ReadControlFrame(&buf, 1<<20)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("round trip length %d: %v", len(payload), err)
		}
	})
}
