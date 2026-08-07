// Package identity defines authenticated Laneway node identities.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const IDSize = 16

var ErrInvalidID = errors.New("invalid Laneway 128-bit ID")

type ID [IDSize]byte
type NetworkID ID
type NodeID ID

func NewID() (ID, error) {
	for {
		var id ID
		if _, err := rand.Read(id[:]); err != nil {
			return ID{}, fmt.Errorf("generate Laneway ID: %w", err)
		}
		if !id.IsZero() {
			return id, nil
		}
	}
}

func NewNetworkID() (NetworkID, error) {
	id, err := NewID()
	return NetworkID(id), err
}

func NewNodeID() (NodeID, error) {
	id, err := NewID()
	return NodeID(id), err
}

func ParseID(s string) (ID, error) {
	if len(s) != 32 {
		return ID{}, fmt.Errorf("%w: expected 32 lowercase hexadecimal characters", ErrInvalidID)
	}
	for i := range s {
		if !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')) {
			return ID{}, fmt.Errorf("%w: non-canonical character at offset %d", ErrInvalidID, i)
		}
	}
	var id ID
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return ID{}, fmt.Errorf("%w: %v", ErrInvalidID, err)
	}
	if id.IsZero() {
		return ID{}, fmt.Errorf("%w: zero ID", ErrInvalidID)
	}
	return id, nil
}

func ParseNetworkID(s string) (NetworkID, error) {
	id, err := ParseID(s)
	return NetworkID(id), err
}

func ParseNodeID(s string) (NodeID, error) {
	id, err := ParseID(s)
	return NodeID(id), err
}

func formatID(id ID) string {
	var out [32]byte
	hex.Encode(out[:], id[:])
	return string(out[:])
}

func (id ID) String() string        { return formatID(id) }
func (id NetworkID) String() string { return formatID(ID(id)) }
func (id NodeID) String() string    { return formatID(ID(id)) }

func (id ID) IsZero() bool        { return id == ID{} }
func (id NetworkID) IsZero() bool { return id == NetworkID{} }
func (id NodeID) IsZero() bool    { return id == NodeID{} }

func (id ID) MarshalText() ([]byte, error)        { return []byte(id.String()), nil }
func (id NetworkID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id NodeID) MarshalText() ([]byte, error)    { return []byte(id.String()), nil }

func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := ParseID(string(text))
	if err == nil {
		*id = parsed
	}
	return err
}

func (id *NetworkID) UnmarshalText(text []byte) error {
	parsed, err := ParseNetworkID(string(text))
	if err == nil {
		*id = parsed
	}
	return err
}

func (id *NodeID) UnmarshalText(text []byte) error {
	parsed, err := ParseNodeID(string(text))
	if err == nil {
		*id = parsed
	}
	return err
}
