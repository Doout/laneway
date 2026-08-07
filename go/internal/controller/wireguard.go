package controller

import (
	"crypto/ecdh"
	"errors"
	"fmt"
)

const WireGuardKeySize = 32

// WireGuardPublicKey is the raw X25519 public key bound by the controller to a
// single NetworkID/NodeID. Its zero value represents a pre-migration node that
// has not renewed yet and is never accepted for a new protocol enrollment.
type WireGuardPublicKey [WireGuardKeySize]byte

func ParseWireGuardPublicKey(raw []byte) (WireGuardPublicKey, error) {
	var result WireGuardPublicKey
	if len(raw) != WireGuardKeySize {
		return result, fmt.Errorf("%w: WireGuard public key must be exactly %d bytes", ErrInvalid, WireGuardKeySize)
	}
	curve := ecdh.X25519()
	public, err := curve.NewPublicKey(raw)
	if err != nil {
		return result, fmt.Errorf("%w: invalid WireGuard public key", ErrInvalid)
	}
	// X25519 has a small set of low-order public inputs. Confirm that an ECDH
	// operation does not yield the forbidden all-zero shared secret so a stored
	// identity key can actually authenticate a WireGuard handshake.
	probeRaw := make([]byte, WireGuardKeySize)
	probeRaw[0] = 1
	probe, err := curve.NewPrivateKey(probeRaw)
	if err != nil {
		return result, errors.New("initialize X25519 key validator")
	}
	if _, err := probe.ECDH(public); err != nil {
		return result, fmt.Errorf("%w: low-order WireGuard public key", ErrInvalid)
	}
	copy(result[:], raw)
	return result, nil
}

func (k WireGuardPublicKey) IsZero() bool {
	var zero WireGuardPublicKey
	return k == zero
}

func (k WireGuardPublicKey) Bytes() []byte {
	if k.IsZero() {
		return nil
	}
	return append([]byte(nil), k[:]...)
}

func nullableWireGuardKey(key WireGuardPublicKey) any {
	if key.IsZero() {
		return nil
	}
	return key[:]
}

func scanWireGuardPublicKey(raw []byte) (WireGuardPublicKey, error) {
	if len(raw) == 0 {
		return WireGuardPublicKey{}, nil
	}
	key, err := ParseWireGuardPublicKey(raw)
	if err != nil {
		return WireGuardPublicKey{}, errors.New("corrupt node WireGuard public key")
	}
	return key, nil
}
