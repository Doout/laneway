// Package wireguard owns local WireGuard identity material and the boundary
// between controller metadata and platform-specific device implementations.
package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

const KeySize = 32

type PrivateKey [KeySize]byte
type PublicKey [KeySize]byte

func GenerateKey() (PrivateKey, PublicKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("generate WireGuard identity key: %w", err)
	}
	var privateKey PrivateKey
	var publicKey PublicKey
	copy(privateKey[:], private.Bytes())
	copy(publicKey[:], private.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func ParsePrivateKey(raw []byte) (PrivateKey, PublicKey, error) {
	if len(raw) != KeySize {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("WireGuard private key must be exactly %d bytes", KeySize)
	}
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return PrivateKey{}, PublicKey{}, errors.New("invalid WireGuard private key")
	}
	var privateKey PrivateKey
	var publicKey PublicKey
	copy(privateKey[:], private.Bytes())
	copy(publicKey[:], private.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func (k PrivateKey) Bytes() []byte { return append([]byte(nil), k[:]...) }
func (k PublicKey) Bytes() []byte  { return append([]byte(nil), k[:]...) }

func (k PublicKey) Equal(raw []byte) bool {
	return len(raw) == KeySize && subtle.ConstantTimeCompare(k[:], raw) == 1
}

func ZeroPrivateKey(key *PrivateKey) {
	if key == nil {
		return
	}
	for i := range key {
		key[i] = 0
	}
}
