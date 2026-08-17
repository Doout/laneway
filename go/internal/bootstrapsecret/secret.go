// Package bootstrapsecret seals short-lived Connector setup tokens for the
// one-time Docker bootstrap flow. The decryption key is never sent to or
// stored by the control plane.
package bootstrapsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/bootstrap"
)

const (
	MaxLifetime  = bootstrap.MaxBundleLifetime
	MaxTokenSize = 64 << 10
	version      = byte(1)
	headerSize   = 1 + 8
)

var encoding = base64.RawURLEncoding.Strict()

// Seal encrypts and authenticates token with a fresh AES-256-GCM key. The
// returned key and envelope use unpadded base64url so they are safe as one
// shell argument and one script payload line respectively.
func Seal(token []byte, now, expiresAt time.Time) (keyText, envelopeText string, err error) {
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if len(token) == 0 || len(token) > MaxTokenSize || containsSpace(token) {
		return "", "", errors.New("bootstrap secret: setup token is invalid")
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(MaxLifetime)) {
		return "", "", fmt.Errorf("bootstrap secret: expiry must be in (0,%s]", MaxLifetime)
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", "", fmt.Errorf("bootstrap secret: generate key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	header := make([]byte, headerSize)
	header[0] = version
	binary.BigEndian.PutUint64(header[1:], uint64(expiresAt.Unix()))
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", fmt.Errorf("bootstrap secret: generate nonce: %w", err)
	}
	envelope := make([]byte, 0, len(header)+len(nonce)+len(token)+aead.Overhead())
	envelope = append(envelope, header...)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, token, header)
	return encoding.EncodeToString(key), encoding.EncodeToString(envelope), nil
}

// Open authenticates and decrypts an envelope and enforces its embedded
// deadline. Authentication failures deliberately have one generic error.
func Open(keyText, envelopeText string, now time.Time) ([]byte, error) {
	if strings.TrimSpace(keyText) != keyText || strings.TrimSpace(envelopeText) != envelopeText {
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	key, err := encoding.DecodeString(keyText)
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	defer clear(key)
	envelope, err := encoding.DecodeString(envelopeText)
	if err != nil {
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	defer clear(envelope)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	if len(envelope) < headerSize+aead.NonceSize()+aead.Overhead()+1 || envelope[0] != version {
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	header := envelope[:headerSize]
	nonce := envelope[headerSize : headerSize+aead.NonceSize()]
	plaintext, err := aead.Open(nil, nonce, envelope[headerSize+aead.NonceSize():], header)
	if err != nil || len(plaintext) == 0 || len(plaintext) > MaxTokenSize || containsSpace(plaintext) {
		clear(plaintext)
		return nil, errors.New("bootstrap secret: invalid key or payload")
	}
	expiresAt := time.Unix(int64(binary.BigEndian.Uint64(header[1:])), 0).UTC()
	if !expiresAt.After(now.UTC()) {
		clear(plaintext)
		return nil, errors.New("bootstrap secret: payload has expired")
	}
	return plaintext, nil
}

func containsSpace(value []byte) bool {
	for _, character := range value {
		switch character {
		case ' ', '\t', '\r', '\n':
			return true
		}
	}
	return false
}
