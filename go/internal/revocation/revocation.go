// Package revocation publishes controller certificate-revocation snapshots to
// concurrent TLS verifiers and active-session owners.
package revocation

import (
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
)

var ErrInvalidSerial = errors.New("revocation: invalid certificate serial")

type snapshot struct {
	serials map[string]struct{}
}

// Set is a complete, atomically replaced revocation snapshot. Its zero value
// is an initialized empty set. Subscribers are notified after each successful
// replacement so active session owners can fail closed promptly.
type Set struct {
	current atomic.Pointer[snapshot]
	mu      sync.Mutex
	nextID  uint64
	watch   map[uint64]func()
}

func validateSerial(serial []byte) error {
	if len(serial) < 1 || len(serial) > 32 || serial[0] == 0 {
		return ErrInvalidSerial
	}
	return nil
}

// Replace validates and publishes a complete snapshot. Duplicates are
// rejected so malformed controller data cannot be silently normalized.
func (s *Set) Replace(serials [][]byte) error {
	next := &snapshot{serials: make(map[string]struct{}, len(serials))}
	for _, serial := range serials {
		if err := validateSerial(serial); err != nil {
			return err
		}
		key := string(serial)
		if _, duplicate := next.serials[key]; duplicate {
			return ErrInvalidSerial
		}
		next.serials[key] = struct{}{}
	}
	s.current.Store(next)
	s.mu.Lock()
	callbacks := make([]func(), 0, len(s.watch))
	for _, callback := range s.watch {
		callbacks = append(callbacks, callback)
	}
	s.mu.Unlock()
	for _, callback := range callbacks {
		callback()
	}
	return nil
}

func (s *Set) IsRevoked(serial []byte) bool {
	if s == nil || validateSerial(serial) != nil {
		return false
	}
	current := s.current.Load()
	if current == nil {
		return false
	}
	_, found := current.serials[string(serial)]
	return found
}

func (s *Set) CheckCertificate(certificate *x509.Certificate) error {
	if certificate == nil || certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 {
		return ErrInvalidSerial
	}
	if s.IsRevoked(certificate.SerialNumber.Bytes()) {
		return errors.New("revocation: certificate is revoked")
	}
	return nil
}

// Subscribe registers a prompt active-session recheck. The returned function
// is safe to call repeatedly and removes the subscription.
func (s *Set) Subscribe(callback func()) func() {
	if s == nil || callback == nil {
		return func() {}
	}
	s.mu.Lock()
	if s.watch == nil {
		s.watch = make(map[uint64]func())
	}
	s.nextID++
	id := s.nextID
	s.watch[id] = callback
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.watch, id)
			s.mu.Unlock()
		})
	}
}
