package adminauth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	DefaultConcurrentPasswordVerifications = 2
	MaximumConcurrentPasswordVerifications = 4
)

var ErrPasswordVerificationBusy = errors.New("administrator password verification capacity exhausted")

// PasswordHashVerifier is the deliberately small injection boundary used by
// PasswordVerifier. Production callers should leave it unset so VerifyPassword
// is used; tests can supply a synchronized implementation without running the
// memory-hard function.
type PasswordHashVerifier func(encoded string, password []byte) (bool, error)

type PasswordVerifierOptions struct {
	// MaxConcurrent bounds memory-hard work. Zero selects the conservative
	// default; larger values are capped to prevent a configuration typo from
	// turning unauthenticated login attempts into a memory-exhaustion primitive.
	MaxConcurrent int
	// DummyHash is verified for unknown, disabled, or otherwise unusable
	// principals. When empty, a fresh valid dummy credential is generated.
	DummyHash string
	// Random is used only when DummyHash is empty.
	Random io.Reader
	// Verify is an optional test seam. Production callers leave it nil.
	Verify PasswordHashVerifier
}

// PasswordCandidate describes the constant-shape principal and credential
// lookup performed before password verification. Unusable records always take
// the dummy-hash path, even when Hash happens to be populated.
type PasswordCandidate struct {
	Hash   string
	Usable bool
}

// PasswordVerifier admits a bounded number of memory-hard password checks. It
// fails fast when capacity is exhausted so callers cannot build an unbounded
// queue of requests retaining passwords and HTTP resources.
type PasswordVerifier struct {
	semaphore chan struct{}
	dummyHash string
	verify    PasswordHashVerifier
}

func NewPasswordVerifier(options PasswordVerifierOptions) (*PasswordVerifier, error) {
	concurrency := options.MaxConcurrent
	if concurrency == 0 {
		concurrency = DefaultConcurrentPasswordVerifications
	}
	if concurrency < 1 || concurrency > MaximumConcurrentPasswordVerifications {
		return nil, fmt.Errorf("administrator password verification concurrency must be 1..%d", MaximumConcurrentPasswordVerifications)
	}
	dummyHash := options.DummyHash
	if dummyHash == "" {
		var err error
		dummyHash, err = newDummyPasswordHash(options.Random)
		if err != nil {
			return nil, err
		}
	}
	if err := ValidatePasswordHash(dummyHash); err != nil {
		return nil, fmt.Errorf("validate administrator dummy password hash: %w", err)
	}
	verify := options.Verify
	if verify == nil {
		verify = VerifyPassword
	}
	return &PasswordVerifier{
		semaphore: make(chan struct{}, concurrency),
		dummyHash: dummyHash,
		verify:    verify,
	}, nil
}

// Verify performs exactly one admitted hash verification. A false Usable flag
// selects the precomputed dummy hash and masks a matching result, giving unknown
// and disabled principals the same expensive path without authenticating them.
// ErrPasswordVerificationBusy is returned without starting hash work.
func (v *PasswordVerifier) Verify(candidate PasswordCandidate, password []byte) (bool, error) {
	if v == nil || v.verify == nil || v.semaphore == nil || v.dummyHash == "" {
		return false, errors.New("administrator password verifier is not initialized")
	}
	select {
	case v.semaphore <- struct{}{}:
		defer func() { <-v.semaphore }()
	default:
		return false, ErrPasswordVerificationBusy
	}
	encoded := candidate.Hash
	if !candidate.Usable {
		encoded = v.dummyHash
	}
	matched, err := v.verify(encoded, password)
	if err != nil {
		return false, err
	}
	return candidate.Usable && matched, nil
}

func newDummyPasswordHash(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	password := make([]byte, secretBytes)
	defer clear(password)
	if _, err := io.ReadFull(random, password); err != nil {
		return "", fmt.Errorf("generate administrator dummy password: %w", err)
	}
	hash, err := HashPassword(password, random)
	if err != nil {
		return "", fmt.Errorf("hash administrator dummy password: %w", err)
	}
	return hash, nil
}
