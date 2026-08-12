package adminauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestPasswordVerifierBoundsConcurrentHashWork(t *testing.T) {
	dummyHash := testPasswordHash(1)
	started := make(chan struct{}, MaximumConcurrentPasswordVerifications)
	release := make(chan struct{})
	verifier, err := NewPasswordVerifier(PasswordVerifierOptions{
		MaxConcurrent: 2,
		DummyHash:     dummyHash,
		Verify: func(string, []byte) (bool, error) {
			started <- struct{}{}
			<-release
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			matched, verifyErr := verifier.Verify(PasswordCandidate{Hash: dummyHash, Usable: true}, []byte("a sufficiently long password"))
			if verifyErr == nil && !matched {
				verifyErr = errors.New("admitted password did not match")
			}
			results <- verifyErr
		}()
	}
	// Receiving both starts proves both semaphore slots are held. The next call
	// must therefore fail synchronously; no timing assertion is involved.
	<-started
	<-started
	if matched, err := verifier.Verify(PasswordCandidate{Hash: dummyHash, Usable: true}, []byte("a sufficiently long password")); matched || !errors.Is(err, ErrPasswordVerificationBusy) {
		t.Fatalf("verification beyond capacity matched=%t err=%v", matched, err)
	}
	close(release)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}

	if matched, err := verifier.Verify(PasswordCandidate{Hash: dummyHash, Usable: true}, []byte("a sufficiently long password")); err != nil || !matched {
		t.Fatalf("verification after release matched=%t err=%v", matched, err)
	}
}

func TestPasswordVerifierUsesDummyHashForUnusableCandidate(t *testing.T) {
	dummyHash := testPasswordHash(2)
	realHash := testPasswordHash(3)
	var gotHash string
	verifier, err := NewPasswordVerifier(PasswordVerifierOptions{
		MaxConcurrent: 1,
		DummyHash:     dummyHash,
		Verify: func(encoded string, _ []byte) (bool, error) {
			gotHash = encoded
			return true, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	matched, err := verifier.Verify(PasswordCandidate{Hash: realHash, Usable: false}, []byte("a sufficiently long password"))
	if err != nil || matched {
		t.Fatalf("dummy verification matched=%t err=%v", matched, err)
	}
	if gotHash != dummyHash {
		t.Fatal("unusable credential did not take the dummy-hash path")
	}

	matched, err = verifier.Verify(PasswordCandidate{Hash: realHash, Usable: true}, []byte("a sufficiently long password"))
	if err != nil || !matched || gotHash != realHash {
		t.Fatalf("usable verification matched=%t hash-selected=%t err=%v", matched, gotHash == realHash, err)
	}
}

func TestPasswordVerifierValidatesConfiguration(t *testing.T) {
	dummyHash := testPasswordHash(4)
	for _, concurrency := range []int{-1, MaximumConcurrentPasswordVerifications + 1} {
		if _, err := NewPasswordVerifier(PasswordVerifierOptions{MaxConcurrent: concurrency, DummyHash: dummyHash}); err == nil {
			t.Fatalf("concurrency %d accepted", concurrency)
		}
	}
	if _, err := NewPasswordVerifier(PasswordVerifierOptions{DummyHash: "not-a-password-hash"}); err == nil {
		t.Fatal("malformed dummy hash accepted")
	}
	failingRandom := &errorReader{err: errors.New("entropy unavailable")}
	if _, err := NewPasswordVerifier(PasswordVerifierOptions{Random: failingRandom}); !errors.Is(err, failingRandom.err) {
		t.Fatalf("dummy generation error=%v", err)
	}
	var uninitialized *PasswordVerifier
	if _, err := uninitialized.Verify(PasswordCandidate{}, nil); err == nil {
		t.Fatal("uninitialized verifier accepted a request")
	}
}

func testPasswordHash(fill byte) string {
	salt := bytes.Repeat([]byte{fill}, passwordSaltSize)
	digest := bytes.Repeat([]byte{fill + 1}, argonKeyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB,
		argonIterations, argonParallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
}

type errorReader struct{ err error }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }
