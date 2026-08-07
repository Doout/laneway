package revocation

import (
	"crypto/x509"
	"math/big"
	"sync/atomic"
	"testing"
)

func TestSetReplacementChecksAndSubscriptions(t *testing.T) {
	set := new(Set)
	var calls atomic.Int32
	unsubscribe := set.Subscribe(func() { calls.Add(1) })
	if err := set.Replace([][]byte{{1}, {2, 3}}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !set.IsRevoked([]byte{1}) || set.IsRevoked([]byte{2}) {
		t.Fatalf("calls=%d one=%t two=%t", calls.Load(), set.IsRevoked([]byte{1}), set.IsRevoked([]byte{2}))
	}
	if err := set.CheckCertificate(&x509.Certificate{SerialNumber: big.NewInt(1)}); err == nil {
		t.Fatal("revoked certificate accepted")
	}
	if err := set.Replace([][]byte{{4}}); err != nil {
		t.Fatal(err)
	}
	if set.IsRevoked([]byte{1}) || !set.IsRevoked([]byte{4}) {
		t.Fatal("replacement was not complete")
	}
	unsubscribe()
	if err := set.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("callbacks after unsubscribe=%d", calls.Load())
	}
}

func TestSetRejectsNoncanonicalAndDuplicateSerials(t *testing.T) {
	for _, serials := range [][][]byte{{{}}, {{0}}, {{0, 1}}, {{1}, {1}}} {
		if err := new(Set).Replace(serials); err == nil {
			t.Fatalf("accepted serials=%x", serials)
		}
	}
}
