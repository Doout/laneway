package bootstrapsecret

import (
	"strings"
	"testing"
	"time"
)

func TestSealOpenAndExpiry(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	token := []byte("st1.fixture")
	key, envelope, err := Seal(token, now, now.Add(MaxLifetime))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(key, envelope, now.Add(9*time.Minute))
	if err != nil || string(opened) != string(token) {
		t.Fatalf("opened %q, %v", opened, err)
	}
	clear(opened)
	if _, err := Open(key, envelope, now.Add(MaxLifetime)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry error = %v", err)
	}
}

func TestSealRejectsInvalidTokenAndLifetime(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	for _, token := range [][]byte{nil, []byte("has space"), []byte("has\nnewline")} {
		if _, _, err := Seal(token, now, now.Add(time.Minute)); err == nil {
			t.Fatalf("accepted token %q", token)
		}
	}
	if _, _, err := Seal([]byte("token"), now, now.Add(MaxLifetime+time.Second)); err == nil {
		t.Fatal("accepted excessive lifetime")
	}
}

func TestOpenRejectsWrongKeyAndTampering(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key, envelope, err := Seal([]byte("st1.fixture"), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := Seal([]byte("st1.other"), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(otherKey, envelope, now); err == nil {
		t.Fatal("wrong key was accepted")
	}
	tampered := envelope[:len(envelope)-1] + "A"
	if tampered == envelope {
		tampered = envelope[:len(envelope)-1] + "B"
	}
	if _, err := Open(key, tampered, now); err == nil {
		t.Fatal("tampered envelope was accepted")
	}
}
