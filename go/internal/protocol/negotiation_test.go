package protocol

import (
	"errors"
	"testing"
)

func TestNegotiate(t *testing.T) {
	got, err := Negotiate(
		Version{Major: 1, Minor: 4}, Version{Major: 1, Minor: 2},
		CapabilityRelayV1|CapabilityIPv6V1|Capability(1<<63),
		CapabilityRelayV1|CapabilityDirectPeerV1|Capability(1<<63),
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != (Version{Major: 1, Minor: 2}) || got.Capabilities != CapabilityRelayV1 {
		t.Fatalf("negotiated %#v", got)
	}
	if !got.Capabilities.Has(CapabilityRelayV1) || got.Capabilities.Has(CapabilityIPv6V1) {
		t.Fatal("capability Has failed")
	}
}

func TestNegotiateIncompatible(t *testing.T) {
	for _, versions := range [][2]Version{
		{{Major: 1}, {Major: 2}},
		{{Major: 2}, {Major: 2}},
		{{}, {Major: 1}},
		{{Major: 1}, {}},
	} {
		if _, err := Negotiate(versions[0], versions[1], 0, 0); !errors.Is(err, ErrIncompatibleVersion) {
			t.Fatalf("%v: %v", versions, err)
		}
	}
}

func TestCapabilityString(t *testing.T) {
	if got := (CapabilityRelayV1 | CapabilityIPv6V1).String(); got != "relay-v1,ipv6-v1" {
		t.Fatalf("got %q", got)
	}
	if got := Capability(0).String(); got != "none" {
		t.Fatalf("got %q", got)
	}
}
