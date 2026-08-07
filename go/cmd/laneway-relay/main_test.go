package main

import (
	"testing"

	"laneway.dev/laneway/internal/config"
)

func TestStaticAuthorizer(t *testing.T) {
	authorizer, err := staticAuthorizer([]config.AuthorizedPeer{{
		NetworkID: "000102030405060708090a0b0c0d0e0f",
		NodeID:    "101112131415161718191a1b1c1d1e1f",
		Prefixes:  []string{"100.96.0.1/32", "192.168.50.0/24"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, authorization := range authorizer {
		if len(authorization.OverlayAddresses) != 1 || len(authorization.AuthorizedPrefixes) != 2 {
			t.Fatalf("unexpected authorization: %#v", authorization)
		}
	}
	if _, err := staticAuthorizer([]config.AuthorizedPeer{
		{NetworkID: "000102030405060708090a0b0c0d0e0f", NodeID: "101112131415161718191a1b1c1d1e1f", Prefixes: []string{"192.168.0.0/24"}},
	}); err == nil {
		t.Fatal("peer without overlay host address accepted")
	}
}
