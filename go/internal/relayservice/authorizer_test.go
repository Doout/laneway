package relayservice

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"laneway.dev/laneway/internal/identity"
)

func TestAtomicAuthorizerSnapshots(t *testing.T) {
	id := identity.NodeIdentity{NetworkID: identity.NetworkID(testAuthorizationID(1)), NodeID: identity.NodeID(testAuthorizationID(2))}
	authorizer := new(AtomicAuthorizer)
	if _, err := authorizer.Authorize(context.Background(), id); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero-value authorization error = %v", err)
	}
	assignment := Authorization{
		OverlayAddresses:   []netip.Addr{netip.MustParseAddr("100.96.0.2")},
		AuthorizedPrefixes: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")},
	}
	if err := authorizer.Replace(map[identity.NodeIdentity]Authorization{id: assignment}); err != nil {
		t.Fatal(err)
	}
	assignment.OverlayAddresses[0] = netip.MustParseAddr("100.96.0.99")
	got, err := authorizer.Authorize(context.Background(), id)
	if err != nil || got.OverlayAddresses[0].String() != "100.96.0.2" {
		t.Fatalf("authorization = %#v, %v", got, err)
	}
	got.AuthorizedPrefixes[0] = netip.MustParsePrefix("10.0.0.0/8")
	again, _ := authorizer.Authorize(context.Background(), id)
	if again.AuthorizedPrefixes[0].String() != "100.96.0.2/32" {
		t.Fatal("returned authorization mutated published snapshot")
	}
	if err := authorizer.Replace(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(context.Background(), id); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("removed authorization error = %v", err)
	}
}

func TestAtomicAuthorizerRejectsInvalidSnapshot(t *testing.T) {
	id := identity.NodeIdentity{NetworkID: identity.NetworkID(testAuthorizationID(1)), NodeID: identity.NodeID(testAuthorizationID(2))}
	if err := new(AtomicAuthorizer).Replace(map[identity.NodeIdentity]Authorization{id: {}}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalid snapshot error = %v", err)
	}
}

func testAuthorizationID(last byte) identity.ID {
	var id identity.ID
	id[len(id)-1] = last
	return id
}
