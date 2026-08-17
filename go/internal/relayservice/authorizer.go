// Package relayservice integrates authenticated QUIC and TLS/TCP transports,
// the control handshake, and relay dataplane into a runnable relay server.
package relayservice

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/Doout/laneway/go/internal/identity"
)

var ErrUnauthorized = errors.New("relay service: identity is not authorized")

// Authorization is controller-owned state attached to an authenticated node.
// OverlayAddresses are returned in Welcome. AuthorizedPrefixes are the source
// and destination ownership set enforced by the dataplane.
type Authorization struct {
	OverlayAddresses   []netip.Addr
	AuthorizedPrefixes []netip.Prefix
}

type authorizationSnapshot struct {
	assignments map[identity.NodeIdentity]Authorization
}

// AtomicAuthorizer publishes complete controller snapshots without exposing a
// partially updated authorization map to new relay sessions. Its zero value
// fails closed.
type AtomicAuthorizer struct {
	current atomic.Pointer[authorizationSnapshot]
}

func (a *AtomicAuthorizer) Replace(assignments map[identity.NodeIdentity]Authorization) error {
	next := make(map[identity.NodeIdentity]Authorization, len(assignments))
	for id, authorization := range assignments {
		if err := id.Validate(); err != nil || len(authorization.OverlayAddresses) == 0 || len(authorization.AuthorizedPrefixes) == 0 {
			return ErrUnauthorized
		}
		for _, address := range authorization.OverlayAddresses {
			if !address.IsValid() || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
				return ErrUnauthorized
			}
		}
		for _, prefix := range authorization.AuthorizedPrefixes {
			if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
				return ErrUnauthorized
			}
		}
		next[id] = cloneAuthorization(authorization)
	}
	a.current.Store(&authorizationSnapshot{assignments: next})
	return nil
}

func (a *AtomicAuthorizer) Authorize(_ context.Context, id identity.NodeIdentity) (Authorization, error) {
	if a == nil {
		return Authorization{}, ErrUnauthorized
	}
	snapshot := a.current.Load()
	if snapshot == nil {
		return Authorization{}, ErrUnauthorized
	}
	authorization, ok := snapshot.assignments[id]
	if !ok {
		return Authorization{}, ErrUnauthorized
	}
	return cloneAuthorization(authorization), nil
}

// Authorizer resolves assignments using the identity authenticated by mTLS.
// Implementations must not trust identity claims from Hello.
type Authorizer interface {
	Authorize(context.Context, identity.NodeIdentity) (Authorization, error)
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(context.Context, identity.NodeIdentity) (Authorization, error)

func (f AuthorizerFunc) Authorize(ctx context.Context, id identity.NodeIdentity) (Authorization, error) {
	return f(ctx, id)
}

// StaticAuthorizer is an immutable-by-convention assignment table suitable
// for static deployments and tests. Do not mutate it while a server is using
// it. Returned assignments are defensive copies.
type StaticAuthorizer map[identity.NodeIdentity]Authorization

func (a StaticAuthorizer) Authorize(_ context.Context, id identity.NodeIdentity) (Authorization, error) {
	authorization, ok := a[id]
	if !ok {
		return Authorization{}, ErrUnauthorized
	}
	return cloneAuthorization(authorization), nil
}

func cloneAuthorization(in Authorization) Authorization {
	return Authorization{
		OverlayAddresses:   append([]netip.Addr(nil), in.OverlayAddresses...),
		AuthorizedPrefixes: append([]netip.Prefix(nil), in.AuthorizedPrefixes...),
	}
}
