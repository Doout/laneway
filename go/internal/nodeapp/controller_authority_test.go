package nodeapp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/endpointpin"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/netvalidate"
	"github.com/Doout/laneway/go/internal/nodeservice"
)

type nodeRelayTestResolver struct {
	answers  map[string][]netip.Addr
	failures map[string]error
	wait     map[string]bool
	canceled chan string
}

func TestControllerCertificateRenewalTracksClockBoundary(t *testing.T) {
	threshold := time.Unix(2_000_000_000, 0).UTC()
	state := &controllerApplyState{}
	state.certificateRenewAfter.Store(uint64(threshold.Unix()))
	if state.CertificateRenewalNeeded(threshold.Add(-time.Second)) {
		t.Fatal("renewal was needed before the threshold")
	}
	if !state.CertificateRenewalNeeded(threshold) {
		t.Fatal("renewal was not needed at the exact threshold")
	}
	state.certificateRenewAfter.Store(uint64(threshold.Add(time.Hour).Unix()))
	state.certificateRenewalNeeded.Store(true)
	if !state.CertificateRenewalNeeded(threshold) {
		t.Fatal("forced renewal state was not preserved")
	}
}

func (r *nodeRelayTestResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, errors.New("unexpected lookup network")
	}
	if r.wait[host] {
		<-ctx.Done()
		if r.canceled != nil {
			r.canceled <- host
		}
		return nil, ctx.Err()
	}
	if err := r.failures[host]; err != nil {
		return nil, err
	}
	return append([]netip.Addr(nil), r.answers[host]...), nil
}

func TestValidateNodeRuntimeAuthorityConsumesAllIssuedFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	relay := identity.ID{1}
	alternateRelay := identity.ID{9}
	exit := identity.NodeID{2}
	authority := &nodeRuntimeAuthority{
		relayServiceID: relay, relayEndpoint: "127.0.0.1:4433",
		directEnabled: true, maxCandidates: 8, candidateTTL: 120 * time.Second,
		certificateSerial: []byte{3}, certificateNotAfter: uint64(now.Add(time.Hour).Unix()),
		certificateRenewAfter: uint64(now.Add(-time.Minute).Unix()),
	}
	valid := func() *lanewayv1.NodeConfiguration {
		return &lanewayv1.NodeConfiguration{
			Relays:            []*lanewayv1.RelayEndpoint{{ServiceId: relay[:], Name: "relay-a", Endpoint: "127.0.0.1:4433"}},
			CandidateExchange: &lanewayv1.CandidateExchangePolicy{Enabled: true, MaxCandidates: 4, CandidateTtlSeconds: 60},
			ExitPolicy:        &lanewayv1.ExitNodePolicy{AuthorizedNodeIds: [][]byte{exit[:]}},
			Routes:            &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{{Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT, ViaNodeId: exit[:]}}},
			CertificateHealth: &lanewayv1.CertificateHealth{
				PresentedSerial: []byte{3}, NotAfterUnixSeconds: uint64(now.Add(time.Hour).Unix()),
				RenewAfterUnixSeconds: uint64(now.Add(-time.Minute).Unix()),
			},
		}
	}

	status, err := validateNodeRuntimeAuthority(valid(), authority, now)
	if err != nil {
		t.Fatal(err)
	}
	if !status.candidateEnabled || status.candidateMax != 4 || status.candidateTTLSeconds != 60 || !status.renewalNeeded {
		t.Fatalf("authority status = %#v", status)
	}

	configuration := valid()
	configuration.Relays = nil
	if _, err := validateNodeRuntimeAuthority(configuration, authority, now); !errors.Is(err, errControllerRuntimeUnauthorized) {
		t.Fatalf("missing active relay error = %v", err)
	}

	configuration = valid()
	for i := 1; i < netvalidate.MaxRelayEndpoints+1; i++ {
		service := identity.ID{byte(i + 1)}
		configuration.Relays = append(configuration.Relays, &lanewayv1.RelayEndpoint{
			ServiceId: service[:], Name: fmt.Sprintf("relay-%d", i), Endpoint: fmt.Sprintf("192.0.2.%d:4433", i),
		})
	}
	if _, err := validateNodeRuntimeAuthority(configuration, authority, now); err == nil {
		t.Fatal("oversized controller relay snapshot was accepted")
	}

	configuration = valid()
	configuration.Relays = []*lanewayv1.RelayEndpoint{{ServiceId: alternateRelay[:], Name: "relay-b", Endpoint: "127.0.0.1:9443"}}
	status, err = validateNodeRuntimeAuthority(configuration, authority, now)
	if err != nil || len(status.relayTargets) != 1 || status.relayTargets[0].ServiceID != alternateRelay {
		t.Fatalf("alternate-only relay authority status=%#v error=%v", status, err)
	}

	configuration = valid()
	configuration.CandidateExchange.Enabled = false
	configuration.CandidateExchange.MaxCandidates = 0
	configuration.CandidateExchange.CandidateTtlSeconds = 0
	status, err = validateNodeRuntimeAuthority(configuration, authority, now)
	if err != nil || status.candidateEnabled {
		t.Fatalf("disabled dynamic candidate policy status=%#v error=%v", status, err)
	}

	configuration = valid()
	configuration.ExitPolicy.AuthorizedNodeIds = nil
	if _, err := validateNodeRuntimeAuthority(configuration, authority, now); err == nil {
		t.Fatal("exit-policy/route disagreement was accepted")
	}

	configuration = valid()
	configuration.CertificateHealth.PresentedSerial = []byte{4}
	if _, err := validateNodeRuntimeAuthority(configuration, authority, now); err == nil {
		t.Fatal("mismatched certificate health was accepted")
	}

	configuration = valid()
	configuration.RevokedCertificateSerials = [][]byte{{3}}
	configuration.CertificateHealth.Revoked = true
	if _, err := validateNodeRuntimeAuthority(configuration, authority, now); !errors.Is(err, errControllerRuntimeUnauthorized) {
		t.Fatalf("revoked local certificate error = %v", err)
	}
}

func TestCanonicalRelayEndpoint(t *testing.T) {
	value, err := canonicalRelayEndpoint("Example.COM.:443")
	if err != nil || value != "example.com:443" {
		t.Fatalf("canonical endpoint = %q, %v", value, err)
	}
	if _, err := canonicalRelayEndpoint("example.com:0"); err == nil {
		t.Fatal("zero endpoint port was accepted")
	}
}

func TestResolveNodeRelayTargetsToleratesPartialFailure(t *testing.T) {
	resolver := &nodeRelayTestResolver{
		answers:  map[string][]netip.Addr{"good.example": {netip.MustParseAddr("192.0.2.10")}},
		failures: map[string]error{"bad.example": errors.New("not found")},
	}
	targets := []nodeservice.RelayTarget{
		{ServiceID: identity.ID{1}, Address: "bad.example:4433"},
		{ServiceID: identity.ID{2}, Address: "good.example:4433"},
	}
	resolved, bypass, err := resolveNodeRelayTargetsWithOptions(
		context.Background(), targets, endpointpin.Options{Resolver: resolver}, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0].ServiceID != (identity.ID{2}) || resolved[0].Address != "192.0.2.10:4433" {
		t.Fatalf("resolved targets = %+v", resolved)
	}
	if len(bypass) != 1 || bypass[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("relay bypasses = %v", bypass)
	}
}

func TestResolveNodeRelayTargetsSortsDeduplicatesAndPreservesIdentity(t *testing.T) {
	resolver := &nodeRelayTestResolver{answers: map[string][]netip.Addr{"shared.example": {
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("192.0.2.11"),
		netip.MustParseAddr("::ffff:192.0.2.11"),
		netip.MustParseAddr("192.0.2.10"),
	}}}
	targets := []nodeservice.RelayTarget{
		{ServiceID: identity.ID{2}, Address: "shared.example:4433"},
		{ServiceID: identity.ID{1}, Address: "shared.example:4433"},
	}
	resolved, bypass, err := resolveNodeRelayTargetsWithOptions(
		context.Background(), targets, endpointpin.Options{Resolver: resolver}, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantAddresses := []string{"192.0.2.10:4433", "192.0.2.11:4433", "[2001:db8::2]:4433"}
	if len(resolved) != 2*len(wantAddresses) {
		t.Fatalf("resolved targets = %+v", resolved)
	}
	for serviceIndex, service := range []identity.ID{{1}, {2}} {
		for addressIndex, address := range wantAddresses {
			got := resolved[serviceIndex*len(wantAddresses)+addressIndex]
			if got.ServiceID != service || got.Address != address {
				t.Fatalf("resolved target %d = %+v", serviceIndex*len(wantAddresses)+addressIndex, got)
			}
		}
	}
	wantBypass := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("2001:db8::2"),
	}
	if fmt.Sprint(bypass) != fmt.Sprint(wantBypass) {
		t.Fatalf("relay bypasses = %v, want %v", bypass, wantBypass)
	}
}

func TestResolveNodeRelayTargetsFailsClosedWhenAllFail(t *testing.T) {
	resolver := &nodeRelayTestResolver{failures: map[string]error{
		"first.example": errors.New("not found"), "second.example": errors.New("temporary failure"),
	}}
	_, _, err := resolveNodeRelayTargetsWithOptions(context.Background(), []nodeservice.RelayTarget{
		{ServiceID: identity.ID{1}, Address: "first.example:4433"},
		{ServiceID: identity.ID{2}, Address: "second.example:4433"},
	}, endpointpin.Options{Resolver: resolver}, time.Second)
	if err == nil {
		t.Fatal("all-failed relay authority was accepted")
	}
}

func TestResolveNodeRelayTargetsEnforcesCapsAndDeadline(t *testing.T) {
	t.Run("relay count", func(t *testing.T) {
		targets := make([]nodeservice.RelayTarget, netvalidate.MaxRelayEndpoints+1)
		if _, _, err := resolveNodeRelayTargetsWithOptions(context.Background(), targets, endpointpin.Options{}, time.Second); err == nil {
			t.Fatal("oversized relay target set was accepted")
		}
	})

	t.Run("per relay answers", func(t *testing.T) {
		answers := make([]netip.Addr, netvalidate.MaxRelayAddressesPerEndpoint+1)
		for i := range answers {
			answers[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		}
		resolver := &nodeRelayTestResolver{answers: map[string][]netip.Addr{"overflow.example": answers}}
		resolved, _, err := resolveNodeRelayTargetsWithOptions(context.Background(), []nodeservice.RelayTarget{
			{ServiceID: identity.ID{1}, Address: "overflow.example:4433"},
			{ServiceID: identity.ID{2}, Address: "192.0.2.200:4433"},
		}, endpointpin.Options{Resolver: resolver}, time.Second)
		if err != nil || len(resolved) != 1 || resolved[0].ServiceID != (identity.ID{2}) {
			t.Fatalf("overflow relay was not skipped: targets=%+v error=%v", resolved, err)
		}
	})

	t.Run("aggregate targets", func(t *testing.T) {
		answers := make(map[string][]netip.Addr)
		targets := make([]nodeservice.RelayTarget, 0, 9)
		for relay := 0; relay < 9; relay++ {
			host := fmt.Sprintf("relay-%d.example", relay)
			for answer := 0; answer < netvalidate.MaxRelayAddressesPerEndpoint; answer++ {
				answers[host] = append(answers[host], netip.AddrFrom4([4]byte{198, byte(relay + 1), 0, byte(answer + 1)}))
			}
			targets = append(targets, nodeservice.RelayTarget{
				ServiceID: identity.ID{byte(relay + 1)}, Address: host + ":4433",
			})
		}
		resolver := &nodeRelayTestResolver{answers: answers}
		if _, _, err := resolveNodeRelayTargetsWithOptions(
			context.Background(), targets, endpointpin.Options{Resolver: resolver}, time.Second,
		); err == nil {
			t.Fatal("aggregate relay target overflow was accepted")
		}
	})

	t.Run("global deadline retains completed relay", func(t *testing.T) {
		canceled := make(chan string, 1)
		resolver := &nodeRelayTestResolver{
			answers:  map[string][]netip.Addr{"ready.example": {netip.MustParseAddr("203.0.113.10")}},
			wait:     map[string]bool{"waiting.example": true},
			canceled: canceled,
		}
		started := time.Now()
		resolved, bypass, err := resolveNodeRelayTargetsWithOptions(context.Background(), []nodeservice.RelayTarget{
			{ServiceID: identity.ID{1}, Address: "ready.example:4433"},
			{ServiceID: identity.ID{2}, Address: "waiting.example:4433"},
		}, endpointpin.Options{Resolver: resolver}, 20*time.Millisecond)
		if err != nil || len(resolved) != 1 || len(bypass) != 1 {
			t.Fatalf("deadline result targets=%+v bypass=%v error=%v", resolved, bypass, err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("global relay resolution deadline took %v", elapsed)
		}
		select {
		case host := <-canceled:
			if host != "waiting.example" {
				t.Fatalf("canceled host = %q", host)
			}
		case <-time.After(time.Second):
			t.Fatal("timed-out resolver did not observe cancellation")
		}
	})
}
