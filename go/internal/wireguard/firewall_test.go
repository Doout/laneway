package wireguard

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func firewallID(value byte) identity.ID {
	var result identity.ID
	result[len(result)-1] = value
	return result
}

func firewallNode(value byte) identity.NodeID { return identity.NodeID(firewallID(value)) }

func TestCompileFirewallPlanPreservesOrderedDirectionalPolicy(t *testing.T) {
	local, first, second := firewallNode(1), firewallNode(2), firewallNode(3)
	plan, statements, err := compileFirewallPlan(FirewallPlan{
		Epoch: 7, LocalNode: local, DefaultAction: FirewallDeny,
		PeerPrefixes: map[identity.NodeID][]netip.Prefix{
			first:  {netip.MustParsePrefix("100.64.0.2/32")},
			second: {netip.MustParsePrefix("fd00::3/128")},
		},
		Rules: []FirewallRule{
			{ID: firewallID(2), Priority: 20, Action: FirewallDeny, Protocol: 256},
			{ID: firewallID(1), Priority: 10, Action: FirewallAccept, SourceNodes: []identity.NodeID{first},
				DestinationNodes: []identity.NodeID{local}, Protocol: 256,
				DestinationPorts: []FirewallPortRange{{First: 443, Last: 443}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Rules[0].ID != firewallID(1) || len(statements) != 4 {
		t.Fatalf("rules=%+v statements=%+v", plan.Rules, statements)
	}
	// The first rule applies inbound only and ANY+ports expands to TCP then UDP.
	if statements[0].Direction != firewallInbound || statements[0].Protocol != 6 ||
		statements[1].Direction != firewallInbound || statements[1].Protocol != 17 ||
		statements[0].SourceOwnerPrefix.String() != "100.64.0.2/32" {
		t.Fatalf("directional expansion = %+v", statements[:2])
	}
	// The wildcard deny is emitted after the higher-priority accept for both directions.
	if statements[2].Action != FirewallDeny || statements[2].Direction != firewallInbound ||
		statements[3].Action != FirewallDeny || statements[3].Direction != firewallOutbound {
		t.Fatalf("default statements = %+v", statements[2:])
	}
}

func TestCompileFirewallPlanRejectsUnsafeSnapshots(t *testing.T) {
	local, first, second := firewallNode(1), firewallNode(2), firewallNode(3)
	base := func() FirewallPlan {
		return FirewallPlan{Epoch: 1, LocalNode: local, DefaultAction: FirewallDeny,
			PeerPrefixes: map[identity.NodeID][]netip.Prefix{
				first: {netip.MustParsePrefix("10.0.0.0/24")},
			}, Rules: []FirewallRule{{ID: firewallID(9), Action: FirewallAccept, Protocol: 6}}}
	}
	for name, mutate := range map[string]func(*FirewallPlan){
		"accept default": func(p *FirewallPlan) { p.DefaultAction = FirewallAccept },
		"unknown node":   func(p *FirewallPlan) { p.Rules[0].SourceNodes = []identity.NodeID{second} },
		"overlap":        func(p *FirewallPlan) { p.PeerPrefixes[second] = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")} },
		"invalid ports": func(p *FirewallPlan) {
			p.Rules[0].Protocol = 1
			p.Rules[0].DestinationPorts = []FirewallPortRange{{First: 80, Last: 80}}
		},
		"zero rule": func(p *FirewallPlan) { p.Rules[0].ID = identity.ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			plan := base()
			mutate(&plan)
			if _, _, err := compileFirewallPlan(plan); !errors.Is(err, ErrInvalidFirewall) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCompileFirewallPlanBoundsExpansionAndSkipsWrongLocalSide(t *testing.T) {
	local, first := firewallNode(1), firewallNode(2)
	plan := FirewallPlan{Epoch: 1, LocalNode: local, DefaultAction: FirewallDeny, MaxExpandedRules: 1,
		PeerPrefixes: map[identity.NodeID][]netip.Prefix{first: {netip.MustParsePrefix("10.0.0.2/32")}},
		Rules: []FirewallRule{{ID: firewallID(1), Action: FirewallAccept, SourceNodes: []identity.NodeID{local},
			DestinationNodes: []identity.NodeID{first}, Protocol: 6}}}
	_, statements, err := compileFirewallPlan(plan)
	if err != nil || len(statements) != 1 || statements[0].Direction != firewallOutbound {
		t.Fatalf("statements=%+v error=%v", statements, err)
	}
	plan.Rules[0].SourceNodes = nil
	plan.Rules[0].DestinationNodes = nil
	if _, _, err := compileFirewallPlan(plan); !errors.Is(err, ErrInvalidFirewall) {
		t.Fatalf("unbounded expansion error=%v", err)
	}
}

func TestCompileFirewallPlanDropsMixedFamilyCartesianProducts(t *testing.T) {
	local, peer := firewallNode(1), firewallNode(2)
	_, statements, err := compileFirewallPlan(FirewallPlan{Epoch: 1, LocalNode: local, DefaultAction: FirewallDeny,
		PeerPrefixes: map[identity.NodeID][]netip.Prefix{peer: {netip.MustParsePrefix("10.0.0.2/32")}},
		Rules: []FirewallRule{{ID: firewallID(1), Action: FirewallAccept, SourceNodes: []identity.NodeID{peer},
			DestinationNodes: []identity.NodeID{local}, SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, Protocol: 256}}})
	if err != nil || len(statements) != 0 {
		t.Fatalf("statements=%+v error=%v", statements, err)
	}
}
