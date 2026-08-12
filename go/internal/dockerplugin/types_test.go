package dockerplugin

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy(map[string]any{"com.docker.network.generic": map[string]any{OptionPolicy: "selective", OptionEgressCIDRs: "10.2.0.0/16,10.1.0.0/16", OptionIngress: "allow", OptionIngressSources: "192.0.2.0/24", OptionMTU: "1300"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Egress != EgressSelective || p.Ingress != IngressAllow || p.MTU != 1300 || p.EgressCIDRs[0].String() != "10.1.0.0/16" {
		t.Fatalf("unexpected policy: %+v", p)
	}
}

func TestFileAuthorizationSourceRequiresPrivateRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization.json")
	authorization := Authorization{Epoch: 1, ValidUntil: time.Now().Add(time.Hour)}
	data, _ := json.Marshal(authorization)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileAuthorizationSource{Path: path}).Current(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected private-file error, got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileAuthorizationSource{Path: path}).Current(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestParsePolicyRejectsUnsafeCombinations(t *testing.T) {
	cases := []map[string]any{{OptionPolicy: "selective"}, {OptionPolicy: "full-tunnel"}, {OptionPolicy: "direct", OptionEgressCIDRs: "10.0.0.0/8"}, {OptionIngress: "allow"}, {OptionFailMode: "open"}, {OptionEgressCIDRs: "10.0.0.0/8,10.1.0.0/16"}, {OptionEgressCIDRs: "2001:db8::/32", OptionPolicy: "selective"}}
	for _, options := range cases {
		if _, err := ParsePolicy(options); err == nil {
			t.Fatalf("accepted unsafe options: %#v", options)
		}
	}
}

func TestAuthorization(t *testing.T) {
	a := Authorization{ValidUntil: time.Now().Add(time.Hour), ContainerSubnets: []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}, EgressCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, IngressSources: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Exits: []string{"exit-a"}}
	p := Policy{Egress: EgressFullTunnel, Ingress: IngressAllow, IngressSources: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/25")}, Exit: "exit-a", FailMode: "closed", MTU: 1380}
	if err := a.Authorize(time.Now(), netip.MustParsePrefix("172.30.50.0/24"), p); err != nil {
		t.Fatal(err)
	}
	p.Exit = "other"
	if err := a.Authorize(time.Now(), netip.MustParsePrefix("172.30.50.0/24"), p); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}
