//go:build linux

package wireguard

import (
	"context"
	"os"
	"testing"
)

func TestPrivilegedFirewallCrashRecoveryAgainstNftables(t *testing.T) {
	if os.Getenv("LANEWAY_RUN_PRIVILEGED") != "1" {
		t.Skip("set LANEWAY_RUN_PRIVILEGED=1 inside an isolated network namespace")
	}
	config := FirewallConfig{Interface: "lanetest0", Table: "laneway_wg_test", NFTCommand: "nft"}
	first, err := NewFirewallManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	// Deliberately abandon the first manager without Close to model process
	// death. A fresh process must validate every chain and rule before reclaim.
	second, err := NewFirewallManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Apply(context.Background(), testFirewallPlan()); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
