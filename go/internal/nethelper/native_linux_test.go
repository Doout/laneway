package nethelper

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Exercise the production Rust executable with the installed Go client. A
// replacement route must survive a requester exit and a hard helper death.
func TestNativeHelperRouteRecovery(t *testing.T) {
	if os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Getenv("LANEWAY_TEST_HELPER") == "" || os.Geteuid() != 0 {
		t.Skip("requires the Rust helper and an isolated privileged Linux network namespace")
	}
	const prefix = "198.18.42.0/24"
	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), "ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	route := func() string { return ip("-4", "-o", "route", "show", "exact", prefix) }
	if got := route(); got != "" {
		t.Fatalf("fixture prefix already present: %s", got)
	}
	ip("route", "add", prefix, "dev", "lo", "proto", "static", "metric", "42")
	t.Cleanup(func() { _ = exec.Command("ip", "route", "del", prefix, "dev", "lo", "metric", "42").Run() })
	prior := route()
	plan := RoutePlan{Routes: []Route{{Prefix: prefix, Metric: 42}}}
	start := func(routes RoutePlan) *Session {
		t.Helper()
		s, err := Start(t.Context(), Setup{Name: "lanerecover0", MTU: 1280,
			Addresses: []string{"100.64.99.4/32"}, Routes: routes},
			StartOptions{Executable: helperExecutable(), Direct: true})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := start(plan)
	// Do not leave a handle to the initial TUN in the client on failure.
	t.Cleanup(func() { _ = s.TUN.Close(); _ = s.conn.Close() })
	if got := route(); !strings.Contains(got, "dev lanerecover0") {
		t.Fatalf("helper did not take ownership of the route: %s", got)
	}
	if err := s.ApplyRoutes(t.Context(), RoutePlan{}); err != nil || route() != prior {
		t.Fatalf("withdrawing the route did not restore the original: %v", err)
	}
	if err := s.ApplyRoutes(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	if err := s.kill(); err != nil {
		t.Fatal(err)
	}
	_ = s.TUN.Close()
	_ = s.conn.Close()
	select {
	case <-s.wait:
	case <-time.After(10 * time.Second):
		t.Fatal("killed helper did not exit")
	}
	restarted := start(RoutePlan{})
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if got := route(); got != prior {
		t.Fatalf("after recovery route = %q; want %q", got, prior)
	}
}
