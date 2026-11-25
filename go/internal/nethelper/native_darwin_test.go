package nethelper

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The release job runs this test on a disposable macOS runner. The ordinary
// unit suite uses socket pairs and never opens a system interface.
func TestDarwinNativeHelper(t *testing.T) {
	binary := os.Getenv("LANEWAY_TEST_HELPER")
	if binary == "" || os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires a Rust helper on a disposable privileged macOS runner")
	}
	const destination = "198.51.100.77"
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	session, err := Start(ctx, Setup{
		Name: "utun", MTU: 1280, Addresses: []string{"192.0.2.77/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: destination + "/32"}}},
	}, StartOptions{Executable: binary, Direct: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	name := session.TUN.Name()
	routeInterface := func() string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "-inet", destination).CombinedOutput()
		if err != nil {
			t.Fatalf("inspect host route: %v: %s", err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "interface:" {
				return fields[1]
			}
		}
		t.Fatalf("missing interface in host route: %s", out)
		return ""
	}
	if !strings.HasPrefix(name, "utun") || routeInterface() != name {
		t.Fatalf("missing host route through allocated interface %s", name)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(destination), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("Laneway utun descriptor transfer")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 1280)
	for {
		n, err := session.TUN.Read(ctx, packet)
		if err != nil {
			t.Fatal(err)
		}
		if n >= 28 && packet[0]>>4 == 4 && packet[9] == 17 && bytes.HasSuffix(packet[:n], payload) {
			break
		}
	}
	if err := session.ApplyRoutes(ctx, RoutePlan{}); err != nil {
		t.Fatal(err)
	}
	if routeInterface() == name {
		t.Fatal("withdrawing the route left it pointed at utun")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}
