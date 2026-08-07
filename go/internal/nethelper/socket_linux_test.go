//go:build linux

package nethelper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/platform"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "_network-helper" {
		err := ServeInheritedFD(context.Background(), 0, ProductionConfig())
		if err != nil {
			os.Exit(71)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "_network-helper-client" {
		session, err := Start(context.Background(), Setup{
			Name: "lanecrash0", MTU: 1200, Addresses: []string{"100.64.99.2/32"},
			Routes: RoutePlan{Routes: []Route{{Prefix: "203.0.113.0/24"}}},
		}, StartOptions{Executable: os.Args[0], Direct: true})
		if err != nil {
			os.Exit(72)
		}
		fmt.Printf("READY %d\n", session.helperPID)
		select {}
	}
}

type testTUN struct {
	mu     sync.Mutex
	closed bool
}

func (*testTUN) Name() string                               { return "lane-test" }
func (*testTUN) MTU() int                                   { return 1200 }
func (*testTUN) Addresses() []netip.Prefix                  { return nil }
func (*testTUN) Read(context.Context, []byte) (int, error)  { return 0, platform.ErrClosed }
func (*testTUN) Write(context.Context, []byte) (int, error) { return 0, platform.ErrClosed }
func (t *testTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

type testRoutes struct {
	mu      sync.Mutex
	applied []platform.RoutePlan
	closed  bool
}

func (r *testRoutes) Apply(_ context.Context, plan platform.RoutePlan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = append(r.applied, plan)
	return nil
}
func (*testRoutes) Restore(context.Context) error { return nil }
func (r *testRoutes) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(fd int) *net.UnixConn {
		file := os.NewFile(uintptr(fd), "helper-test")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		return connection.(*net.UnixConn)
	}
	return wrap(fds[0]), wrap(fds[1])
}

func testService(t *testing.T) (*net.UnixConn, *testTUN, *testRoutes, *exitnode.MemoryRouteManager, *exitnode.MemoryDNSManager, <-chan error) {
	t.Helper()
	clientConn, serviceConn := socketPair(t)
	tun := &testTUN{}
	routes := &testRoutes{}
	exitRoutes := exitnode.NewMemoryRouteManager()
	dns := exitnode.NewMemoryDNSManager()
	done := make(chan error, 1)
	go func() {
		done <- Serve(context.Background(), serviceConn, ServiceConfig{
			OpenTUN:       func(context.Context, platform.TUNConfig) (platform.TUNDevice, error) { return tun, nil },
			NewRoutes:     func(platform.RouteManagerConfig) (platform.RouteManager, error) { return routes, nil },
			NewExitRoutes: func(exitnode.RouteManagerConfig) (exitnode.RouteManager, error) { return exitRoutes, nil },
			NewDNS:        func(exitnode.DNSManagerConfig) (exitnode.DNSManager, error) { return dns, nil },
			Duplicate:     func(platform.TUNDevice) (*os.File, error) { return os.Open("/dev/null") },
			Harden:        func() error { return nil },
		})
	}()
	return clientConn, tun, routes, exitRoutes, dns, done
}

func TestServeAllowsOnlyStructuredOperationsAndCleans(t *testing.T) {
	clientConn, tun, routes, exitRoutes, dns, done := testService(t)
	defer clientConn.Close()
	client := &unixPacketConn{conn: clientConn}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 1, Op: "setup", Setup: &Setup{
		Name: "lane-test", MTU: 1200, Addresses: []string{"100.64.0.1/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: "10.0.0.0/8"}}},
	}})
	reply, files := readResponse(t, client)
	if !reply.OK || len(files) != 1 {
		t.Fatalf("setup reply=%+v files=%d", reply, len(files))
	}
	files[0].Close()

	writeRequest(t, client, request{Version: ProtocolVersion, ID: 2, Op: "exec"})
	if reply, _ := readResponse(t, client); reply.OK {
		t.Fatalf("arbitrary operation accepted: %+v", reply)
	}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 3, Op: "apply-routes", Routes: &RoutePlan{Routes: []Route{{Prefix: "192.0.2.0/24", Metric: 5}}}})
	if reply, _ := readResponse(t, client); !reply.OK {
		t.Fatalf("apply routes failed: %+v", reply)
	}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 4, Op: "apply-exit-routes", Exit: &ExitRoutePlan{
		TunnelPrefixes: []string{"0.0.0.0/1", "128.0.0.0/1"}, TransportBypass: []string{"192.0.2.1"},
	}})
	if reply, _ := readResponse(t, client); !reply.OK {
		t.Fatalf("apply exit routes failed: %+v", reply)
	}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 5, Op: "apply-dns", DNS: &DNSPlan{Servers: []string{"192.0.2.53"}}})
	if reply, _ := readResponse(t, client); !reply.OK {
		t.Fatalf("apply DNS failed: %+v", reply)
	}
	if _, active := exitRoutes.Snapshot(); !active {
		t.Fatal("exit route plan was not applied")
	}
	if _, active := dns.Snapshot(); !active {
		t.Fatal("DNS plan was not applied")
	}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 6, Op: "close"})
	if reply, _ := readResponse(t, client); !reply.OK {
		t.Fatalf("close failed: %+v", reply)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !tun.closed || !routes.closed || len(routes.applied) != 2 {
		t.Fatalf("cleanup state: tun=%v routes=%v applies=%d", tun.closed, routes.closed, len(routes.applied))
	}
}

func TestServeCleansWhenRequesterDies(t *testing.T) {
	clientConn, tun, routes, _, _, done := testService(t)
	client := &unixPacketConn{conn: clientConn}
	writeRequest(t, client, request{Version: ProtocolVersion, ID: 1, Op: "setup", Setup: &Setup{Name: "lane-test", MTU: 1200}})
	_, files := readResponse(t, client)
	files[0].Close()
	clientConn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !tun.closed || !routes.closed {
		t.Fatal("requester death did not restore helper-owned state")
	}
}

func TestRoutePlanRejectsMalformedOrDefaultRoutes(t *testing.T) {
	for _, plan := range []RoutePlan{
		{Routes: []Route{{Prefix: "0.0.0.0/0"}}},
		{Routes: []Route{{Prefix: "10.1.0.0/8"}}},
		{Bypasses: []string{"0.0.0.0"}},
	} {
		if _, err := parseRoutePlan(plan); err == nil {
			t.Fatalf("accepted invalid plan %+v", plan)
		}
	}
}

func TestPrivilegedHelperLifecycle(t *testing.T) {
	if os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("set LANEWAY_PRIVILEGED_TEST=1 inside an isolated privileged network namespace")
	}
	session, err := Start(context.Background(), Setup{
		Name: "lanehelp0", MTU: 1200, Addresses: []string{"100.64.99.1/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: "198.51.100.0/24", Metric: 17}}},
	}, StartOptions{Executable: os.Args[0], Direct: true})
	if err != nil {
		t.Fatal(err)
	}
	parentGroup, err := unix.Getpgid(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	helperGroup, err := unix.Getpgid(session.helperPID)
	if err != nil {
		t.Fatal(err)
	}
	if helperGroup == parentGroup {
		t.Fatal("network helper shares the foreground client process group")
	}
	status, err := os.ReadFile("/proc/" + strconv.Itoa(session.helperPID) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"CapEff:\t0000000000001000", "CapBnd:\t0000000000001000", "CapAmb:\t0000000000001000", "NoNewPrivs:\t1"} {
		if !strings.Contains(string(status), expected) {
			t.Fatalf("helper status lacks %q:\n%s", expected, status)
		}
	}
	if output, err := exec.Command("ip", "route", "show", "198.51.100.0/24").CombinedOutput(); err != nil || !strings.Contains(string(output), "lanehelp0") {
		t.Fatalf("route not installed: %v: %s", err, output)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "show", "lanehelp0").Run(); err == nil {
		t.Fatal("helper left TUN behind")
	}
	if output, _ := exec.Command("ip", "route", "show", "198.51.100.0/24").Output(); len(output) != 0 {
		t.Fatalf("helper left route behind: %s", output)
	}
}

func TestPrivilegedHelperRestoresAfterRequesterSIGKILL(t *testing.T) {
	if os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("set LANEWAY_PRIVILEGED_TEST=1 inside an isolated privileged network namespace")
	}
	command := exec.Command(os.Args[0], "_network-helper-client")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("client did not become ready: %v", scanner.Err())
	}
	var helperPID int
	if _, err := fmt.Sscanf(scanner.Text(), "READY %d", &helperPID); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("ip", "route", "show", "203.0.113.0/24").CombinedOutput(); err != nil || !strings.Contains(string(output), "lanecrash0") {
		t.Fatalf("route not installed before crash: %v: %s", err, output)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, procErr := os.Stat("/proc/" + strconv.Itoa(helperPID))
		route, _ := exec.Command("ip", "route", "show", "203.0.113.0/24").Output()
		linkErr := exec.Command("ip", "link", "show", "lanecrash0").Run()
		if os.IsNotExist(procErr) && len(route) == 0 && linkErr != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper did not restore after SIGKILL: proc=%v route=%s linkErr=%v", procErr, route, linkErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSudoHelperLifecycle(t *testing.T) {
	if os.Getenv("LANEWAY_SUDO_TEST") != "1" || os.Geteuid() == 0 {
		t.Skip("run as a non-root user with passwordless sudo and LANEWAY_SUDO_TEST=1")
	}
	session, err := Start(context.Background(), Setup{
		Name: "lanesudo0", MTU: 1200, Addresses: []string{"100.64.99.3/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: "192.0.2.0/24"}}},
	}, StartOptions{Executable: os.Args[0]})
	if err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile("/proc/" + strconv.Itoa(session.helperPID) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"CapEff:\t0000000000001000", "CapBnd:\t0000000000001000", "NoNewPrivs:\t1"} {
		if !strings.Contains(string(status), expected) {
			t.Fatalf("sudo helper status lacks %q:\n%s", expected, status)
		}
	}
	if output, err := exec.Command("ip", "route", "show", "192.0.2.0/24").CombinedOutput(); err != nil || !strings.Contains(string(output), "lanesudo0") {
		t.Fatalf("sudo helper route not installed: %v: %s", err, output)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "show", "lanesudo0").Run(); err == nil {
		t.Fatal("sudo helper left TUN behind")
	}
}

func writeRequest(t *testing.T, conn packetConn, req request) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WritePacket(data, nil); err != nil {
		t.Fatal(err)
	}
}

func readResponse(t *testing.T, conn packetConn) (response, []*os.File) {
	t.Helper()
	data := make([]byte, maxMessageSize)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, err := conn.ReadPacket(data, oob)
	if err != nil {
		t.Fatal(err)
	}
	var reply response
	if err := json.Unmarshal(data[:n], &reply); err != nil {
		t.Fatal(err)
	}
	files, err := rightsFiles(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	return reply, files
}
