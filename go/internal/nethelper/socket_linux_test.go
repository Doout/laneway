//go:build linux

package nethelper

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "_network-helper-client" {
		session, err := Start(context.Background(), Setup{
			Name: "lanecrash0", MTU: 1200, Addresses: []string{"100.64.99.2/32"},
			Routes: RoutePlan{Routes: []Route{{Prefix: "203.0.113.0/24"}}},
		}, StartOptions{Executable: os.Getenv("LANEWAY_TEST_HELPER"), Direct: true})
		if err != nil {
			os.Exit(72)
		}
		fmt.Printf("READY %d\n", session.helperPID)
		select {}
	}
}

func TestUnixStreamFramingPreservesMessageAndRights(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(fd int) *net.UnixConn {
		file := os.NewFile(uintptr(fd), "stream-helper-test")
		connection, err := net.FileConn(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		return connection.(*net.UnixConn)
	}
	client := &unixPacketConn{conn: wrap(fds[0]), stream: true}
	server := &unixPacketConn{conn: wrap(fds[1]), stream: true}
	defer client.Close()
	defer server.Close()
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := client.WritePacket([]byte("packet"), unix.UnixRights(int(file.Fd()))); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxMessageSize)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, err := server.ReadPacket(data, oob)
	if err != nil {
		t.Fatal(err)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != "packet" {
		t.Fatalf("invalid frame payload=%q flags=%d", data[:n], flags)
	}
	received, err := rightsFiles(oob[:oobn])
	if err != nil {
		t.Fatal(err)
	}
	for _, receivedFile := range received {
		defer receivedFile.Close()
	}
	if len(received) != 1 {
		t.Fatalf("received %d descriptors", len(received))
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
	if os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Getenv("LANEWAY_TEST_HELPER") == "" || os.Geteuid() != 0 {
		t.Skip("requires the Rust helper and an isolated privileged Linux network namespace")
	}
	session, err := Start(context.Background(), Setup{
		Name: "lanehelp0", MTU: 1200, Addresses: []string{"100.64.99.1/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: "198.51.100.0/24", Metric: 17}}},
	}, StartOptions{Executable: os.Getenv("LANEWAY_TEST_HELPER"), Direct: true})
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
	if os.Getenv("LANEWAY_PRIVILEGED_TEST") != "1" || os.Getenv("LANEWAY_TEST_HELPER") == "" || os.Geteuid() != 0 {
		t.Skip("requires the Rust helper and an isolated privileged Linux network namespace")
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
	if os.Getenv("LANEWAY_SUDO_TEST") != "1" || os.Getenv("LANEWAY_TEST_HELPER") == "" || os.Geteuid() == 0 {
		t.Skip("requires the Rust helper, a non-root user with passwordless sudo and LANEWAY_SUDO_TEST=1")
	}
	session, err := Start(context.Background(), Setup{
		Name: "lanesudo0", MTU: 1200, Addresses: []string{"100.64.99.3/32"},
		Routes: RoutePlan{Routes: []Route{{Prefix: "192.0.2.0/24"}}},
	}, StartOptions{Executable: os.Getenv("LANEWAY_TEST_HELPER")})
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
