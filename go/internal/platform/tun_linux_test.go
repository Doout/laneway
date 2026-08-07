//go:build linux

package platform

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeTUNFile struct {
	mu        sync.Mutex
	closed    bool
	readWait  chan struct{}
	readOnce  sync.Once
	started   chan struct{}
	startOnce sync.Once
}

func newFakeTUNFile() *fakeTUNFile {
	return &fakeTUNFile{readWait: make(chan struct{}), started: make(chan struct{})}
}
func (f *fakeTUNFile) Read([]byte) (int, error) {
	f.startOnce.Do(func() { close(f.started) })
	<-f.readWait
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, io.ErrClosedPipe
	}
	return 0, errors.New("deadline")
}
func (f *fakeTUNFile) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTUNFile) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.readOnce.Do(func() { close(f.readWait) })
	return nil
}
func (f *fakeTUNFile) Fd() uintptr { return 42 }
func (f *fakeTUNFile) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		f.readOnce.Do(func() { close(f.readWait) })
	}
	return nil
}
func (f *fakeTUNFile) SetWriteDeadline(time.Time) error { return nil }

type fakeTUNBackend struct {
	file          *fakeTUNFile
	attachName    string
	configured    string
	configuredMTU int
	attachFlags   uint16
	addresses     []netip.Prefix
	removed       []netip.Prefix
	attachErr     error
	configureErr  error
}

type observedRawTUNFile struct {
	*rawTUNFile
	started chan struct{}
	once    sync.Once
}

func (f *observedRawTUNFile) Read(buffer []byte) (int, error) {
	f.once.Do(func() { close(f.started) })
	return f.rawTUNFile.Read(buffer)
}

func (b *fakeTUNBackend) open() (tunFile, error) { return b.file, nil }
func (b *fakeTUNBackend) attach(fd uintptr, name string, flags uint16) (string, error) {
	if fd != 42 {
		return "", errors.New("unexpected fd")
	}
	b.attachName = name
	b.attachFlags = flags
	return name, b.attachErr
}
func (b *fakeTUNBackend) configure(_ context.Context, name string, mtu int, addresses []netip.Prefix) ([]netip.Prefix, error) {
	b.configured, b.configuredMTU = name, mtu
	b.addresses = append([]netip.Prefix(nil), addresses...)
	if b.configureErr != nil {
		return nil, b.configureErr
	}
	return append([]netip.Prefix(nil), addresses...), nil
}
func (b *fakeTUNBackend) removeAddresses(_ context.Context, _ string, addresses []netip.Prefix) error {
	b.removed = append(b.removed, addresses...)
	return nil
}

func TestOpenTUNUsesBackendAndContextRead(t *testing.T) {
	backend := &fakeTUNBackend{file: newFakeTUNFile()}
	address := netip.MustParsePrefix("100.96.0.1/32")
	device, err := openTUN(context.Background(), TUNConfig{Name: "lane0", MTU: 1400, Addresses: []netip.Prefix{address}}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if device.Name() != "lane0" || device.MTU() != 1400 || backend.attachName != "lane0" || backend.attachFlags != uint16(unix.IFF_TUN|unix.IFF_NO_PI) || backend.configured != "lane0" || backend.configuredMTU != 1400 {
		t.Fatalf("unexpected device/backend state: device=(%s,%d), backend=%+v", device.Name(), device.MTU(), backend)
	}
	gotAddresses := device.Addresses()
	if !slices.Equal(gotAddresses, []netip.Prefix{address}) || !slices.Equal(backend.addresses, []netip.Prefix{address}) {
		t.Fatalf("addresses = %v, backend addresses = %v", gotAddresses, backend.addresses)
	}
	gotAddresses[0] = netip.MustParsePrefix("100.96.0.9/32")
	if device.Addresses()[0] != address {
		t.Fatal("Addresses returned a mutable internal slice")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := device.Read(ctx, make([]byte, 16)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read error = %v", err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(backend.removed, []netip.Prefix{address}) {
		t.Fatalf("removed addresses = %v", backend.removed)
	}
}

func TestOpenTUNClosesFileOnSetupFailure(t *testing.T) {
	for _, backend := range []*fakeTUNBackend{
		{file: newFakeTUNFile(), attachErr: errors.New("attach failed")},
		{file: newFakeTUNFile(), configureErr: errors.New("configure failed")},
	} {
		if _, err := openTUN(context.Background(), TUNConfig{}, backend); err == nil {
			t.Fatal("openTUN unexpectedly succeeded")
		}
		backend.file.mu.Lock()
		closed := backend.file.closed
		backend.file.mu.Unlock()
		if !closed {
			t.Fatal("file was not closed after setup failure")
		}
	}
}

func TestLinuxTUNCloseUnblocksRead(t *testing.T) {
	backend := &fakeTUNBackend{file: newFakeTUNFile()}
	device, err := openTUN(context.Background(), TUNConfig{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := device.Read(context.Background(), make([]byte, 64))
		result <- err
	}()
	select {
	case <-backend.file.started:
	case <-time.After(time.Second):
		t.Fatal("Read did not start")
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Read error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

func TestLinuxTUNCloseUnblocksRawNonblockingRead(t *testing.T) {
	pipe := make([]int, 2)
	if err := unix.Pipe2(pipe, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[1]) })
	file := &observedRawTUNFile{rawTUNFile: &rawTUNFile{fd: pipe[0]}, started: make(chan struct{})}
	device := &linuxTUN{
		file: file, name: "lane0", mtu: 1280,
		backend: &fakeTUNBackend{}, done: make(chan struct{}),
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := device.Read(context.Background(), make([]byte, 1280))
		readResult <- err
	}()
	select {
	case <-file.started:
	case <-time.After(time.Second):
		t.Fatal("raw nonblocking read did not start")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- device.Close() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock raw nonblocking read")
	}
	if err := <-readResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Read error = %v, want ErrClosed", err)
	}
}

type addressCommandRunner struct {
	mu       sync.Mutex
	existing string
	calls    [][]string
	failOn   string
}

func (r *addressCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string{name}, args...))
	joined := strings.Join(args, " ")
	if r.failOn != "" && strings.Contains(joined, r.failOn) {
		return []byte("injected address failure"), errors.New("exit status 2")
	}
	if strings.Contains(joined, "address show") {
		return []byte(r.existing), nil
	}
	return nil, nil
}

func TestLinuxAddressConfigurationTracksOnlyNewAddresses(t *testing.T) {
	existing := netip.MustParsePrefix("100.96.0.1/32")
	added := netip.MustParsePrefix("100.96.0.2/32")
	runner := &addressCommandRunner{existing: "7: lane0    inet 100.96.0.1/32 scope global lane0\n"}
	backend := linuxTUNBackend{ip: "ip-test", runner: runner}
	owned, err := backend.applyAddresses(context.Background(), "lane0", []netip.Prefix{existing, added})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(owned, []netip.Prefix{added}) {
		t.Fatalf("owned = %v", owned)
	}
	if err := backend.removeAddresses(context.Background(), "lane0", owned); err != nil {
		t.Fatal(err)
	}
	joined := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		joined = append(joined, strings.Join(call, " "))
	}
	all := strings.Join(joined, "\n")
	if strings.Contains(all, "address replace 100.96.0.1/32") || strings.Contains(all, "address del 100.96.0.1/32") {
		t.Fatalf("existing address was mutated:\n%s", all)
	}
	if !strings.Contains(all, "ip-test -4 address replace 100.96.0.2/32 dev lane0") || !strings.Contains(all, "ip-test -4 address del 100.96.0.2/32 dev lane0") {
		t.Fatalf("new address was not applied and removed:\n%s", all)
	}
}

func TestLinuxAddressConfigurationRollsBackPartialFailure(t *testing.T) {
	first := netip.MustParsePrefix("100.96.0.1/32")
	second := netip.MustParsePrefix("100.96.0.2/32")
	runner := &addressCommandRunner{failOn: "address replace 100.96.0.2/32"}
	backend := linuxTUNBackend{ip: "ip", runner: runner}
	if _, err := backend.applyAddresses(context.Background(), "lane0", []netip.Prefix{first, second}); err == nil || !strings.Contains(err.Error(), "injected address failure") {
		t.Fatalf("applyAddresses error = %v", err)
	}
	var deletedFirst bool
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call, " "), "address del 100.96.0.1/32 dev lane0") {
			deletedFirst = true
		}
	}
	if !deletedFirst {
		t.Fatalf("first address was not rolled back: %v", runner.calls)
	}
}

func TestLinuxAddressConfigurationUsesBothFamilies(t *testing.T) {
	runner := &addressCommandRunner{}
	backend := linuxTUNBackend{ip: "ip-test", runner: runner}
	addresses := []netip.Prefix{
		netip.MustParsePrefix("100.96.0.1/32"),
		netip.MustParsePrefix("2001:db8::1/128"),
	}
	owned, err := backend.applyAddresses(context.Background(), "lane0", addresses)
	if err != nil || !slices.Equal(owned, addresses) {
		t.Fatalf("owned = %v, %v", owned, err)
	}
	if err := backend.removeAddresses(context.Background(), "lane0", owned); err != nil {
		t.Fatal(err)
	}
	var commands string
	for _, call := range runner.calls {
		commands += strings.Join(call, " ") + "\n"
	}
	for _, want := range []string{
		"ip-test -4 address replace 100.96.0.1/32 dev lane0",
		"ip-test -6 address replace 2001:db8::1/128 dev lane0",
		"ip-test -6 address del 2001:db8::1/128 dev lane0",
	} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %q in:\n%s", want, commands)
		}
	}
}
