//go:build darwin

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type darwinCommandRunner struct{}

func (darwinCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type darwinTUN struct {
	device    wgtun.Device
	name      string
	mtu       int
	addresses []netip.Prefix
	readMu    sync.Mutex
	writeMu   sync.Mutex
	close     sync.Once
	closeErr  error
}

var _ TUNDevice = (*darwinTUN)(nil)

func OpenTUN(ctx context.Context, config TUNConfig) (TUNDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if config.Name == DefaultTUNName {
		config.Name = "utun"
	}
	if config.Name == "" {
		config.Name = "utun"
	}
	normalized, err := normalizeTUNConfig(config)
	if err != nil {
		return nil, err
	}
	device, err := wgtun.CreateTUN(normalized.Name, normalized.MTU)
	if err != nil {
		return nil, fmt.Errorf("platform: create macOS utun: %w", err)
	}
	name, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("platform: read macOS utun name: %w", err)
	}
	runner := normalized.Runner
	if runner == nil {
		runner = darwinCommandRunner{}
	}
	ifconfig := normalized.IPCommand
	if ifconfig == "" {
		ifconfig = "/sbin/ifconfig"
	}
	for _, address := range normalized.Addresses {
		var args []string
		if address.Addr().Is4() {
			args = []string{name, "inet", address.Addr().String(), address.Addr().String(), "netmask", "255.255.255.255", "up"}
		} else {
			args = []string{name, "inet6", address.Addr().String(), "prefixlen", strconv.Itoa(address.Bits()), "up"}
		}
		if output, runErr := runner.Run(ctx, ifconfig, args...); runErr != nil {
			_ = device.Close()
			return nil, darwinCommandError("configure "+name, output, runErr)
		}
	}
	return &darwinTUN{device: device, name: name, mtu: normalized.MTU, addresses: append([]netip.Prefix(nil), normalized.Addresses...)}, nil
}

func DuplicateTUNFile(device TUNDevice) (*os.File, error) {
	tun, ok := device.(*darwinTUN)
	if !ok || tun.device.File() == nil {
		return nil, fmt.Errorf("platform: TUN device cannot be transferred")
	}
	fd, err := unix.FcntlInt(tun.device.File().Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("platform: duplicate macOS utun descriptor: %w", err)
	}
	return os.NewFile(uintptr(fd), tun.name), nil
}

func AdoptTUNFile(file *os.File, config TUNConfig) (TUNDevice, error) {
	if file == nil {
		return nil, fmt.Errorf("%w: missing transferred descriptor", ErrInvalidTUN)
	}
	normalized, err := normalizeTUNConfig(config)
	if err != nil {
		return nil, err
	}
	device, err := adoptDarwinTUNDevice(file, normalized.MTU, wgtun.CreateTUNFromFile)
	if err != nil {
		return nil, fmt.Errorf("platform: adopt macOS utun descriptor: %w", err)
	}
	name, err := device.Name()
	if err != nil || name != normalized.Name {
		_ = device.Close()
		if err == nil {
			err = fmt.Errorf("transferred interface is %s, expected %s", name, normalized.Name)
		}
		return nil, fmt.Errorf("platform: verify macOS utun descriptor: %w", err)
	}
	return &darwinTUN{device: device, name: name, mtu: normalized.MTU, addresses: append([]netip.Prefix(nil), normalized.Addresses...)}, nil
}

func adoptDarwinTUNDevice(file *os.File, expectedMTU int, create func(*os.File, int) (wgtun.Device, error)) (wgtun.Device, error) {
	// The privileged helper already configured the interface MTU. Passing it
	// again makes wireguard-go issue SIOCSIFMTU from the unprivileged client,
	// which macOS correctly rejects with EPERM.
	device, err := create(file, 0)
	if err != nil {
		return nil, err
	}
	actualMTU, err := device.MTU()
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("read transferred interface MTU: %w", err)
	}
	if actualMTU != expectedMTU {
		_ = device.Close()
		return nil, fmt.Errorf("transferred interface MTU is %d, expected %d", actualMTU, expectedMTU)
	}
	return device, nil
}

func (t *darwinTUN) Name() string { return t.name }
func (t *darwinTUN) MTU() int     { return t.mtu }
func (t *darwinTUN) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), t.addresses...)
}

func (t *darwinTUN) Read(ctx context.Context, buffer []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	packet := make([]byte, len(buffer)+4)
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.device.File().SetReadDeadline(deadline)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = t.device.File().SetReadDeadline(time.Now()); close(fired) })
	sizes := []int{0}
	n, err := t.device.Read([][]byte{packet}, sizes, 4)
	if !stop() {
		<-fired
	}
	_ = t.device.File().SetReadDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	if err != nil {
		return 0, err
	}
	if n != 1 || sizes[0] < 0 || sizes[0] > len(buffer) {
		return 0, fmt.Errorf("platform: invalid macOS utun read size")
	}
	copy(buffer, packet[4:4+sizes[0]])
	return sizes[0], nil
}

func (t *darwinTUN) Write(ctx context.Context, packet []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(packet) > t.mtu {
		return 0, fmt.Errorf("%w: packet length %d exceeds MTU %d", ErrInvalidTUN, len(packet), t.mtu)
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	framed := make([]byte, len(packet)+4)
	copy(framed[4:], packet)
	if deadline, ok := ctx.Deadline(); ok {
		_ = t.device.File().SetWriteDeadline(deadline)
	}
	written, err := t.device.Write([][]byte{framed}, 4)
	_ = t.device.File().SetWriteDeadline(time.Time{})
	if err != nil {
		return 0, err
	}
	if written != 1 {
		return 0, errors.New("platform: macOS utun packet was not written")
	}
	return len(packet), nil
}

func (t *darwinTUN) Close() error {
	t.close.Do(func() { t.closeErr = t.device.Close() })
	if errors.Is(t.closeErr, os.ErrClosed) {
		return nil
	}
	return t.closeErr
}
