//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type tunFile interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Fd() uintptr
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type tunBackend interface {
	open() (tunFile, error)
	attach(uintptr, string, uint16) (string, error)
	configure(context.Context, string, int, []netip.Prefix) ([]netip.Prefix, error)
	removeAddresses(context.Context, string, []netip.Prefix) error
}

type linuxTUNBackend struct {
	ip     string
	runner CommandRunner
}

type rawTUNFile struct {
	fd       int
	close    sync.Once
	closeErr error
}

func (f *rawTUNFile) Read(buffer []byte) (int, error)  { return unix.Read(f.fd, buffer) }
func (f *rawTUNFile) Write(packet []byte) (int, error) { return unix.Write(f.fd, packet) }
func (f *rawTUNFile) Fd() uintptr                      { return uintptr(f.fd) }
func (*rawTUNFile) SetReadDeadline(time.Time) error    { return nil }
func (*rawTUNFile) SetWriteDeadline(time.Time) error   { return nil }
func (f *rawTUNFile) Close() error {
	f.close.Do(func() { f.closeErr = unix.Close(f.fd) })
	return f.closeErr
}

const tunDeviceFlags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)

func (linuxTUNBackend) open() (tunFile, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &rawTUNFile{fd: fd}, nil
}

func (linuxTUNBackend) attach(fd uintptr, name string, flags uint16) (string, error) {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return "", err
	}
	request.SetUint16(flags)
	if err := unix.IoctlIfreq(int(fd), unix.TUNSETIFF, request); err != nil {
		return "", err
	}
	return request.Name(), nil
}

func (b linuxTUNBackend) configure(ctx context.Context, name string, mtu int, addresses []netip.Prefix) ([]netip.Prefix, error) {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(socket) //nolint:errcheck

	request, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	request.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(socket, unix.SIOCSIFMTU, request); err != nil {
		return nil, err
	}
	request, err = unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, request); err != nil {
		return nil, err
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, request); err != nil {
		return nil, err
	}
	return b.applyAddresses(ctx, name, addresses)
}

func (b linuxTUNBackend) applyAddresses(ctx context.Context, name string, addresses []netip.Prefix) ([]netip.Prefix, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	existing := make(map[netip.Prefix]struct{})
	for _, family := range addressFamilies(addresses) {
		output, err := b.runner.Run(ctx, b.ip, family, "-o", "address", "show", "dev", name)
		if err != nil {
			return nil, commandError("inspect interface addresses", output, err)
		}
		for prefix := range parseAddresses(string(output)) {
			existing[prefix] = struct{}{}
		}
	}
	added := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		if _, ok := existing[address]; ok {
			continue
		}
		output, err := b.runner.Run(ctx, b.ip, addressFamily(address), "address", "replace", address.String(), "dev", name)
		if err != nil {
			applyErr := commandError("assign interface address "+address.String(), output, err)
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			cleanupErr := b.removeAddresses(cleanupCtx, name, added)
			cancel()
			if cleanupErr != nil {
				return nil, errors.Join(applyErr, fmt.Errorf("platform: roll back interface addresses: %w", cleanupErr))
			}
			return nil, applyErr
		}
		added = append(added, address)
	}
	return added, nil
}

func (b linuxTUNBackend) removeAddresses(ctx context.Context, name string, addresses []netip.Prefix) error {
	var result error
	for i := len(addresses) - 1; i >= 0; i-- {
		address := addresses[i]
		output, err := b.runner.Run(ctx, b.ip, addressFamily(address), "address", "del", address.String(), "dev", name)
		if err != nil {
			result = errors.Join(result, commandError("remove interface address "+address.String(), output, err))
		}
	}
	return result
}

func parseAddresses(output string) map[netip.Prefix]struct{} {
	addresses := make(map[netip.Prefix]struct{})
	fields := strings.Fields(output)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "inet" && fields[i] != "inet6" {
			continue
		}
		if prefix, err := netip.ParsePrefix(fields[i+1]); err == nil && !prefix.Addr().Is4In6() {
			addresses[prefix.Masked()] = struct{}{}
		}
	}
	return addresses
}

func addressFamily(prefix netip.Prefix) string {
	if prefix.Addr().Is4() {
		return "-4"
	}
	return "-6"
}

func addressFamilies(addresses []netip.Prefix) []string {
	var ipv4, ipv6 bool
	for _, address := range addresses {
		ipv4 = ipv4 || address.Addr().Is4()
		ipv6 = ipv6 || address.Addr().Is6()
	}
	families := make([]string, 0, 2)
	if ipv4 {
		families = append(families, "-4")
	}
	if ipv6 {
		families = append(families, "-6")
	}
	return families
}

func commandError(operation string, output []byte, err error) error {
	if detail := strings.TrimSpace(string(output)); detail != "" {
		return fmt.Errorf("platform: %s: %w: %s", operation, err, detail)
	}
	return fmt.Errorf("platform: %s: %w", operation, err)
}

type linuxTUN struct {
	file           tunFile
	name           string
	mtu            int
	addresses      []netip.Prefix
	ownedAddresses []netip.Prefix
	backend        tunBackend
	done           chan struct{}

	readMu   sync.Mutex
	writeMu  sync.Mutex
	close    sync.Once
	closeErr error
}

var _ TUNDevice = (*linuxTUN)(nil)

func OpenTUN(ctx context.Context, config TUNConfig) (TUNDevice, error) {
	if config.IPCommand == "" {
		config.IPCommand = "ip"
	}
	if config.Runner == nil {
		config.Runner = execCommandRunner{}
	}
	return openTUN(ctx, config, linuxTUNBackend{ip: config.IPCommand, runner: config.Runner})
}

func openTUN(ctx context.Context, config TUNConfig, backend tunBackend) (TUNDevice, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := normalizeTUNConfig(config)
	if err != nil {
		return nil, err
	}
	file, err := backend.open()
	if err != nil {
		return nil, fmt.Errorf("platform: open /dev/net/tun: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	name, err := backend.attach(file.Fd(), config.Name, tunDeviceFlags)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("platform: attach TUN %s with IFF_TUN|IFF_NO_PI: %w", config.Name, err)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return nil, err
	}
	ownedAddresses, err := backend.configure(ctx, name, config.MTU, config.Addresses)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("platform: configure TUN %s: %w", name, err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupErr := backend.removeAddresses(cleanupCtx, name, ownedAddresses)
		cancel()
		closeErr := file.Close()
		return nil, errors.Join(ctxErr, cleanupErr, closeErr)
	}
	return &linuxTUN{
		file: file, name: name, mtu: config.MTU,
		addresses:      append([]netip.Prefix(nil), config.Addresses...),
		ownedAddresses: append([]netip.Prefix(nil), ownedAddresses...), backend: backend,
		done: make(chan struct{}),
	}, nil
}

func (t *linuxTUN) Name() string { return t.name }
func (t *linuxTUN) MTU() int     { return t.mtu }
func (t *linuxTUN) Addresses() []netip.Prefix {
	return append([]netip.Prefix(nil), t.addresses...)
}

func (t *linuxTUN) Read(ctx context.Context, buffer []byte) (int, error) {
	if err := t.closedError(); err != nil {
		return 0, err
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	if err := t.closedError(); err != nil {
		return 0, err
	}
	n, err := contextIO(ctx, t.done, t.file.Fd(), unix.POLLIN, t.file.SetReadDeadline, func() (int, error) { return t.file.Read(buffer) })
	if closedErr := t.closedError(); closedErr != nil {
		return n, closedErr
	}
	return n, err
}

func (t *linuxTUN) Write(ctx context.Context, packet []byte) (int, error) {
	if err := t.closedError(); err != nil {
		return 0, err
	}
	if len(packet) > t.mtu {
		return 0, fmt.Errorf("%w: packet length %d exceeds MTU %d", ErrInvalidTUN, len(packet), t.mtu)
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := t.closedError(); err != nil {
		return 0, err
	}
	n, err := contextIO(ctx, t.done, t.file.Fd(), unix.POLLOUT, t.file.SetWriteDeadline, func() (int, error) { return t.file.Write(packet) })
	if closedErr := t.closedError(); closedErr != nil {
		return n, closedErr
	}
	return n, err
}

func contextIO(ctx context.Context, done <-chan struct{}, fd uintptr, events int16, setDeadline func(time.Time) error, operation func() (int, error)) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := setDeadline(deadline); err != nil {
			return 0, err
		}
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(fired)
	})
	var n int
	var err error
	for {
		n, err = operation()
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if waitErr := pollTUN(ctx, done, fd, events); waitErr != nil {
			err = waitErr
			break
		}
	}
	if !stop() {
		<-fired
	}
	_ = setDeadline(time.Time{})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func pollTUN(ctx context.Context, done <-chan struct{}, fd uintptr, events int16) error {
	poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-done:
			return ErrClosed
		default:
		}
		timeout := 100
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond); milliseconds < timeout {
				timeout = milliseconds
			}
		}
		ready, err := unix.Poll(poll, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready > 0 {
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return fmt.Errorf("platform: TUN poll revents %#x", poll[0].Revents)
			}
			if poll[0].Revents&events != 0 {
				return nil
			}
		}
	}
}

func (t *linuxTUN) Close() error {
	t.close.Do(func() {
		close(t.done)
		_ = t.file.SetReadDeadline(time.Now())
		_ = t.file.SetWriteDeadline(time.Now())
		t.readMu.Lock()
		t.writeMu.Lock()
		defer t.readMu.Unlock()
		defer t.writeMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addressErr := t.backend.removeAddresses(ctx, t.name, t.ownedAddresses)
		cancel()
		t.closeErr = errors.Join(addressErr, t.file.Close())
	})
	if errors.Is(t.closeErr, os.ErrClosed) {
		return nil
	}
	return t.closeErr
}

func (t *linuxTUN) closedError() error {
	select {
	case <-t.done:
		return ErrClosed
	default:
		return nil
	}
}
