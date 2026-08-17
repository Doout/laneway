//go:build linux || darwin

package nethelper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Doout/laneway/go/internal/exitnode"
	"github.com/Doout/laneway/go/internal/platform"
	"golang.org/x/sys/unix"
)

type unixPacketConn struct {
	conn   *net.UnixConn
	stream bool
}

const (
	unixMessageTruncated = unix.MSG_TRUNC
	unixControlTruncated = unix.MSG_CTRUNC
	operationTimeout     = 10 * time.Second
)

func (c *unixPacketConn) ReadPacket(data, oob []byte) (int, int, int, error) {
	if c.stream {
		var header [4]byte
		n, oobn, flags, _, err := c.conn.ReadMsgUnix(header[:], oob)
		if err != nil {
			return 0, oobn, flags, err
		}
		if n == 0 {
			return 0, oobn, flags, io.EOF
		}
		if n < len(header) {
			if _, err := io.ReadFull(c.conn, header[n:]); err != nil {
				return 0, oobn, flags, err
			}
		}
		length := int(binary.BigEndian.Uint32(header[:]))
		if length <= 0 || length > len(data) || length > maxMessageSize {
			return 0, oobn, flags, errors.New("network helper frame has invalid length")
		}
		if _, err := io.ReadFull(c.conn, data[:length]); err != nil {
			return 0, oobn, flags, err
		}
		return length, oobn, flags, nil
	}
	n, oobn, flags, _, err := c.conn.ReadMsgUnix(data, oob)
	return n, oobn, flags, err
}
func (c *unixPacketConn) WritePacket(data, oob []byte) error {
	if c.stream {
		if len(data) == 0 || len(data) > maxMessageSize {
			return errors.New("network helper frame has invalid length")
		}
		frame := make([]byte, 4+len(data))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
		copy(frame[4:], data)
		n, oobn, err := c.conn.WriteMsgUnix(frame, oob, nil)
		if err != nil {
			return err
		}
		if oobn != len(oob) {
			return io.ErrShortWrite
		}
		for n < len(frame) {
			written, err := c.conn.Write(frame[n:])
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
			n += written
		}
		return nil
	}
	_, _, err := c.conn.WriteMsgUnix(data, oob, nil)
	return err
}
func (c *unixPacketConn) Close() error                         { return c.conn.Close() }
func (c *unixPacketConn) SetDeadline(deadline time.Time) error { return c.conn.SetDeadline(deadline) }

type ServiceConfig struct {
	OpenTUN       func(context.Context, platform.TUNConfig) (platform.TUNDevice, error)
	NewRoutes     func(platform.RouteManagerConfig) (platform.RouteManager, error)
	NewExitRoutes func(exitnode.RouteManagerConfig) (exitnode.RouteManager, error)
	NewDNS        func(exitnode.DNSManagerConfig) (exitnode.DNSManager, error)
	Duplicate     func(platform.TUNDevice) (*os.File, error)
	Harden        func() error
}

func ProductionConfig() ServiceConfig {
	return ServiceConfig{
		OpenTUN: platform.OpenTUN, NewRoutes: platform.NewRouteManager,
		NewExitRoutes: exitnode.NewRouteManager, NewDNS: exitnode.NewDNSManager,
		Duplicate: platform.DuplicateTUNFile, Harden: hardenProcess,
	}
}

type StartOptions struct {
	// Executable defaults to the current Laneway executable. SudoPath defaults
	// to sudo for non-root callers. Tests may set Direct only when already
	// running in an isolated privileged namespace.
	Executable string
	SudoPath   string
	Direct     bool
}

// Start launches the helper with a full-duplex socket on stdin/stdout. Using a
// standard descriptor is deliberate: sudo preserves it without a permissive
// closefrom_override rule, while the helper still has no network listener or
// reusable filesystem endpoint.
func Start(ctx context.Context, setup Setup, options StartOptions) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	executable := options.Executable
	if executable == "" {
		var err error
		executable, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	executable, err := filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	if executable, err = filepath.EvalSymlinks(executable); err != nil {
		return nil, fmt.Errorf("resolve Laneway executable: %w", err)
	}
	if os.Geteuid() != 0 && !options.Direct {
		if err := validateRootOwnedExecutable(executable); err != nil {
			return nil, err
		}
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, helperSocketType(), 0)
	if err != nil {
		return nil, fmt.Errorf("create network helper channel: %w", err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parentFile := os.NewFile(uintptr(fds[0]), "laneway-network-client")
	childFile := os.NewFile(uintptr(fds[1]), "laneway-network-helper")
	defer parentFile.Close()
	defer childFile.Close()
	connection, err := net.FileConn(parentFile)
	if err != nil {
		return nil, err
	}
	parentFile.Close()
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, errors.New("network helper channel is not a Unix socket")
	}

	args := []string{"_network-helper", "--control-fd=0"}
	commandName := executable
	if os.Geteuid() != 0 && !options.Direct {
		commandName = options.SudoPath
		if commandName == "" {
			commandName, err = exec.LookPath("sudo")
			if err != nil {
				return nil, errors.New("sudo is required to start the network helper")
			}
		}
		if commandName, err = filepath.EvalSymlinks(commandName); err != nil {
			return nil, fmt.Errorf("resolve sudo executable: %w", err)
		}
		if err := validateRootOwnedExecutable(commandName); err != nil {
			return nil, fmt.Errorf("unsafe sudo executable: %w", err)
		}
		args = append([]string{"--", executable}, args...)
	}
	command := exec.Command(commandName, args...)
	// Keep sudo in the foreground process group while it authenticates. The
	// helper isolates itself after sudo has replaced it; detaching here causes
	// an interactive sudo to be stopped by SIGTTIN while reading /dev/tty.
	command.Stdin = childFile
	command.Stdout = childFile
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		unixConn.Close()
		return nil, fmt.Errorf("start network helper: %w", err)
	}
	childFile.Close()
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	fail := func(cause error) (*Session, error) {
		unixConn.Close()
		_ = command.Process.Kill()
		<-waitDone
		return nil, cause
	}

	client := &unixPacketConn{conn: unixConn, stream: helperSocketProtocol() == unix.SOCK_STREAM}
	deadline := time.Now().Add(roundTripTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := client.SetDeadline(deadline); err != nil {
		return fail(err)
	}
	defer client.SetDeadline(time.Time{})
	request := request{Version: ProtocolVersion, ID: 1, Op: "setup", Setup: &setup}
	payload, err := json.Marshal(request)
	if err != nil {
		return fail(err)
	}
	if err := client.WritePacket(payload, nil); err != nil {
		return fail(fmt.Errorf("network helper setup: %w", err))
	}
	data := make([]byte, maxMessageSize)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, err := client.ReadPacket(data, oob)
	if err != nil {
		return fail(fmt.Errorf("network helper setup: %w", err))
	}
	var reply response
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || decodeStrict(data[:n], &reply) != nil || reply.Version != ProtocolVersion || reply.ID != 1 {
		return fail(errors.New("invalid network helper setup response"))
	}
	if !reply.OK {
		return fail(fmt.Errorf("network helper: %s", reply.Error))
	}
	if reply.HelperPID <= 0 || reply.InterfaceName == "" {
		return fail(errors.New("network helper omitted its process or interface identity"))
	}
	files, err := rightsFiles(oob[:oobn])
	if err != nil {
		return fail(err)
	}
	if len(files) != 1 {
		for _, file := range files {
			file.Close()
		}
		return fail(errors.New("network helper must return exactly one TUN descriptor"))
	}
	tunConfig, _, err := parseSetup(setup)
	if err != nil {
		files[0].Close()
		return fail(err)
	}
	tunConfig.Name = reply.InterfaceName
	tun, err := platform.AdoptTUNFile(files[0], tunConfig)
	if err != nil {
		files[0].Close()
		return fail(err)
	}
	return &Session{conn: client, TUN: tun, next: 1, wait: waitDone, kill: command.Process.Kill, helperPID: reply.HelperPID}, nil
}

func validateRootOwnedExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect privileged executable %q: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("privileged executable %q must be a root-owned regular file not writable by group or other", path)
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Stat(directory)
		if err != nil {
			return fmt.Errorf("inspect privileged executable parent %q: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("privileged executable parent %q must be a root-owned directory not writable by group or other", directory)
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func rightsFiles(oob []byte) ([]*os.File, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse network helper descriptor: %w", err)
	}
	var files []*os.File
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		if err != nil {
			for _, file := range files {
				file.Close()
			}
			return nil, fmt.Errorf("parse network helper rights: %w", err)
		}
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "laneway-tun"))
		}
	}
	return files, nil
}

func ServeInheritedFD(ctx context.Context, fd int, config ServiceConfig) error {
	if fd < 0 {
		return errors.New("network helper control descriptor is invalid")
	}
	// The foreground client owns signal handling. Isolate only the authenticated
	// helper so terminal Ctrl-C cannot interrupt cleanup after setup succeeds.
	if err := isolateProcessGroup(); err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "laneway-network-helper")
	if file == nil {
		return errors.New("invalid network helper control descriptor")
	}
	defer file.Close()
	connection, err := net.FileConn(file)
	if err != nil {
		return fmt.Errorf("open network helper control channel: %w", err)
	}
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return errors.New("network helper requires a Unix socket")
	}
	defer unixConn.Close()
	return Serve(ctx, unixConn, config)
}

func isolateProcessGroup() error {
	if err := unix.Setpgid(0, 0); err != nil {
		group, groupErr := unix.Getpgid(0)
		if groupErr == nil && group == os.Getpid() {
			return nil
		}
		return fmt.Errorf("isolate network helper process group: %w", err)
	}
	return nil
}

func Serve(ctx context.Context, conn *net.UnixConn, config ServiceConfig) error {
	if config.OpenTUN == nil || config.NewRoutes == nil || config.NewExitRoutes == nil || config.NewDNS == nil || config.Duplicate == nil || config.Harden == nil {
		return errors.New("network helper service is incompletely configured")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketType int
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		socketType, inspectErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if inspectErr == nil {
			inspectErr = authenticateHelperPeer(int(fd))
		}
	}); err != nil {
		return err
	}
	if inspectErr != nil {
		return fmt.Errorf("inspect network helper peer: %w", inspectErr)
	}
	if socketType != helperSocketProtocol() {
		return errors.New("network helper requires an authenticated message-oriented Unix socket peer")
	}

	packet := &unixPacketConn{conn: conn, stream: socketType == unix.SOCK_STREAM}
	req, err := readRequest(packet)
	if err != nil {
		return err
	}
	if req.Op != "setup" || req.Setup == nil || req.Routes != nil || req.Exit != nil || req.DNS != nil {
		_ = writeResponse(packet, req.ID, errors.New("first operation must be setup"), nil)
		return errors.New("first operation must be setup")
	}
	tunConfig, initialPlan, err := parseSetup(*req.Setup)
	if err != nil {
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	setupCtx, cancelSetup := context.WithTimeout(ctx, operationTimeout)
	tun, err := config.OpenTUN(setupCtx, tunConfig)
	if err != nil {
		cancelSetup()
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	defer tun.Close()
	routes, err := config.NewRoutes(platform.RouteManagerConfig{InterfaceName: tun.Name()})
	if err != nil {
		cancelSetup()
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	defer routes.Close()
	exitRoutes, err := config.NewExitRoutes(exitnode.RouteManagerConfig{InterfaceName: tun.Name()})
	if err != nil {
		cancelSetup()
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	defer exitRoutes.Close()
	dns, err := config.NewDNS(exitnode.DNSManagerConfig{InterfaceName: tun.Name()})
	if err != nil {
		cancelSetup()
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	defer dns.Close()
	if err := routes.Apply(setupCtx, initialPlan); err != nil {
		cancelSetup()
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	cancelSetup()
	if err := config.Harden(); err != nil {
		_ = writeResponse(packet, req.ID, fmt.Errorf("reduce helper privileges: %w", err), nil)
		return err
	}
	transfer, err := config.Duplicate(tun)
	if err != nil {
		_ = writeResponse(packet, req.ID, err, nil)
		return err
	}
	if err := writeSetupResponse(packet, req.ID, transfer, os.Getpid(), tun.Name()); err != nil {
		transfer.Close()
		return err
	}
	transfer.Close()

	lastID := req.ID
	for {
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetReadDeadline(deadline)
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}
		req, err := readRequest(packet)
		if errors.Is(err, io.EOF) {
			return nil // requester death/close: deferred restoration is authoritative
		}
		if err != nil {
			return err
		}
		if req.ID <= lastID {
			if writeErr := writeResponse(packet, req.ID, errors.New("request IDs must increase monotonically"), nil); writeErr != nil {
				return writeErr
			}
			continue
		}
		lastID = req.ID
		switch req.Op {
		case "apply-routes":
			if req.Routes == nil || req.Setup != nil || req.Exit != nil || req.DNS != nil {
				err = errors.New("apply-routes requires exactly one route plan")
			} else if plan, parseErr := parseRoutePlan(*req.Routes); parseErr != nil {
				err = parseErr
			} else {
				applyCtx, cancelApply := context.WithTimeout(ctx, operationTimeout)
				err = routes.Apply(applyCtx, plan)
				cancelApply()
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		case "apply-exit-routes":
			if req.Exit == nil || req.Setup != nil || req.Routes != nil || req.DNS != nil {
				err = errors.New("apply-exit-routes requires exactly one exit route plan")
			} else if plan, parseErr := parseExitRoutePlan(*req.Exit); parseErr != nil {
				err = parseErr
			} else {
				applyCtx, cancelApply := context.WithTimeout(ctx, operationTimeout)
				err = exitRoutes.Apply(applyCtx, plan)
				cancelApply()
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		case "restore-exit-routes":
			if req.Setup != nil || req.Routes != nil || req.Exit != nil || req.DNS != nil {
				err = errors.New("restore-exit-routes does not accept fields")
			} else {
				restoreCtx, cancelRestore := context.WithTimeout(ctx, operationTimeout)
				err = exitRoutes.Restore(restoreCtx)
				cancelRestore()
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		case "apply-dns":
			if req.DNS == nil || req.Setup != nil || req.Routes != nil || req.Exit != nil {
				err = errors.New("apply-dns requires exactly one DNS plan")
			} else if servers, parseErr := parseDNSPlan(*req.DNS); parseErr != nil {
				err = parseErr
			} else {
				applyCtx, cancelApply := context.WithTimeout(ctx, operationTimeout)
				err = dns.Apply(applyCtx, servers)
				cancelApply()
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		case "restore-dns":
			if req.Setup != nil || req.Routes != nil || req.Exit != nil || req.DNS != nil {
				err = errors.New("restore-dns does not accept fields")
			} else {
				restoreCtx, cancelRestore := context.WithTimeout(ctx, operationTimeout)
				err = dns.Restore(restoreCtx)
				cancelRestore()
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		case "close":
			if req.Routes != nil || req.Setup != nil || req.Exit != nil || req.DNS != nil {
				err = errors.New("close does not accept fields")
			}
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
			return err
		default:
			err = fmt.Errorf("operation %q is not allowed", req.Op)
			if writeErr := writeResponse(packet, req.ID, err, nil); writeErr != nil {
				return writeErr
			}
		}
	}
}

func readRequest(conn packetConn) (request, error) {
	data := make([]byte, maxMessageSize)
	oob := make([]byte, 1)
	n, oobn, flags, err := conn.ReadPacket(data, oob)
	if err != nil {
		return request{}, err
	}
	if n == 0 {
		return request{}, io.EOF
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || oobn != 0 {
		return request{}, errors.New("invalid or truncated network helper request")
	}
	var req request
	if err := decodeStrict(data[:n], &req); err != nil {
		return request{}, err
	}
	if req.Version != ProtocolVersion || req.ID == 0 {
		return request{}, errors.New("unsupported network helper protocol or request ID")
	}
	return req, nil
}

func writeResponse(conn packetConn, id uint64, cause error, file *os.File, helperPID ...int) error {
	reply := response{Version: ProtocolVersion, ID: id, OK: cause == nil}
	if len(helperPID) == 1 {
		reply.HelperPID = helperPID[0]
	}
	return writeResponseValue(conn, reply, cause, file)
}

func writeSetupResponse(conn packetConn, id uint64, file *os.File, helperPID int, interfaceName string) error {
	reply := response{Version: ProtocolVersion, ID: id, OK: true, HelperPID: helperPID, InterfaceName: interfaceName}
	return writeResponseValue(conn, reply, nil, file)
}

func writeResponseValue(conn packetConn, reply response, cause error, file *os.File) error {
	if cause != nil {
		reply.Error = cause.Error()
	}
	data, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	var oob []byte
	if file != nil {
		oob = unix.UnixRights(int(file.Fd()))
	}
	return conn.WritePacket(data, oob)
}
