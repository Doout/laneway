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
