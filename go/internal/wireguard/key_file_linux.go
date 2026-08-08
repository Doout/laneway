//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// LoadPrivateKeyFile opens a raw key without following symlinks and verifies
// the descriptor after open, closing the path-swap window. Managed 0640 files
// may be group-readable, but are never group-writable or accessible by others.
func LoadPrivateKeyFile(path string) (PrivateKey, PublicKey, error) {
	if path == "" {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("%w: empty private key path", ErrInvalidDevice)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("wireguard: open private key: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return PrivateKey{}, PublicKey{}, fmt.Errorf("wireguard: open private key descriptor")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("wireguard: stat private key: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() != KeySize || info.Mode().Perm()&0o027 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("%w: private key must be an owned regular %d-byte file with mode 0600 or 0640", ErrInvalidDevice, KeySize)
	}
	var raw [KeySize]byte
	defer clear(raw[:])
	if _, err := io.ReadFull(file, raw[:]); err != nil {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("wireguard: read private key: %w", err)
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return PrivateKey{}, PublicKey{}, fmt.Errorf("%w: private key changed while reading", ErrInvalidDevice)
	}
	return ParsePrivateKey(raw[:])
}
