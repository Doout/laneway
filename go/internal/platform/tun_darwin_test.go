//go:build darwin

package platform

import (
	"errors"
	"os"
	"strings"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type fakeDarwinWireGuardTUN struct {
	mtu      int
	mtuErr   error
	closed   bool
	closeErr error
}

func (*fakeDarwinWireGuardTUN) File() *os.File                         { return nil }
func (*fakeDarwinWireGuardTUN) Read([][]byte, []int, int) (int, error) { return 0, nil }
func (*fakeDarwinWireGuardTUN) Write([][]byte, int) (int, error)       { return 0, nil }
func (t *fakeDarwinWireGuardTUN) MTU() (int, error)                    { return t.mtu, t.mtuErr }
func (*fakeDarwinWireGuardTUN) Name() (string, error)                  { return "utun9", nil }
func (*fakeDarwinWireGuardTUN) Events() <-chan wgtun.Event             { return nil }
func (t *fakeDarwinWireGuardTUN) Close() error                         { t.closed = true; return t.closeErr }
func (*fakeDarwinWireGuardTUN) BatchSize() int                         { return 1 }

func TestAdoptDarwinTUNDeviceDoesNotResetMTU(t *testing.T) {
	device := &fakeDarwinWireGuardTUN{mtu: 1280}
	createdMTU := -1
	got, err := adoptDarwinTUNDevice(nil, 1280, func(_ *os.File, mtu int) (wgtun.Device, error) {
		createdMTU = mtu
		return device, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != device {
		t.Fatal("adopted a different TUN device")
	}
	if createdMTU != 0 {
		t.Fatalf("CreateTUNFromFile MTU = %d, want 0 to avoid an unprivileged MTU mutation", createdMTU)
	}
	if device.closed {
		t.Fatal("matching TUN device was closed")
	}
}

func TestAdoptDarwinTUNDeviceRejectsUnexpectedMTU(t *testing.T) {
	device := &fakeDarwinWireGuardTUN{mtu: 1500}
	_, err := adoptDarwinTUNDevice(nil, 1280, func(_ *os.File, _ int) (wgtun.Device, error) {
		return device, nil
	})
	if err == nil || !strings.Contains(err.Error(), "MTU is 1500, expected 1280") {
		t.Fatalf("adoptDarwinTUNDevice error = %v", err)
	}
	if !device.closed {
		t.Fatal("TUN device with unexpected MTU was not closed")
	}
}

func TestAdoptDarwinTUNDeviceClosesAfterMTUReadFailure(t *testing.T) {
	device := &fakeDarwinWireGuardTUN{mtuErr: errors.New("read failed")}
	_, err := adoptDarwinTUNDevice(nil, 1280, func(_ *os.File, _ int) (wgtun.Device, error) {
		return device, nil
	})
	if err == nil || !strings.Contains(err.Error(), "read transferred interface MTU") {
		t.Fatalf("adoptDarwinTUNDevice error = %v", err)
	}
	if !device.closed {
		t.Fatal("TUN device was not closed after an MTU read failure")
	}
}
