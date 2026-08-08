//go:build linux

package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeCommandRunner struct {
	calls  [][]string
	failAt int
}

func (r *fakeCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	if r.failAt != 0 && len(r.calls) == r.failAt {
		return []byte("injected command failure"), errors.New("injected")
	}
	return nil, nil
}

type fakeControlClient struct {
	configs []wgtypes.Config
	failAt  int
	closed  bool
}

func (c *fakeControlClient) ConfigureDevice(_ string, config wgtypes.Config) error {
	c.configs = append(c.configs, config)
	if c.failAt != 0 && len(c.configs) == c.failAt {
		return errors.New("injected control failure")
	}
	return nil
}

func (c *fakeControlClient) Close() error { c.closed = true; return nil }

func validLinuxDeviceConfig(t *testing.T) DeviceConfig {
	t.Helper()
	privateKey, _ := deviceKey(t)
	_, peerKey := deviceKey(t)
	return DeviceConfig{
		Name: "lane0", MTU: 1280, PrivateKey: privateKey, ListenPort: 51820,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("2001:db8::1/128")},
		Peers:     []Peer{{PublicKey: peerKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}}},
	}
}

func TestOpenLinuxDeviceOwnsCreationConfigurationAndCleanup(t *testing.T) {
	runner, control := new(fakeCommandRunner), new(fakeControlClient)
	config := validLinuxDeviceConfig(t)
	device, err := openLinuxDevice(context.Background(), config, runner, control)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := [][]string{
		{"ip", "link", "add", "dev", "lane0", "type", "wireguard"},
		{"ip", "link", "set", "dev", "lane0", "mtu", "1280", "up"},
		{"ip", "-4", "address", "add", "100.96.0.1/32", "dev", "lane0"},
		{"ip", "-6", "address", "add", "2001:db8::1/128", "dev", "lane0"},
	}
	if !reflect.DeepEqual(runner.calls, wantPrefix) {
		t.Fatalf("platform calls = %#v, want %#v", runner.calls, wantPrefix)
	}
	if len(control.configs) != 1 || control.configs[0].PrivateKey == nil || !control.configs[0].ReplacePeers || len(control.configs[0].Peers) != 1 {
		t.Fatalf("initial kernel config = %+v", control.configs)
	}
	if device.ListenPort() != config.ListenPort || control.configs[0].ListenPort == nil || *control.configs[0].ListenPort != int(config.ListenPort) {
		t.Fatalf("listen port device=%d kernel=%v", device.ListenPort(), control.configs[0].ListenPort)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if !control.closed || len(runner.calls) != 5 || strings.Join(runner.calls[4], " ") != "ip link delete dev lane0" {
		t.Fatalf("cleanup control_closed=%v calls=%v", control.closed, runner.calls)
	}
	if err := device.Close(); err != nil || len(runner.calls) != 5 {
		t.Fatalf("idempotent close error=%v calls=%v", err, runner.calls)
	}
}

func TestOpenLinuxDeviceSelectsBoundedEphemeralPort(t *testing.T) {
	runner, control := new(fakeCommandRunner), new(fakeControlClient)
	config := validLinuxDeviceConfig(t)
	config.ListenPort = 0
	device, err := openLinuxDevice(context.Background(), config, runner, control)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if device.ListenPort() < MinEphemeralPort || device.ListenPort() > MaxEphemeralPort ||
		control.configs[0].ListenPort == nil || *control.configs[0].ListenPort != int(device.ListenPort()) {
		t.Fatalf("ephemeral listen port device=%d kernel=%v", device.ListenPort(), control.configs[0].ListenPort)
	}
}

func TestOpenLinuxDeviceRollsBackOnlyOwnedInterface(t *testing.T) {
	for _, failAt := range []int{2, 3, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			runner, control := &fakeCommandRunner{failAt: failAt}, new(fakeControlClient)
			if device, err := openLinuxDevice(context.Background(), validLinuxDeviceConfig(t), runner, control); device != nil || err == nil {
				t.Fatalf("device=%v error=%v", device, err)
			}
			last := strings.Join(runner.calls[len(runner.calls)-1], " ")
			if last != "ip link delete dev lane0" {
				t.Fatalf("last call = %q, want owned interface cleanup", last)
			}
		})
	}
	runner, control := &fakeCommandRunner{failAt: 1}, new(fakeControlClient)
	if _, err := openLinuxDevice(context.Background(), validLinuxDeviceConfig(t), runner, control); err == nil {
		t.Fatal("pre-existing interface collision accepted")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("creation failure attempted destructive cleanup: %v", runner.calls)
	}
}

func TestApplyPeersRestoresPriorKernelSnapshot(t *testing.T) {
	runner, control := new(fakeCommandRunner), new(fakeControlClient)
	deviceRaw, err := openLinuxDevice(context.Background(), validLinuxDeviceConfig(t), runner, control)
	if err != nil {
		t.Fatal(err)
	}
	device := deviceRaw.(*linuxDevice)
	previous := device.Peers()
	_, replacementKey := deviceKey(t)
	replacement := []Peer{{PublicKey: replacementKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.3/32")}}}
	control.failAt = 2
	if err := device.ApplyPeers(context.Background(), replacement); err == nil {
		t.Fatal("injected kernel rejection was ignored")
	}
	if got := device.Peers(); !reflect.DeepEqual(got, previous) {
		t.Fatalf("in-memory snapshot changed after rollback: got=%+v want=%+v", got, previous)
	}
	if len(control.configs) != 3 || len(control.configs[2].Peers) != 1 || control.configs[2].Peers[0].PublicKey != wgtypes.Key(previous[0].PublicKey) {
		t.Fatalf("prior kernel snapshot was not restored: %+v", control.configs)
	}
	control.failAt = 0
	if err := device.ApplyPeers(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if got := device.Peers(); !reflect.DeepEqual(got, replacement) {
		t.Fatalf("committed peer snapshot = %+v want %+v", got, replacement)
	}
	_ = device.Close()
}

func TestApplyPeersRejectsLocalKeyWithoutTouchingKernel(t *testing.T) {
	runner, control := new(fakeCommandRunner), new(fakeControlClient)
	config := validLinuxDeviceConfig(t)
	device, err := openLinuxDevice(context.Background(), config, runner, control)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	_, localPublicKey, err := ParsePrivateKey(config.PrivateKey[:])
	if err != nil {
		t.Fatal(err)
	}
	before := len(control.configs)
	if err := device.ApplyPeers(context.Background(), []Peer{{PublicKey: localPublicKey}}); !errors.Is(err, ErrInvalidPeer) {
		t.Fatalf("local peer error = %v", err)
	}
	if len(control.configs) != before {
		t.Fatal("local peer rejection touched kernel state")
	}
}

func TestPrivilegedKernelWireGuardLifecycle(t *testing.T) {
	if os.Getenv("LANEWAY_WIREGUARD_PRIVILEGED") != "1" {
		t.Skip("set LANEWAY_WIREGUARD_PRIVILEGED=1 in a disposable privileged host namespace")
	}
	config := validLinuxDeviceConfig(t)
	config.Name = "lane-wgtest0"
	device, err := OpenDevice(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = device.Close() }()
	client, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	kernelDevice, err := client.Device(config.Name)
	if err != nil {
		t.Fatal(err)
	}
	if kernelDevice.ListenPort != int(config.ListenPort) || len(kernelDevice.Peers) != 1 || kernelDevice.Peers[0].PublicKey != wgtypes.Key(config.Peers[0].PublicKey) {
		t.Fatalf("kernel device = %+v", kernelDevice)
	}
	_, replacementKey := deviceKey(t)
	if err := device.ApplyPeers(context.Background(), []Peer{{PublicKey: replacementKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.3/32")}}}); err != nil {
		t.Fatal(err)
	}
	kernelDevice, err = client.Device(config.Name)
	if err != nil || len(kernelDevice.Peers) != 1 || kernelDevice.Peers[0].PublicKey != wgtypes.Key(replacementKey) {
		t.Fatalf("reconciled kernel peers = %+v error=%v", kernelDevice, err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("ip", "link", "show", "dev", config.Name).CombinedOutput(); err == nil {
		t.Fatalf("owned interface survived close: %s", output)
	}
}
