//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/wireguard"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

var ephemeralExitRuntimeName = regexp.MustCompile(`^laneway-ephemeral-exit-[a-f0-9]{16}$`)

type ephemeralExitPrepareResult struct {
	RuntimeName string `json:"runtime_name"`
	NodeID      string `json:"node_id"`
	NetworkID   string `json:"network_id"`
	Config      string `json:"config"`
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	ExpiresAt   int64  `json:"expires_at_unix_seconds"`
}

func runEphemeralExitPrepare(args []string) error {
	fs := flag.NewFlagSet("node ephemeral-exit-prepare", flag.ContinueOnError)
	authority := fs.String("authority", "", "controller public authority")
	runtimeDir := fs.String("runtime-dir", "", "verified RAM-backed bootstrap directory")
	runtimeName := fs.String("runtime-name", "", "random transient runtime name")
	name := fs.String("name", "", "invite-bound Exit name")
	tokenFD := fs.Int("token-fd", -1, "protected descriptor containing the one-use invitation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *authority == "" || *runtimeDir == "" || !ephemeralExitRuntimeName.MatchString(*runtimeName) ||
		*name == "" || strings.TrimSpace(*name) != *name || len(*name) > 253 || *tokenFD < 3 {
		return errors.New("invalid ephemeral Exit preparation invocation")
	}
	if os.Geteuid() != 0 {
		return errors.New("ephemeral Exit preparation requires root")
	}
	if err := validateEphemeralExitRuntimeDirectory(*runtimeDir); err != nil {
		return err
	}
	if err := hardenEphemeralExitPreparation(); err != nil {
		return err
	}
	defer unix.Munlockall()
	tokenFile := os.NewFile(uintptr(*tokenFD), "ephemeral-exit-invitation")
	if tokenFile == nil {
		return errors.New("invitation descriptor is unavailable")
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(tokenFile, 129))
	_ = tokenFile.Close()
	if err != nil || len(tokenBytes) == 0 || len(tokenBytes) > 128 {
		clear(tokenBytes)
		return errors.New("read bounded invitation from protected descriptor")
	}
	token := strings.TrimSpace(string(tokenBytes))
	clear(tokenBytes)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("invitation has an invalid shape")
	}
	discoveryCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	metadata, err := bootstrap.Fetch(discoveryCtx, *authority)
	cancel()
	if err != nil {
		return err
	}
	enrollCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	enrollment, err := enrollManagedNode(enrollCtx, metadata, token, *name, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER)
	cancel()
	token = ""
	if err != nil {
		return err
	}
	defer wireguard.ZeroPrivateKey(&enrollment.wireGuardPrivateKey)
	paths := map[string]string{
		"ca": filepath.Join(*runtimeDir, "ca.crt"), "certificate": filepath.Join(*runtimeDir, "node.crt"),
		"private_key": filepath.Join(*runtimeDir, "node.key"), "wireguard_key": filepath.Join(*runtimeDir, "wireguard.key"),
		"config": filepath.Join(*runtimeDir, "laneway.toml"),
	}
	wireGuardKey := enrollment.wireGuardPrivateKey.Bytes()
	defer clear(wireGuardKey)
	for label, contents := range map[string][]byte{"ca": []byte(metadata.Trust.CAPEM), "certificate": enrollment.certificatePEM,
		"private_key": enrollment.privateKeyPEM, "wireguard_key": wireGuardKey} {
		if err := writeEphemeralExitFile(paths[label], contents); err != nil {
			return err
		}
	}
	wireguard.ZeroPrivateKey(&enrollment.wireGuardPrivateKey)
	clear(enrollment.privateKeyPEM)
	expectedNetwork, _ := identity.ParseNetworkID(metadata.NetworkID)
	expectedController, _ := identity.ParseID(metadata.Controller.ServiceID)
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: metadata.Controller.EnrollmentEndpoint, QUICEndpoint: metadata.Controller.QUICEndpoint,
		CAFile: paths["ca"], CertificateFile: paths["certificate"], PrivateKeyFile: paths["private_key"],
		ServerName: metadata.Controller.ServerName, ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedController,
		EphemeralExitLeaseGeneration: enrollment.ephemeralExitLeaseGeneration,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	configurationCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	initial, _, err := client.Configuration(configurationCtx, 0)
	cancel()
	if err != nil {
		return fmt.Errorf("fetch initial ephemeral Exit configuration: %w", err)
	}
	if initial.GetEphemeralExitLeaseGeneration() != enrollment.ephemeralExitLeaseGeneration {
		return errors.New("controller changed the ephemeral Exit lease generation")
	}
	relay, err := managedNodeRelayFromConfiguration(initial)
	if err != nil {
		return err
	}
	managedName := connectLocalName(initial, enrollment.identity.NodeID)
	configBytes, err := renderEphemeralExitConfig(metadata, managedName, relay, *runtimeName, enrollment.ephemeralExitLeaseGeneration)
	if err != nil {
		return err
	}
	if err := writeEphemeralExitFile(paths["config"], configBytes); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(ephemeralExitPrepareResult{RuntimeName: *runtimeName, NodeID: enrollment.identity.NodeID.String(),
		NetworkID: enrollment.identity.NetworkID.String(), Config: paths["config"], CA: paths["ca"], Certificate: paths["certificate"],
		PrivateKey: paths["private_key"], ExpiresAt: enrollment.leaseExpiresAt.Unix()})
}

func hardenEphemeralExitPreparation() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable preparation process dumps: %w", err)
	}
	limit := &unix.Rlimit{}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, limit); err != nil {
		return fmt.Errorf("disable preparation core files: %w", err)
	}
	limit.Cur, limit.Max = unix.RLIM_INFINITY, unix.RLIM_INFINITY
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit); err != nil {
		return fmt.Errorf("raise preparation locked-memory limit: %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("lock preparation memory: %w", err)
	}
	return nil
}

func validateEphemeralExitRuntimeDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(path, "/run/") {
		return errors.New("ephemeral Exit runtime directory must be a clean child of /run")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("ephemeral Exit runtime directory is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 2 {
		return errors.New("ephemeral Exit runtime directory is not exclusively root-owned")
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil || uint64(filesystem.Type) != uint64(unix.TMPFS_MAGIC) {
		return errors.New("ephemeral Exit runtime directory is not RAM-backed tmpfs")
	}
	return nil
}

func writeEphemeralExitFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return err
	}
	if _, err = file.Write(contents); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(err, closeErr)
	}
	return nil
}

func renderEphemeralExitConfig(metadata bootstrap.Metadata, name string, relay managedNodeRelay, runtimeName string, generation uint64) ([]byte, error) {
	value := config.Defaults()
	value.Mode = config.ModeNode
	value.StateDir = "/run/" + runtimeName + "/state"
	value.SocketPath = "/run/" + runtimeName + "/lanewayd.sock"
	value.TLS.CertificateFile = "@credential/node.crt"
	value.TLS.PrivateKeyFile = "@credential/node.key"
	value.TLS.CAFile = "@credential/ca.crt"
	value.WireGuard.Enabled = true
	value.WireGuard.PrivateKeyFile = "@credential/wireguard.key"
	value.WireGuard.InterfaceName = "lane0"
	value.WireGuard.MTU = 1280
	value.Node.Name = name
	value.Node.RelayAddress = relay.endpoint
	value.Node.RelayNetworkID = metadata.NetworkID
	value.Node.RelayServiceID = relay.serviceID.String()
	value.Node.ReconnectMin = config.Duration(time.Second)
	value.Node.ReconnectMax = config.Duration(10 * time.Second)
	value.Controller.Endpoint = metadata.Controller.EnrollmentEndpoint
	value.Controller.QUICEndpoint = metadata.Controller.QUICEndpoint
	value.Controller.ServerName = metadata.Controller.ServerName
	value.Controller.NetworkID = metadata.NetworkID
	value.Controller.ServiceID = metadata.Controller.ServiceID
	value.Controller.PollInterval = config.Duration(10 * time.Second)
	value.Direct.Enabled = false
	value.Exit.Enabled = false
	value.Exit.Serve = true
	value.Exit.FailureMode = "closed"
	value.Exit.LeaseGeneration = generation
	value.Routing.OutputInterface = "uplink0"
	contents, err := toml.Marshal(value)
	if err != nil {
		return nil, err
	}
	if _, err := config.Decode(bytes.NewReader(contents)); err != nil {
		return nil, fmt.Errorf("validate ephemeral Exit configuration: %w", err)
	}
	return contents, nil
}
