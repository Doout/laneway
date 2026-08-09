//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"
	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/bootstrap"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/pki"
	"laneway.dev/laneway/internal/wireguard"
)

const managedNodeManifestVersion = 1

var nodeSystemctl = func(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "systemctl", args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}

var (
	nodeSystemctlActive = func(ctx context.Context) error {
		return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "lanewayd.service").Run()
	}
	nodeSystemctlResetFailed = func(ctx context.Context) error {
		return exec.CommandContext(ctx, "systemctl", "reset-failed", "lanewayd.service").Run()
	}
	managedNodeActiveProbeInterval = 200 * time.Millisecond
)

type managedNodeManifest struct {
	Version   int    `json:"version"`
	Authority string `json:"authority"`
	NetworkID string `json:"network_id"`
	NodeID    string `json:"node_id"`
	Direct    bool   `json:"direct_enabled"`
}

type managedNodeRelay struct {
	serviceID identity.ID
	endpoint  string
}

func runNodeInstall(args []string) error {
	fs := flag.NewFlagSet("node install", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "protected file containing the durable node invite")
	name := fs.String("name", "", "requested node name (an invite-bound name takes precedence)")
	noDirect := fs.Bool("no-direct", false, "explicitly disable authenticated direct paths")
	noStart := fs.Bool("no-start", false, "install without enabling and starting lanewayd")
	installArgs := args
	authority := ""
	if len(installArgs) != 0 && !strings.HasPrefix(installArgs[0], "-") {
		authority, installArgs = installArgs[0], installArgs[1:]
	}
	if err := fs.Parse(installArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && authority != "") {
		return nodeInstallUsage()
	}
	if fs.NArg() == 1 {
		authority = fs.Arg(0)
	}
	if authority == "" || strings.TrimSpace(*name) != *name || len(*name) > 253 {
		return nodeInstallUsage()
	}
	if os.Geteuid() != 0 {
		return errors.New("node install must run as root (for example: sudo laneway node install ...)")
	}
	groupID, err := managedNodePreflight()
	if err != nil {
		return err
	}
	manifestPath := "/etc/laneway/node-install.json"
	if _, err := os.Lstat(manifestPath); err == nil {
		manifest, loadErr := loadManagedNodeManifest(manifestPath)
		if loadErr != nil {
			return loadErr
		}
		if manifest.Authority != authority || manifest.Direct != !*noDirect {
			return errors.New("existing managed node was installed with different authority or dataplane settings")
		}
		if err := validateManagedNodeFiles(groupID); err != nil {
			return err
		}
		if !*noStart {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			err = nodeSystemctl(ctx, "enable", "--now", "lanewayd.service")
			if err == nil {
				err = waitManagedNodeActive(ctx)
			}
			cancel()
			if err != nil {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
				cleanupErr := cleanupManagedNodeService(cleanupCtx)
				cleanupCancel()
				return fmt.Errorf("start existing managed node: %w", errors.Join(err, cleanupErr))
			}
		}
		fmt.Printf("managed node already installed network=%s node=%s direct=%t\n", manifest.NetworkID, manifest.NodeID, manifest.Direct)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect managed node manifest: %w", err)
	}
	for _, path := range managedNodeFiles() {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to replace unmanaged path %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	discoveryCtx, cancelDiscovery := context.WithTimeout(context.Background(), 20*time.Second)
	metadata, err := bootstrap.Fetch(discoveryCtx, authority)
	cancelDiscovery()
	if err != nil {
		return err
	}
	if _, err := metadata.ArtifactForCurrentPlatform(); err != nil {
		return err
	}
	code, err := connectEnrollmentCode(*tokenFile)
	if err != nil {
		return err
	}
	enrollCtx, cancelEnroll := context.WithTimeout(context.Background(), 30*time.Second)
	enrollment, err := enrollDurableNode(enrollCtx, metadata, code, *name)
	cancelEnroll()
	code = ""
	if err != nil {
		return err
	}

	workDir, err := os.MkdirTemp("", "laneway-node-install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	if err := os.Chmod(workDir, 0o700); err != nil {
		return err
	}
	caPath := filepath.Join(workDir, "ca.crt")
	certPath := filepath.Join(workDir, "node.crt")
	keyPath := filepath.Join(workDir, "node.key")
	for path, contents := range map[string][]byte{caPath: []byte(metadata.Trust.CAPEM), certPath: enrollment.certificatePEM, keyPath: enrollment.privateKeyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			return err
		}
	}
	expectedNetwork, _ := identity.ParseNetworkID(metadata.NetworkID)
	expectedController, _ := identity.ParseID(metadata.Controller.ServiceID)
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: metadata.Controller.EnrollmentEndpoint, QUICEndpoint: metadata.Controller.QUICEndpoint,
		CAFile: caPath, CertificateFile: certPath, PrivateKeyFile: keyPath, ServerName: metadata.Controller.ServerName,
		ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedController,
	})
	if err != nil {
		return err
	}
	configurationCtx, cancelConfiguration := context.WithTimeout(context.Background(), 20*time.Second)
	initial, _, err := client.Configuration(configurationCtx, 0)
	cancelConfiguration()
	if err != nil {
		return fmt.Errorf("fetch initial managed-node configuration: %w", err)
	}
	relay, err := managedNodeRelayFromConfiguration(initial)
	if err != nil {
		return err
	}
	managedName := connectLocalName(initial, enrollment.identity.NodeID)
	configBytes, err := renderManagedNodeConfig(metadata, managedName, relay, !*noDirect)
	if err != nil {
		return err
	}
	manifest := managedNodeManifest{Version: managedNodeManifestVersion, Authority: authority, NetworkID: enrollment.identity.NetworkID.String(), NodeID: enrollment.identity.NodeID.String(), Direct: !*noDirect}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	contents := map[string][]byte{
		"/etc/laneway/ca.crt":            []byte(metadata.Trust.CAPEM),
		"/etc/laneway/node.crt":          enrollment.certificatePEM,
		"/etc/laneway/node.key":          enrollment.privateKeyPEM,
		"/etc/laneway/wireguard.key":     enrollment.wireGuardPrivateKey.Bytes(),
		"/etc/laneway/laneway.toml":      configBytes,
		"/etc/laneway/node-install.json": manifestBytes,
	}
	if err := installManagedNodeFiles(contents, groupID); err != nil {
		return err
	}
	if !*noStart {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		err = nodeSystemctl(ctx, "enable", "--now", "lanewayd.service")
		if err == nil {
			err = waitManagedNodeActive(ctx)
		}
		cancel()
		if err != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
			stopErr := cleanupManagedNodeService(cleanupCtx)
			cleanupCancel()
			removeErr := removeManagedNodeFiles(false)
			return fmt.Errorf("start managed node (installed credentials were removed; issue a new invite before retrying): %w", errors.Join(err, stopErr, removeErr))
		}
	}
	fmt.Printf("managed node installed network=%s node=%s name=%s direct=%t\n", manifest.NetworkID, manifest.NodeID, managedName, manifest.Direct)
	return nil
}

func nodeInstallUsage() error {
	return errors.New("usage: laneway node install lane.example.com [--token-file PATH] [--name NAME] [--no-direct] [--no-start]")
}

func waitManagedNodeActive(ctx context.Context) error {
	// Type=simple enters active state before ExecStart has proved stable. Require
	// several consecutive observations so an immediate crash cannot be reported
	// as a successful install.
	for probe := 0; probe < 10; probe++ {
		if err := nodeSystemctlActive(ctx); err != nil {
			return fmt.Errorf("lanewayd did not remain active after start: %w", err)
		}
		if probe == 9 {
			return nil
		}
		timer := time.NewTimer(managedNodeActiveProbeInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	panic("unreachable")
}

func runNodeUninstall(args []string) error {
	fs := flag.NewFlagSet("node uninstall", flag.ContinueOnError)
	keepState := fs.Bool("keep-state", false, "preserve /var/lib/laneway after removing managed credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: laneway node uninstall [--keep-state]")
	}
	if os.Geteuid() != 0 {
		return errors.New("node uninstall requires root on Linux")
	}
	manifest, err := loadManagedNodeManifest("/etc/laneway/node-install.json")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	err = cleanupManagedNodeService(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("gracefully stop managed node: %w", err)
	}
	if err := removeManagedNodeFiles(!*keepState); err != nil {
		return err
	}
	fmt.Printf("managed node uninstalled network=%s node=%s\n", manifest.NetworkID, manifest.NodeID)
	return nil
}

func runManagedNodeRenew(args []string) error {
	fs := flag.NewFlagSet("node renew", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: laneway node renew")
	}
	if os.Geteuid() != 0 {
		return errors.New("node renew requires root on Linux")
	}
	groupID, err := managedNodePreflight()
	if err != nil {
		return err
	}
	manifest, err := loadManagedNodeManifest("/etc/laneway/node-install.json")
	if err != nil {
		return err
	}
	if err := validateManagedNodeFiles(groupID); err != nil {
		return err
	}
	cfg, err := config.Load("/etc/laneway/laneway.toml")
	if err != nil {
		return err
	}
	workDir, err := os.MkdirTemp("/etc/laneway", ".node-renew-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	if err := os.Chmod(workDir, 0o700); err != nil {
		return err
	}
	stagedCert, stagedKey, stagedWireGuardKey := filepath.Join(workDir, "node.crt"), filepath.Join(workDir, "node.key"), filepath.Join(workDir, "wireguard.key")
	if err := runRenew([]string{
		"--controller", cfg.Controller.Endpoint, "--controller-quic", cfg.Controller.QUICEndpoint,
		"--server-name", cfg.Controller.ServerName, "--controller-network-id", cfg.Controller.NetworkID,
		"--controller-service-id", cfg.Controller.ServiceID, "--ca", cfg.TLS.CAFile,
		"--cert", cfg.TLS.CertificateFile, "--key", cfg.TLS.PrivateKeyFile,
		"--out-cert", stagedCert, "--out-key", stagedKey, "--out-wireguard-key", stagedWireGuardKey,
	}); err != nil {
		return err
	}
	newCertificate, err := os.ReadFile(stagedCert)
	if err != nil {
		return err
	}
	newKey, err := os.ReadFile(stagedKey)
	if err != nil {
		return err
	}
	newWireGuardKey, err := os.ReadFile(stagedWireGuardKey)
	if err != nil {
		return err
	}
	oldCertificate, err := os.ReadFile(cfg.TLS.CertificateFile)
	if err != nil {
		return err
	}
	oldKey, err := os.ReadFile(cfg.TLS.PrivateKeyFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	stopErr := nodeSystemctl(ctx, "stop", "lanewayd.service")
	cancel()
	if stopErr != nil {
		return fmt.Errorf("stop managed node for credential rotation: %w", stopErr)
	}
	if err := replaceManagedCredentialTriple(cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, cfg.WireGuard.PrivateKeyFile, newCertificate, newKey, newWireGuardKey, groupID); err != nil {
		// The controller has already committed the new WireGuard binding. Keep or
		// reconcile that key even while restoring the independently usable old TLS
		// pair; restoring the old WireGuard key would strand this identity.
		wireGuardReconcileErr := replaceManagedNodeFile(cfg.WireGuard.PrivateKeyFile, newWireGuardKey, 0o640, groupID)
		rollbackErr := replaceManagedCredentialPair(cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, oldCertificate, oldKey, groupID)
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		var restartErr error
		if wireGuardReconcileErr == nil {
			restartErr = nodeSystemctl(ctx, "start", "lanewayd.service")
		}
		if restartErr == nil && wireGuardReconcileErr == nil {
			restartErr = waitManagedNodeActive(ctx)
		}
		cancel()
		return fmt.Errorf("promote renewed credential; restored previous TLS pair and retained controller-bound WireGuard key: %w", errors.Join(err, wireGuardReconcileErr, rollbackErr, restartErr))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
	startErr := nodeSystemctl(ctx, "start", "lanewayd.service")
	if startErr == nil {
		startErr = waitManagedNodeActive(ctx)
	}
	cancel()
	if startErr != nil {
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		stopNewErr := nodeSystemctl(ctx, "stop", "lanewayd.service")
		cancel()
		rollbackErr := replaceManagedCredentialPair(cfg.TLS.CertificateFile, cfg.TLS.PrivateKeyFile, oldCertificate, oldKey, groupID)
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		_ = nodeSystemctl(ctx, "reset-failed", "lanewayd.service")
		restartErr := nodeSystemctl(ctx, "start", "lanewayd.service")
		if restartErr == nil {
			restartErr = waitManagedNodeActive(ctx)
		}
		cancel()
		return fmt.Errorf("renewed credential failed to start; restored previous TLS credential and retained controller-bound WireGuard key: %w", errors.Join(startErr, stopNewErr, rollbackErr, restartErr))
	}
	fmt.Printf("managed node renewed network=%s node=%s\n", manifest.NetworkID, manifest.NodeID)
	return nil
}

func replaceManagedCredentialPair(certPath, keyPath string, certificate, key []byte, groupID int) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) || len(certificate) == 0 || len(key) == 0 {
		return errors.New("managed credential replacement is incomplete")
	}
	if err := replaceManagedNodeFile(keyPath, key, 0o640, groupID); err != nil {
		return err
	}
	return replaceManagedNodeFile(certPath, certificate, 0o640, groupID)
}

func replaceManagedCredentialTriple(certPath, keyPath, wireGuardKeyPath string, certificate, key, wireGuardKey []byte, groupID int) error {
	if filepath.Clean(wireGuardKeyPath) == filepath.Clean(certPath) || filepath.Clean(wireGuardKeyPath) == filepath.Clean(keyPath) || len(wireGuardKey) != wireguard.KeySize {
		return errors.New("managed credential replacement has an invalid WireGuard key or overlapping path")
	}
	if err := replaceManagedNodeFile(wireGuardKeyPath, wireGuardKey, 0o640, groupID); err != nil {
		return err
	}
	return replaceManagedCredentialPair(certPath, keyPath, certificate, key, groupID)
}

func replaceManagedNodeFile(path string, contents []byte, mode os.FileMode, gid int) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".node-replace-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(0, gid); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func cleanupManagedNodeService(ctx context.Context) error {
	// reset-failed is hygiene, not a prerequisite for removing the boot-time
	// enablement link. Run it while the unit is still loaded, but do not let a
	// non-failed state block cleanup.
	_ = nodeSystemctlResetFailed(ctx)
	stopErr := nodeSystemctl(ctx, "stop", "lanewayd.service")
	disableErr := nodeSystemctl(ctx, "disable", "lanewayd.service")
	return errors.Join(stopErr, disableErr)
}

func managedNodePreflight() (int, error) {
	for _, path := range []string{"/usr/local/bin/laneway", "/usr/local/lib/systemd/system/lanewayd.service"} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return 0, fmt.Errorf("managed node requires a root-owned, non-writable package file at %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return 0, fmt.Errorf("managed node package file is not root-owned: %s", path)
		}
	}
	account, err := user.Lookup("laneway")
	if err != nil {
		return 0, errors.New("laneway service account is missing; install the release package first")
	}
	group, err := user.LookupGroup("laneway")
	if err != nil || account.Gid != group.Gid || account.HomeDir != "/var/lib/laneway" {
		return 0, errors.New("laneway service account does not match the hardened package account")
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil || uid >= 1000 || gid >= 1000 {
		return 0, errors.New("laneway service account must use system UID and GID values")
	}
	groupIDs, err := account.GroupIds()
	if err != nil || len(groupIDs) != 1 || groupIDs[0] != group.Gid {
		return 0, errors.New("laneway service account has unexpected supplementary groups")
	}
	lookupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	passwdRecord, passwdErr := exec.CommandContext(lookupCtx, "/usr/bin/getent", "passwd", "laneway").Output()
	groupRecord, groupErr := exec.CommandContext(lookupCtx, "/usr/bin/getent", "group", "laneway").Output()
	cancel()
	passwdFields := strings.Split(strings.TrimSpace(string(passwdRecord)), ":")
	groupFields := strings.Split(strings.TrimSpace(string(groupRecord)), ":")
	if passwdErr != nil || groupErr != nil || len(passwdFields) != 7 || len(groupFields) != 4 ||
		(!strings.HasSuffix(passwdFields[6], "/nologin") && !strings.HasSuffix(passwdFields[6], "/false")) ||
		(groupFields[3] != "" && groupFields[3] != "laneway") {
		return 0, errors.New("laneway service account is not locked or has unexpected group members")
	}
	return gid, nil
}

func enrollDurableNode(ctx context.Context, metadata bootstrap.Metadata, code, requestedName string) (connectEnrollment, error) {
	expectedNetwork, err := identity.ParseNetworkID(metadata.NetworkID)
	if err != nil {
		return connectEnrollment{}, err
	}
	expectedService, err := identity.ParseID(metadata.Controller.ServiceID)
	if err != nil {
		return connectEnrollment{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return connectEnrollment{}, err
	}
	wireGuardPrivateKey, wireGuardPublicKey, err := wireguard.GenerateKey()
	if err != nil {
		return connectEnrollment{}, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "laneway-persistent-node"}}, private)
	if err != nil {
		return connectEnrollment{}, err
	}
	client, err := controllerclient.New(controllerclient.Options{Endpoint: metadata.Controller.EnrollmentEndpoint, CAPEM: []byte(metadata.Trust.CAPEM), ServerName: metadata.Controller.ServerName, ExpectedNetworkID: expectedNetwork, ExpectedServiceID: expectedService})
	if err != nil {
		return connectEnrollment{}, err
	}
	response, err := client.EnrollForNetworkAndClass(ctx, code, requestedName, csrDER, wireGuardPublicKey.Bytes(), expectedNetwork, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE)
	if err != nil {
		return connectEnrollment{}, err
	}
	if len(response.GetNetworkId()) != identity.IDSize || len(response.GetNodeId()) != identity.IDSize || response.GetCertificateChain() == nil || len(response.GetCertificateChain().GetCertificatesDer()) == 0 || len(response.GetOverlayAddresses()) == 0 || response.GetEnrollmentClass() != lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE || response.GetLeaseExpiresAtUnixSeconds() != 0 {
		return connectEnrollment{}, errors.New("controller returned an incomplete or non-durable enrollment response")
	}
	leaf, err := x509.ParseCertificate(response.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		return connectEnrollment{}, err
	}
	authenticated, err := identity.IdentityFromCertificate(leaf)
	if err != nil || authenticated.NetworkID != expectedNetwork || !bytes.Equal(authenticated.NetworkID[:], response.GetNetworkId()) || !bytes.Equal(authenticated.NodeID[:], response.GetNodeId()) {
		return connectEnrollment{}, errors.New("issued certificate identity does not match authenticated bootstrap and enrollment response")
	}
	if !wireGuardPublicKey.Equal(response.GetWireguardPublicKey()) {
		return connectEnrollment{}, errors.New("controller returned a different WireGuard public key than the locally generated key")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(public)
	gotPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(wantPublic, gotPublic) {
		return connectEnrollment{}, errors.New("issued certificate does not contain the locally generated public key")
	}
	overlays := make([]netip.Prefix, 0, len(response.GetOverlayAddresses()))
	for _, raw := range response.GetOverlayAddresses() {
		address, ok := netip.AddrFromSlice(raw)
		if !ok || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() {
			return connectEnrollment{}, errors.New("controller returned an invalid overlay address")
		}
		overlays = append(overlays, netip.PrefixFrom(address, address.BitLen()))
	}
	var certificatePEM []byte
	for _, der := range response.GetCertificateChain().GetCertificatesDer() {
		if _, err := x509.ParseCertificate(der); err != nil {
			return connectEnrollment{}, err
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := pki.PrivateKeyPEM(private)
	if err != nil {
		return connectEnrollment{}, err
	}
	return connectEnrollment{identity: authenticated, certificatePEM: certificatePEM, privateKeyPEM: privatePEM, overlays: overlays, class: response.GetEnrollmentClass(), wireGuardPrivateKey: wireGuardPrivateKey}, nil
}

func managedNodeRelayFromConfiguration(configuration *lanewayv1.NodeConfiguration) (managedNodeRelay, error) {
	if configuration == nil || len(configuration.GetRelays()) == 0 {
		return managedNodeRelay{}, errors.New("controller authorized no relay for the managed node")
	}
	values := append([]*lanewayv1.RelayEndpoint(nil), configuration.GetRelays()...)
	sort.Slice(values, func(i, j int) bool {
		return hex.EncodeToString(values[i].GetServiceId())+values[i].GetEndpoint() < hex.EncodeToString(values[j].GetServiceId())+values[j].GetEndpoint()
	})
	selected := values[0]
	if len(selected.GetServiceId()) != identity.IDSize || selected.GetEndpoint() == "" {
		return managedNodeRelay{}, errors.New("controller returned an invalid relay record")
	}
	var serviceID identity.ID
	copy(serviceID[:], selected.GetServiceId())
	if serviceID.IsZero() {
		return managedNodeRelay{}, errors.New("controller returned a zero relay identity")
	}
	return managedNodeRelay{serviceID: serviceID, endpoint: selected.GetEndpoint()}, nil
}

func renderManagedNodeConfig(metadata bootstrap.Metadata, name string, relay managedNodeRelay, direct bool) ([]byte, error) {
	type tlsSection struct {
		Certificate string `toml:"certificate"`
		PrivateKey  string `toml:"private_key"`
		CA          string `toml:"ca"`
		ServerName  string `toml:"server_name"`
	}
	type nodeSection struct {
		Name           string `toml:"name"`
		RelayAddress   string `toml:"relay_address"`
		RelayNetworkID string `toml:"relay_network_id"`
		RelayServiceID string `toml:"relay_service_id"`
		ReconnectMin   string `toml:"reconnect_min"`
		ReconnectMax   string `toml:"reconnect_max"`
	}
	type controllerSection struct {
		Endpoint     string `toml:"endpoint"`
		QUICEndpoint string `toml:"quic_endpoint"`
		ServerName   string `toml:"server_name"`
		NetworkID    string `toml:"network_id"`
		ServiceID    string `toml:"service_id"`
		PollInterval string `toml:"poll_interval"`
	}
	type directSection struct {
		Enabled            bool   `toml:"enabled"`
		Listen             string `toml:"listen"`
		CandidateTTL       string `toml:"candidate_ttl"`
		ProbeInterval      string `toml:"probe_interval"`
		ProbeTimeout       string `toml:"probe_timeout"`
		RendezvousInterval string `toml:"rendezvous_interval"`
		MaxCandidates      int    `toml:"max_candidates"`
	}
	type exitSection struct {
		Enabled     bool   `toml:"enabled"`
		FailureMode string `toml:"failure_mode"`
	}
	type wireGuardSection struct {
		Enabled    bool   `toml:"enabled"`
		PrivateKey string `toml:"private_key"`
		Interface  string `toml:"interface"`
		ListenPort uint16 `toml:"listen_port"`
		MTU        int    `toml:"mtu"`
	}
	value := struct {
		Mode       string            `toml:"mode"`
		StateDir   string            `toml:"state_dir"`
		SocketPath string            `toml:"socket_path"`
		TLS        tlsSection        `toml:"tls"`
		Node       nodeSection       `toml:"node"`
		Controller controllerSection `toml:"controller"`
		Direct     directSection     `toml:"direct"`
		Exit       exitSection       `toml:"exit"`
		WireGuard  wireGuardSection  `toml:"wireguard"`
	}{
		Mode: "node", StateDir: "/var/lib/laneway", SocketPath: "/run/laneway/lanewayd.sock",
		TLS:        tlsSection{Certificate: "/etc/laneway/node.crt", PrivateKey: "/etc/laneway/node.key", CA: "/etc/laneway/ca.crt"},
		Node:       nodeSection{Name: name, RelayAddress: relay.endpoint, RelayNetworkID: metadata.NetworkID, RelayServiceID: relay.serviceID.String(), ReconnectMin: "1s", ReconnectMax: "30s"},
		Controller: controllerSection{Endpoint: metadata.Controller.EnrollmentEndpoint, QUICEndpoint: metadata.Controller.QUICEndpoint, ServerName: metadata.Controller.ServerName, NetworkID: metadata.NetworkID, ServiceID: metadata.Controller.ServiceID, PollInterval: "30s"},
		Direct:     directSection{Enabled: direct, Listen: "0.0.0.0:0", CandidateTTL: "2m", ProbeInterval: "200ms", ProbeTimeout: "3s", RendezvousInterval: "30s", MaxCandidates: 8},
		Exit:       exitSection{FailureMode: "closed"},
		WireGuard:  wireGuardSection{Enabled: false, PrivateKey: "/etc/laneway/wireguard.key", Interface: "lane0", MTU: 1280},
	}
	contents, err := toml.Marshal(value)
	if err != nil {
		return nil, err
	}
	if _, err := config.Decode(bytes.NewReader(contents)); err != nil {
		return nil, fmt.Errorf("validate generated managed-node configuration: %w", err)
	}
	return contents, nil
}

func managedNodeFiles() []string {
	return []string{"/etc/laneway/ca.crt", "/etc/laneway/node.crt", "/etc/laneway/node.key", "/etc/laneway/wireguard.key", "/etc/laneway/laneway.toml"}
}

func installManagedNodeFiles(contents map[string][]byte, groupID int) error {
	if err := os.MkdirAll("/etc/laneway", 0o750); err != nil {
		return err
	}
	info, err := os.Lstat("/etc/laneway")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("/etc/laneway is not a safe directory")
	}
	if err := os.Chmod("/etc/laneway", 0o750); err != nil {
		return err
	}
	if err := os.Chown("/etc/laneway", 0, groupID); err != nil {
		return err
	}
	written := make([]string, 0, len(contents))
	defer func() {
		if len(written) != len(contents) {
			for _, path := range written {
				_ = os.Remove(path)
			}
		}
	}()
	order := append(managedNodeFiles(), "/etc/laneway/node-install.json")
	for _, path := range order {
		data, ok := contents[path]
		if !ok {
			return fmt.Errorf("managed node contents omit %s", path)
		}
		mode := os.FileMode(0o640)
		gid := groupID
		if strings.HasSuffix(path, "node-install.json") {
			mode, gid = 0o600, 0
		}
		if err := writeManagedNodeFile(path, data, mode, gid); err != nil {
			return err
		}
		written = append(written, path)
	}
	return nil
}

func writeManagedNodeFile(path string, contents []byte, mode os.FileMode, gid int) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".node-install-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(0, gid); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("install %s without replacement: %w", path, err)
	}
	return nil
}

func loadManagedNodeManifest(path string) (managedNodeManifest, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return managedNodeManifest{}, errors.New("managed node manifest is missing or unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return managedNodeManifest{}, errors.New("managed node manifest is not root-owned")
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) > 4096 {
		return managedNodeManifest{}, errors.New("managed node manifest is unreadable or oversized")
	}
	var manifest managedNodeManifest
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != managedNodeManifestVersion {
		return managedNodeManifest{}, errors.New("managed node manifest is invalid")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return managedNodeManifest{}, errors.New("managed node manifest has trailing data")
	}
	if _, err := identity.ParseNetworkID(manifest.NetworkID); err != nil {
		return managedNodeManifest{}, errors.New("managed node manifest has invalid network identity")
	}
	if _, err := identity.ParseNodeID(manifest.NodeID); err != nil {
		return managedNodeManifest{}, errors.New("managed node manifest has invalid node identity")
	}
	return manifest, nil
}

func validateManagedNodeFiles(groupID int) error {
	for _, path := range managedNodeFiles() {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
			return fmt.Errorf("managed node path is missing or unsafe: %s", path)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || int(stat.Gid) != groupID {
			return fmt.Errorf("managed node path has unsafe ownership: %s", path)
		}
	}
	_, err := config.Load("/etc/laneway/laneway.toml")
	return err
}

func removeManagedNodeFiles(removeState bool) error {
	var result error
	for _, path := range append(managedNodeFiles(), "/etc/laneway/node-install.json") {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			result = errors.Join(result, fmt.Errorf("refuse to remove non-regular managed path %s", path))
			continue
		}
		result = errors.Join(result, os.Remove(path))
	}
	if removeState {
		if info, err := os.Lstat("/var/lib/laneway"); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			result = errors.Join(result, os.RemoveAll("/var/lib/laneway"))
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	return result
}
