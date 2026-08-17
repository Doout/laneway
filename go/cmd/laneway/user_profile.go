package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/wireguard"
)

const userProfileVersion = 1

type userProfile struct {
	Version             int       `json:"version"`
	Authority           string    `json:"authority"`
	NetworkID           string    `json:"network_id"`
	ControllerServiceID string    `json:"controller_service_id"`
	NodeID              string    `json:"node_id"`
	Name                string    `json:"name"`
	Generation          string    `json:"generation"`
	CreatedAt           time.Time `json:"created_at"`
}

type userProfileFiles struct {
	directory, ca, certificate, privateKey, wireGuardKey string
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	tokenFile := fs.String("token-file", "", "protected file containing the one-time login token")
	loginArgs := args
	authority := ""
	if len(loginArgs) != 0 && !strings.HasPrefix(loginArgs[0], "-") {
		authority, loginArgs = loginArgs[0], loginArgs[1:]
	}
	if err := fs.Parse(loginArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && authority != "") {
		return errors.New("usage: laneway login DOMAIN [--token-file PATH]")
	}
	if fs.NArg() == 1 {
		authority = fs.Arg(0)
	}
	if authority == "" {
		return errors.New("usage: laneway login DOMAIN [--token-file PATH]")
	}
	if _, _, err := loadUserProfile(authority); err == nil {
		return fmt.Errorf("already logged in to %s; use 'laneway logout %s' before replacing this identity", authority, authority)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	metadata, err := bootstrap.Fetch(ctx, authority)
	cancel()
	if err != nil {
		return err
	}
	if err := validatePlatformArtifact(metadata); err != nil {
		return err
	}
	code, err := connectEnrollmentCode(*tokenFile)
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	enrollment, err := enrollForConnect(ctx, metadata, code, lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER)
	cancel()
	code = ""
	if err != nil {
		return err
	}
	profile := userProfile{
		Version: userProfileVersion, Authority: authority, NetworkID: metadata.NetworkID,
		ControllerServiceID: metadata.Controller.ServiceID, NodeID: enrollment.identity.NodeID.String(),
		Name: "remembered-user", CreatedAt: time.Now().UTC(),
	}
	if err := saveUserProfile(profile, []byte(metadata.Trust.CAPEM), enrollment.certificatePEM, enrollment.privateKeyPEM, enrollment.wireGuardPrivateKey.Bytes()); err != nil {
		return err
	}
	fmt.Printf("logged in network=%s node=%s profile=%s\n", profile.NetworkID, profile.NodeID, profilePath(authority))
	fmt.Println("Connect with: laneway connect")
	return nil
}

func runLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: laneway logout DOMAIN")
	}
	directory := profilePath(fs.Arg(0))
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("open saved login: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("saved login path is not a safe directory")
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove saved login: %w", err)
	}
	fmt.Printf("logged out of %s; the controller identity remains revocable by its NodeID\n", fs.Arg(0))
	return nil
}

func userProfileRoot() string {
	if override := os.Getenv("LANEWAY_PROFILE_DIR"); override != "" {
		return override
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(".", ".laneway")
	}
	return filepath.Join(root, "laneway", "profiles")
}

func profilePath(authority string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(authority))))
	return filepath.Join(userProfileRoot(), hex.EncodeToString(digest[:16]))
}

func defaultUserProfileAuthority() (string, error) {
	root := userProfileRoot()
	if err := requireSafeDirectory(root); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var authorities []string
	for _, entry := range entries {
		name := entry.Name()
		if len(name) != 32 {
			continue
		}
		if _, err := hex.DecodeString(name); err != nil {
			continue
		}
		directory := filepath.Join(root, name)
		if err := requireSafeDirectory(directory); err != nil {
			return "", err
		}
		manifest, err := readProtectedProfileFile(filepath.Join(directory, "profile.json"), 64<<10)
		if err != nil {
			return "", err
		}
		var candidate struct {
			Authority string `json:"authority"`
		}
		if err := json.Unmarshal(manifest, &candidate); err != nil || candidate.Authority == "" || profilePath(candidate.Authority) != directory {
			return "", errors.New("saved login metadata is invalid or stored under the wrong authority")
		}
		if _, _, err := loadUserProfile(candidate.Authority); err != nil {
			return "", err
		}
		authorities = append(authorities, candidate.Authority)
	}
	sort.Strings(authorities)
	switch len(authorities) {
	case 0:
		return "", os.ErrNotExist
	case 1:
		return authorities[0], nil
	default:
		return "", fmt.Errorf("multiple saved logins (%s); specify DOMAIN", strings.Join(authorities, ", "))
	}
}

func saveUserProfile(profile userProfile, ca, certificate, privateKey, wireGuardKey []byte) error {
	if len(wireGuardKey) != wireguard.KeySize {
		return errors.New("saved login contains an invalid WireGuard private key")
	}
	root := userProfileRoot()
	if !filepath.IsAbs(root) {
		return errors.New("LANEWAY_PROFILE_DIR must be an absolute path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create profile root: %w", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("saved login root must be a real directory, not a symlink")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return err
	}
	directory := profilePath(profile.Authority)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create profile: %w", err)
	}
	if err := requireSafeDirectory(directory); err != nil {
		return err
	}
	generationDirectory, err := os.MkdirTemp(directory, "credentials-")
	if err != nil {
		return err
	}
	if err := os.Chmod(generationDirectory, 0o700); err != nil {
		return err
	}
	profile.Generation = filepath.Base(generationDirectory)
	for name, contents := range map[string][]byte{"ca.crt": ca, "node.crt": certificate, "node.key": privateKey, "wireguard.key": wireGuardKey} {
		if err := os.WriteFile(filepath.Join(generationDirectory, name), contents, 0o600); err != nil {
			return fmt.Errorf("write saved %s: %w", name, err)
		}
	}
	manifest, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	manifest = append(manifest, '\n')
	temporary, err := os.CreateTemp(directory, ".profile-*.json")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(manifest); err != nil {
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
	if err := os.Rename(temporaryName, filepath.Join(directory, "profile.json")); err != nil {
		return err
	}
	return nil
}

func loadUserProfile(authority string) (userProfile, userProfileFiles, error) {
	directory := profilePath(authority)
	if err := requireSafeDirectory(directory); err != nil {
		return userProfile{}, userProfileFiles{}, err
	}
	manifestPath := filepath.Join(directory, "profile.json")
	manifest, err := readProtectedProfileFile(manifestPath, 64<<10)
	if err != nil {
		return userProfile{}, userProfileFiles{}, err
	}
	var profile userProfile
	decoder := json.NewDecoder(bytes.NewReader(manifest))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return userProfile{}, userProfileFiles{}, fmt.Errorf("parse saved login: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return userProfile{}, userProfileFiles{}, errors.New("saved login metadata contains trailing data")
	}
	if profile.Version != userProfileVersion || !strings.EqualFold(profile.Authority, authority) || profile.Generation == "" || filepath.Base(profile.Generation) != profile.Generation || !strings.HasPrefix(profile.Generation, "credentials-") {
		return userProfile{}, userProfileFiles{}, errors.New("saved login metadata is invalid or belongs to another authority")
	}
	if _, err := identity.ParseNetworkID(profile.NetworkID); err != nil {
		return userProfile{}, userProfileFiles{}, errors.New("saved login has an invalid network identity")
	}
	if _, err := identity.ParseID(profile.ControllerServiceID); err != nil {
		return userProfile{}, userProfileFiles{}, errors.New("saved login has an invalid controller identity")
	}
	if _, err := identity.ParseNodeID(profile.NodeID); err != nil {
		return userProfile{}, userProfileFiles{}, errors.New("saved login has an invalid node identity")
	}
	generation := filepath.Join(directory, profile.Generation)
	if err := requireSafeDirectory(generation); err != nil {
		return userProfile{}, userProfileFiles{}, err
	}
	files := userProfileFiles{directory: directory, ca: filepath.Join(generation, "ca.crt"), certificate: filepath.Join(generation, "node.crt"), privateKey: filepath.Join(generation, "node.key"), wireGuardKey: filepath.Join(generation, "wireguard.key")}
	for _, path := range []string{files.ca, files.certificate, files.privateKey, files.wireGuardKey} {
		if _, err := readProtectedProfileFile(path, 256<<10); err != nil {
			return userProfile{}, userProfileFiles{}, err
		}
	}
	return profile, files, nil
}

func requireSafeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("saved login directory %s must be a private mode-0700 directory, not a symlink", path)
	}
	return nil
}

func readProtectedProfileFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("saved login file %s must be a private regular file", path)
	}
	return os.ReadFile(path)
}

func validateProfileMetadata(profile userProfile, files userProfileFiles, metadata bootstrap.Metadata) error {
	if profile.NetworkID != metadata.NetworkID || profile.ControllerServiceID != metadata.Controller.ServiceID {
		return errors.New("controller identity changed; refusing to use the saved login (log out and verify before logging in again)")
	}
	ca, err := readProtectedProfileFile(files.ca, 256<<10)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace([]byte(metadata.Trust.CAPEM))) {
		return errors.New("controller CA changed; refusing to use the saved login")
	}
	return nil
}

func profileRenewalDue(certificatePath string, now time.Time) (bool, time.Time, error) {
	contents, err := readProtectedProfileFile(certificatePath, 256<<10)
	if err != nil {
		return false, time.Time{}, err
	}
	leaf, err := firstCertificatePEM(contents)
	if err != nil {
		return false, time.Time{}, err
	}
	if !now.Before(leaf.NotAfter) {
		return false, time.Time{}, errors.New("saved login certificate expired; log in again with a new token")
	}
	renewAt := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
	return !now.Before(renewAt), renewAt, nil
}

func renewUserProfile(ctx context.Context, profile userProfile, files userProfileFiles, metadata bootstrap.Metadata) (userProfile, userProfileFiles, error) {
	currentPEM, err := readProtectedProfileFile(files.certificate, 256<<10)
	if err != nil {
		return profile, files, err
	}
	currentLeaf, err := firstCertificatePEM(currentPEM)
	if err != nil {
		return profile, files, err
	}
	currentIdentity, err := identity.IdentityFromCertificate(currentLeaf)
	if err != nil {
		return profile, files, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return profile, files, err
	}
	wgPrivate, wgPublic, err := wireguard.GenerateKey()
	if err != nil {
		return profile, files, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: currentLeaf.Subject}, private)
	if err != nil {
		return profile, files, err
	}
	networkID, _ := identity.ParseNetworkID(profile.NetworkID)
	controllerID, _ := identity.ParseID(profile.ControllerServiceID)
	client, err := controllerclient.New(controllerclient.Options{Endpoint: metadata.Controller.EnrollmentEndpoint, QUICEndpoint: metadata.Controller.QUICEndpoint, CAFile: files.ca, CertificateFile: files.certificate, PrivateKeyFile: files.privateKey, ServerName: metadata.Controller.ServerName, ExpectedNetworkID: networkID, ExpectedServiceID: controllerID})
	if err != nil {
		return profile, files, err
	}
	response, err := client.Renew(ctx, csr, wgPublic.Bytes())
	if err != nil {
		return profile, files, fmt.Errorf("refresh saved login: %w", err)
	}
	if response.GetCertificateChain() == nil || len(response.GetCertificateChain().GetCertificatesDer()) == 0 {
		return profile, files, errors.New("controller returned an incomplete login refresh")
	}
	issued, err := x509.ParseCertificate(response.GetCertificateChain().GetCertificatesDer()[0])
	if err != nil {
		return profile, files, err
	}
	issuedIdentity, err := identity.IdentityFromCertificate(issued)
	if err != nil || issuedIdentity != currentIdentity {
		return profile, files, errors.New("refreshed login changed the authenticated identity")
	}
	wantPublic, _ := x509.MarshalPKIXPublicKey(public)
	gotPublic, marshalErr := x509.MarshalPKIXPublicKey(issued.PublicKey)
	if marshalErr != nil || !bytes.Equal(wantPublic, gotPublic) || !wgPublic.Equal(response.GetWireguardPublicKey()) {
		return profile, files, errors.New("refreshed login does not contain the locally generated keys")
	}
	var certificatePEM []byte
	for _, der := range response.GetCertificateChain().GetCertificatesDer() {
		if _, err := x509.ParseCertificate(der); err != nil {
			return profile, files, err
		}
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	privatePEM, err := pki.PrivateKeyPEM(private)
	if err != nil {
		return profile, files, err
	}
	ca, err := readProtectedProfileFile(files.ca, 256<<10)
	if err != nil {
		return profile, files, err
	}
	if err := saveUserProfile(profile, ca, certificatePEM, privatePEM, wgPrivate.Bytes()); err != nil {
		return profile, files, err
	}
	updated, updatedFiles, err := loadUserProfile(profile.Authority)
	return updated, updatedFiles, err
}
