// Package bootstrap defines the public, non-secret discovery document used by
// a fresh Laneway client before it trusts a private network CA. The document
// is authenticated by the HTTPS origin's public Web PKI certificate; every
// private identity and transport endpoint is then pinned explicitly.
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/netvalidate"
	"github.com/Doout/laneway/go/internal/protocol"
)

const (
	SchemaVersion       = uint32(1)
	WellKnownPath       = "/.well-known/laneway/bootstrap.json"
	BundlePathPrefix    = "/.well-known/laneway/bootstrap/"
	BundleIDLength      = 43 // 32 bytes in unpadded base64url.
	MaxBundleBytes      = 96 << 10
	MaxBundleLifetime   = 10 * time.Minute
	MaxDocumentBytes    = 256 << 10
	MaxArtifactBytes    = int64(512 << 20)
	MaxDocumentLifetime = 10 * time.Minute
	MaxClockSkew        = 2 * time.Minute
)

// BundleIDFromPath recognizes the deliberately narrow public capability path.
// The separate decryption key is never part of this path or sent to the host.
func BundleIDFromPath(path string) (string, bool) {
	if !strings.HasPrefix(path, BundlePathPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, BundlePathPrefix)
	if len(id) != BundleIDLength {
		return "", false
	}
	for _, character := range id {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return "", false
		}
	}
	return id, true
}

type Metadata struct {
	SchemaVersion uint32     `json:"schema_version"`
	GeneratedAt   int64      `json:"generated_at_unix_seconds"`
	ValidUntil    int64      `json:"valid_until_unix_seconds"`
	NetworkID     string     `json:"network_id"`
	Controller    Controller `json:"controller"`
	Relays        []Relay    `json:"relays"`
	Trust         Trust      `json:"trust"`
	Protocol      Protocol   `json:"protocol"`
	Artifacts     []Artifact `json:"artifacts"`
}

type Controller struct {
	EnrollmentEndpoint string `json:"enrollment_endpoint"`
	QUICEndpoint       string `json:"quic_endpoint"`
	ServerName         string `json:"server_name"`
	ServiceID          string `json:"service_id"`
}

type Relay struct {
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	ServiceID string `json:"service_id"`
}

type Trust struct {
	CAPEM string `json:"ca_pem"`
}

type Protocol struct {
	ControlMajor uint32   `json:"control_major"`
	ControlMinor uint32   `json:"control_minor"`
	Packet       []uint32 `json:"packet_versions"`
	Capabilities uint64   `json:"capabilities"`
}

type Artifact struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

func (m Metadata) Validate(now time.Time) error {
	now = now.UTC()
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("bootstrap: unsupported schema version %d", m.SchemaVersion)
	}
	generated, validUntil := time.Unix(m.GeneratedAt, 0).UTC(), time.Unix(m.ValidUntil, 0).UTC()
	if generated.After(now.Add(MaxClockSkew)) || !validUntil.After(now) || !validUntil.After(generated) || validUntil.Sub(generated) > MaxDocumentLifetime {
		return errors.New("bootstrap: metadata validity window is invalid or expired")
	}
	networkID, err := identity.ParseNetworkID(m.NetworkID)
	if err != nil || networkID.IsZero() {
		return errors.New("bootstrap: invalid network identity")
	}
	if _, err := httpsOrigin(m.Controller.EnrollmentEndpoint); err != nil {
		return fmt.Errorf("bootstrap: controller enrollment endpoint: %w", err)
	}
	if _, err := netvalidate.CanonicalHostPort(m.Controller.QUICEndpoint); err != nil {
		return errors.New("bootstrap: invalid controller QUIC endpoint")
	}
	if err := validateDNSName(m.Controller.ServerName); err != nil {
		return fmt.Errorf("bootstrap: controller server name: %w", err)
	}
	if serviceID, err := identity.ParseID(m.Controller.ServiceID); err != nil || serviceID.IsZero() {
		return errors.New("bootstrap: invalid controller service identity")
	}
	if len(m.Relays) == 0 || len(m.Relays) > netvalidate.MaxRelayEndpoints {
		return fmt.Errorf("bootstrap: relay count must be from 1 through %d", netvalidate.MaxRelayEndpoints)
	}
	seenRelays := make(map[string]struct{}, len(m.Relays))
	for _, relay := range m.Relays {
		if relay.Name == "" || relay.Name != strings.TrimSpace(relay.Name) || len(relay.Name) > 253 {
			return errors.New("bootstrap: invalid relay name")
		}
		endpoint, err := netvalidate.CanonicalHostPort(relay.Endpoint)
		if err != nil || endpoint != relay.Endpoint {
			return errors.New("bootstrap: invalid or noncanonical relay endpoint")
		}
		serviceID, err := identity.ParseID(relay.ServiceID)
		if err != nil || serviceID.IsZero() {
			return errors.New("bootstrap: invalid relay service identity")
		}
		key := relay.ServiceID + "\x00" + relay.Endpoint
		if _, exists := seenRelays[key]; exists {
			return errors.New("bootstrap: duplicate relay identity and endpoint")
		}
		seenRelays[key] = struct{}{}
	}
	if err := validateTrust(m.Trust.CAPEM); err != nil {
		return err
	}
	if m.Protocol.ControlMajor != protocol.ProtocolMajor1 || m.Protocol.Packet == nil || !slices.Contains(m.Protocol.Packet, uint32(protocol.PacketVersion1)) || protocol.Capability(m.Protocol.Capabilities).Unknown() != 0 {
		return errors.New("bootstrap: unsupported or invalid protocol declaration")
	}
	if len(m.Artifacts) > 16 {
		return errors.New("bootstrap: artifact set is unbounded")
	}
	seenArtifacts := make(map[string]struct{}, len(m.Artifacts))
	for _, artifact := range m.Artifacts {
		if (artifact.OS != "linux" && artifact.OS != "darwin") || (artifact.Arch != "amd64" && artifact.Arch != "arm64") {
			return errors.New("bootstrap: unsupported artifact platform")
		}
		parsed, err := url.Parse(artifact.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return errors.New("bootstrap: artifact URL must be an HTTPS URL without credentials or fragment")
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != sha256.Size || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
			return errors.New("bootstrap: artifact SHA-256 is not canonical")
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > MaxArtifactBytes {
			return errors.New("bootstrap: artifact size is invalid")
		}
		key := artifact.OS + "/" + artifact.Arch
		if _, exists := seenArtifacts[key]; exists {
			return errors.New("bootstrap: duplicate artifact platform")
		}
		seenArtifacts[key] = struct{}{}
	}
	return nil
}

func validateTrust(contents string) error {
	if contents == "" || len(contents) > 128<<10 {
		return errors.New("bootstrap: CA bundle is empty or too large")
	}
	rest := []byte(contents)
	certificates := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("bootstrap: CA bundle contains invalid PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return errors.New("bootstrap: CA bundle contains a non-CA certificate")
		}
		certificates++
		if certificates > 8 {
			return errors.New("bootstrap: CA bundle has too many certificates")
		}
		rest = remaining
	}
	if certificates == 0 {
		return errors.New("bootstrap: CA bundle contains no certificate")
	}
	return nil
}

func httpsOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("must be an HTTPS origin")
	}
	return parsed, nil
}

func validateDNSName(value string) error {
	if value == "" || value != strings.ToLower(value) || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil || len(value) > 253 {
		return errors.New("must be a canonical ASCII DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("must be a canonical ASCII DNS name")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("must be a canonical ASCII DNS name")
			}
		}
	}
	return nil
}

func Decode(reader io.Reader, now time.Time) (Metadata, error) {
	limited := io.LimitReader(reader, MaxDocumentBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return Metadata{}, fmt.Errorf("bootstrap: read metadata: %w", err)
	}
	if len(contents) > MaxDocumentBytes {
		return Metadata{}, errors.New("bootstrap: metadata exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var metadata Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return Metadata{}, fmt.Errorf("bootstrap: decode metadata: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Metadata{}, errors.New("bootstrap: metadata contains trailing JSON")
	}
	if err := metadata.Validate(now); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (m Metadata) ArtifactForCurrentPlatform() (Artifact, error) {
	for _, artifact := range m.Artifacts {
		if artifact.OS == runtime.GOOS && artifact.Arch == runtime.GOARCH {
			return artifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("bootstrap: no verified artifact for %s/%s", runtime.GOOS, runtime.GOARCH)
}

func VerifyArtifact(reader io.Reader, artifact Artifact) error {
	if artifact.SizeBytes <= 0 || artifact.SizeBytes > MaxArtifactBytes {
		return errors.New("bootstrap: invalid expected artifact size")
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(reader, artifact.SizeBytes+1))
	if err != nil {
		return fmt.Errorf("bootstrap: read artifact: %w", err)
	}
	if read != artifact.SizeBytes {
		return fmt.Errorf("bootstrap: artifact size %d does not match authenticated size %d", read, artifact.SizeBytes)
	}
	want, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(want) != sha256.Size || !bytes.Equal(hash.Sum(nil), want) {
		return errors.New("bootstrap: artifact SHA-256 does not match authenticated metadata")
	}
	return nil
}
