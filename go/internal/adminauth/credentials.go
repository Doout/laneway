package adminauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/Doout/laneway/go/internal/identity"
	"golang.org/x/crypto/argon2"
)

const (
	MinPasswordBytes         = 15
	MaxPasswordBytes         = 1024
	secretBytes              = 32
	passwordSaltSize         = 16
	argonMemoryKiB           = 64 * 1024
	argonIterations          = 3
	argonParallelism         = 1
	argonKeyBytes            = 32
	ServiceAccessTokenPrefix = "lnw_spat_v1"
)

type SecretPurpose string

const (
	SecretSession            SecretPurpose = "session"
	SecretCSRF               SecretPurpose = "csrf"
	SecretRecovery           SecretPurpose = "recovery"
	SecretServiceAccessToken SecretPurpose = "service_access_token"
)

func (p SecretPurpose) Valid() bool {
	return p == SecretSession || p == SecretCSRF || p == SecretRecovery ||
		p == SecretServiceAccessToken
}

// NewServiceAccessToken creates a self-identifying opaque bearer. The ID is
// public routing metadata; only a purpose-separated digest of the random
// secret is persisted.
func NewServiceAccessToken(tokenID identity.ID, random io.Reader) (string, [sha256.Size]byte, error) {
	if tokenID.IsZero() {
		return "", [sha256.Size]byte{}, errors.New("invalid service access token ID")
	}
	secret, _, err := NewSecret(SecretServiceAccessToken, random)
	if err != nil {
		return "", [sha256.Size]byte{}, err
	}
	bearer := ServiceAccessTokenPrefix + "." + tokenID.String() + "." + secret
	digest := digestServiceAccessToken(tokenID, secret)
	return bearer, digest, nil
}

func ParseServiceAccessToken(bearer string) (identity.ID, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 || parts[0] != ServiceAccessTokenPrefix {
		return identity.ID{}, zero, errors.New("invalid service access token")
	}
	tokenID, err := identity.ParseID(parts[1])
	if err != nil || tokenID.IsZero() {
		return identity.ID{}, zero, errors.New("invalid service access token")
	}
	if _, err := HashSecret(SecretServiceAccessToken, parts[2]); err != nil {
		return identity.ID{}, zero, errors.New("invalid service access token")
	}
	return tokenID, digestServiceAccessToken(tokenID, parts[2]), nil
}

func digestServiceAccessToken(tokenID identity.ID, secret string) [sha256.Size]byte {
	prefix := "laneway-service-access-token-v1\x00"
	material := make([]byte, 0, len(prefix)+len(tokenID)+len(secret))
	material = append(material, prefix...)
	material = append(material, tokenID[:]...)
	material = append(material, secret...)
	digest := sha256.Sum256(material)
	clear(material)
	return digest
}

func ValidatePassword(password []byte) error {
	if len(password) < MinPasswordBytes || len(password) > MaxPasswordBytes {
		return fmt.Errorf("administrator password must be %d..%d bytes", MinPasswordBytes, MaxPasswordBytes)
	}
	return nil
}

func HashPassword(password []byte, random io.Reader) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, passwordSaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	digest := argon2.IDKey(password, salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyBytes)
	defer clear(digest)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB,
		argonIterations, argonParallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

// ValidatePasswordHash validates the bounded PHC representation without
// performing memory-hard work.
func ValidatePasswordHash(encoded string) error {
	_, digest, err := parsePasswordHash(encoded)
	clear(digest)
	return err
}

func VerifyPassword(encoded string, password []byte) (bool, error) {
	if err := ValidatePassword(password); err != nil {
		return false, nil
	}
	salt, want, err := parsePasswordHash(encoded)
	if err != nil {
		return false, err
	}
	defer clear(want)
	got := argon2.IDKey(password, salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyBytes)
	defer clear(got)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func parsePasswordHash(encoded string) ([]byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", argonMemoryKiB, argonIterations, argonParallelism) {
		return nil, nil, errors.New("unsupported administrator password hash")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != passwordSaltSize {
		return nil, nil, errors.New("invalid administrator password salt")
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) != argonKeyBytes {
		return nil, nil, errors.New("invalid administrator password digest")
	}
	return salt, want, nil
}

func NewSecret(purpose SecretPurpose, random io.Reader) (string, [sha256.Size]byte, error) {
	if !purpose.Valid() {
		return "", [sha256.Size]byte{}, errors.New("invalid administrator secret purpose")
	}
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, secretBytes)
	defer clear(raw)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate administrator secret: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(raw)
	return plain, digestSecret(purpose, plain), nil
}

func HashSecret(purpose SecretPurpose, secret string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if !purpose.Valid() {
		return zero, errors.New("invalid administrator secret purpose")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	defer clear(raw)
	if err != nil || len(raw) != secretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return zero, errors.New("invalid administrator secret")
	}
	return digestSecret(purpose, secret), nil
}

func SecretMatches(purpose SecretPurpose, hash [sha256.Size]byte, secret string) bool {
	digest, err := HashSecret(purpose, secret)
	return err == nil && subtle.ConstantTimeCompare(hash[:], digest[:]) == 1
}

func digestSecret(purpose SecretPurpose, secret string) [sha256.Size]byte {
	prefix := "laneway-admin-" + string(purpose) + "-v1\x00"
	material := make([]byte, 0, len(prefix)+len(secret))
	material = append(material, prefix...)
	material = append(material, secret...)
	digest := sha256.Sum256(material)
	clear(material)
	return digest
}
