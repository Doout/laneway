//go:build !linux

package wireguard

func LoadPrivateKeyFile(string) (PrivateKey, PublicKey, error) {
	return PrivateKey{}, PublicKey{}, ErrUnsupported
}
