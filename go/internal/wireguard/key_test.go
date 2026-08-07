package wireguard

import "testing"

func TestGenerateParseAndPublicBinding(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	parsed, parsedPublic, err := ParsePrivateKey(privateKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != privateKey || parsedPublic != publicKey || !publicKey.Equal(parsedPublic.Bytes()) {
		t.Fatal("WireGuard private/public key binding changed during parse")
	}
	if _, _, err := ParsePrivateKey(make([]byte, KeySize-1)); err == nil {
		t.Fatal("short private key accepted")
	}
	ZeroPrivateKey(&parsed)
	if parsed != (PrivateKey{}) {
		t.Fatal("private key was not zeroed")
	}
}
