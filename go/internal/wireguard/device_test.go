package wireguard

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func deviceKey(t *testing.T) (PrivateKey, PublicKey) {
	t.Helper()
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func TestNormalizeDeviceConfigRejectsUnsafeIdentityAndRoutes(t *testing.T) {
	privateKey, localPublicKey := deviceKey(t)
	_, peerOne := deviceKey(t)
	_, peerTwo := deviceKey(t)
	base := DeviceConfig{Name: "lane0", MTU: 1280, PrivateKey: privateKey, Addresses: []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32")}}

	tests := []struct {
		name  string
		peers []Peer
	}{
		{"local key", []Peer{{PublicKey: localPublicKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}}}},
		{"low order key", []Peer{{PublicKey: PublicKey{}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}}}},
		{"overlapping owners", []Peer{
			{PublicKey: peerOne, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
			{PublicKey: peerTwo, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.8/32")}},
		}},
		{"multicast route", []Peer{{PublicKey: peerOne, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("224.0.0.0/4")}}}},
		{"excessive keepalive", []Peer{{PublicKey: peerOne, PersistentKeepalive: 25 * time.Hour}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Peers = test.peers
			if _, err := normalizeDeviceConfig(config); !errors.Is(err, ErrInvalidPeer) {
				t.Fatalf("error = %v, want ErrInvalidPeer", err)
			}
		})
	}
}

func TestNormalizePeersCopiesAndSortsSnapshot(t *testing.T) {
	_, keyOne := deviceKey(t)
	_, keyTwo := deviceKey(t)
	peers := []Peer{
		{PublicKey: keyTwo, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/64")}, Endpoint: netip.MustParseAddrPort("[2001:db8::2]:51820")},
		{PublicKey: keyOne, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.96.2.0/24"), netip.MustParsePrefix("100.96.1.0/24")}},
	}
	normalized, err := normalizePeers(peers)
	if err != nil {
		t.Fatal(err)
	}
	peers[0].AllowedIPs[0] = netip.MustParsePrefix("192.0.2.0/24")
	if normalized[0].PublicKey == normalized[1].PublicKey || normalized[0].AllowedIPs[0] == netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("normalization aliased or lost peers: %+v", normalized)
	}
	for i := 1; i < len(normalized); i++ {
		if string(normalized[i-1].PublicKey[:]) > string(normalized[i].PublicKey[:]) {
			t.Fatalf("peer snapshot is not deterministic: %+v", normalized)
		}
	}
}
