package netvalidate

import "testing"

func TestCanonicalHostPort(t *testing.T) {
	for input, want := range map[string]string{
		"Relay-New.Example.:4433": "relay-new.example:4433",
		"relay:443":               "relay:443",
		"192.0.2.4:8443":          "192.0.2.4:8443",
		"[2001:db8::1]:4433":      "[2001:db8::1]:4433",
	} {
		if got, err := CanonicalHostPort(input); err != nil || got != want {
			t.Errorf("CanonicalHostPort(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{
		"https://relay:443", "relay", "relay:0", "bad host:443", "-relay:443", "relay_:443", "[fe80::1%eth0]:443",
		"0.0.0.0:443", "224.0.0.1:443", "255.255.255.255:443", "[::]:443", "[ff02::1]:443", "[::ffff:192.0.2.1]:443",
	} {
		if got, err := CanonicalHostPort(input); err == nil {
			t.Errorf("CanonicalHostPort(%q) = %q, want error", input, got)
		}
	}
}
