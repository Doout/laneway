package nodelocation

import (
	"math"
	"net/netip"
	"testing"
)

func TestPublicIP(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("public: %s", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "100.96.0.2", "169.254.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "255.255.255.255", "224.0.0.1", "0.1.2.3", "::1", "::", "fc00::1", "fe80::1%en0", "2001:db8::1", "2002:0808:0808::1", "64:ff9b::808:808", "::ffff:10.0.0.1"} {
		if PublicIP(netip.MustParseAddr(ip)) {
			t.Errorf("non-public: %s", ip)
		}
	}
	if PublicIP(netip.Addr{}) {
		t.Fatal("invalid accepted")
	}
}

func TestLocationValidation(t *testing.T) {
	if err := (Location{Label: "Equator", Latitude: 0, Longitude: 0}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, l := range []Location{{Label: ""}, {Label: " "}, {Label: "bad\nlabel"}, {Label: "x", Latitude: 91}, {Label: "x", Longitude: 181}, {Label: "x", Latitude: math.NaN()}, {Label: "x", Longitude: math.Inf(1)}} {
		if l.Validate() == nil {
			t.Fatalf("invalid accepted: %+v", l)
		}
	}
	if _, err := Open(t.TempDir() + "/missing.mmdb"); err == nil {
		t.Fatal("missing database accepted")
	}
}

func TestCityDatabaseLookup(t *testing.T) {
	db, err := Open("testdata/GeoIP2-City-Test.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	location, err := db.Lookup(netip.MustParseAddr("81.2.69.142"))
	if err != nil || location == nil {
		t.Fatalf("location=%+v err=%v", location, err)
	}
	if location.Label != "London, GB" || location.Latitude < 51 || location.Latitude > 52 || location.Longitude > 0 {
		t.Fatalf("unexpected location %+v", location)
	}
	unknown, err := db.Lookup(netip.MustParseAddr("1.1.1.1"))
	if err != nil || unknown != nil {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
	private, err := db.Lookup(netip.MustParseAddr("10.0.0.1"))
	if err != nil || private != nil {
		t.Fatalf("private=%+v err=%v", private, err)
	}
}
