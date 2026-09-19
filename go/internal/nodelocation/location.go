// Package nodelocation resolves approximate locations without external requests.
package nodelocation

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"unicode"

	"github.com/oschwald/maxminddb-golang/v2"
)

type Location struct {
	Label      string  `json:"label"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	AccuracyKM uint16  `json:"accuracy_km"`
}

func (l Location) Validate() error {
	if strings.TrimSpace(l.Label) == "" || len(l.Label) > 253 || strings.IndexFunc(l.Label, unicode.IsControl) >= 0 ||
		math.IsNaN(l.Latitude) || math.IsInf(l.Latitude, 0) || math.Abs(l.Latitude) > 90 ||
		math.IsNaN(l.Longitude) || math.IsInf(l.Longitude, 0) || math.Abs(l.Longitude) > 180 {
		return errors.New("location requires a label and valid latitude/longitude")
	}
	return nil
}

// Exclude non-public and transition addresses even when IsGlobalUnicast is true.
var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range excluded {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type Database struct{ reader *maxminddb.Reader }

func Open(path string) (*Database, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	if err := db.Verify(); err != nil {
		db.Close()
		return nil, err
	}
	if !strings.Contains(db.Metadata.DatabaseType, "City") {
		db.Close()
		return nil, errors.New("location database must be a City database")
	}
	return &Database{reader: db}, nil
}

func (d *Database) Close() error { return d.reader.Close() }

func (d *Database) Provider() string {
	if strings.Contains(strings.ToLower(d.reader.Metadata.DatabaseType), "dbip") {
		return "db-ip"
	}
	return "maxmind"
}

func (d *Database) Lookup(ip netip.Addr) (*Location, error) {
	if !PublicIP(ip) {
		return nil, nil
	}
	var record struct {
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Location struct {
			Latitude  *float64 `maxminddb:"latitude"`
			Longitude *float64 `maxminddb:"longitude"`
			Accuracy  uint16   `maxminddb:"accuracy_radius"`
		} `maxminddb:"location"`
	}
	if err := d.reader.Lookup(ip.Unmap()).Decode(&record); err != nil {
		return nil, err
	}
	if record.Location.Latitude == nil || record.Location.Longitude == nil || record.Country.ISO == "" {
		return nil, nil
	}
	label := record.Country.ISO
	if city := record.City.Names["en"]; city != "" {
		label = city + ", " + label
	}
	l := &Location{Label: label, Latitude: *record.Location.Latitude, Longitude: *record.Location.Longitude, AccuracyKM: record.Location.Accuracy}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}
