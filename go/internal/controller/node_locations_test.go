package controller

import (
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodelocation"
)

func TestNodeLocationOverrideFreshnessAndScope(t *testing.T) {
	s, _ := openTestStore(t)
	now := time.Unix(1_900_100_000, 0)
	s.now = func() time.Time { return now }
	network := resourceTestNetwork(t, s, "map", "10.110.0.0/24")
	node := resourceTestNode(t, s, network.ID, "map-node", 0)
	if _, err := s.AddCertificate(t.Context(), network.ID, node.ID, []byte{1}, []byte{1}, now.Add(-time.Minute), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	caller := identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}
	read := administratorRootDecision(t, s, administratorNodeLocationsPolicy, adminauth.NetworkTarget(network.ID))
	set := administratorRootDecision(t, s, administratorNodeLocationSetPolicy, adminauth.ObjectTarget(identity.ID(node.ID)))
	clear := administratorRootDecision(t, s, administratorNodeLocationClearPolicy, adminauth.ObjectTarget(identity.ID(node.ID)))
	check := func(source string, stale bool) NodeLocation {
		t.Helper()
		values, err := s.AdministratorNodeLocations(t.Context(), read, network.ID, 100)
		if err != nil || len(values) != 1 {
			t.Fatalf("values=%+v error=%v", values, err)
		}
		if values[0].Source != source || values[0].Stale != stale {
			t.Fatalf("location=%+v", values[0])
		}
		return values[0]
	}
	check("unknown", false)
	auto := nodelocation.Location{Label: "Toronto, CA", Latitude: 43.65, Longitude: -79.38, AccuracyKM: 50}
	if err := s.RecordNodeLocation(t.Context(), caller, &auto, now, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if value := check("ip", false); !value.Online || value.PublicIP != "8.8.8.8" || value.LastSeen != now.Unix() {
		t.Fatalf("presence=%+v", value)
	}
	now = now.Add(6 * time.Minute)
	if check("ip", false).Online {
		t.Fatal("expired heartbeat remains online")
	}
	now = now.Add(24 * time.Hour)
	check("ip", true)
	manual := nodelocation.Location{Label: "Office", Latitude: 43.7, Longitude: -79.4}
	if err := s.AdministratorSetNodeLocation(t.Context(), set, node.ID, &manual); err != nil {
		t.Fatal(err)
	}
	if check("manual", false).Location.Label != "Office" {
		t.Fatal("override lost")
	}
	if check("manual", false).Online {
		t.Fatal("manual location refreshed presence")
	}
	if err := s.RecordNodeLocation(t.Context(), caller, nil, now); err != nil {
		t.Fatal(err)
	}
	check("manual", false)
	if err := s.AdministratorSetNodeLocation(t.Context(), set, node.ID, nil); err == nil {
		t.Fatal("PUT decision accepted for DELETE")
	}
	if err := s.AdministratorSetNodeLocation(t.Context(), clear, node.ID, nil); err != nil {
		t.Fatal(err)
	}
	check("unknown", false)
	// An old source observation must not restore a location after a newer unknown source.
	if err := s.RecordNodeLocation(t.Context(), caller, &auto, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	check("unknown", false)
	other := resourceTestNetwork(t, s, "other-map", "10.111.0.0/24")
	if _, err := s.AdministratorNodeLocations(t.Context(), read, other.ID, 100); err == nil {
		t.Fatal("cross-network read accepted")
	}
	otherNode := resourceTestNode(t, s, other.ID, "other-node", 0)
	if err := s.AdministratorSetNodeLocation(t.Context(), set, otherNode.ID, &manual); err == nil {
		t.Fatal("cross-object update accepted")
	}
	var audits int
	if err := s.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action IN ('node.location.set','node.location.clear')`).Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audits=%d err=%v", audits, err)
	}
}
