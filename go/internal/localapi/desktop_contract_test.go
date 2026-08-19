package localapi

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedDesktopStatusContract(t *testing.T) {
	contents, err := os.ReadFile("../../../testvectors/local-api/desktop-snapshot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ContractVersion int             `json:"contract_version"`
		Platform        string          `json:"platform"`
		Ownership       string          `json:"ownership"`
		Capabilities    map[string]bool `json:"capabilities"`
		Status          Status          `json:"status"`
		Peers           []Peer          `json:"peers"`
		Routes          []Route         `json:"routes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ContractVersion != 1 || fixture.Platform != "linux" || fixture.Ownership != "same-user-daemon" {
		t.Fatalf("contract identity = version %d platform %q ownership %q", fixture.ContractVersion, fixture.Platform, fixture.Ownership)
	}
	if fixture.Capabilities["connection_control"] || fixture.Capabilities["exit_selection"] || fixture.Capabilities["snapshot_coherence"] {
		t.Fatalf("capabilities = %#v", fixture.Capabilities)
	}
	if fixture.Status.Name != "workstation" || len(fixture.Peers) != 1 || fixture.Peers[0].Name != "office-exit" || len(fixture.Routes) != 1 || fixture.Routes[0].Prefix != "10.20.0.0/16" {
		t.Fatalf("fixture drifted: status=%#v peers=%#v routes=%#v", fixture.Status, fixture.Peers, fixture.Routes)
	}
}
