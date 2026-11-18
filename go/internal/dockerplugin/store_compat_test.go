package dockerplugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The Linux Go plugin and the candidate Rust driver read these same v1 files.
func TestGoRustJournalFixture(t *testing.T) {
	directory := t.TempDir()
	fixtureDir := filepath.Join("..", "..", "..", "testvectors", "docker-plugin")
	for _, name := range []string{"state-v1.json", "authorization-v1.json"} {
		data, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenStore(filepath.Join(directory, "state-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	network := store.Snapshot()["net-fixture"]
	bridge, table := networkNames("net-fixture")
	if network == nil || network.Bridge != bridge || network.Table != table || network.Phase != "active" {
		t.Fatalf("invalid ownership fixture: %+v", network)
	}
	endpoint := network.Endpoints["endpoint-fixture"]
	host, peer := endpointNames("endpoint-fixture")
	if endpoint == nil || endpoint.HostVeth != host || endpoint.PeerVeth != peer || !endpoint.Joined {
		t.Fatalf("invalid endpoint fixture: %+v", endpoint)
	}
	source := FileAuthorizationSource{Path: filepath.Join(directory, "authorization-v1.json")}
	lease, err := source.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Authorize(network.CreatedAt.Add(time.Hour), network.Subnet, network.Policy); err != nil {
		t.Fatal(err)
	}
}
