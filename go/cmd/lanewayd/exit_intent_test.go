package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/exitnode"
	"laneway.dev/laneway/internal/identity"
	"laneway.dev/laneway/internal/routing"
)

func TestExitIntentStaticBootstrapAndDurablePrecedence(t *testing.T) {
	directory := t.TempDir()
	store := newExitIntentStore(directory)
	static := config.Exit{
		Enabled: true, SelectedNodeID: identity.NodeID(testID(3)).String(), FailureMode: "closed",
		DNSServers: []string{"1.1.1.1"}, LocalLANBypasses: []string{"192.168.0.0/16"},
	}
	loaded, persisted, err := store.Load(static)
	if err != nil || persisted || loaded.SelectedNodeID != static.SelectedNodeID || !loaded.Enabled {
		t.Fatalf("static bootstrap = %#v, persisted=%t, error=%v", loaded, persisted, err)
	}

	selected := identity.NodeID(testID(4))
	if err := store.Save(true, selected, "open"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("intent permissions = %04o", info.Mode().Perm())
	}
	loaded, persisted, err = store.Load(static)
	if err != nil || !persisted || !loaded.Enabled || loaded.SelectedNodeID != selected.String() || loaded.FailureMode != "open" {
		t.Fatalf("persisted precedence = %#v, persisted=%t, error=%v", loaded, persisted, err)
	}
	if strings.Join(loaded.DNSServers, ",") != "1.1.1.1" || strings.Join(loaded.LocalLANBypasses, ",") != "192.168.0.0/16" {
		t.Fatalf("static DNS/LAN settings were replaced: %#v", loaded)
	}

	if err := store.Save(false, identity.NodeID{}, ""); err != nil {
		t.Fatal(err)
	}
	loaded, persisted, err = store.Load(static)
	if err != nil || !persisted || loaded.Enabled || loaded.SelectedNodeID != "" {
		t.Fatalf("durable disable = %#v, persisted=%t, error=%v", loaded, persisted, err)
	}
	contents, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "{\"version\":1,\"enabled\":false}\n" {
		t.Fatalf("disabled intent is not neutral: %s", contents)
	}
}

func TestExitIntentStrictSchemaAndFileSafety(t *testing.T) {
	validNode := identity.NodeID(testID(7)).String()
	tests := map[string]string{
		"unknown":           `{"version":1,"enabled":false,"extra":0}`,
		"duplicate":         `{"version":1,"enabled":false,"enabled":false}`,
		"missing version":   `{"enabled":false}`,
		"future version":    `{"version":2,"enabled":false}`,
		"non-neutral off":   `{"version":1,"enabled":false,"failure_mode":"closed"}`,
		"missing mode":      `{"version":1,"enabled":true,"selected_node_id":"` + validNode + `"}`,
		"invalid node":      `{"version":1,"enabled":true,"selected_node_id":"nope","failure_mode":"closed"}`,
		"invalid mode":      `{"version":1,"enabled":true,"selected_node_id":"` + validNode + `","failure_mode":"maybe"}`,
		"trailing document": `{"version":1,"enabled":false} {}`,
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			store := newExitIntentStore(directory)
			if err := os.WriteFile(store.path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Load(config.Exit{}); err == nil {
				t.Fatal("invalid persisted intent was accepted")
			}
		})
	}

	t.Run("permissions", func(t *testing.T) {
		directory := t.TempDir()
		store := newExitIntentStore(directory)
		if err := os.WriteFile(store.path, []byte(`{"version":1,"enabled":false}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(config.Exit{}); err == nil || !strings.Contains(err.Error(), "want 0600") {
			t.Fatalf("permission error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		store := newExitIntentStore(directory)
		target := filepath.Join(directory, "target")
		if err := os.WriteFile(target, []byte(`{"version":1,"enabled":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, store.path); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(config.Exit{}); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink error = %v", err)
		}
	})
}

func TestSetSelectionPersistsBeforePublishingAndDisableRemainsNeutral(t *testing.T) {
	directory := t.TempDir()
	store := newExitIntentStore(directory)
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	routes := exitnode.NewMemoryRouteManager()
	dns := exitnode.NewMemoryDNSManager()
	client, err := exitnode.NewClientManager(routes, dns, 0)
	if err != nil {
		t.Fatal(err)
	}
	managers := &daemonExitManagers{
		client: client, local: local, failureMode: exitnode.FailureModeClosed, failureModeConfigured: true,
		bypass: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		routeTable: routing.NewTable(nil), pathHealthy: func(identity.NodeID) bool { return true }, intentStore: store,
	}
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
		{Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0}, ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT},
	}}}
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err := managers.SetSelection(context.Background(), true, selected); err != nil {
		t.Fatal(err)
	}
	if status := managers.Status(); !status.Enabled || !status.Authorized {
		t.Fatalf("selected status = %#v", status)
	}
	loaded, persisted, err := store.Load(config.Exit{})
	if err != nil || !persisted || !loaded.Enabled || loaded.SelectedNodeID != selected.String() || loaded.FailureMode != "closed" {
		t.Fatalf("stored selection = %#v, persisted=%t, error=%v", loaded, persisted, err)
	}
	if err := managers.SetSelection(context.Background(), false, identity.NodeID{}); err != nil {
		t.Fatal(err)
	}
	loaded, persisted, err = store.Load(config.Exit{Enabled: true, SelectedNodeID: selected.String(), FailureMode: "closed"})
	if err != nil || !persisted || loaded.Enabled || loaded.SelectedNodeID != "" {
		t.Fatalf("stored disable = %#v, persisted=%t, error=%v", loaded, persisted, err)
	}
}

func TestSetSelectionDoesNotMutateWhenPersistenceFails(t *testing.T) {
	directory := t.TempDir()
	store := newExitIntentStore(directory)
	if err := os.Mkdir(store.path, 0o700); err != nil {
		t.Fatal(err)
	}
	managers := &daemonExitManagers{
		client: mustMemoryExitClient(t), local: identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))},
		failureMode: exitnode.FailureModeClosed, failureModeConfigured: true,
		bypass: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		intentStore: store,
	}
	selected := identity.NodeID(testID(3))
	err := managers.SetSelection(context.Background(), true, selected)
	if err == nil || !strings.Contains(err.Error(), "persist exit selection") {
		t.Fatalf("persistence error = %v", err)
	}
	if managers.enabled || !managers.selected.IsZero() {
		t.Fatalf("failed persistence mutated selection: enabled=%t selected=%s", managers.enabled, managers.selected)
	}
}

func TestSetSelectionRollsBackFirstIntentWhenHostApplyFails(t *testing.T) {
	store := newExitIntentStore(t.TempDir())
	applyErr := errors.New("resolver apply failed")
	client, err := exitnode.NewClientManager(exitnode.NewMemoryRouteManager(), failingIntentDNS{err: applyErr}, 0)
	if err != nil {
		t.Fatal(err)
	}
	local := identity.NodeIdentity{NetworkID: identity.NetworkID(testID(1)), NodeID: identity.NodeID(testID(2))}
	selected := identity.NodeID(testID(3))
	managers := &daemonExitManagers{
		client: client, local: local, failureMode: exitnode.FailureModeClosed, failureModeConfigured: true,
		bypass: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		routeTable: routing.NewTable(nil), pathHealthy: func(identity.NodeID) bool { return true }, intentStore: store,
	}
	configuration := &lanewayv1.NodeConfiguration{Routes: &lanewayv1.RouteSnapshot{Routes: []*lanewayv1.Route{
		{Destination: &lanewayv1.IpPrefix{Address: []byte{0, 0, 0, 0}, PrefixLength: 0}, ViaNodeId: selected[:], Kind: lanewayv1.RouteKind_ROUTE_KIND_EXIT},
	}}}
	if err := managers.Apply(context.Background(), configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err := managers.SetSelection(context.Background(), true, selected); !errors.Is(err, applyErr) {
		t.Fatalf("host apply error = %v", err)
	}
	if managers.enabled || managers.intentPersisted {
		t.Fatalf("failed host apply retained intent: enabled=%t persisted=%t", managers.enabled, managers.intentPersisted)
	}
	if _, err := os.Stat(store.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first selection left intent path: %v", err)
	}
}

type failingIntentDNS struct{ err error }

func (f failingIntentDNS) Apply(context.Context, []netip.Addr) error { return f.err }
func (f failingIntentDNS) Restore(context.Context) error             { return nil }
func (f failingIntentDNS) Close() error                              { return nil }

func mustMemoryExitClient(t *testing.T) *exitnode.ClientManager {
	t.Helper()
	client, err := exitnode.NewClientManager(exitnode.NewMemoryRouteManager(), exitnode.NewMemoryDNSManager(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestExitIntentRemoveIsIdempotent(t *testing.T) {
	store := newExitIntentStore(t.TempDir())
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(false, identity.NodeID{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed path stat error = %v", err)
	}
}
