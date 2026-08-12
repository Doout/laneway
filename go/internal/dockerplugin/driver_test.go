package dockerplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type fakeBackend struct{ applied, removed, joined, left int }

func (b *fakeBackend) ApplyNetwork(context.Context, *Network, Authorization) error {
	b.applied++
	return nil
}
func (b *fakeBackend) RemoveNetwork(context.Context, *Network, Authorization) error {
	b.removed++
	return nil
}
func (b *fakeBackend) Join(context.Context, *Network, *Endpoint) error  { b.joined++; return nil }
func (b *fakeBackend) Leave(context.Context, *Network, *Endpoint) error { b.left++; return nil }

func TestDriverLifecycle(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	driver, err := NewDriver(DriverOptions{Store: store, Backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	handler := driver.Handler()
	call := func(path string, value any) map[string]any {
		t.Helper()
		data, _ := json.Marshal(value)
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var body map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if message, _ := body["Err"].(string); message != "" {
			t.Fatalf("%s: %s", path, message)
		}
		return body
	}
	call("/NetworkDriver.CreateNetwork", map[string]any{"NetworkID": "network-one", "IPv4Data": []any{map[string]any{"Pool": "172.30.50.0/24", "Gateway": "172.30.50.1/24"}}, "Options": map[string]any{OptionPolicy: "direct"}})
	call("/NetworkDriver.CreateEndpoint", map[string]any{"NetworkID": "network-one", "EndpointID": "endpoint-one", "Interface": map[string]any{"Address": "172.30.50.2/24"}})
	join := call("/NetworkDriver.Join", map[string]any{"NetworkID": "network-one", "EndpointID": "endpoint-one", "SandboxKey": "/var/run/docker/netns/test"})
	if join["Gateway"] != "172.30.50.1" {
		t.Fatalf("join=%v", join)
	}
	call("/NetworkDriver.Leave", map[string]any{"NetworkID": "network-one", "EndpointID": "endpoint-one"})
	call("/NetworkDriver.DeleteEndpoint", map[string]any{"NetworkID": "network-one", "EndpointID": "endpoint-one"})
	call("/NetworkDriver.DeleteNetwork", map[string]any{"NetworkID": "network-one"})
	if backend.applied != 1 || backend.removed != 1 || backend.joined != 1 || backend.left != 1 {
		t.Fatalf("backend=%+v", backend)
	}
	reopened, err := OpenStore(filepath.Join(filepath.Dir(store.path), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Snapshot()) != 0 {
		t.Fatal("state was not cleaned")
	}
}

func TestDriverRejectsOverlappingNetworks(t *testing.T) {
	store, _ := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	driver, _ := NewDriver(DriverOptions{Store: store, Backend: &fakeBackend{}})
	create := func(id, pool, gateway string) string {
		data, _ := json.Marshal(map[string]any{"NetworkID": id, "IPv4Data": []any{map[string]any{"Pool": pool, "Gateway": gateway}}, "Options": map[string]any{}})
		response := httptest.NewRecorder()
		driver.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/NetworkDriver.CreateNetwork", bytes.NewReader(data)))
		var body map[string]string
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		return body["Err"]
	}
	if err := create("one", "172.30.0.0/16", "172.30.0.1/16"); err != "" {
		t.Fatal(err)
	}
	if err := create("two", "172.30.1.0/24", "172.30.1.1/24"); err == "" {
		t.Fatal("overlap accepted")
	}
}
