//go:build rustinterop

package controllerservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"testing"
	"time"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

// Use the actual Go HTTP response as the oracle. Keep the writer open so
// committed records may still be in the WAL when the Rust process opens it.
func TestRustControllerInventory(t *testing.T) {
	bin := os.Getenv("LANEWAY_RUST_CONTROLLER")
	if bin == "" {
		t.Fatal("set LANEWAY_RUST_CONTROLLER to the built controller binary")
	}
	f := newFixture(t, 0, nil)
	compare := func(path string, limit int, args ...string) {
		t.Helper()
		n := strconv.Itoa(limit)
		response := httptest.NewRecorder()
		f.service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path+"?limit="+n, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("Go list: status %d: %s", response.Code, response.Body)
		}
		output, err := exec.CommandContext(t.Context(), bin, append(append([]string{"inventory"}, args...), n)...).CombinedOutput()
		if err != nil {
			t.Fatalf("Rust inventory: %v: %s", err, output)
		}
		parse := func(raw []byte) any {
			t.Helper()
			var v any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if !json.Valid(raw) {
				t.Fatalf("invalid JSON: %q", raw)
			}
			if err := decoder.Decode(&v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		if !reflect.DeepEqual(parse(response.Body.Bytes()), parse(output)) {
			t.Fatalf("inventory mismatch\nGo: %s\nRust: %s", response.Body, output)
		}
	}
	networks := func(n int) { compare("/v1/admin/networks", n, "networks", f.dbPath) }
	nodes := func(n int) {
		id := f.network.ID.String()
		compare("/v1/admin/networks/"+id+"/nodes", n, "nodes", f.dbPath, id)
	}
	networks(100)
	dual, err := f.store.CreateNetworkDualStack(t.Context(), "dual stack", netip.MustParsePrefix("10.80.0.0/16"), netip.MustParsePrefix("fd55::/64"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.AddACLRule(t.Context(), f.network.ID, 7, controller.ACLActionAccept, "{}", "test rule"); err != nil {
		t.Fatal(err)
	}
	networks(1)
	networks(1000)
	empty := f.network
	f.network = dual
	nodes(100)
	durable, res := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "durable")
	if res.Code != http.StatusCreated {
		t.Fatalf("enroll durable: %d", res.Code)
	}
	token, err := f.store.IssueEnrollmentTokenWithOptions(t.Context(), dual.ID, "temporary", time.Now().Add(time.Minute), controller.EnrollmentTokenOptions{
		Class: controller.EnrollmentClassEphemeral, SessionLifetime: controller.MinEphemeralLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, res = enrollClass(t, f, token.Secret, csrDER(t, ""), "temporary", lanewayv1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER)
	if res.Code != http.StatusCreated {
		t.Fatalf("enroll ephemeral: %d", res.Code)
	}
	nodes(1)
	nodes(100)
	if _, err := f.store.RevokeNode(t.Context(), identity.NodeID(durable.GetNodeId()), "test revocation"); err != nil {
		t.Fatal(err)
	}
	nodes(100)
	f.network = empty
	nodes(100)
}
