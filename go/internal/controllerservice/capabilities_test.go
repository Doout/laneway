package controllerservice

import (
	"net/http"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
)

func TestAdminCapabilityGrantEnablesSubnetAdvertisement(t *testing.T) {
	f := newFixture(t, DefaultMaxBodyBytes, nil)
	enrollment, result := enroll(t, f, issueToken(t, f, time.Now().Add(time.Hour)), csrDER(t, ""), "gateway")
	if result.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d", result.Code)
	}
	if len(enrollment.GetNodeId()) != identity.IDSize {
		t.Fatalf("node ID length = %d", len(enrollment.GetNodeId()))
	}
	var nodeID identity.NodeID
	copy(nodeID[:], enrollment.GetNodeId())
	grant := jsonRequest(t, f.service.Handler(), http.MethodPut, "/v1/admin/nodes/"+nodeID.String()+"/capabilities", nodeCapabilitiesRequest{
		EnabledCapabilities: uint64(protocol.CapabilitySubnetRouterV1),
	})
	if grant.Code != http.StatusOK {
		t.Fatalf("grant status=%d body=%s", grant.Code, grant.Body.String())
	}
	node, err := f.store.Node(t.Context(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if node.EnabledCapabilities != uint64(protocol.CapabilitySubnetRouterV1) {
		t.Fatalf("enabled capabilities = %#x", node.EnabledCapabilities)
	}
}
