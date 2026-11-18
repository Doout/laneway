//go:build rustinterop

package controllerservice

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
)

func testRustConnectionDiagnostics(t *testing.T, f fixture, client *http.Client, endpoint, session, csrf string) {
	t.Helper()
	ctx := t.Context()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	browser := labCredentials{session: session, csrf: csrf}
	network, err := f.store.CreateNetwork(ctx, "diagnostics", netip.MustParsePrefix("10.195.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	base := "/v1/admin/networks/" + network.ID.String()
	path := base + "/diagnostics"
	userID := send(endpoint, "POST", base+"/users", `{"name":"diagnostics-user"}`, root, 201)["user_id"].(string)
	user, err := identity.ParseID(userID)
	if err != nil {
		t.Fatal(err)
	}
	node := func(net identity.NetworkID, name string, owner *identity.ID) (controller.Node, tls.Certificate) {
		t.Helper()
		now := time.Now()
		token, err := f.store.IssueEnrollmentTokenWithOptions(ctx, net, name, now.Add(time.Hour), controller.EnrollmentTokenOptions{UserID: owner})
		if err != nil {
			t.Fatal(err)
		}
		var peer tls.Certificate
		enrollment, err := f.store.EnrollNodeWithCertificate(ctx, token.Secret, name, 0, func(_ context.Context, n controller.Node) (controller.CertificateMaterial, error) {
			material, leaf, err := pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: net, NodeID: n.ID}, now, time.Hour)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			peer = tls.Certificate{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return enrollment.Node, peer
	}
	source, cert := node(network.ID, "diagnostic-source", &user)
	target, _ := node(network.ID, "diagnostic-target", nil)
	other, _ := node(f.network.ID, "diagnostic-foreign", nil)
	if _, err = f.store.SetNodeCapabilities(ctx, target.ID, protocol.CapabilitySubnetRouterV1); err != nil {
		t.Fatal(err)
	}
	route, err := f.store.AdvertiseRoute(ctx, target.ID, netip.MustParsePrefix("172.31.101.0/24"), controller.RouteKindSubnet, controller.RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ApproveRoute(ctx, route.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.AddACLRule(ctx, network.ID, 0, controller.ACLActionAccept, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "manual allow"); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.Network(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	nodeTransport := client.Transport.(*http.Transport).Clone()
	nodeTransport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	nodeClient := &http.Client{Transport: nodeTransport, Timeout: 5 * time.Second}
	defer nodeClient.CloseIdleConnections()
	report := fmt.Sprintf(`{"valid_for_seconds":300,"product_version":"diagnostics-test","platform":"linux","certificate_state":"healthy","configuration_state":"current","carrier_state":"relay_quic","route_state":"ready","selected_exit_state":"not_selected","cleanup_failure_count":0,"configuration_epoch":%d}`, current.ConfigurationEpoch-1)
	labManagementHTTP(t, nodeClient)(endpoint, "PUT", "/v1/status", report, labCredentials{}, 204)

	principal := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"diagnostics-read","permissions":["acl.read"],"network_ids":[%q]}`, network.ID.String()), root, 201)["principal_id"].(string)
	key := send(endpoint, "POST", "/v1/admin/service-principals/"+principal+"/tokens", fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)
	reader := labCredentials{bearer: key}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	state := func() [3]int64 {
		t.Helper()
		var out [3]int64
		if err := db.QueryRow(`SELECT configuration_epoch,(SELECT count(*) FROM audit_events),
			(SELECT count(*) FROM endpoint_status_latest) FROM networks WHERE id=?`, network.ID[:]).Scan(&out[0], &out[1], &out[2]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	flow := func(to, ip, dns string) string {
		return fmt.Sprintf(`{"source_node_id":%q,"destination_node_id":%q,"destination_ip":%q,"protocol":"tcp","destination_port":443,"dns_name":%q}`, source.ID.String(), to, ip, dns)
	}
	diag := func(raw string, c labCredentials, want int) map[string]any {
		t.Helper()
		return send(endpoint, "POST", path, raw, c, want)
	}
	check := func(result map[string]any, action string, expected map[string]string) {
		t.Helper()
		if result["reachability"] != "unknown" || result["policy"].(map[string]any)["action"] != action || len(result["limitations"].([]any)) != 3 {
			t.Fatalf("wrong diagnostic verdict: %#v", result)
		}
		got := make(map[string]string)
		for _, entry := range result["findings"].([]any) {
			item := entry.(map[string]any)
			got[item["code"].(string)] = item["status"].(string)
		}
		for code, status := range expected {
			if got[code] != status {
				t.Fatalf("expected %s=%s, got %#v", code, status, result)
			}
		}
		if got["path_not_probed"] != "unknown" || got["service_not_probed"] != "unknown" {
			t.Fatalf("invented reachability evidence: %#v", result)
		}
	}
	zone := "." + network.ID.String() + ".laneway.internal"
	name := "n-" + target.ID.String() + zone
	req := flow(target.ID.String(), "", name)
	before := state()
	check(diag(req, reader, 200), "deny", map[string]string{
		"source_credentials_valid": "pass", "source_status_current": "pass", "source_runtime_report": "warning",
		"destination_never_reported": "unknown", "destination_node_known": "pass", "dns_name_not_in_catalog": "unknown",
	})
	check(diag(flow("", "172.31.101.9", ""), reader, 200), "deny", map[string]string{"route_candidates": "pass", "dns_not_requested": "unknown"})
	check(diag(flow("", "192.0.2.11", ""), browser, 200), "unknown", map[string]string{"no_route_candidate": "unknown"})
	diag(req, labCredentials{session: session}, 403)
	diag(flow(other.ID.String(), "", ""), root, 404)
	diag(strings.Replace(req, `"tcp"`, `"unsupported"`, 1), root, 400)
	diag(strings.Replace(req, `"dns_name":`, `"unexpected_field":`, 1), root, 400)
	diag(flow(target.ID.String(), "", "bad/name"), root, 400)
	send(endpoint, "POST", "/v1/admin/networks/"+f.network.ID.String()+"/diagnostics", req, reader, 403)
	if after := state(); after != before {
		t.Fatalf("diagnostics changed persistent state: before=%v after=%v", before, after)
	}

	send(endpoint, "POST", base+"/access-grants", fmt.Sprintf(`{"subject_kind":"user","subject_id":%q,"target_kind":"node","node_id":%q}`, userID, target.ID.String()), root, 201)
	req = flow(target.ID.String(), "", strings.ToUpper(name)+".")
	allowed := diag(req, reader, 200)
	check(allowed, "accept", map[string]string{"dns_configured": "pass"})
	check(diag(flow(target.ID.String(), "", "n-"+source.ID.String()+zone), reader, 200), "accept", map[string]string{"dns_destination_mismatch": "warning"})
	previewReq, _ := json.Marshal(map[string]any{"flow": map[string]any{"source_node_id": source.ID.String(), "destination_node_id": target.ID.String(), "protocol": "tcp", "destination_port": 443}})
	preview := send(endpoint, "POST", base+"/policy-preview", string(previewReq), reader, 200)["current"]
	if !reflect.DeepEqual(allowed["policy"], preview) {
		t.Fatalf("diagnostics and policy preview disagree: %#v vs %#v", allowed["policy"], preview)
	}
	if _, err := db.Exec(`UPDATE endpoint_status_latest SET observed_at=observed_at-301,expires_at=expires_at-301 WHERE node_id=?`, source.ID[:]); err != nil {
		t.Fatal(err)
	}
	check(diag(req, reader, 200), "accept", map[string]string{"source_status_stale": "unknown"})
	if _, err := f.store.RevokeNode(ctx, target.ID, "diagnostics lab"); err != nil {
		t.Fatal(err)
	}
	check(diag(req, reader, 200), "unknown", map[string]string{"destination_credentials_inactive": "blocked", "policy_endpoint_inactive": "unknown"})

	expired, _ := node(network.ID, "expired-overlay", nil)
	gateway, _ := node(network.ID, "diagnostic-exit", nil)
	if _, err := f.store.SetNodeCapabilities(ctx, gateway.ID, protocol.CapabilityExitNodeV1); err != nil {
		t.Fatal(err)
	}
	defaultRoute, err := f.store.AdvertiseRoute(ctx, gateway.ID, netip.MustParsePrefix("0.0.0.0/0"), controller.RouteKindExit, controller.RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ApproveRoute(ctx, defaultRoute.ID); err != nil {
		t.Fatal(err)
	}
	// Simulate lease expiry before maintenance releases the address.
	if _, err := db.Exec(`UPDATE nodes SET enrollment_class='ephemeral',lease_expires_at=unixepoch()-1 WHERE id=?`, expired.ID[:]); err != nil {
		t.Fatal(err)
	}
	check(diag(flow("", expired.IPv4Address.String(), ""), reader, 200), "unknown", map[string]string{"destination_credentials_inactive": "blocked", "policy_endpoint_inactive": "unknown"})
}
