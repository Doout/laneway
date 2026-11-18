//go:build rustinterop

package controllerservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
)

func testRustPrivateDNS(t *testing.T, f fixture, client *http.Client, endpoint string) {
	t.Helper()
	ctx := t.Context()
	root := labCredentials{bearer: testRootBearer}
	send := labManagementHTTP(t, client)
	network, err := f.store.CreateNetworkDualStack(ctx, "private-dns-lab", netip.MustParsePrefix("10.191.0.0/24"), netip.MustParsePrefix("fd00:191::/64"))
	if err != nil {
		t.Fatal(err)
	}
	zone := network.ID.String() + ".laneway.internal"
	base := "/v1/admin/networks/" + network.ID.String()
	userID := send(endpoint, "POST", base+"/users", `{"name":"directory-reader"}`, root, 201)["user_id"].(string)
	user, err := identity.ParseID(userID)
	if err != nil {
		t.Fatal(err)
	}
	provision := func(name string, user *identity.ID) (controller.Node, pki.Material, *x509.Certificate) {
		t.Helper()
		now := time.Now().UTC()
		token, err := f.store.IssueEnrollmentTokenWithOptions(ctx, network.ID, name, now.Add(time.Hour), controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable, UserID: user})
		if err != nil {
			t.Fatal(err)
		}
		var material pki.Material
		var leaf *x509.Certificate
		enrollment, err := f.store.EnrollNodeWithCertificate(ctx, token.Secret, name, 0, func(_ context.Context, node controller.Node) (controller.CertificateMaterial, error) {
			var err error
			material, leaf, err = pki.IssueNode(f.service.ca, f.service.caKey, identity.NodeIdentity{NetworkID: network.ID, NodeID: node.ID}, now, time.Hour)
			if err != nil {
				return controller.CertificateMaterial{}, err
			}
			return controller.CertificateMaterial{Serial: leaf.SerialNumber.Bytes(), DER: leaf.Raw, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return enrollment.Node, material, leaf
	}
	caller, cert, leaf := provision("client", &user)
	target, _, _ := provision("Private DB", nil)
	hidden, _, _ := provision("private_db", nil)
	path := "/v1/node/private-dns"
	send(endpoint, "GET", path, "", root, 401)
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.CertificateDER}, PrivateKey: cert.PrivateKey}}
	nodeClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer nodeClient.CloseIdleConnections()
	read := func(want int) map[string]any {
		t.Helper()
		res, err := nodeClient.Get(endpoint + path + "?network_id=" + f.network.ID.String())
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil || res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("private DNS response: %d %+v %v", res.StatusCode, body, err)
		}
		return body
	}
	canonical := func(id string) string { return "n-" + id + "." + zone }
	assertCatalog := func(body map[string]any, services int, nodes ...controller.Node) {
		t.Helper()
		if body["zone"] != zone || body["network_id"] != network.ID.String() || len(body["services"].([]any)) != services {
			t.Fatalf("invalid private catalog: %#v", body)
		}
		want, seen := map[string]bool{}, map[string]bool{}
		for _, node := range nodes {
			want[node.ID.String()] = true
		}
		for _, item := range body["records"].([]any) {
			entry := item.(map[string]any)
			name, id := entry["name"].(string), entry["node_id"].(string)
			if !want[id] || name == "private-db."+zone || seen[name] || len(entry["addresses"].([]any)) != 2 {
				t.Fatalf("unexpected private record: %#v", entry)
			}
			seen[name] = true
		}
		for id := range want {
			if !seen[canonical(id)] {
				t.Fatalf("missing permanent private name: %s", id)
			}
		}
		if want[caller.ID.String()] && !seen["client."+zone] {
			t.Fatal("missing unique friendly alias")
		}
		end := int64(body["valid_until_unix_seconds"].(float64))
		if now := time.Now().Unix(); end <= now || end > now+30 {
			t.Fatalf("unexpected directory lifetime: %d", end-now)
		}
	}
	assertCatalog(read(200), 0, caller)
	if _, _, err := f.store.AddACLRule(ctx, network.ID, 0, controller.ACLActionAccept, `{"ip_protocol":"IP_PROTOCOL_ANY"}`, "Manual allow"); err != nil {
		t.Fatal(err)
	}
	assertCatalog(read(200), 0, caller)
	if _, err := f.store.SetNodeCapabilities(ctx, hidden.ID, protocol.CapabilityExitNodeV1); err != nil {
		t.Fatal(err)
	}
	exit, err := f.store.AdvertiseRoute(ctx, hidden.ID, netip.MustParsePrefix("0.0.0.0/0"), controller.RouteKindExit, controller.RouteModeNAT, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ApproveRoute(ctx, exit.ID); err != nil {
		t.Fatal(err)
	}
	send(endpoint, "POST", base+"/access-grants", fmt.Sprintf(`{"subject_kind":"user","subject_id":%q,"target_kind":"exit","node_id":%q}`, userID, hidden.ID.String()), root, 201)
	assertCatalog(read(200), 0, caller)
	resource := send(endpoint, "POST", base+"/resources", fmt.Sprintf(`{"name":"Database","target_kind":"node","node_id":%q}`, target.ID.String()), root, 201)["resource_id"].(string)
	service := send(endpoint, "POST", base+"/services", `{"name":"SQL","protocol":"tcp","ports":[{"first":5432,"last":5433}]}`, root, 201)["service_id"].(string)
	grant := send(endpoint, "POST", base+"/resource-access-grants", fmt.Sprintf(`{"subject_kind":"user","subject_id":%q,"resource_id":%q,"service_id":%q}`, userID, resource, service), root, 201)["grant_id"].(string)
	view := read(200)
	assertCatalog(view, 1, caller, target)
	named := view["services"].([]any)[0].(map[string]any)
	port := named["ports"].([]any)[0].(map[string]any)
	if named["host"] != canonical(target.ID.String()) || named["protocol"] != "tcp" || named["resource_id"] != resource || named["service_id"] != service || port["first"] != float64(5432) || port["last"] != float64(5433) {
		t.Fatalf("wrong named service: %#v", named)
	}
	reader := send(endpoint, "POST", "/v1/admin/service-principals", fmt.Sprintf(`{"name":"directory-bot","permissions":["acl.read"],"network_ids":[%q]}`, network.ID.String()), root, 201)["principal_id"].(string)
	readToken := send(endpoint, "POST", "/v1/admin/service-principals/"+reader+"/tokens", fmt.Sprintf(`{"label":"directory","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix()), root, 201)["access_token"].(string)
	credentials := labCredentials{bearer: readToken}
	assertCatalog(send(endpoint, "GET", base+"/private-dns", "", credentials, 200), 1, caller, target, hidden)
	send(endpoint, "GET", "/v1/admin/networks/"+f.network.ID.String()+"/private-dns", "", credentials, 403)
	send(endpoint, "PATCH", "/v1/admin/users/"+userID, `{"enabled":false}`, root, 200)
	assertCatalog(read(200), 0, caller)
	send(endpoint, "PATCH", "/v1/admin/users/"+userID, `{"enabled":true}`, root, 200)
	send(endpoint, "DELETE", "/v1/admin/resource-access-grants/"+grant, "", root, 200)
	assertCatalog(read(200), 0, caller)
	if _, err := f.store.RevokeCertificateBySerial(ctx, network.ID, leaf.SerialNumber.Bytes(), "private DNS test"); err != nil {
		t.Fatal(err)
	}
	read(403)
}
