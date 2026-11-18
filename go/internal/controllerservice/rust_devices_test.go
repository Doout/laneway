//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func testRustDeviceManagement(t *testing.T, f fixture, client *http.Client, goURL, rustURL string) {
	t.Helper()
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	net := f.network.ID
	other, err := f.store.CreateNetwork(ctx, "device-foreign", netip.MustParsePrefix("10.220.0.0/24"))
	must(err)
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	bot := func(permission string) labCredentials {
		t.Helper()
		data := fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":[%q]}`, permission, permission, net)
		id := send(goURL, "POST", "/v1/admin/service-principals", data, root, 201)["principal_id"].(string)
		data = fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix())
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+id+"/tokens", data, root, 201)["access_token"].(string)}
	}
	web := func(role string) labCredentials {
		t.Helper()
		p, err := f.store.AdministratorPasswordCandidate(ctx, "web-"+role)
		must(err)
		_, token, csrf, err := f.store.CreateAdministratorSessionAfterPassword(ctx, p, controller.AdministratorSessionOptions{})
		must(err)
		return labCredentials{session: token, csrf: csrf}
	}
	asClient := func(chain *v1.CertificateChain, key ed25519.PrivateKey) *http.Client {
		tr := client.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: chain.CertificatesDer, PrivateKey: key}}
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		t.Cleanup(c.CloseIdleConnections)
		return c
	}
	enroll := func(network identity.NetworkID, name string) (identity.NodeID, *v1.CertificateChain, ed25519.PrivateKey, []byte) {
		t.Helper()
		token, err := f.store.IssueEnrollmentToken(ctx, network, name, time.Now().Add(time.Hour))
		must(err)
		_, key, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		must(err)
		out := labRedeem(t, client, goURL, &v1.EnrollmentRequest{
			RequestedName: name, EnrollmentToken: token.Secret, Pkcs10CsrDer: csr, ExpectedNetworkId: network[:],
			ExpectedEnrollmentClass: v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE,
		}, 201)
		var id identity.NodeID
		copy(id[:], out.NodeId)
		return id, out.CertificateChain, key, csr
	}
	doProto := func(c *http.Client, method, base, path string, body []byte, want int) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
		must(err)
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := c.Do(req)
		must(err)
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		must(err)
		if resp.StatusCode != want {
			var msg v1.ProtocolError
			_ = proto.Unmarshal(got, &msg)
			t.Fatalf("%s %s: got %d (%s), want %d", method, path, resp.StatusCode, msg.Detail, want)
		}
		return got
	}
	target, chain, key, csr := enroll(net, "device-target")
	targetClient := asClient(chain, key)
	_, observerChain, observerKey, _ := enroll(net, "device-observer")
	observer := asClient(observerChain, observerKey)
	foreign, foreignChain, foreignKey, _ := enroll(other.ID, "device-outsider")
	outsider := asClient(foreignChain, foreignKey)
	serial := hex.EncodeToString(parseLeaf(t, chain).SerialNumber.Bytes())
	foreignSerial := hex.EncodeToString(parseLeaf(t, foreignChain).SerialNumber.Bytes())
	raw, err := proto.Marshal(&v1.RenewalRequest{Pkcs10CsrDer: csr})
	must(err)
	var renewal v1.RenewalResponse
	must(proto.Unmarshal(doProto(targetClient, http.MethodPost, rustURL, "/v1/renew", raw, 200), &renewal))
	fresh := asClient(renewal.CertificateChain, key)
	freshSerial := hex.EncodeToString(parseLeaf(t, renewal.CertificateChain).SerialNumber.Bytes())
	list := "/v1/admin/networks/" + net.String() + "/certificates"
	nodePath := "/v1/admin/nodes/" + target.String()
	reader, revoker, operatorBot := bot("certificate.read"), bot("certificate.revoke"), bot("node.manage")
	auditor, operator := web("auditor"), web("operator")
	compare := func(path string, auth labCredentials) {
		t.Helper()
		a, b := send(goURL, "GET", path, "", auth, 200), send(rustURL, "GET", path, "", auth, 200)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("certificate inventory mismatch: Go=%#v Rust=%#v", a, b)
		}
	}
	compare(list+"?limit=1", reader)
	compare(list, auditor)
	send(rustURL, "GET", list, "", revoker, 403)
	send(rustURL, "POST", nodePath+"/revoke", `{"reason":"retired"}`, auditor, 403)
	send(rustURL, "POST", "/v1/admin/nodes/"+foreign.String()+"/revoke", `{"reason":"retired"}`, operatorBot, 404)
	send(rustURL, "POST", list+"/"+foreignSerial+"/revoke", `{"reason":"retired"}`, revoker, 404)
	send(rustURL, "POST", list+"/"+serial+"/revoke", `{"reason":"retired"}`, operatorBot, 403)
	send(rustURL, "POST", list+"/00/revoke", `{"reason":"retired"}`, revoker, 400)

	epoch := func() uint64 {
		n, err := f.store.Network(ctx, net)
		must(err)
		return n.ConfigurationEpoch
	}
	caps := func(c protocol.Capability, cred labCredentials, want int) {
		t.Helper()
		send(rustURL, "PUT", nodePath+"/capabilities", fmt.Sprintf(`{"enabled_capabilities":%d}`, c), cred, want)
	}
	before := epoch()
	caps(1, operator, 400)
	caps(protocol.CapabilityExitNodeV1|protocol.CapabilitySubnetRouterV1, operatorBot, 200)
	caps(protocol.CapabilityExitNodeV1|protocol.CapabilitySubnetRouterV1, operator, 200)
	if epoch() != before+1 {
		t.Fatal("duplicate capability assignment changed epoch")
	}
	subnet, err := f.store.AdvertiseRoute(ctx, target, netip.MustParsePrefix("198.51.100.0/24"), controller.RouteKindSubnet, controller.RouteModeNAT, 3, nil)
	must(err)
	_, err = f.store.ApproveRoute(ctx, subnet.ID)
	must(err)
	exit, err := f.store.AdvertiseRoute(ctx, target, netip.MustParsePrefix("0.0.0.0/0"), controller.RouteKindExit, controller.RouteModeNAT, 60, nil)
	must(err)
	caps(protocol.CapabilityExitNodeV1, operator, 200)
	db, err := sql.Open("sqlite", f.dbPath)
	must(err)
	defer db.Close()
	routeState := func(id identity.ID) string {
		t.Helper()
		var state string
		must(db.QueryRow("SELECT state FROM routes WHERE id=?", id[:]).Scan(&state))
		return state
	}
	if routeState(subnet.ID) != "withdrawn" || routeState(exit.ID) != "advertised" {
		t.Fatal("capability removal did not withdraw exactly the affected routes")
	}
	const probe = "/v1/revocations/"
	doProto(observer, "GET", rustURL, probe+serial, nil, 204)
	before = epoch()
	send(rustURL, "POST", list+"/"+serial+"/revoke", `{"reason":"rotated"}`, revoker, 200)
	send(rustURL, "POST", list+"/"+serial+"/revoke", `{"reason":"rotated"}`, revoker, 409)
	received := doProto(observer, "GET", rustURL, probe+serial, nil, 200)
	reference := doProto(observer, "GET", goURL, probe+serial, nil, 200)
	if !bytes.Equal(received, reference) || epoch() != before+1 {
		t.Fatal("workload revocation record differs from Go")
	}
	doProto(targetClient, "GET", rustURL, probe+serial, nil, 403)
	doProto(fresh, "GET", rustURL, probe+freshSerial, nil, 204)
	doProto(outsider, "GET", rustURL, probe+serial, nil, 404)

	_, err = db.Exec("CREATE TRIGGER fail_node_audit BEFORE INSERT ON audit_events WHEN NEW.action='node.revoke' BEGIN SELECT RAISE(ABORT,'lab'); END")
	must(err)
	before = epoch()
	send(rustURL, "POST", nodePath+"/revoke", `{"reason":"retired"}`, operator, 500)
	_, err = db.Exec("DROP TRIGGER fail_node_audit")
	must(err)
	doProto(fresh, "GET", rustURL, probe+freshSerial, nil, 204)
	if routeState(exit.ID) != "advertised" || epoch() != before {
		t.Fatal("failed node revocation leaked a route or epoch change")
	}
	send(rustURL, "POST", nodePath+"/revoke", `{"reason":"retired"}`, operatorBot, 200)
	send(rustURL, "POST", nodePath+"/revoke", `{"reason":"retired"}`, operator, 409)
	caps(0, operator, 404)
	doProto(fresh, "GET", rustURL, probe+freshSerial, nil, 403)
	doProto(observer, "GET", rustURL, probe+freshSerial, nil, 200)
	var addresses int
	must(db.QueryRow("SELECT count(*) FROM overlay_addresses WHERE node_id=? AND released_at IS NULL", target[:]).Scan(&addresses))
	if addresses != 0 || routeState(exit.ID) != "withdrawn" || epoch() != before+1 {
		t.Fatal("node revocation left active addresses or routes")
	}
	compare(list, reader)
}
