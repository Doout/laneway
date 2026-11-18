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
	"strconv"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/nodelocation"
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
	enroll := func(network identity.NetworkID, name string, ephemeralExit bool) (identity.NodeID, *v1.CertificateChain, ed25519.PrivateKey, []byte) {
		t.Helper()
		options := controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable}
		class := v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
		if ephemeralExit {
			options.Class = controller.EnrollmentClassEphemeral
			options.SessionLifetime = 5 * time.Minute
			options.EnabledCapabilities = uint64(protocol.CapabilityExitNodeV1)
			class = v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
		}
		token, err := f.store.IssueEnrollmentTokenWithOptions(ctx, network, name, time.Now().Add(time.Hour), options)
		must(err)
		_, key, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		must(err)
		out := labRedeem(t, client, goURL, &v1.EnrollmentRequest{
			RequestedName: name, EnrollmentToken: token.Secret, Pkcs10CsrDer: csr, ExpectedNetworkId: network[:],
			ExpectedEnrollmentClass: class,
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
		if want == http.StatusNotModified {
			end, err := strconv.ParseInt(resp.Header.Get(SnapshotValidityHeader), 10, 64)
			must(err)
			if len(got) != 0 || end <= time.Now().Unix() {
				t.Fatalf("invalid HTTPS configuration lease: %d, body %x", end, got)
			}
		}
		return got
	}
	target, chain, key, csr := enroll(net, "device-target", false)
	targetClient := asClient(chain, key)
	observerID, observerChain, observerKey, _ := enroll(net, "device-observer", false)
	observer := asClient(observerChain, observerKey)
	foreign, foreignChain, foreignKey, _ := enroll(other.ID, "device-outsider", false)
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
	nodeReader := bot("node.read")
	health := "/v1/admin/networks/" + net.String() + "/endpoint-statuses"
	status := func(name string) map[string]any {
		t.Helper()
		a := send(goURL, "GET", health, "", nodeReader, 200)
		b := send(rustURL, "GET", health, "", auditor, 200)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("endpoint status mismatch: Go=%#v Rust=%#v", a, b)
		}
		for _, raw := range b["endpoint_statuses"].([]any) {
			record := raw.(map[string]any)
			if record["node_name"] == name {
				return record
			}
		}
		t.Fatalf("endpoint status missing for %s", name)
		return nil
	}
	report := func(epoch uint64, version string) string {
		return fmt.Sprintf(`{"valid_for_seconds":30,"product_version":%q,"platform":"linux","certificate_state":"healthy",
			"configuration_state":"current","carrier_state":"relay_quic","route_state":"ready","selected_exit_state":"not_selected",
			"cleanup_failure_count":0,"configuration_epoch":%d}`, version, epoch)
	}
	publish := func(c *http.Client, base, data string, want int) {
		t.Helper()
		labManagementHTTP(t, c)(base, "PUT", "/v1/status", data, labCredentials{}, want)
	}
	send(rustURL, "GET", health, "", operatorBot, 403)
	send(rustURL, "GET", "/v1/admin/networks/"+other.ID.String()+"/endpoint-statuses", "", nodeReader, 403)
	if got := status("device-observer"); got["freshness"] != "never_reported" || got["report"] != nil {
		t.Fatalf("node without a report did not remain unknown: %#v", got)
	}
	publish(client, rustURL, "not JSON", 401)
	publish(fresh, rustURL, `{"node_id":"cannot claim another node"}`, 400)
	publish(fresh, rustURL, report(before+1, "future"), 409)
	publish(fresh, rustURL, report(before-1, "older"), 204)
	staleHealth := status("device-target")
	if staleHealth["freshness"] != "current" ||
		staleHealth["report"].(map[string]any)["configuration_state"] != "stale" {
		t.Fatalf("older epoch did not project stale configuration: %#v", staleHealth)
	}
	publish(fresh, goURL, report(before, "latest"), 204)
	if got := status("device-target")["report"].(map[string]any)["product_version"]; got != "latest" {
		t.Fatalf("latest report written through Go was not shown in Rust: %v", got)
	}
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
	const config = "/v1/configuration"
	configReq := func(epoch, generation uint64) []byte {
		t.Helper()
		data, err := proto.Marshal(&v1.ConfigurationRequest{
			KnownConfigurationEpoch: epoch, EphemeralExitLeaseGeneration: generation,
		})
		must(err)
		return data
	}
	loadConfig := func(base string, known uint64) *v1.NodeConfiguration {
		t.Helper()
		snapshot := new(v1.NodeConfiguration)
		must(proto.Unmarshal(doProto(fresh, "POST", base, config, configReq(known, 0), 200), snapshot))
		return snapshot
	}
	hasSubnet := func(snapshot *v1.NodeConfiguration) bool {
		for _, route := range snapshot.GetRoutes().GetRoutes() {
			if bytes.Equal(route.GetViaNodeId(), target[:]) &&
				bytes.Equal(route.GetDestination().GetAddress(), subnet.Prefix.Addr().AsSlice()) &&
				route.GetDestination().GetPrefixLength() == uint32(subnet.Prefix.Bits()) {
				return true
			}
		}
		return false
	}
	referenceConfig, rustConfig := loadConfig(goURL, 0), loadConfig(rustURL, 0)
	if !hasSubnet(referenceConfig) || !hasSubnet(rustConfig) ||
		rustConfig.ConfigurationEpoch != referenceConfig.ConfigurationEpoch ||
		rustConfig.EnabledCapabilities != referenceConfig.EnabledCapabilities ||
		!reflect.DeepEqual(rustConfig.OverlayAddresses, referenceConfig.OverlayAddresses) {
		t.Fatal("Rust HTTPS configuration differs from Go for the live node")
	}
	doProto(fresh, "POST", rustURL, config, configReq(rustConfig.ConfigurationEpoch, 0), 304)
	doProto(client, "POST", rustURL, config, nil, 401)
	doProto(fresh, "POST", rustURL, config, configReq(rustConfig.ConfigurationEpoch, 1), 400)
	var stale v1.ProtocolError
	must(proto.Unmarshal(doProto(fresh, "POST", rustURL, config, configReq(rustConfig.ConfigurationEpoch+1, 0), 409), &stale))
	if stale.Code != v1.ErrorCode_ERROR_CODE_STALE_EPOCH {
		t.Fatalf("unexpected stale epoch error: %s", stale.Code)
	}
	caps(protocol.CapabilityExitNodeV1, operator, 200)
	if snapshot := loadConfig(rustURL, rustConfig.ConfigurationEpoch); hasSubnet(snapshot) ||
		snapshot.ConfigurationEpoch != rustConfig.ConfigurationEpoch+1 {
		t.Fatal("capability removal did not invalidate the HTTPS snapshot and withdraw the route")
	}
	db, err := sql.Open("sqlite", f.dbPath)
	must(err)
	defer db.Close()
	var reportsCount int
	must(db.QueryRow("SELECT count(*) FROM endpoint_status_latest WHERE node_id=?", target[:]).Scan(&reportsCount))
	if reportsCount != 1 {
		t.Fatalf("expected a single retained observation, got %d", reportsCount)
	}
	_, err = db.Exec("UPDATE endpoint_status_latest SET observed_at=unixepoch()-30, expires_at=unixepoch() WHERE node_id=?", target[:])
	must(err)
	if got := status("device-target"); got["freshness"] != "expired" || got["report"] != nil || got["last_reported_at_unix_seconds"] == nil {
		t.Fatalf("expired report leaked runtime health or lost its timestamp: %#v", got)
	}
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
	doProto(targetClient, "POST", rustURL, config, nil, 403)
	publish(targetClient, rustURL, "not JSON", 403)
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
	publish(fresh, rustURL, report(epoch(), "revoked"), 403)
	if got := status("device-target"); got["freshness"] != "node_inactive" || got["report"] != nil {
		t.Fatalf("revoked node still displayed live health: %#v", got)
	}
	doProto(observer, "GET", rustURL, probe+freshSerial, nil, 200)
	var addresses int
	must(db.QueryRow("SELECT count(*) FROM overlay_addresses WHERE node_id=? AND released_at IS NULL", target[:]).Scan(&addresses))
	if addresses != 0 || routeState(exit.ID) != "withdrawn" || epoch() != before+1 {
		t.Fatal("node revocation left active addresses or routes")
	}
	compare(list, reader)

	t.Run("map-locations", func(t *testing.T) {
		path := "/v1/admin/networks/" + net.String() + "/node-locations"
		edit := "/v1/admin/nodes/" + observerID.String() + "/location"
		location := func() map[string]any {
			t.Helper()
			a := send(goURL, "GET", path, "", auditor, 200)
			b := send(rustURL, "GET", path, "", nodeReader, 200)
			if !reflect.DeepEqual(a, b) || b["automatic_enabled"] != true || b["location_provider"] != "maxmind" {
				t.Fatalf("map inventory differs: Go=%#v Rust=%#v", a, b)
			}
			for _, row := range b["node_locations"].([]any) {
				r := row.(map[string]any)
				if r["node_id"] == observerID.String() {
					return r
				}
			}
			t.Fatal("node missing from map inventory")
			return nil
		}
		if v := location(); v["online"] != false || v["identity_active"] != true || v["source"] != "unknown" {
			t.Fatalf("unenriched node misclassified: %#v", v)
		}
		body := `{"label":"Equator","latitude":0,"longitude":0}`
		send(rustURL, "PUT", edit, body, auditor, 403)
		send(rustURL, "PUT", "/v1/admin/nodes/"+foreign.String()+"/location", body, operatorBot, 404)
		send(rustURL, "PUT", edit, `{"label":"missing","latitude":0}`, operator, 400)
		send(rustURL, "PUT", edit, `{"label":"invalid","latitude":91,"longitude":0}`, operator, 400)
		before := epoch()
		send(rustURL, "PUT", edit, body, operator, 204)
		must(f.store.RecordNodeLocation(ctx, identity.NodeIdentity{NetworkID: net, NodeID: observerID},
			&nodelocation.Location{Label: "London, GB", Latitude: 51.5, Longitude: -0.1, AccuracyKM: 20},
			time.Now().Add(-25*time.Hour), "81.2.69.142"))
		if v := location(); v["source"] != "manual" || v["stale"] != false ||
			v["location"].(map[string]any)["latitude"] != float64(0) || v["online"] != false {
			t.Fatalf("manual location changed presence or lost zero coordinate: %#v", v)
		}
		_, err := db.Exec("CREATE TRIGGER fail_location_audit BEFORE INSERT ON audit_events WHEN NEW.action='node.location.clear' BEGIN SELECT RAISE(ABORT,'lab'); END")
		must(err)
		send(rustURL, "DELETE", edit, "", operatorBot, 500)
		_, err = db.Exec("DROP TRIGGER fail_location_audit")
		must(err)
		if v := location(); v["source"] != "manual" {
			t.Fatalf("failed audit still cleared an override: %#v", v)
		}
		send(rustURL, "DELETE", edit, "", operatorBot, 204)
		if v := location(); v["source"] != "ip" || v["stale"] != true ||
			v["public_ip"] != "81.2.69.142" || v["location"].(map[string]any)["accuracy_km"] != float64(20) {
			t.Fatalf("clear did not reveal the last automatic observation: %#v", v)
		}
		send(goURL, "PUT", edit, body, operator, 204)
		request, err := http.NewRequestWithContext(ctx, "PUT", rustURL+"/v1/status",
			bytes.NewBufferString(report(before, "presence")))
		must(err)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Forwarded-For", "81.2.69.142")
		request.Header.Set("X-Real-IP", "81.2.69.142")
		request.Header.Set("Forwarded", "for=81.2.69.142")
		response, err := observer.Do(request)
		must(err)
		response.Body.Close()
		if response.StatusCode != 204 {
			t.Fatalf("authenticated status response=%d", response.StatusCode)
		}
		if v := location(); v["source"] != "manual" || v["online"] != true || v["public_ip"] != nil {
			t.Fatalf("private TLS peer trusted a header or lost manual location: %#v", v)
		}
		send(rustURL, "DELETE", edit, "", operatorBot, 204)
		if v := location(); v["source"] != "unknown" || v["online"] != true || v["location"] != nil || epoch() != before {
			t.Fatalf("presence changed from an override or inferred a location for a private peer: %#v", v)
		}
	})

	exitID, exitChain, exitKey, _ := enroll(other.ID, "device-ephemeral-exit", true)
	exitSession, err := f.store.EphemeralExitSession(ctx, exitID)
	must(err)
	exitClient := asClient(exitChain, exitKey)
	doProto(exitClient, "POST", goURL, config, configReq(0, exitSession.Generation), 403)
	doProto(exitClient, "POST", rustURL, config, configReq(0, exitSession.Generation), 403)
}
