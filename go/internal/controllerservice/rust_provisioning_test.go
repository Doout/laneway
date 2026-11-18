//go:build rustinterop

package controllerservice

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/protocol"
)

func testRustProvisioning(t *testing.T, f fixture, client *http.Client, goURL, rustURL, session, csrf string) {
	t.Helper()
	root := labCredentials{bearer: testRootBearer}
	web := labCredentials{session: session, csrf: csrf}
	send := labManagementHTTP(t, client)
	body := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlRun := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	issueAccess := func(operation string, scoped bool) labCredentials {
		t.Helper()
		params := map[string]any{"name": "provision-" + strings.Split(operation, ".")[0], "permissions": []string{operation}}
		if scoped {
			params["network_ids"] = []string{f.network.ID.String()}
		}
		principal := send(goURL, "POST", "/v1/admin/service-principals", body(params), root, 201)["principal_id"].(string)
		fields := body(map[string]any{"label": "lab", "expires_at_unix_seconds": time.Now().Add(time.Hour).Unix()})
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+principal+"/tokens", fields, root, 201)["access_token"].(string)}
	}

	installer := "/v1/admin/networks/" + f.network.ID.String() + "/node-installers"
	connector := issueAccess("enrollment.issue", true)
	artifact := issueAccess("bootstrap_bundle.create", false)
	send(rustURL, "POST", installer, `{"name":"unsupported","kind":"node","install_mode":"container"}`, root, 422)
	send(rustURL, "POST", installer, `{"name":"unsupported","kind":"unknown","install_mode":"systemd"}`, root, 400)
	send(rustURL, "POST", installer, `{"name":"denied","kind":"node","install_mode":"systemd"}`, artifact, 403)
	send(rustURL, "POST", "/v1/admin/networks/abcabcabcabcabcabcabcabcabcabcab/node-installers",
		`{"name":"denied","kind":"node","install_mode":"systemd"}`, connector, 403)
	secretPattern := regexp.MustCompile(`printf %s '([A-Za-z0-9_-]{43})' > "\$token_file"`)
	for _, test := range []struct {
		kind string
		caps protocol.Capability
		auth labCredentials
	}{
		{"node", 0, web}, {"connector", protocol.CapabilitySubnetRouterV1, connector},
		{"exit", protocol.CapabilityExitNodeV1, root},
	} {
		name := "fixture'" + test.kind
		res := send(rustURL, "POST", installer, body(map[string]string{"name": name, "kind": test.kind, "install_mode": "systemd"}), test.auth, 201)
		command := res["command"].(string)
		match := secretPattern.FindStringSubmatch(command)
		if len(match) != 2 || !strings.Contains(command, "sudo laneway node install '"+rustURL+"'") ||
			!strings.HasSuffix(command, `--name 'fixture'"'"'`+test.kind+"'") {
			t.Fatal("installer did not safely quote its URL, name, and enrollment code")
		}
		var boundName, class string
		var capabilities, lifetime int64
		err := db.QueryRowContext(t.Context(), `SELECT requested_name,enrollment_class,enabled_capabilities,expires_at-created_at
			FROM enrollment_tokens WHERE lower(hex(id))=? AND lower(hex(network_id))=?`, res["installation_id"], f.network.ID.String()).
			Scan(&boundName, &class, &capabilities, &lifetime)
		if err != nil || boundName != name || class != "durable" || capabilities != int64(test.caps) || lifetime != 600 {
			t.Fatalf("installer binding differs from the enrollment contract: %v", err)
		}
		if test.kind == "connector" {
			msg := &v1.EnrollmentRequest{EnrollmentToken: match[1], ExpectedNetworkId: f.network.ID[:],
				ExpectedEnrollmentClass: v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE,
				Pkcs10CsrDer:            csrDER(t, ""), WireguardPublicKey: testWireGuardPublicKey(t)}
			reply := labRedeem(t, client, goURL, msg, 201)
			nodeID := identity.NodeID(reply.NodeId)
			node, err := f.store.Node(t.Context(), nodeID)
			if err != nil || node.Name != name || node.EnabledCapabilities != uint64(test.caps) {
				t.Fatal("Go did not enroll the connector with its bound name and capability")
			}
		}
	}

	const bundleRoute = "/v1/admin/bootstrap-bundles"
	const script = "#!/bin/bash\n# lab encrypted-wrapper fixture\n:\n"
	expires := time.Now().Add(5 * time.Minute).Unix()
	payload := body(map[string]any{"payload": script, "expires_at_unix_seconds": expires})
	send(rustURL, "POST", bundleRoute, payload, connector, 403)
	send(rustURL, "POST", bundleRoute, body(map[string]any{"payload": "not bash", "expires_at_unix_seconds": expires}), root, 400)
	send(rustURL, "POST", bundleRoute, body(map[string]any{"payload": script, "expires_at_unix_seconds": time.Now().Unix() - 1}), root, 400)
	candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-auditor")
	if err != nil {
		t.Fatal(err)
	}
	_, auditToken, auditCSRF, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	send(rustURL, "POST", bundleRoute, payload, labCredentials{session: auditToken, csrf: auditCSRF}, 403)
	sqlRun(`CREATE TRIGGER lab_bootstrap_abort BEFORE INSERT ON audit_events
		WHEN NEW.action='bootstrap_bundle.create' BEGIN SELECT RAISE(ABORT,'lab rollback'); END`)
	send(rustURL, "POST", bundleRoute, payload, web, 500)
	sqlRun("DROP TRIGGER lab_bootstrap_abort")

	service, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	material, _, err := pki.IssueService(f.service.ca, f.service.caKey,
		pki.ServiceIdentity{NetworkID: f.network.ID, ServiceID: service, Role: pki.RoleRelay},
		nil, nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{material.CertificateDER}, PrivateKey: material.PrivateKey}}
	relayHTTP := &http.Client{Transport: tr, Timeout: client.Timeout}
	defer relayHTTP.CloseIdleConnections()
	fetch := func(c *http.Client, base, method, path string, want int) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("bootstrap fetch got HTTP %d, expected %d: %v", resp.StatusCode, want, err)
		}
		if want == 200 && (string(b) != script || resp.Header.Get("Content-Type") != "text/x-shellscript; charset=utf-8") {
			t.Fatal("authorized fetch returned the wrong wrapper or media type")
		}
	}
	private := func(base string, caller labCredentials) string {
		t.Helper()
		b := send(base, "POST", bundleRoute, payload, caller, 201)
		id := b["bundle_id"].(string)
		if len(id) != 43 || b["public_path"] != "/.well-known/laneway/bootstrap/"+id || b["expires_at_unix_seconds"] != float64(expires) {
			t.Fatal("invalid bootstrap capability envelope")
		}
		return "/v1/bootstrap-bundles/" + id
	}
	path := private(rustURL, artifact)
	fetch(client, rustURL, "GET", path, 401)
	fetch(relayHTTP, rustURL, "GET", path, 401)
	relay, _, err := f.store.RegisterRelay(t.Context(), f.network.ID, service, nil, "provisioning-relay", "provisioning.example:4433")
	if err != nil {
		t.Fatal(err)
	}
	fetch(relayHTTP, rustURL, "HEAD", path, 405)
	fetch(relayHTTP, rustURL, "GET", path+"?not-allowed=true", 404)
	fetch(relayHTTP, rustURL, "GET", path, 200)
	fetch(relayHTTP, rustURL, "GET", path, 404)
	fetch(relayHTTP, goURL, "GET", private(goURL, web), 200)
	second := private(rustURL, web)
	if _, err := f.store.DisableRelay(t.Context(), relay.ID); err != nil {
		t.Fatal(err)
	}
	fetch(relayHTTP, rustURL, "GET", second, 401)
	var recorded int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_events WHERE action='bootstrap_bundle.create'
		AND target_id IS NULL AND details_json='{"storage":"ephemeral"}'`).Scan(&recorded); err != nil || recorded != 3 {
		t.Fatalf("incorrect bootstrap audit count: %d (%v)", recorded, err)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM audit_events WHERE instr(details_json,?)>0", script).Scan(&recorded); err != nil || recorded != 0 {
		t.Fatal("bootstrap payload appeared in the audit log")
	}
}
