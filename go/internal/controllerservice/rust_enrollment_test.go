//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/protocol"
	"google.golang.org/protobuf/proto"
)

func labRedeem(t *testing.T, client *http.Client, server string, msg *v1.EnrollmentRequest, want int) *v1.EnrollmentResponse {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var res *http.Response
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(t.Context(), "POST", server+"/v1/enroll", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		res, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		// The other interop cases use the same loopback source. Retry only
		// explicit pre-admission throttling, never an ambiguous redemption.
		if res.StatusCode != 429 || want == 429 || attempt == 3 || res.Header.Get("Retry-After") != "1" {
			break
		}
		res.Body.Close()
		select {
		case <-time.After(time.Second):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		t.Fatalf("redeem: HTTP %d, want %d", res.StatusCode, want)
	}
	if want != 201 {
		return nil
	}
	data, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	reply := new(v1.EnrollmentResponse)
	if err := proto.Unmarshal(data, reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func testRustEnrollmentIssuance(t *testing.T, f fixture, client *http.Client, goURL, rustURL, token, csrf string) {
	send := labManagementHTTP(t, client)
	const issue = "/v1/admin/enrollment-tokens"
	root := labCredentials{bearer: testRootBearer}
	owner := labCredentials{session: token, csrf: csrf}
	web := func(role string) (labCredentials, string) {
		t.Helper()
		candidate, err := f.store.AdministratorPasswordCandidate(t.Context(), "web-"+role)
		if err != nil {
			t.Fatal(err)
		}
		s, tok, proof, err := f.store.CreateAdministratorSessionAfterPassword(t.Context(), candidate, controller.AdministratorSessionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return labCredentials{session: tok, csrf: proof}, s.PrincipalID.String()
	}
	operator, operatorID := web("operator")
	auditor, _ := web("auditor")
	other, err := f.store.CreateNetwork(t.Context(), "ungranted-enrollment", netip.MustParsePrefix("10.211.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	netID := f.network.ID.String()
	expiry := time.Now().Add(time.Hour).Unix()
	jsonBody := func(in any) string {
		t.Helper()
		data, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	principal := send(goURL, "POST", "/v1/admin/service-principals", jsonBody(map[string]any{"name": "enrollment-bot", "permissions": []string{"enrollment.issue"}, "network_ids": []string{netID}}), root, 201)["principal_id"].(string)
	automationResponse := send(goURL, "POST", "/v1/admin/service-principals/"+principal+"/tokens", jsonBody(map[string]any{"label": "lab", "expires_at_unix_seconds": expiry}), root, 201)
	automation := labCredentials{bearer: automationResponse["access_token"].(string)}
	userID := send(goURL, "POST", "/v1/admin/networks/"+netID+"/users", `{"name":"invited-user"}`, root, 201)["user_id"].(string)
	state, err := f.store.AdministratorAuthState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		class, user, kind, actor string
		c                        labCredentials
		wire                     v1.EnrollmentClass
		caps                     uint64
		lifetime                 int64
	}{
		{"durable", "", "service_principal", state.RootServicePrincipalID.String(), root, v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE, uint64(protocol.CapabilitySubnetRouterV1), 0},
		{"remembered", userID, "administrator", operatorID, operator, v1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER, 0, 0},
		{"ephemeral", "", "service_principal", principal, automation, v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER, uint64(protocol.CapabilityExitNodeV1), 300},
	} {
		name := "interop-" + tc.class
		form := tokenRequest{NetworkID: netID, UserID: tc.user, Label: "lab", ExpiresAtUnix: expiry, RequestedName: name, EnrollmentClass: tc.class, SessionLifetimeSeconds: tc.lifetime, EnabledCapabilities: tc.caps}
		if tc.class == "durable" {
			form.EnrollmentClass = ""
		}
		reference := send(goURL, "POST", issue, jsonBody(form), tc.c, 201)
		got := send(rustURL, "POST", issue, jsonBody(form), tc.c, 201)
		secret := got["enrollment_token"].(string)
		id := got["token_id"].(string)
		for _, v := range []map[string]any{got, reference} {
			delete(v, "enrollment_token")
			delete(v, "token_id")
		}
		if !reflect.DeepEqual(got, reference) {
			t.Fatal("issuance response fields differ from Go")
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
		if err != nil || len(raw) != 32 {
			t.Fatal("unexpected token encoding")
		}
		digest := sha256.Sum256(raw)
		var stored []byte
		var details string
		err = db.QueryRow(`SELECT e.token_hash,a.details_json FROM enrollment_tokens e JOIN audit_events a ON a.target_id=e.id AND a.network_id=e.network_id WHERE lower(hex(e.id))=? AND a.action='enrollment_token.issue' AND a.target_type='enrollment_token' AND a.actor_kind=? AND lower(hex(a.actor_id))=? AND e.created_at=a.created_at AND e.consumed_at IS NULL`, id, tc.kind, tc.actor).Scan(&stored, &details)
		if err != nil || !bytes.Equal(stored, digest[:]) || strings.Contains(details, secret) {
			t.Fatalf("stored digest or audit mismatch: %v", err)
		}
		expected := map[string]any{"enrollment_class": tc.class, "requested_name": name, "enabled_capabilities": float64(tc.caps)}
		if tc.lifetime != 0 {
			expected["session_lifetime_seconds"] = float64(tc.lifetime)
		}
		var audit map[string]any
		if json.Unmarshal([]byte(details), &audit) != nil || !reflect.DeepEqual(audit, expected) {
			t.Fatal("wrong enrollment audit detail")
		}
		msg := &v1.EnrollmentRequest{EnrollmentToken: secret, ExpectedNetworkId: f.network.ID[:], ExpectedEnrollmentClass: tc.wire, Pkcs10CsrDer: csrDER(t, ""), WireguardPublicKey: testWireGuardPublicKey(t)}
		if tc.class == "remembered" {
			msg.ExpectedNetworkId = other.ID[:]
			labRedeem(t, client, goURL, msg, 403)
			msg.ExpectedNetworkId = f.network.ID[:]
			msg.RequestedName = "wrong"
			labRedeem(t, client, goURL, msg, 403)
			msg.RequestedName = ""
			msg.ExpectedEnrollmentClass = v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
			labRedeem(t, client, goURL, msg, 403)
			msg.ExpectedEnrollmentClass = tc.wire
		}
		res := labRedeem(t, client, goURL, msg, 201)
		labRedeem(t, client, goURL, msg, 409)
		leaf := parseLeaf(t, res.GetCertificateChain())
		subject, err := identity.IdentityFromCertificate(leaf)
		if err != nil || subject.NetworkID != f.network.ID || !bytes.Equal(subject.NodeID[:], res.NodeId) || leaf.CheckSignatureFrom(f.service.ca) != nil || res.EnrollmentClass != tc.wire || len(res.OverlayAddresses) == 0 || !bytes.Equal(res.WireguardPublicKey, msg.WireguardPublicKey) {
			t.Fatal("Go did not return the expected signed node identity")
		}
		node, err := f.store.Node(t.Context(), subject.NodeID)
		if err != nil || node.Name != name || string(node.EnrollmentClass) != tc.class || node.EnabledCapabilities != tc.caps || (node.UserID == nil) != (tc.user == "") || (node.UserID != nil && node.UserID.String() != tc.user) {
			t.Fatal("redeemed grant differs from issued grant")
		}
		if tc.lifetime > 0 && (node.LeaseExpiresAt == nil || leaf.NotAfter.Unix() != node.CreatedAt.Unix()+tc.lifetime || !leaf.NotAfter.Equal(*node.LeaseExpiresAt) || res.EphemeralExitLeaseGeneration == 0) {
			t.Fatal("ephemeral exit did not receive the bounded lease")
		}
	}

	valid := map[string]any{"network_id": netID, "expires_at_unix_seconds": expiry}
	test := func(c labCredentials, patch map[string]any, status int) {
		t.Helper()
		form := map[string]any{}
		for k, v := range valid {
			form[k] = v
		}
		for k, v := range patch {
			form[k] = v
		}
		a := send(goURL, "POST", issue, jsonBody(form), c, status)
		b := send(rustURL, "POST", issue, jsonBody(form), c, status)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("error mismatch for HTTP %d", status)
		}
	}
	test(auditor, nil, 403)
	test(labCredentials{session: token, csrf: "wrong"}, nil, 403)
	test(labCredentials{}, nil, 401)
	test(automation, map[string]any{"network_id": other.ID.String()}, 403)
	test(operator, map[string]any{"network_id": other.ID.String()}, 403)
	test(root, map[string]any{"network_id": "0"}, 400)
	test(root, map[string]any{"network_id": strings.Repeat("e", 32)}, 404)
	test(owner, map[string]any{"user_id": "0"}, 400)
	test(root, map[string]any{"user_id": strings.Repeat("e", 32)}, 404)
	test(root, map[string]any{"network_id": other.ID.String(), "user_id": userID}, 404)
	test(root, map[string]any{"expires_at_unix_seconds": time.Now().Unix() - 1}, 400)
	test(root, map[string]any{"expires_at_unix_seconds": expiry + 30*86400}, 400)
	test(root, map[string]any{"label": strings.Repeat("a", 257)}, 400)
	test(root, map[string]any{"requested_name": "not trimmed "}, 400)
	test(root, map[string]any{"enabled_capabilities": 1}, 400)
	test(root, map[string]any{"enrollment_class": "unknown"}, 400)
	test(root, map[string]any{"session_lifetime_seconds": 300}, 400)
	for _, s := range []int64{299, 86401} {
		test(owner, map[string]any{"enrollment_class": "ephemeral", "session_lifetime_seconds": s}, 400)
	}
	test(root, map[string]any{"enrollment_class": "ephemeral", "session_lifetime_seconds": 300, "enabled_capabilities": 24}, 400)
	pending := send(rustURL, "POST", issue, jsonBody(tokenRequest{NetworkID: netID, UserID: userID, ExpiresAtUnix: expiry, RequestedName: "pending-user"}), owner, 201)
	send(goURL, "PATCH", "/v1/admin/users/"+userID, `{"enabled":false}`, root, 200)
	test(root, map[string]any{"user_id": userID}, 409)
	if _, err := f.store.EnrollNode(t.Context(), pending["enrollment_token"].(string), "pending-user", 0); !errors.Is(err, controller.ErrTokenInvalid) {
		t.Fatalf("disabled user could still redeem pending token: %v", err)
	}
	tokenID := automationResponse["token"].(map[string]any)["token_id"].(string)
	send(goURL, "POST", "/v1/admin/service-access-tokens/"+tokenID+"/revoke", `{"reason":"fixture complete"}`, root, 204)
	test(automation, nil, 401)
	// Advance just this disposable credential to its exact expiry boundary.
	expired := send(rustURL, "POST", issue, jsonBody(tokenRequest{NetworkID: netID, ExpiresAtUnix: expiry, RequestedName: "expired-token"}), root, 201)
	if _, err = db.Exec("UPDATE enrollment_tokens SET created_at=unixepoch()-60, expires_at=unixepoch() WHERE lower(hex(id))=?", expired["token_id"]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.EnrollNode(t.Context(), expired["enrollment_token"].(string), "expired-token", 0); !errors.Is(err, controller.ErrTokenExpired) {
		t.Fatalf("expired Rust-issued token: %v", err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_token_audit BEFORE INSERT ON audit_events WHEN NEW.action='enrollment_token.issue' BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	rejected := send(rustURL, "POST", issue, jsonBody(tokenRequest{NetworkID: netID, Label: "no-leak", ExpiresAtUnix: expiry}), owner, 500)
	var n int
	if _, leaked := rejected["enrollment_token"]; leaked {
		t.Fatal("credential returned despite failed commit")
	}
	if err = db.QueryRow("SELECT count(*) FROM enrollment_tokens WHERE label='no-leak'").Scan(&n); err != nil || n != 0 {
		t.Fatal("audit failure left a usable token")
	}
	if _, err = db.Exec("DROP TRIGGER reject_token_audit"); err != nil {
		t.Fatal(err)
	}
}
