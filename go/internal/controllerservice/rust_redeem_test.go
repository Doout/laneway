//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"google.golang.org/protobuf/proto"
)

// A Go client sends protobuf over real TLS. No DB changes are mocked: Go
// creates the invitations and reads the Rust commits through its own store.
func testRustRedemption(t *testing.T, f fixture, client *http.Client, rustURL, goURL string) {
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n, err := f.store.CreateNetworkDualStack(t.Context(), "rust-redeem", netip.MustParsePrefix("10.212.0.0/29"), netip.MustParsePrefix("fd00:212::/120"))
	if err != nil {
		t.Fatal(err)
	}
	userID, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO access_users(id,network_id,name,created_at,updated_at) VALUES(?,?,'member',unixepoch(),unixepoch())", userID[:], n.ID[:]); err != nil {
		t.Fatal(err)
	}
	newInvite := func(name string, class controller.EnrollmentClass, wire v1.EnrollmentClass, caps uint64) *v1.EnrollmentRequest {
		opts := controller.EnrollmentTokenOptions{RequestedName: name, Class: class, EnabledCapabilities: caps}
		if class == controller.EnrollmentClassRemembered {
			opts.UserID = &userID
		}
		if class == controller.EnrollmentClassEphemeral {
			opts.SessionLifetime = 5 * time.Minute
		}
		tok, err := f.store.IssueEnrollmentTokenWithOptions(t.Context(), n.ID, "test", time.Now().Add(time.Hour), opts)
		if err != nil {
			t.Fatal(err)
		}
		return &v1.EnrollmentRequest{EnrollmentToken: tok.Secret, Pkcs10CsrDer: csrDER(t, ""), ExpectedNetworkId: n.ID[:], ExpectedEnrollmentClass: wire, WireguardPublicKey: testWireGuardPublicKey(t)}
	}
	post := func(url string, msg *v1.EnrollmentRequest) (int, []byte, error) {
		data, err := proto.Marshal(msg)
		if err != nil {
			return 0, nil, err
		}
		for i := 0; i < 5; i++ {
			req, err := http.NewRequestWithContext(t.Context(), "POST", url+"/v1/enroll", bytes.NewReader(data))
			if err != nil {
				return 0, nil, err
			}
			req.Header.Set("Content-Type", "application/protobuf")
			res, err := client.Do(req)
			if err != nil {
				return 0, nil, err
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return 0, nil, err
			}
			if res.Header.Get("Content-Type") != "application/x-protobuf" {
				return 0, nil, fmt.Errorf("not a protobuf reply: HTTP %d", res.StatusCode)
			}
			if res.StatusCode != 429 {
				return res.StatusCode, body, nil
			}
			if res.Header.Get("Retry-After") != "1" {
				return 0, nil, fmt.Errorf("missing retry interval")
			}
			time.Sleep(time.Second)
		}
		return 0, nil, fmt.Errorf("enrollment admission timed out")
	}
	check := func(msg *v1.EnrollmentRequest, want int) *v1.EnrollmentResponse {
		t.Helper()
		status, data, err := post(rustURL, msg)
		if err != nil || status != want {
			t.Fatalf("enroll: HTTP %d, want %d: %v", status, want, err)
		}
		if status != 201 {
			var e v1.ProtocolError
			if proto.Unmarshal(data, &e) != nil || e.Code == 0 || e.Detail == "" {
				t.Fatal("missing protocol error")
			}
			return nil
		}
		r := new(v1.EnrollmentResponse)
		if err := proto.Unmarshal(data, r); err != nil {
			t.Fatal(err)
		}
		leaf := parseLeaf(t, r.CertificateChain)
		id, err := identity.IdentityFromCertificate(leaf)
		if err != nil || leaf.CheckSignatureFrom(f.service.ca) != nil || !bytes.Equal(id.NodeID[:], r.NodeId) || id.NetworkID != n.ID || !bytes.Equal(r.NetworkId, n.ID[:]) || r.EnrollmentClass != msg.ExpectedEnrollmentClass || !bytes.Equal(r.WireguardPublicKey, msg.WireguardPublicKey) {
			t.Fatal("Go rejected Rust identity")
		}
		node, err := f.store.Node(t.Context(), id.NodeID)
		if err != nil || len(r.OverlayAddresses) != 2 || !bytes.Equal(node.IPv4Address.AsSlice(), r.OverlayAddresses[0]) || !bytes.Equal(node.IPv6Address.AsSlice(), r.OverlayAddresses[1]) {
			t.Fatal("stored addresses differ from wire result")
		}
		var stored []byte
		if err := db.QueryRow("SELECT der FROM certificates WHERE node_id=? AND revoked_at IS NULL", r.NodeId).Scan(&stored); err != nil || !bytes.Equal(stored, leaf.Raw) {
			t.Fatal("incorrect stored certificate")
		}
		return r
	}
	const durable = v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
	const ephemeral = v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
	const remembered = v1.EnrollmentClass_ENROLLMENT_CLASS_REMEMBERED_USER
	msg := newInvite("native-exit", controller.EnrollmentClassEphemeral, ephemeral, 16)
	// Each rejected attempt must leave this same invite usable.
	msg.ExpectedNetworkId = f.network.ID[:]
	check(msg, 403)
	msg.ExpectedNetworkId = n.ID[:]
	msg.ExpectedEnrollmentClass = durable
	check(msg, 403)
	msg.ExpectedEnrollmentClass = ephemeral
	msg.RequestedName = "other"
	check(msg, 403)
	msg.RequestedName = ""
	key := msg.WireguardPublicKey
	msg.WireguardPublicKey = make([]byte, 32)
	check(msg, 400)
	msg.WireguardPublicKey = key
	msg.Pkcs10CsrDer[len(msg.Pkcs10CsrDer)-1] ^= 1
	check(msg, 400)
	msg.Pkcs10CsrDer[len(msg.Pkcs10CsrDer)-1] ^= 1
	// Force failure after node, routes, leases, addresses, cert, epoch and token writes.
	if _, err = db.Exec("CREATE TRIGGER fail_rust_certificate_audit BEFORE INSERT ON audit_events WHEN NEW.action='certificate.issue' BEGIN SELECT RAISE(ABORT,'lab'); END"); err != nil {
		t.Fatal(err)
	}
	check(msg, 500)
	var epoch, c4, c6, nodes, spent, events int
	if err = db.QueryRow(`SELECT configuration_epoch,next_ipv4,next_ipv6,(SELECT count(*) FROM nodes WHERE network_id=networks.id),(SELECT count(*) FROM enrollment_tokens WHERE network_id=networks.id AND consumed_at IS NOT NULL),(SELECT count(*) FROM audit_events WHERE network_id=networks.id AND action IN ('node.enroll','route.invited_exit.approve','ephemeral_exit.session.start','certificate.issue')) FROM networks WHERE id=?`, n.ID[:]).Scan(&epoch, &c4, &c6, &nodes, &spent, &events); err != nil || epoch != 1 || c4 != 1 || c6 != 1 || nodes+spent+events != 0 {
		t.Fatalf("partial enrollment survived: %v %d %d %d %d %d %d", err, epoch, c4, c6, nodes, spent, events)
	}
	if _, err = db.Exec("DROP TRIGGER fail_rust_certificate_audit"); err != nil {
		t.Fatal(err)
	}
	exit := check(msg, 201)
	check(msg, 409)
	var gen, lease int64
	if err = db.QueryRow("SELECT e.generation,r.valid_until FROM ephemeral_exit_sessions e JOIN routes r ON e.node_id=r.node_id WHERE e.node_id=? AND r.metric=100 AND r.state='approved'", exit.NodeId).Scan(&gen, &lease); err != nil || gen <= 0 || uint64(gen) != exit.EphemeralExitLeaseGeneration || uint64(lease) != exit.LeaseExpiresAtUnixSeconds || lease != parseLeaf(t, exit.CertificateChain).NotAfter.Unix() {
		t.Fatal("incorrect ephemeral exit session")
	}
	// Expedite expiry in this isolated DB; a new invite may then reuse its name.
	if _, err = db.Exec("UPDATE nodes SET created_at=unixepoch()-601, lease_expires_at=unixepoch()-1 WHERE id=?", exit.NodeId); err != nil {
		t.Fatal(err)
	}
	again := newInvite("native-exit", controller.EnrollmentClassRemembered, remembered, 0)
	if _, err = db.Exec("UPDATE access_users SET enabled=0 WHERE id=?", userID[:]); err != nil {
		t.Fatal(err)
	}
	check(again, 401)
	if _, err = db.Exec("UPDATE access_users SET enabled=1 WHERE id=?", userID[:]); err != nil {
		t.Fatal(err)
	}
	// Force round-robin back to the released addresses.
	if _, err = db.Exec("UPDATE networks SET next_ipv4=1,next_ipv6=1 WHERE id=?", n.ID[:]); err != nil {
		t.Fatal(err)
	}
	next := check(again, 201)
	var boundID []byte
	if err = db.QueryRow("SELECT user_id FROM nodes WHERE id=?", next.NodeId).Scan(&boundID); err != nil || !bytes.Equal(boundID, userID[:]) {
		t.Fatal("remembered user binding lost")
	}
	if !bytes.Equal(next.OverlayAddresses[0], exit.OverlayAddresses[0]) || !bytes.Equal(next.OverlayAddresses[1], exit.OverlayAddresses[1]) {
		t.Fatal("released addresses not reused")
	}
	var inactive int
	if err = db.QueryRow(`SELECT count(*) FROM nodes n JOIN certificates c ON c.node_id=n.id JOIN routes r ON r.node_id=n.id JOIN ephemeral_exit_sessions e ON e.node_id=n.id WHERE n.id=? AND n.revoked_at IS NOT NULL AND c.revoked_at IS NOT NULL AND e.terminated_at IS NOT NULL AND r.state='withdrawn'`, exit.NodeId).Scan(&inactive); err != nil || inactive != 1 {
		t.Fatal("expired authorization retained")
	}
	node := newInvite("native-router", controller.EnrollmentClassDurable, durable, 8)
	_, nodeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node.Pkcs10CsrDer, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	// Released addresses with a still-valid cert must not be reassigned.
	if _, err = db.Exec("UPDATE overlay_addresses SET released_at=unixepoch() WHERE node_id=?", next.NodeId); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE networks SET next_ipv4=1,next_ipv6=1 WHERE id=?", n.ID[:]); err != nil {
		t.Fatal(err)
	}
	router := check(node, 201)
	if replayed := check(node, 201); !proto.Equal(router, replayed) {
		t.Fatal("retry changed the Connector enrollment")
	}
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: router.CertificateChain.CertificatesDer, PrivateKey: nodeKey}}
	mtls := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer mtls.CloseIdleConnections()
	renewal, err := proto.Marshal(&v1.RenewalRequest{Pkcs10CsrDer: node.Pkcs10CsrDer, WireguardPublicKey: node.WireguardPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	res, err := mtls.Post(goURL+"/v1/renew", "application/x-protobuf", bytes.NewReader(renewal))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	var renewed v1.RenewalResponse
	if err != nil || res.StatusCode != 200 || proto.Unmarshal(body, &renewed) != nil || !bytes.Equal(renewed.WireguardPublicKey, node.WireguardPublicKey) {
		t.Fatalf("Rust-issued identity could not renew at Go: HTTP %d", res.StatusCode)
	}
	before := parseLeaf(t, router.CertificateChain)
	after := parseLeaf(t, renewed.CertificateChain)
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 || before.URIs[0].String() != after.URIs[0].String() || after.CheckSignatureFrom(f.service.ca) != nil {
		t.Fatal("Go renewed the wrong identity")
	}
	if bytes.Equal(router.OverlayAddresses[0], next.OverlayAddresses[0]) || bytes.Equal(router.OverlayAddresses[1], next.OverlayAddresses[1]) {
		t.Fatal("reused address with valid certificate")
	}
	race := newInvite("once-only", controller.EnrollmentClassDurable, durable, 0)
	results := make(chan int, 2)
	start := make(chan struct{})
	for _, url := range []string{goURL, rustURL} {
		go func() { <-start; status, _, _ := post(url, race); results <- status }()
	}
	close(start)
	a, b := <-results, <-results
	if !(a == 201 && b == 409 || a == 409 && b == 201) {
		t.Fatalf("Go/Rust race: %d, %d", a, b)
	}
	retry := newInvite("native-retry", controller.EnrollmentClassDurable, durable, 0)
	original := check(retry, 201)
	if replayed := check(retry, 201); !proto.Equal(original, replayed) {
		t.Fatal("retry did not return the originally committed enrollment")
	}
	changed := proto.CloneOf(retry)
	changed.Pkcs10CsrDer = csrDER(t, "")
	check(changed, 409)
	changed = proto.CloneOf(retry)
	changed.WireguardPublicKey = testWireGuardPublicKey(t)
	check(changed, 409)
	if _, err := db.Exec("UPDATE certificates SET revoked_at=unixepoch() WHERE node_id=?", original.NodeId); err != nil {
		t.Fatal(err)
	}
	check(retry, 409)
	expired := newInvite("native-expired-retry", controller.EnrollmentClassDurable, durable, 0)
	expiredNode := check(expired, 201)
	if _, err := db.Exec("UPDATE enrollment_tokens SET created_at=unixepoch()-2,expires_at=unixepoch()-1 WHERE consumed_by=?", expiredNode.NodeId); err != nil {
		t.Fatal(err)
	}
	check(expired, 409)

}
