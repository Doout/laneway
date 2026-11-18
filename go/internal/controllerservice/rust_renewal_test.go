//go:build rustinterop

package controllerservice

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"testing"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"google.golang.org/protobuf/proto"
)

func testRustRenewal(t *testing.T, f fixture, client *http.Client, rustURL, goURL string) {
	ctx := t.Context()
	db, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	net, err := f.store.CreateNetwork(ctx, "renewals", netip.MustParsePrefix("10.218.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	clientWith := func(chain [][]byte, key crypto.Signer) *http.Client {
		tr := client.Transport.(*http.Transport).Clone()
		// Always send the chosen leaf, even for the unknown-CA rejection test.
		tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{Certificate: chain, PrivateKey: key}, nil
		}
		cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		t.Cleanup(cl.CloseIdleConnections)
		return cl
	}
	csr := func() (ed25519.PrivateKey, []byte) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if err != nil {
			t.Fatal(err)
		}
		return k, der
	}
	enroll := func(name string, ephemeral bool, key []byte) (*http.Client, *v1.EnrollmentResponse) {
		opts := controller.EnrollmentTokenOptions{Class: controller.EnrollmentClassDurable}
		want := v1.EnrollmentClass_ENROLLMENT_CLASS_DURABLE_NODE
		if ephemeral {
			opts.Class = controller.EnrollmentClassEphemeral
			opts.SessionLifetime = 5 * time.Minute
			want = v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER
		}
		tok, err := f.store.IssueEnrollmentTokenWithOptions(ctx, net.ID, name, time.Now().Add(time.Hour), opts)
		if err != nil {
			t.Fatal(err)
		}
		private, der := csr()
		r := labRedeem(t, client, goURL, &v1.EnrollmentRequest{RequestedName: name, EnrollmentToken: tok.Secret, Pkcs10CsrDer: der, ExpectedNetworkId: net.ID[:], ExpectedEnrollmentClass: want, WireguardPublicKey: key}, 201)
		return clientWith(r.CertificateChain.CertificatesDer, private), r
	}
	args := func(der, wg []byte) []byte {
		b, err := proto.Marshal(&v1.RenewalRequest{Pkcs10CsrDer: der, WireguardPublicKey: wg})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	post := func(cl *http.Client, url string, body []byte, want int) *v1.RenewalResponse {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "POST", url+"/v1/renew", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("X-Forwarded-Client-Cert", "test")
		req.Header.Set("Authorization", "Bearer "+testRootBearer)
		resp, err := cl.Do(req)
		if want == 0 {
			if err == nil {
				resp.Body.Close()
				t.Fatal("unexpected accepted client handshake")
			}
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want || resp.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Fatalf("renew HTTP %d, want %d: %v", resp.StatusCode, want, err)
		}
		if want != 200 {
			var e v1.ProtocolError
			if proto.Unmarshal(data, &e) != nil || e.Code == 0 {
				t.Fatal("missing protocol error")
			}
			return nil
		}
		var got v1.RenewalResponse
		if err := proto.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		return &got
	}
	oldKey, newKey, otherKey := testWireGuardPublicKey(t), testWireGuardPublicKey(t), testWireGuardPublicKey(t)
	old, enrolled := enroll("durable", false, oldKey)
	_, _ = enroll("occupied", false, otherKey)
	node := enrolled.NodeId
	private, der := csr()
	snapshot := func() (s struct {
		Certs, Epoch, Rotations, Issues int
		Key                             string
	}) {
		t.Helper()
		err := db.QueryRow(`SELECT hex(n.wireguard_public_key),w.configuration_epoch,
            (SELECT count(*) FROM certificates c WHERE c.node_id=n.id),
            (SELECT count(*) FROM audit_events a WHERE a.actor_id=n.id AND a.action='node.wireguard_key.rotate'),
            (SELECT count(*) FROM audit_events a WHERE a.actor_id=n.id AND a.action='certificate.issue')
            FROM nodes n JOIN networks w ON w.id=n.network_id WHERE n.id=?`, node).Scan(&s.Key, &s.Epoch, &s.Certs, &s.Rotations, &s.Issues)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	post(client, rustURL, []byte{0xff}, 401) // a header is not a TLS identity
	relay, _, err := pki.IssueService(f.service.ca, f.service.caKey, pki.ServiceIdentity{NetworkID: net.ID, ServiceID: identity.ID(net.ID), Role: pki.RoleRelay}, nil, nil, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	post(clientWith([][]byte{relay.CertificateDER}, relay.PrivateKey), rustURL, nil, 401)
	subject, err := identity.IdentityFromCertificate(parseLeaf(t, enrolled.CertificateChain))
	if err != nil {
		t.Fatal(err)
	}
	unrecorded, _, err := pki.IssueNode(f.service.ca, f.service.caKey, subject, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	post(clientWith([][]byte{unrecorded.CertificateDER}, unrecorded.PrivateKey), rustURL, nil, 403)
	outsider, outsiderCA, err := pki.NewAuthority("untrusted lab CA", time.Now().Add(-time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	untrusted, _, err := pki.IssueNode(outsiderCA, outsider.PrivateKey, subject, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	post(clientWith([][]byte{untrusted.CertificateDER}, untrusted.PrivateKey), rustURL, nil, 0)

	start := snapshot()
	post(old, rustURL, args(der, make([]byte, 32)), 400)
	post(old, rustURL, args([]byte{1}, newKey), 400)
	post(old, rustURL, args(der, otherKey), 409)
	if _, err = db.Exec("CREATE TRIGGER fail_key_audit BEFORE INSERT ON audit_events WHEN NEW.action='node.wireguard_key.rotate' BEGIN SELECT RAISE(ABORT,'lab'); END"); err != nil {
		t.Fatal(err)
	}
	post(old, rustURL, args(der, newKey), 500)
	if snapshot() != start {
		t.Fatal("failed renewal changed certificate, key, epoch, or audit")
	}
	if _, err = db.Exec("DROP TRIGGER fail_key_audit"); err != nil {
		t.Fatal(err)
	}

	kept := post(old, rustURL, args(der, nil), 200)
	same := snapshot()
	if !bytes.Equal(kept.WireguardPublicKey, oldKey) || same.Certs != start.Certs+1 || same.Issues != start.Issues+1 || same.Key != start.Key || same.Epoch != start.Epoch || same.Rotations != start.Rotations {
		t.Fatal("omitted key changed identity or epoch")
	}
	rotated := post(old, rustURL, args(der, newKey), 200)
	end := snapshot()
	if !bytes.Equal(rotated.WireguardPublicKey, newKey) || end.Key == same.Key || end.Epoch != same.Epoch+1 || end.Rotations != same.Rotations+1 || end.Certs != same.Certs+1 || end.Issues != same.Issues+1 {
		t.Fatal("rotation was not atomic")
	}
	leaf := parseLeaf(t, rotated.CertificateChain)
	id, err := identity.IdentityFromCertificate(leaf)
	if err != nil || id != subject || leaf.CheckSignatureFrom(f.service.ca) != nil || !bytes.Equal(leaf.PublicKey.(ed25519.PublicKey), private.Public().(ed25519.PublicKey)) {
		t.Fatal("incorrect renewed certificate")
	}
	fresh := clientWith(rotated.CertificateChain.CertificatesDer, private)
	post(fresh, goURL, args(der, nil), 200) // Rust's replacement key proves possession to Go

	// Revoke AFTER rustls and the handler have authorized the request, but
	// BEFORE sending its CSR. The writer must recheck the original leaf.
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	body := args(der, newKey)
	req, err := http.NewRequestWithContext(ctx, "POST", rustURL+"/v1/renew", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Expect", "100-continue")
	admitted := make(chan struct{})
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{Got100Continue: func() { close(admitted) }}))
	status := make(chan int, 1)
	go func() {
		r, e := old.Do(req)
		if e != nil {
			status <- 0
			return
		}
		r.Body.Close()
		status <- r.StatusCode
	}()
	select {
	case <-admitted:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal was not admitted before body")
	}
	serial := parseLeaf(t, enrolled.CertificateChain).SerialNumber.Bytes()
	if _, err := f.store.RevokeCertificateBySerial(ctx, net.ID, serial, "retired"); err != nil {
		t.Fatal(err)
	}
	snap := snapshot()
	if _, err = writer.Write(body); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if got := <-status; got != 403 || snapshot() != snap {
		t.Fatalf("in-flight revoked certificate: HTTP %d", got)
	}
	post(old, rustURL, []byte{0xff}, 403)
	post(fresh, rustURL, args(der, nil), 200)
	if _, err = f.store.RevokeNode(ctx, subject.NodeID, "retired"); err != nil {
		t.Fatal(err)
	}
	post(fresh, rustURL, args(der, nil), 403)

	short, session := enroll("ephemeral", true, nil)
	limited := post(short, rustURL, args(der, nil), 200)
	if limited.CertificateChain.NotAfterUnixSeconds != session.LeaseExpiresAtUnixSeconds || len(limited.WireguardPublicKey) != 0 {
		t.Fatal("renewal escaped lease or bound a legacy node")
	}
	first := post(short, rustURL, args(der, testWireGuardPublicKey(t)), 200)
	if len(first.WireguardPublicKey) != 32 {
		t.Fatal("failed to bind legacy node on renewal")
	}
	if _, err = db.Exec("UPDATE nodes SET lease_expires_at=unixepoch()-1 WHERE id=?", session.NodeId); err != nil {
		t.Fatal(err)
	}
	post(short, rustURL, args(der, nil), 403)
}
