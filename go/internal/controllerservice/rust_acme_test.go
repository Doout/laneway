//go:build rustinterop

package controllerservice

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func testRustAcme(t *testing.T, pebble, relay, relayConfig string, apiRoots *x509.CertPool, apiCert, apiKey, apiCA string) {
	t.Helper()
	const name = "relay.acme.test"
	authAddr, adminAddr, validationAddr := unusedLocalAddr(t), unusedLocalAddr(t), unusedLocalAddr(t)
	_, validationPort, err := net.SplitHostPort(validationAddr)
	if err != nil {
		t.Fatal(err)
	}
	dns := acmeLabDNS(t, name)
	state := t.TempDir()
	pebbleConfig := fmt.Sprintf(`{"pebble":{
		"listenAddress":%q,"managementListenAddress":%q,"tlsPort":%s,
		"certificate":%q,"privateKey":%q,"keyAlgorithm":"ecdsa",
		"profiles":{"default":{"validityPeriod":30}},
		"retryAfter":{"authz":1,"order":1}
	}}`, authAddr, adminAddr, validationPort, apiCert, apiKey)
	dirURL := "https://" + authAddr + "/dir"
	write := func(name, value string) string {
		t.Helper()
		path := filepath.Join(state, name)
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p := exec.CommandContext(t.Context(), pebble, "-config", write("pebble.json", pebbleConfig), "-dnsserver", dns)
	p.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_VA_ALWAYS_VALID=0",
		"PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0")
	p.Stdout, p.Stderr = os.Stderr, os.Stderr
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stopCA := func() { once.Do(func() { _ = p.Process.Kill(); _ = p.Wait() }) }
	t.Cleanup(stopCA)
	api := acmeHTTP(apiRoots, "")
	defer api.CloseIdleConnections()
	waitACME(t, 10*time.Second, "Pebble ACME directory", func() bool {
		resp, err := api.Get(dirURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var doc map[string]any
		return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&doc) == nil && doc["newOrder"] != nil
	})
	resp, err := api.Get("https://" + adminAddr + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	_ = resp.Body.Close()
	issuedRoots := x509.NewCertPool()
	if err != nil || resp.StatusCode != 200 || !issuedRoots.AppendCertsFromPEM(ca) {
		t.Fatal("Pebble did not provide the isolated issuance root")
	}
	base, _, found := strings.Cut(relayConfig, "[public_https]")
	if !found {
		t.Fatal("missing public HTTPS fixture configuration")
	}
	base = strings.Replace(base, "[tcp_fallback]\nlisten = \"127.0.0.1:0\"", fmt.Sprintf("[tcp_fallback]\nlisten = %q", validationAddr), 1)
	cache := filepath.Join(state, "cache")
	cfg := write("acme-relay.toml", base+fmt.Sprintf(`[public_https]
server_name = %q
cache_dir = %q
acme_directory = %q
acme_ca = %q
`, name, cache, dirURL, apiCA))
	addr, stopRelay := startRustPublicRelay(t, relay, cfg)
	if addr != validationAddr {
		t.Fatal("the relay is not listening on the ACME validation port")
	}
	public := acmeHTTP(issuedRoots, name)
	defer public.CloseIdleConnections()
	serial := func() string {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/overview", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = name
		resp, err := public.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if resp.StatusCode != 200 || !strings.Contains(string(body), "<title>Laneway</title>") || resp.TLS == nil ||
			len(resp.TLS.VerifiedChains) == 0 {
			return ""
		}
		return resp.TLS.PeerCertificates[0].SerialNumber.String()
	}
	first := ""
	waitACME(t, 25*time.Second, "initial TLS-ALPN issuance", func() bool {
		first = serial()
		return first != ""
	})
	next := ""
	waitACME(t, 40*time.Second, "rotated leaf on the live relay", func() bool {
		next = serial()
		return next != "" && next != first
	})
	waitACME(t, 5*time.Second, "private persistent ACME cache", func() bool {
		entries, err := os.ReadDir(filepath.Join(cache, "rust-v1"))
		if err != nil {
			return false
		}
		account, leaf := false, false
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				return false
			}
			account = account || strings.HasPrefix(entry.Name(), "account-")
			leaf = leaf || strings.HasPrefix(entry.Name(), "cert-")
		}
		return account && leaf
	})
	stopCA()
	stopRelay()
	public.CloseIdleConnections()
	addr, _ = startRustPublicRelay(t, relay, cfg)
	waitACME(t, 6*time.Second, "cached renewed leaf with the ACME CA offline", func() bool {
		return serial() == next
	})
}

func waitACME(t *testing.T, limit time.Duration, operation string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", operation)
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func acmeHTTP(roots *x509.CertPool, name string) *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true, TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS13,
		},
	}}
}

func unusedLocalAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func acmeLabDNS(t *testing.T, host string) string {
	t.Helper()
	name := dnsmessage.MustNewName(host + ".")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go answerACMEDNS(conn, name)
		}
	}()
	return listener.Addr().String()
}

func answerACMEDNS(conn net.Conn, name dnsmessage.Name) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint16(prefix[:])
	if size > 2048 {
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}
	var query dnsmessage.Message
	if query.Unpack(data) != nil || len(query.Questions) != 1 {
		return
	}
	q := query.Questions[0]
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true},
		Questions: query.Questions,
	}
	if q.Name == name && q.Type == dnsmessage.TypeA {
		reply.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
		}}
	}
	if wire, err := reply.Pack(); err == nil {
		binary.BigEndian.PutUint16(prefix[:], uint16(len(wire)))
		_, _ = conn.Write(append(prefix[:], wire...))
	}
}
