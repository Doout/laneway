package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	v1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/Doout/laneway/go/internal/pki"
	"github.com/Doout/laneway/go/internal/wireguard"
)

// enrollExit exercises the real ephemeral enrollment endpoint with disposable
// keys. This lab-only command does not provision a host service.
func enrollExit(args []string) error {
	fs := flag.NewFlagSet("enroll-exit", flag.ContinueOnError)
	endpoint := fs.String("controller", "", "isolated controller HTTPS origin")
	networkText := fs.String("network-id", "", "expected network")
	serviceText := fs.String("service-id", "", "expected controller service")
	ca := fs.String("ca", "", "fixture CA certificate")
	tokenFile := fs.String("token-file", "", "fixture one-use token file")
	name := fs.String("name", "", "invite-bound name")
	prefix := fs.String("out-prefix", "", "disposable credential filename prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" || *ca == "" || *tokenFile == "" || *name == "" || *prefix == "" || fs.NArg() != 0 {
		return errors.New("missing isolated exit enrollment options")
	}
	network, err := identity.ParseNetworkID(*networkText)
	if err != nil {
		return err
	}
	service, err := identity.ParseID(*serviceText)
	if err != nil {
		return err
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	defer clear(token)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: *name}}, privateKey)
	if err != nil {
		return err
	}
	wgPrivate, wgPublic, err := wireguard.GenerateKey()
	if err != nil {
		return err
	}
	defer wireguard.ZeroPrivateKey(&wgPrivate)
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint: *endpoint, CAFile: *ca, ExpectedNetworkID: network, ExpectedServiceID: service,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.EnrollForNetworkAndClass(ctx, strings.TrimSpace(string(token)), *name, csr,
		wgPublic.Bytes(), network, v1.EnrollmentClass_ENROLLMENT_CLASS_EPHEMERAL_USER)
	if err != nil {
		return err
	}
	if response.GetEphemeralExitLeaseGeneration() == 0 || !wgPublic.Equal(response.GetWireguardPublicKey()) ||
		len(response.GetNodeId()) != identity.IDSize || len(response.GetOverlayAddresses()) != 1 ||
		len(response.GetCertificateChain().GetCertificatesDer()) == 0 {
		return errors.New("incomplete lab exit enrollment response")
	}
	overlay, ok := netip.AddrFromSlice(response.GetOverlayAddresses()[0])
	if !ok || !overlay.Is4() {
		return errors.New("lab exit did not receive an IPv4 overlay")
	}
	keyPEM, err := pki.PrivateKeyPEM(privateKey)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	var certPEM []byte
	for _, certificate := range response.GetCertificateChain().GetCertificatesDer() {
		certPEM = append(certPEM, pki.CertificatePEM(certificate)...)
	}
	if err := writeExitFixtureFile(*prefix+".crt", certPEM); err != nil {
		return err
	}
	if err := writeExitFixtureFile(*prefix+".key", keyPEM); err != nil {
		return err
	}
	if err := writeExitFixtureFile(*prefix+".wireguard.key", wgPrivate[:]); err != nil {
		return err
	}
	fmt.Printf("enrolled network=%s node=%x overlay=%s generation=%d\n", network, response.GetNodeId(),
		netip.PrefixFrom(overlay, 32), response.GetEphemeralExitLeaseGeneration())
	return nil
}

func writeExitFixtureFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(contents)
	return errors.Join(writeErr, file.Close())
}
