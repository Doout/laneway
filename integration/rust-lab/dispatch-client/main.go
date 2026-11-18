// This adapter is compiled inside a temporary, unmodified Dispatch package
// snapshot. API calls run the real Dispatch client implementation.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/doout/dispatch/internal/laneway"
)

type request struct {
	Step, Authority, Address, CAPEM               string
	Code, Verifier, Redirect, ClientID, ClientKey string
	Access, Refresh, Network, Node                string
}

func main() {
	if err := run(); err != nil {
		var status *laneway.HTTPError
		if errors.As(err, &status) {
			fmt.Fprintf(os.Stderr, "Dispatch client returned HTTP %d\n", status.StatusCode)
		} else {
			fmt.Fprintf(os.Stderr, "Dispatch lab operation failed (%T)\n", err)
		}
		os.Exit(1)
	}
}

func run() error {
	var input request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 64*1024)).Decode(&input); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(input.Address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("Dispatch lab requires a numeric loopback address")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(input.CAPEM)) {
		return errors.New("Dispatch lab requires a CA")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, input.Address)
		},
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	client := laneway.Client{
		Authority: input.Authority, Token: input.Access,
		HTTPClient: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	var result any
	switch input.Step {
	case "register":
		result, err = client.ExchangeApplicationRegistration(ctx, laneway.ApplicationRegistrationRequest{
			Code: input.Code, CodeVerifier: input.Verifier,
		})
	case "exchange":
		result, err = client.ExchangeOAuthCode(ctx, input.ClientID, input.ClientKey, laneway.OAuthTokenRequest{
			Code: input.Code, CodeVerifier: input.Verifier, RedirectURI: input.Redirect,
		})
	case "inventory-write":
		return inspectAndWrite(ctx, client, input)
	case "refresh":
		result, err = client.RefreshOAuthToken(ctx, input.ClientID, input.ClientKey, input.Refresh)
	case "revoke":
		return client.RevokeOAuthToken(ctx, input.ClientID, input.ClientKey, input.Refresh)
	default:
		return errors.New("unknown Dispatch lab operation")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func inspectAndWrite(ctx context.Context, client laneway.Client, input request) error {
	inventory, err := client.Inventory(ctx, input.Network)
	if err != nil {
		return err
	}
	if inventory.Network.ID != input.Network || len(inventory.Nodes) == 0 {
		return errors.New("Dispatch received incomplete network inventory")
	}
	if _, err := client.CreateNodeInstaller(ctx, input.Network, laneway.NodeInstallerRequest{
		Name: "dispatch-native-client", Kind: "connector", InstallMode: "systemd",
	}); err != nil {
		return err
	}
	route, err := client.AssignRoute(ctx, input.Network, laneway.AssignRouteRequest{
		NodeID: input.Node, Prefix: "203.0.113.0/24", Mode: "nat", Metric: 22,
	})
	if err != nil {
		return err
	}
	if route.ID == "" || route.NodeID != input.Node {
		return errors.New("Dispatch received an incomplete assigned route")
	}
	return nil
}
