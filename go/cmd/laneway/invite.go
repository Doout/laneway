package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"laneway.dev/laneway/internal/config"
	"laneway.dev/laneway/internal/controllerclient"
	"laneway.dev/laneway/internal/identity"
)

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/laneway/controller.toml", "controller configuration file")
	name := fs.String("name", "", "device name and audit label")
	ephemeral := fs.Bool("ephemeral", false, "issue a fully ephemeral user invite")
	remembered := fs.Bool("remembered", false, "issue a remembered user invite")
	expiresIn := fs.Duration("expires-in", 10*time.Minute, "single-use code lifetime")
	sessionLifetime := fs.Duration("session-lifetime", 8*time.Hour, "ephemeral authorization lifetime")
	jsonOutput := fs.Bool("json", false, "emit the complete invite record as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *name == "" || *expiresIn <= 0 || *expiresIn > time.Hour || (*ephemeral && *remembered) {
		return errors.New("usage: lane invite --name NAME [--ephemeral|--remembered] [--expires-in 10m] [--session-lifetime 8h]")
	}
	class := "durable"
	if *ephemeral {
		class = "ephemeral"
	} else if *remembered {
		class = "remembered"
	}
	if class != "ephemeral" && flagProvided(args, "session-lifetime") {
		return errors.New("--session-lifetime is valid only with --ephemeral")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.Mode != config.ModeController || cfg.Bootstrap.Listen == "" {
		return errors.New("invite requires a controller configuration with public bootstrap enabled")
	}
	networkID, err := identity.ParseNetworkID(cfg.Bootstrap.NetworkID)
	if err != nil {
		return err
	}
	controllerPEM, err := os.ReadFile(cfg.TLS.CertificateFile)
	if err != nil {
		return fmt.Errorf("read controller certificate: %w", err)
	}
	controllerCertificate, err := firstCertificatePEM(controllerPEM)
	if err != nil {
		return fmt.Errorf("parse controller certificate: %w", err)
	}
	controllerIdentity, err := identity.AuthenticatedIdentityFromCertificate(controllerCertificate)
	if err != nil {
		return err
	}
	if controllerIdentity.NetworkID != networkID {
		return errors.New("bootstrap and controller certificate network identities do not match")
	}
	client, err := controllerclient.New(controllerclient.Options{
		Endpoint:          cfg.Bootstrap.ControllerEndpoint,
		CAFile:            cfg.TLS.CAFile,
		ServerName:        cfg.Bootstrap.ControllerServerName,
		ExpectedNetworkID: networkID,
		ExpectedServiceID: controllerIdentity.SubjectID,
		AdminTokenFile:    cfg.Controller.AdminTokenFile,
		DialAddress:       controllerLoopbackDialAddress(cfg.Controller.Listen),
	})
	if err != nil {
		return err
	}
	options := controllerclient.EnrollmentTokenOptions{Class: class, RequestedName: *name}
	if class == "ephemeral" {
		options.SessionLifetime = *sessionLifetime
	}
	ctx, cancel := context.WithTimeout(context.Background(), controllerCommandTimeout)
	defer cancel()
	invite, err := client.IssueEnrollmentTokenWithOptions(ctx, networkID, *name, time.Now().UTC().Add(*expiresIn), options)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return printJSON(invite)
	}
	// The code is intentionally written only to the invoking terminal/stdout.
	// The controller stores its hash and neither request logs nor argv contain it.
	fmt.Fprintln(os.Stderr, "Single-use", class, "invite for", *name, "(expires", time.Unix(invite.ExpiresAtUnix, 0).UTC().Format(time.RFC3339)+"):")
	fmt.Println(invite.EnrollmentToken)
	return nil
}

func controllerLoopbackDialAddress(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return ""
	}
	if host == "" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	address := net.ParseIP(host)
	if address != nil && address.IsUnspecified() {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return listen
}
