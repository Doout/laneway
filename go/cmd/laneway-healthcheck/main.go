// laneway-healthcheck is a minimal container readiness probe. It deliberately
// performs no privileged operation and sends no protocol bytes or credentials.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "laneway-healthcheck:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("laneway-healthcheck", flag.ContinueOnError)
	tcpAddress := fs.String("tcp", "", "TCP listen address to probe")
	tlsCA := fs.String("tls-ca", "", "optional PEM trust bundle for a TLS readiness handshake")
	tlsServerName := fs.String("tls-server-name", "", "expected TLS DNS identity")
	timeout := fs.Duration("timeout", 2*time.Second, "connect timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *tcpAddress == "" || *timeout <= 0 || *timeout > 10*time.Second {
		return errors.New("usage: laneway-healthcheck -tcp HOST:PORT [-timeout 2s]")
	}
	host, port, err := net.SplitHostPort(*tcpAddress)
	if err != nil || host != "127.0.0.1" || port == "" {
		return errors.New("-tcp must be a 127.0.0.1:PORT address")
	}
	if (*tlsCA == "") != (*tlsServerName == "") {
		return errors.New("-tls-ca and -tls-server-name must be provided together")
	}
	dialer := &net.Dialer{Timeout: *timeout}
	var connection net.Conn
	if *tlsCA == "" {
		connection, err = dialer.Dial("tcp", *tcpAddress)
	} else {
		pemBytes, readErr := os.ReadFile(*tlsCA)
		if readErr != nil {
			return fmt.Errorf("read TLS CA: %w", readErr)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return errors.New("TLS CA contains no certificates")
		}
		connection, err = tls.DialWithDialer(dialer, "tcp", *tcpAddress, &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots, ServerName: *tlsServerName,
		})
	}
	if err != nil {
		return fmt.Errorf("probe %s: %w", *tcpAddress, err)
	}
	return connection.Close()
}
