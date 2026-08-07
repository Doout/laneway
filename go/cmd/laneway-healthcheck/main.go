// laneway-healthcheck is a minimal container readiness probe. It deliberately
// performs no privileged operation and sends no protocol bytes or credentials.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	unixPath := fs.String("unix", "", "Unix socket serving the local status API")
	tlsCA := fs.String("tls-ca", "", "optional PEM trust bundle for a TLS readiness handshake")
	tlsServerName := fs.String("tls-server-name", "", "expected TLS DNS identity")
	timeout := fs.Duration("timeout", 2*time.Second, "connect timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*tcpAddress == "") == (*unixPath == "") || *timeout <= 0 || *timeout > 10*time.Second {
		return errors.New("usage: laneway-healthcheck (-tcp 127.0.0.1:PORT | -unix /absolute/socket) [-timeout 2s]")
	}
	if *unixPath != "" {
		return probeUnix(*unixPath, *timeout)
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

func probeUnix(path string, timeout time.Duration) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
		return errors.New("-unix must be a clean absolute socket path")
	}
	connection, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return fmt.Errorf("probe Unix status socket: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := connection.Write([]byte("GET /v1/status HTTP/1.1\r\nHost: lanewayd\r\nConnection: close\r\n\r\n")); err != nil {
		return fmt.Errorf("write Unix status probe: %w", err)
	}
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read Unix status probe: %w", err)
	}
	if strings.TrimSpace(line) != "HTTP/1.1 200 OK" {
		return fmt.Errorf("Unix status probe returned %q", strings.TrimSpace(line))
	}
	return nil
}
