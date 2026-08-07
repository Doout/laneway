package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(done)
	}()
	if err := run([]string{"-tcp", listener.Addr().String(), "-timeout", time.Second.String()}); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestRunRejectsUnsafeTargets(t *testing.T) {
	for _, target := range []string{"", "0.0.0.0:1", "example.com:443", "127.0.0.1"} {
		if err := run([]string{"-tcp", target}); err == nil {
			t.Fatalf("target %q accepted", target)
		}
	}
	if err := run([]string{"-tcp", "127.0.0.1:1", "extra"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("unexpected argument error = %v", err)
	}
	if err := run([]string{"-tcp", "127.0.0.1:1", "-tls-ca", "/missing"}); err == nil || !strings.Contains(err.Error(), "provided together") {
		t.Fatalf("unpaired TLS arguments error = %v", err)
	}
}
