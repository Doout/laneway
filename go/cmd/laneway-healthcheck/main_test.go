package main

import (
	"bufio"
	"net"
	"path/filepath"
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

func TestRunUnixStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lanewayd.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil || line == "\r\n" {
				break
			}
		}
		_, _ = connection.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"))
	}()
	if err := run([]string{"-unix", path, "-timeout", time.Second.String()}); err != nil {
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
	for _, path := range []string{"relative.sock", "/tmp/../tmp/socket", "/tmp/socket\x00bad"} {
		if err := run([]string{"-unix", path}); err == nil {
			t.Fatalf("Unix path %q accepted", path)
		}
	}
	if err := run([]string{"-tcp", "127.0.0.1:1", "-unix", "/tmp/socket"}); err == nil {
		t.Fatal("simultaneous TCP and Unix probes accepted")
	}
	if err := run([]string{"-tcp", "127.0.0.1:1", "-tls-ca", "/missing"}); err == nil || !strings.Contains(err.Error(), "provided together") {
		t.Fatalf("unpaired TLS arguments error = %v", err)
	}
}
