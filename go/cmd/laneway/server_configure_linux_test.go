//go:build linux

package main

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestConfigureServerHostHandoff(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		uid       int
		container bool
		want      string
	}{
		{"container", []string{"lane.example.com"}, 0, true, "exit the container and run sudo laneway configure server lane.example.com"},
		{"nonroot", nil, 1000, false, "run sudo laneway configure server"},
		{"invalid DNS", []string{"https://lane.example.com"}, 0, false, "use a fully qualified DNS name"},
		{"extra arguments", []string{"lane.example.com", "--force"}, 0, false, "usage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			find := func() (string, error) {
				t.Fatal("handoff looked up a host command")
				return "", nil
			}
			err := configureServerOnHost(tt.args, tt.uid, tt.container, find, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConfigureServerDelegatesToInstalledTools(t *testing.T) {
	operator := "/opt/laneway/laneway-control"
	failure := errors.New("operator failure")
	for _, tt := range []struct {
		name      string
		operator  string
		domain    string
		domainErr error
		initErr   error
		want      [][]string
		wantErr   error
	}{
		{
			name:   "fresh production install",
			domain: "lane.example.com",
			want:   [][]string{{serverPackageInstaller, "lane.example.com"}},
		},
		{
			name:     "existing deployment",
			operator: operator,
			domain:   "lane.example.com",
			want:     [][]string{{operator, "", "init"}, {operator, "", "production-check"}},
		},
		{
			name:     "init error prevents production check",
			operator: operator,
			initErr:  failure,
			want:     [][]string{{operator, "", "init"}},
			wantErr:  failure,
		},
		{
			name:      "domain mismatch leaves deployment alone",
			operator:  operator,
			domain:    "lane.example.com",
			domainErr: failure,
			wantErr:   failure,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			find := func() (string, error) { return tt.operator, nil }
			var called [][]string
			run := func(path, domain string, args ...string) error {
				called = append(called, append([]string{path, domain}, args...))
				return tt.initErr
			}
			domainChecked := false
			check := func(path, domain string) error {
				domainChecked = true
				if path != "/opt/laneway/.env" || domain != tt.domain {
					t.Fatalf("unexpected installed domain check for %s at %s", domain, path)
				}
				return tt.domainErr
			}
			var args []string
			if tt.domain != "" {
				args = []string{tt.domain}
			}
			err := configureServerOnHost(args, 0, false, find, check, run)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(called, tt.want) {
				t.Fatalf("commands = %v, want %v", called, tt.want)
			}
			if domainChecked != (tt.domain != "" && tt.operator != "") {
				t.Fatalf("installed domain checked = %t", domainChecked)
			}
		})
	}
}

func TestConfigureServerMissingInstallerInstructions(t *testing.T) {
	err := serverInstallInstructions("installer is missing", "lane.example.com")
	for _, want := range []string{
		"https://github.com/Doout/laneway/releases/latest/download/install.sh",
		"sudo env LANEWAY_DOMAIN=lane.example.com sh ./install.sh --control-plane --production",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("instructions = %v, want %q", err, want)
		}
	}
}

func TestConfigureServerSelectsTrustedInstaller(t *testing.T) {
	unsafe := errors.New("untrusted permissions")
	tests := []struct {
		name      string
		files     map[string]error
		want      string
		wantError string
	}{
		{
			name: "existing verifier",
			want: serverPackageInstaller,
		},
		{
			name:  "client package without verifier",
			files: map[string]error{serverPinnedVerifier: os.ErrNotExist},
			want:  serverReleaseInstaller,
		},
		{
			name:  "outer installer can fetch missing package",
			files: map[string]error{serverPackageInstaller: os.ErrNotExist},
			want:  serverReleaseInstaller,
		},
		{
			name: "standalone installation",
			files: map[string]error{
				serverPackageInstaller: os.ErrNotExist,
				serverReleaseInstaller: os.ErrNotExist,
			},
			wantError: "sudo env LANEWAY_DOMAIN=lane.example.com sh ./install.sh --control-plane --production",
		},
		{
			name: "unsafe release installer",
			files: map[string]error{
				serverPinnedVerifier:   os.ErrNotExist,
				serverReleaseInstaller: unsafe,
			},
			wantError: unsafe.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := func(path string, executable bool) error {
				if !executable {
					t.Fatalf("expected an executable installer component at %s", path)
				}
				return tt.files[path]
			}
			got, args, err := serverInstallerCommand("lane.example.com", check)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("installer = %q, error = %v, want %q", got, err, tt.want)
			}
			var wantArgs []string
			if got == serverReleaseInstaller {
				wantArgs = []string{"--control-plane", "--production"}
			}
			if !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("installer arguments = %v, want %v", args, wantArgs)
			}
		})
	}
}
