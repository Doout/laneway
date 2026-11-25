//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const officeConnector = "laneway-connector-office"

func TestLinuxUpdateTargetDetection(t *testing.T) {
	for _, test := range []struct {
		name       string
		uid        int
		userClient bool
		server     bool
		connectors []string
		dockerErr  error
		want       string
		wantError  string
	}{
		{name: "ordinary client", uid: 1000, want: "client"},
		{name: "per-user CLI skips inaccessible Docker", uid: 1000, userClient: true, dockerErr: errLocalDockerUnavailable, want: "client"},
		{name: "one standard Connector", connectors: []string{officeConnector}, want: "connector"},
		{name: "control plane takes precedence over unavailable Docker", server: true, dockerErr: errLocalDockerUnavailable, want: "server"},
		{name: "both deployment roles", server: true, connectors: []string{officeConnector}, wantError: "both a control plane and managed Connectors"},
		{name: "multiple Connectors", connectors: []string{officeConnector, "laneway-connector-warehouse"}, wantError: "multiple managed Connectors"},
		{name: "system CLI ambiguous with unavailable Docker", dockerErr: errLocalDockerUnavailable, wantError: "choose laneway update client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			update := linuxUpdater{
				uid:        test.uid,
				userClient: test.userClient,
				server:     func() (bool, error) { return test.server, nil },
				managed: func(string) ([]string, error) {
					if test.userClient && !test.server {
						t.Fatal("per-user CLI should not require Docker")
					}
					return test.connectors, test.dockerErr
				},
			}
			got, err := update.detect()
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("expected %q error, got %v", test.wantError, err)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("got target %q, err %v, want %q", got, err, test.want)
			}
		})
	}
}

func TestLinuxUpdateRoutesHostHelpers(t *testing.T) {
	for _, test := range []struct {
		name, target, selected, wantPath string
		args, names, wantArgs            []string
		uid                              int
		wantError                        string
	}{
		{name: "server", target: "server", wantPath: installedControl, wantArgs: []string{"update"}},
		{name: "automatic single Connector", target: "connector", names: []string{officeConnector}, wantPath: connectorUpdater, wantArgs: []string{officeConnector}},
		{name: "explicit Connector", target: "connector", selected: officeConnector, args: []string{"--name", officeConnector}, names: []string{officeConnector}, wantPath: connectorUpdater, wantArgs: []string{officeConnector}},
		{name: "explicit short Connector", target: "connector", selected: officeConnector, args: []string{"office"}, names: []string{officeConnector}, wantPath: connectorUpdater, wantArgs: []string{officeConnector}},
		{name: "ambiguous Connector", target: "connector", names: []string{officeConnector, "laneway-connector-shop"}, wantError: "multiple managed Connectors"},
		{name: "explicit unmanaged Connector", target: "connector", args: []string{officeConnector}, selected: officeConnector, wantError: "is not a running standard managed Connector"},
		{name: "invalid Connector name", target: "connector", args: []string{"--host=remote"}, wantError: "Connector name must be NAME"},
		{name: "server from normal user", target: "server", uid: 501, wantError: "sudo laneway update server"},
		{name: "Connector from normal user", target: "connector", uid: 501, args: []string{officeConnector}, wantError: "sudo laneway update connector " + officeConnector},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			update := linuxUpdater{
				uid:    test.uid,
				server: func() (bool, error) { return true, nil },
				managed: func(name string) ([]string, error) {
					if name != test.selected {
						t.Fatalf("selected %q, want %q", name, test.selected)
					}
					return test.names, nil
				},
				execute: func(path string, args []string) error {
					called = true
					if path != test.wantPath || !slices.Equal(args, test.wantArgs) {
						t.Fatalf("executed %s %q, want %s %q", path, args, test.wantPath, test.wantArgs)
					}
					return nil
				},
			}
			err := update.update(test.target, test.args)
			if test.wantError != "" {
				if called || err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("expected %q error without helper, got %v (helper=%v)", test.wantError, err, called)
				}
			} else if err != nil || !called {
				t.Fatalf("expected helper to run, got %v (helper=%v)", err, called)
			}
		})
	}
}

func TestContainerUpdateBoundaryAndRoles(t *testing.T) {
	for _, cgroup := range []string{
		"12:devices:/docker/641a", "0::/system.slice/docker-641a.scope", "0::/kubepods/pod-ab/641a",
	} {
		if !containerCgroup(cgroup) {
			t.Errorf("did not detect container cgroup %q", cgroup)
		}
	}
	if containerCgroup("0::/system.slice/docker.service") {
		t.Fatal("Docker host service mistaken for a container")
	}
	role, name := containerDeployment("/usr/local/bin/laneway\x00connector\x00run\x00", officeConnector, false)
	if role != "connector" || name != officeConnector {
		t.Fatalf("unexpected Connector role %q, %q", role, name)
	}
	if err := containerUpdateError("", role, name); !strings.Contains(err.Error(), "sudo laneway update connector "+officeConnector) {
		t.Fatal(err)
	}
	role, name = containerDeployment("/usr/local/bin/laneway-compat\x00connector\x00run\x00", officeConnector, false)
	if role != "connector" || name != officeConnector {
		t.Fatalf("unexpected delegated Connector role %q, %q", role, name)
	}
	role, name = containerDeployment("/usr/local/sbin/laneway-controller\x00-config\x00/tmp/controller.toml\x00", "controller", false)
	if role != "server" || name != "" {
		t.Fatalf("unexpected controller role %q, %q", role, name)
	}
	if err := containerUpdateError("client", role, name); !strings.Contains(err.Error(), "sudo laneway update server") {
		t.Fatal(err)
	}
	role, name = containerDeployment("/usr/local/bin/laneway\x00-config\x00/etc/laneway/relay.toml\x00", "relay", false)
	if role != "server" || name != "" {
		t.Fatalf("unexpected scratch relay role %q, %q", role, name)
	}
	if err := containerUpdateError("", "", ""); !strings.HasSuffix(err.Error(), "sudo laneway update") {
		t.Fatal(err)
	}
}

func managedConnectorJSON(name string) string {
	return `{
		"Name":"/` + name + `",
		"Config":{
			"Image":"ghcr.io/doout/lane-edge:0.3.10@sha256:` + strings.Repeat("a", 64) + `",
			"Entrypoint":["/usr/local/bin/laneway"],"Cmd":["connector","run"],"User":"65532:65532",
			"Hostname":"` + name + `","Env":["PATH=/usr/local/bin","SETUP_TOKEN=fixture"]
		},
		"State":{"Running":true},
		"HostConfig":{
			"NetworkMode":"bridge","ReadonlyRootfs":true,"CapDrop":["ALL"],
			"SecurityOpt":["no-new-privileges:true"],"RestartPolicy":{"Name":"unless-stopped"},
			"Tmpfs":{"/tmp":"rw,noexec","/run/laneway":"rw,noexec"}
		},
		"Mounts":[{"Type":"volume","Driver":"local","Name":"` + name + `-state","Destination":"/var/lib/laneway","RW":true}],
		"NetworkSettings":{"Networks":{"bridge":{}}}
	}`
}

func TestDockerConnectorDiscoveryIsReadOnlyAndValidatesDeployment(t *testing.T) {
	other := "laneway-connector-other"
	paths := []string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		paths = append(paths, r.URL.Path)
		if !strings.Contains(r.URL.Query().Get("filters"), "^/laneway-connector-") {
			t.Error("expected server-side prefix restriction")
		}
		w.Write([]byte(`[{"Names":["/ignored"]},{"Names":["/` + other + `"]},{"Names":["/` + officeConnector + `"]}]`))
	})
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/containers/" + officeConnector + "/json":
			w.Write([]byte(managedConnectorJSON(officeConnector)))
		case "/containers/" + other + "/json":
			w.Write([]byte(strings.Replace(managedConnectorJSON(other), `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`, 1)))
		default:
			http.NotFound(w, r)
		}
	})
	client := &http.Client{Transport: dockerTestTransport{mux}}
	got, err := findManagedConnectors(client, "")
	if err != nil || !slices.Equal(got, []string{officeConnector}) {
		t.Fatalf("discovery got %q, %v", got, err)
	}
	wantPaths := []string{"/containers/json", "/containers/" + officeConnector + "/json", "/containers/" + other + "/json"}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("read paths %q, want %q", paths, wantPaths)
	}
	paths = nil
	got, err = findManagedConnectors(client, officeConnector)
	if err != nil || !slices.Equal(got, []string{officeConnector}) ||
		!slices.Equal(paths, []string{"/containers/" + officeConnector + "/json"}) {
		t.Fatalf("explicit selection got %q, %v, paths %q", got, err, paths)
	}
}

func TestManagedConnectorRejectsCustomDeployment(t *testing.T) {
	for _, test := range []struct{ name, old, replacement string }{
		{"compose", `"Hostname":`, `"Labels":{"com.docker.compose.project":"orchestrated"},"Hostname":`},
		{"untrusted image", "ghcr.io/doout", "registry.test/path"},
		{"bind mount", `"Type":"volume"`, `"Type":"bind"`},
		{"foreign volume", officeConnector + "-state", "some-other-volume"},
		{"custom volume driver", `"Driver":"local"`, `"Driver":"third-party"`},
		{"custom security", `["no-new-privileges:true"]`, `["no-new-privileges:true","apparmor=unconfined"]`},
		{"custom env", "PATH=/usr/local/bin", "OPERATOR_SETTING=value"},
		{"published port", `"NetworkMode":`, `"PortBindings":{"443/tcp":[{}]},"NetworkMode":`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var connector dockerConnector
			payload := strings.Replace(managedConnectorJSON(officeConnector), test.old, test.replacement, 1)
			if err := json.Unmarshal([]byte(payload), &connector); err != nil {
				t.Fatal(err)
			}
			if connector.managed(officeConnector) {
				t.Fatal("custom configuration qualified as a standard Connector")
			}
		})
	}
}

type dockerTestTransport struct{ handler http.Handler }

func (d dockerTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "docker" {
		return nil, errors.New("expected local Docker endpoint")
	}
	recorder := httptest.NewRecorder()
	d.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}
