//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	errLocalDockerUnavailable = errors.New("the local Docker Engine is unavailable")
	connectorImageReference   = regexp.MustCompile(`^ghcr\.io/doout/(lane-edge|laneway-connector|laneway-exit-node):[0-9]+\.[0-9]+\.[0-9]+@sha256:[a-f0-9]{64}$`)
)

const localDockerSocket = "/run/docker.sock"

type dockerConnector struct {
	Name   string
	Config struct {
		Image      string
		Hostname   string
		User       string
		Entrypoint []string
		Cmd        []string
		Labels     map[string]string
		Env        []string
	}
	State struct {
		Running bool
	}
	HostConfig struct {
		NetworkMode     string
		Privileged      bool
		ReadonlyRootfs  bool
		PublishAllPorts bool
		CapAdd          []string
		CapDrop         []string
		SecurityOpt     []string
		PortBindings    map[string]json.RawMessage
		Devices         []json.RawMessage
		DeviceRequests  []json.RawMessage
		Tmpfs           map[string]string
		ExtraHosts      []string
		RestartPolicy   struct{ Name string }
	}
	Mounts []struct {
		Type        string
		Name        string
		Driver      string
		Destination string
		RW          bool
	}
	NetworkSettings struct {
		Networks map[string]json.RawMessage
	}
}

func (c dockerConnector) managed(name string) bool {
	host := c.HostConfig
	if c.Name != "/"+name || !c.State.Running || !connectorImageReference.MatchString(c.Config.Image) ||
		c.Config.Hostname != name || c.Config.User != "65532:65532" ||
		!slices.Equal(c.Config.Entrypoint, []string{"/usr/local/bin/laneway"}) ||
		!slices.Equal(c.Config.Cmd, []string{"connector", "run"}) {
		return false
	}
	standardSecurity := slices.Equal(host.SecurityOpt, []string{"no-new-privileges:true"}) ||
		slices.Equal(host.SecurityOpt, []string{"no-new-privileges"})
	if host.Privileged || !host.ReadonlyRootfs || host.PublishAllPorts ||
		len(host.CapAdd) != 0 || !slices.Equal(host.CapDrop, []string{"ALL"}) ||
		!standardSecurity ||
		len(host.PortBindings) != 0 || len(host.Devices) != 0 || len(host.DeviceRequests) != 0 ||
		len(host.ExtraHosts) != 0 || host.RestartPolicy.Name != "unless-stopped" {
		return false
	}
	if host.NetworkMode != "bridge" && host.NetworkMode != "default" {
		return false
	}
	_, bridge := c.NetworkSettings.Networks["bridge"]
	if len(c.NetworkSettings.Networks) != 1 || !bridge {
		return false
	}
	for label := range c.Config.Labels {
		if label != "io.laneway.update-transaction" && !strings.HasPrefix(label, "org.opencontainers.image.") {
			return false
		}
	}
	for _, variable := range c.Config.Env {
		key, _, _ := strings.Cut(variable, "=")
		if key != "PATH" && key != "SETUP_TOKEN" {
			return false
		}
	}
	for destination := range host.Tmpfs {
		if destination != "/tmp" && destination != "/run/laneway" {
			return false
		}
	}
	volumeCount := 0
	for _, mount := range c.Mounts {
		switch {
		case mount.Type == "volume" && mount.Name == name+"-state" &&
			mount.Driver == "local" && mount.Destination == "/var/lib/laneway" && mount.RW:
			volumeCount++
		case mount.Type == "tmpfs" && (mount.Destination == "/tmp" || mount.Destination == "/run/laneway"):
		default:
			return false
		}
	}
	return volumeCount == 1
}

func localManagedConnectors(name string) ([]string, error) {
	socket, err := os.Lstat(localDockerSocket)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errLocalDockerUnavailable, err)
	}
	if socket.Mode()&os.ModeSocket == 0 || unixOwner(socket) != 0 {
		return nil, fmt.Errorf("unsafe local Docker socket %s", localDockerSocket)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Always use the host's standard local Unix socket. Docker contexts,
			// proxies, and environment-based remote targets cannot redirect this.
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", localDockerSocket)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return findManagedConnectors(client, name)
}

func findManagedConnectors(client *http.Client, name string) ([]string, error) {
	candidates := []string{name}
	if name == "" {
		var listed []struct{ Names []string }
		query := url.Values{"filters": {`{"name":["^/laneway-connector-"]}`}}
		found, err := getDockerJSON(client, "/containers/json?"+query.Encode(), &listed)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errors.New("local Docker Engine does not expose the container list")
		}
		candidates = nil
		for _, container := range listed {
			for _, fullName := range container.Names {
				candidate := strings.TrimPrefix(fullName, "/")
				if connectorName.MatchString(candidate) {
					candidates = append(candidates, candidate)
				}
			}
		}
		slices.Sort(candidates)
		candidates = slices.Compact(candidates)
	}
	var managed []string
	for _, candidate := range candidates {
		if !connectorName.MatchString(candidate) {
			return nil, fmt.Errorf("invalid standard Connector name %q", candidate)
		}
		var connector dockerConnector
		found, err := getDockerJSON(client, "/containers/"+candidate+"/json", &connector)
		if err != nil {
			return nil, err
		}
		if found && connector.managed(candidate) {
			managed = append(managed, candidate)
		}
	}
	return managed, nil
}

func getDockerJSON(client *http.Client, path string, output any) (bool, error) {
	response, err := client.Get("http://docker" + path)
	if err != nil {
		return false, fmt.Errorf("%w: %v", errLocalDockerUnavailable, err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output); err != nil {
			return false, fmt.Errorf("decode local Docker response: %w", err)
		}
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("local Docker Engine returned HTTP %d", response.StatusCode)
	}
}
