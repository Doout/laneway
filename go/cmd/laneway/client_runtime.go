package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
	"github.com/Doout/laneway/go/internal/bootstrap"
	"github.com/Doout/laneway/go/internal/controllerclient"
	"github.com/Doout/laneway/go/internal/identity"
	"google.golang.org/protobuf/proto"
)

// Release packaging enables native commands when the matching runtime is present.
var nativeClientCommands string

func nativeClientOutput(cmd *exec.Cmd, operation string) ([]byte, error) {
	data, err := cmd.Output()
	if failed, ok := err.(*exec.ExitError); ok && len(failed.Stderr) != 0 {
		return nil, fmt.Errorf("%s: %s", operation, strings.TrimSpace(string(failed.Stderr)))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return data, nil
}

func fetchBootstrap(ctx context.Context, authority string) (bootstrap.Metadata, error) {
	runtime, err := nativeClientRuntime()
	if err != nil {
		return bootstrap.Metadata{}, err
	}
	if runtime == "" {
		return bootstrap.Fetch(ctx, authority)
	}
	cmd := exec.CommandContext(ctx, runtime, "_client", "discover", "--", authority)
	data, err := nativeClientOutput(cmd, "bootstrap discovery")
	if err != nil {
		return bootstrap.Metadata{}, err
	}
	var metadata bootstrap.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return bootstrap.Metadata{}, fmt.Errorf("decode native bootstrap discovery: %w", err)
	}
	return metadata, nil
}

func submitClientEnrollment(ctx context.Context, metadata bootstrap.Metadata, code string, csrDER, wireGuardPublicKey []byte, network identity.NetworkID, class lanewayv1.EnrollmentClass) (*lanewayv1.EnrollmentResponse, error) {
	runtime, err := nativeClientRuntime()
	if err != nil {
		return nil, err
	}
	controller := metadata.Controller
	if runtime == "" {
		service, err := identity.ParseID(controller.ServiceID)
		if err != nil {
			return nil, err
		}
		client, err := controllerclient.New(controllerclient.Options{
			Endpoint: controller.EnrollmentEndpoint, CAPEM: []byte(metadata.Trust.CAPEM),
			ServerName: controller.ServerName, ExpectedNetworkID: network, ExpectedServiceID: service,
		})
		if err != nil {
			return nil, err
		}
		return client.EnrollForNetworkAndClass(ctx, code, "", csrDER, wireGuardPublicKey, network, class)
	}
	request, err := proto.Marshal(&lanewayv1.EnrollmentRequest{
		EnrollmentToken: code, Pkcs10CsrDer: csrDER, WireguardPublicKey: wireGuardPublicKey,
		ExpectedNetworkId: network[:], ExpectedEnrollmentClass: class,
	})
	if err != nil {
		return nil, err
	}
	defer clear(request)
	input, err := json.Marshal(struct {
		Endpoint   string `json:"endpoint"`
		CAPEM      string `json:"ca_pem"`
		ServerName string `json:"server_name"`
		ServiceID  string `json:"service_id"`
		Request    []byte `json:"request"`
	}{controller.EnrollmentEndpoint, metadata.Trust.CAPEM, controller.ServerName, controller.ServiceID, request})
	if err != nil {
		return nil, err
	}
	defer clear(input)
	cmd := exec.CommandContext(ctx, runtime, "_client", "submit-enrollment")
	cmd.Stdin = bytes.NewReader(input)
	data, err := nativeClientOutput(cmd, "enrollment")
	if err != nil {
		return nil, err
	}
	response := new(lanewayv1.EnrollmentResponse)
	if err := proto.Unmarshal(data, response); err != nil {
		return nil, fmt.Errorf("decode native enrollment response: %w", err)
	}
	return response, nil
}
