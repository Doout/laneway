package controllerservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzStrictManagementJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"name":"prod","ipv4_pool":"100.96.0.0/16"}`),
		[]byte(`{"priority":10,"action":"accept","selector":{"ipProtocol":"IP_PROTOCOL_TCP"}}`),
		[]byte(`{}`),
		[]byte(`null`),
	} {
		f.Add(seed)
	}
	service := &Service{maxBody: 4096}
	f.Fuzz(func(t *testing.T, body []byte) {
		request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var value networkRequest
		err := service.decodeJSON(response, request, &value)
		if int64(len(body)) > service.maxBody && err == nil {
			t.Fatal("oversized body was accepted")
		}
	})
}

func FuzzTrafficSelectorProtoJSON(f *testing.F) {
	for _, seed := range []string{
		`{"ipProtocol":"IP_PROTOCOL_ANY"}`,
		`{"ipProtocol":"IP_PROTOCOL_TCP","destinationPorts":[{"first":443,"last":443}]}`,
		`{"sourcePrefixes":[{"address":"CgAA","prefixLength":8}],"ipProtocol":"IP_PROTOCOL_UDP"}`,
		`{}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		selector, canonical, err := parseTrafficSelector(json.RawMessage(input))
		if err != nil {
			return
		}
		_ = validateTrafficSelector(selector)
		// Successful parses must produce strict protojson that is itself
		// parseable. This catches non-deterministic or lossy parser states.
		if _, _, err := parseTrafficSelector(canonical); err != nil {
			t.Fatalf("canonical selector no longer parses: %v", err)
		}
	})
}
