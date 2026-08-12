package controllerservice

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	lanewayv1 "laneway.dev/laneway/api/laneway/v1"
	"laneway.dev/laneway/internal/adminauth"
	"laneway.dev/laneway/internal/bootstrap"
)

const maxBootstrapBundles = 1024

type bootstrapBundle struct {
	payload   []byte
	expiresAt time.Time
}

type bootstrapBundleStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]bootstrapBundle
}

func newBootstrapBundleStore(now func() time.Time) *bootstrapBundleStore {
	return &bootstrapBundleStore{now: now, entries: make(map[string]bootstrapBundle)}
}

func (s *bootstrapBundleStore) create(payload []byte, expiresAt time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for id, bundle := range s.entries {
		if !bundle.expiresAt.After(now) {
			clear(bundle.payload)
			delete(s.entries, id)
		}
	}
	if len(s.entries) >= maxBootstrapBundles {
		return "", errors.New("bootstrap bundle capacity is exhausted")
	}
	for range 8 {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		id := base64.RawURLEncoding.EncodeToString(random)
		clear(random)
		if _, exists := s.entries[id]; exists {
			continue
		}
		s.entries[id] = bootstrapBundle{payload: append([]byte(nil), payload...), expiresAt: expiresAt.UTC()}
		return id, nil
	}
	return "", errors.New("could not allocate a unique bootstrap bundle")
}

func (s *bootstrapBundleStore) take(id string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bundle, exists := s.entries[id]
	if !exists {
		return nil, false
	}
	delete(s.entries, id)
	if !bundle.expiresAt.After(s.now().UTC()) {
		clear(bundle.payload)
		return nil, false
	}
	payload := append([]byte(nil), bundle.payload...)
	clear(bundle.payload)
	return payload, true
}

func (s *bootstrapBundleStore) discard(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bundle, exists := s.entries[id]; exists {
		clear(bundle.payload)
		delete(s.entries, id)
	}
}

type bootstrapBundleRequest struct {
	Payload       string `json:"payload"`
	ExpiresAtUnix int64  `json:"expires_at_unix_seconds"`
}

type bootstrapBundleResponse struct {
	BundleID      string `json:"bundle_id"`
	PublicPath    string `json:"public_path"`
	ExpiresAtUnix int64  `json:"expires_at_unix_seconds"`
}

func (s *Service) createBootstrapBundle(w http.ResponseWriter, r *http.Request) {
	var request bootstrapBundleRequest
	if err := s.decodeJSON(w, r, &request); err != nil {
		s.writeError(w, err, false)
		return
	}
	payload := []byte(request.Payload)
	now := s.now().UTC()
	expiresAt := time.Unix(request.ExpiresAtUnix, 0).UTC()
	if len(payload) == 0 || len(payload) > bootstrap.MaxBundleBytes || strings.IndexByte(request.Payload, 0) >= 0 ||
		!strings.HasPrefix(request.Payload, "#!/bin/bash\n") {
		s.writeError(w, malformed("bootstrap payload must be a bounded bash script"), false)
		return
	}
	if !expiresAt.After(now) || expiresAt.After(now.Add(bootstrap.MaxBundleLifetime)) {
		s.writeError(w, malformed("bootstrap expiry must be within 10 minutes"), false)
		return
	}
	id, err := s.bootstrapBundles.create(payload, expiresAt)
	clear(payload)
	if err != nil {
		s.writeError(w, &requestError{status: http.StatusServiceUnavailable,
			code: lanewayv1.ErrorCode_ERROR_CODE_INTERNAL, detail: "bootstrap service temporarily unavailable", retryable: true}, false)
		return
	}
	decision, err := s.administratorDecision(r, adminauth.GlobalTarget())
	if err == nil {
		err = s.store.AdministratorAuditMutation(r.Context(), decision, "bootstrap_bundle.create", "bootstrap_bundle",
			`{"storage":"ephemeral"}`)
	}
	if err != nil {
		s.bootstrapBundles.discard(id)
		s.writeError(w, err, false)
		return
	}
	s.writeJSON(w, http.StatusCreated, bootstrapBundleResponse{
		BundleID: id, PublicPath: bootstrap.BundlePathPrefix + id, ExpiresAtUnix: expiresAt.Unix(),
	})
}

func (s *Service) servePrivateBootstrapBundle(w http.ResponseWriter, r *http.Request) {
	if _, err := authenticatedRelay(r); err != nil {
		s.writeError(w, err, false)
		return
	}
	id := r.PathValue("bundle_id")
	if _, valid := bootstrap.BundleIDFromPath(bootstrap.BundlePathPrefix + id); !valid || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	s.serveBootstrapBundle(w, r, id)
}

func (s *Service) serveBootstrapBundle(w http.ResponseWriter, r *http.Request, id string) {
	payload, found := s.bootstrapBundles.take(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	defer clear(payload)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
