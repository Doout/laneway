package nodeapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Doout/laneway/go/internal/config"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	exitIntentFilename = "exit-intent-v1.json"
	exitIntentVersion  = 1
	exitIntentMaxBytes = 4096
)

// exitIntent is the durable local security choice made through `laneway exit`.
// A disabled record is deliberately retained: deleting it would allow an
// enabled static default to return after a restart.
type exitIntent struct {
	Version        uint32
	Enabled        bool
	SelectedNodeID string
	FailureMode    string
}

type exitIntentStore struct{ path string }

func newExitIntentStore(stateDir string) *exitIntentStore {
	return &exitIntentStore{path: filepath.Join(stateDir, exitIntentFilename)}
}

// Load overlays a durable CLI choice on the static configuration. Static
// configuration is the bootstrap default only while no intent file exists.
// DNS servers and LAN bypasses remain administrator-owned static settings.
func (s *exitIntentStore) Load(configured config.Exit) (config.Exit, bool, error) {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return configured, false, nil
	}
	if err != nil {
		return config.Exit{}, false, fmt.Errorf("inspect %s: %w", s.path, err)
	}
	if !info.Mode().IsRegular() {
		return config.Exit{}, false, fmt.Errorf("%s must be a regular file, not %s", s.path, info.Mode().Type())
	}
	if info.Mode().Perm() != 0o600 {
		return config.Exit{}, false, fmt.Errorf("%s permissions are %04o, want 0600", s.path, info.Mode().Perm())
	}
	if info.Size() > exitIntentMaxBytes {
		return config.Exit{}, false, fmt.Errorf("%s exceeds %d bytes", s.path, exitIntentMaxBytes)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return config.Exit{}, false, fmt.Errorf("open %s: %w", s.path, err)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, exitIntentMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return config.Exit{}, false, fmt.Errorf("read %s: %w", s.path, errors.Join(readErr, closeErr))
	}
	if len(contents) > exitIntentMaxBytes {
		return config.Exit{}, false, fmt.Errorf("%s exceeds %d bytes", s.path, exitIntentMaxBytes)
	}
	intent, err := decodeExitIntent(contents)
	if err != nil {
		return config.Exit{}, false, fmt.Errorf("decode %s: %w", s.path, err)
	}
	configured.Enabled = intent.Enabled
	configured.SelectedNodeID = ""
	if intent.Enabled {
		configured.SelectedNodeID = intent.SelectedNodeID
		configured.FailureMode = intent.FailureMode
	}
	return configured, true, nil
}

func (s *exitIntentStore) Save(enabled bool, selected identity.NodeID, failureMode string) error {
	intent := exitIntent{Version: exitIntentVersion, Enabled: enabled}
	if enabled {
		intent.SelectedNodeID = selected.String()
		intent.FailureMode = failureMode
	}
	if err := validateExitIntent(intent); err != nil {
		return err
	}
	contents, err := encodeExitIntent(intent)
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".exit-intent-*")
	if err != nil {
		return fmt.Errorf("create exit intent temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure exit intent temporary file: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write exit intent temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync exit intent temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close exit intent temporary file: %w", err)
	}
	if current, statErr := os.Lstat(s.path); statErr == nil && !current.Mode().IsRegular() {
		return fmt.Errorf("refusing to replace non-regular exit intent path %s", s.path)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect existing exit intent: %w", statErr)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace exit intent: %w", err)
	}
	return syncDirectory(directory)
}

// Remove is used only to roll back a failed first persistence attempt. A user
// disable is represented by a durable neutral record through Save(false, ...).
func (s *exitIntentStore) Remove() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove exit intent: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func encodeExitIntent(intent exitIntent) ([]byte, error) {
	value := struct {
		Version        uint32 `json:"version"`
		Enabled        bool   `json:"enabled"`
		SelectedNodeID string `json:"selected_node_id,omitempty"`
		FailureMode    string `json:"failure_mode,omitempty"`
	}{intent.Version, intent.Enabled, intent.SelectedNodeID, intent.FailureMode}
	contents, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(contents, '\n'), nil
}

// decodeExitIntent rejects unknown, missing, and duplicate members. This is
// intentionally stricter than encoding/json's normal struct decoding because
// the file controls a fail-open/fail-closed security decision.
func decodeExitIntent(contents []byte) (exitIntent, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	token, err := decoder.Token()
	if err != nil {
		return exitIntent{}, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return exitIntent{}, errors.New("exit intent must be one JSON object")
	}
	var intent exitIntent
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		rawName, err := decoder.Token()
		if err != nil {
			return exitIntent{}, err
		}
		name, ok := rawName.(string)
		if !ok {
			return exitIntent{}, errors.New("exit intent member name is not a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return exitIntent{}, fmt.Errorf("duplicate member %q", name)
		}
		seen[name] = struct{}{}
		switch name {
		case "version":
			err = decoder.Decode(&intent.Version)
		case "enabled":
			err = decoder.Decode(&intent.Enabled)
		case "selected_node_id":
			err = decoder.Decode(&intent.SelectedNodeID)
		case "failure_mode":
			err = decoder.Decode(&intent.FailureMode)
		default:
			return exitIntent{}, fmt.Errorf("unknown member %q", name)
		}
		if err != nil {
			return exitIntent{}, fmt.Errorf("member %q: %w", name, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return exitIntent{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return exitIntent{}, errors.New("trailing JSON value")
	}
	if _, ok := seen["version"]; !ok {
		return exitIntent{}, errors.New("missing member \"version\"")
	}
	if _, ok := seen["enabled"]; !ok {
		return exitIntent{}, errors.New("missing member \"enabled\"")
	}
	_, selectedPresent := seen["selected_node_id"]
	_, failurePresent := seen["failure_mode"]
	if intent.Enabled && (!selectedPresent || !failurePresent) {
		return exitIntent{}, errors.New("enabled exit intent requires selected_node_id and failure_mode")
	}
	if !intent.Enabled && (selectedPresent || failurePresent) {
		return exitIntent{}, errors.New("disabled exit intent must be neutral")
	}
	if err := validateExitIntent(intent); err != nil {
		return exitIntent{}, err
	}
	return intent, nil
}

func validateExitIntent(intent exitIntent) error {
	if intent.Version != exitIntentVersion {
		return fmt.Errorf("unsupported exit intent version %d", intent.Version)
	}
	if !intent.Enabled {
		if intent.SelectedNodeID != "" || intent.FailureMode != "" {
			return errors.New("disabled exit intent must be neutral")
		}
		return nil
	}
	selected, err := identity.ParseNodeID(intent.SelectedNodeID)
	if err != nil || selected.IsZero() {
		return errors.New("selected_node_id must be a nonzero canonical NodeID")
	}
	if selected.String() != intent.SelectedNodeID {
		return errors.New("selected_node_id must use canonical lowercase encoding")
	}
	if intent.FailureMode != "open" && intent.FailureMode != "closed" {
		return errors.New("failure_mode must be exactly open or closed")
	}
	return nil
}
