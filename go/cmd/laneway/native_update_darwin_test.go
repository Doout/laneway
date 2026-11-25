package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyMacUpdateRunsCandidateConfigure(t *testing.T) {
	work := t.TempDir()
	candidate := filepath.Join(work, "laneway")
	calls := filepath.Join(work, "calls")
	t.Setenv("LANEWAY_TEST_CONFIGURE_CALLS", calls)
	const fake = `#!/bin/sh
case "$1" in
  version) printf '%s\n' 999999.0.0 ;;
  configure) printf '%s\n' "$*" >"$LANEWAY_TEST_CONFIGURE_CALLS"; exit 17 ;;
  *) exit 18 ;;
esac
`
	if err := os.WriteFile(candidate, []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "laneway-compat"), []byte("#!/bin/sh\n[ \"$1\" = version ] || exit 19\necho 999999.0.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "lanewayd"), []byte("#!/bin/sh\necho 'lanewayd 999999.0.0'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	updateErr := installVerifiedMacUpdate(candidate, "v999999.0.0", true)
	if updateErr == nil || !strings.Contains(updateErr.Error(), "exit status 17") {
		t.Fatalf("expected candidate installer failure, got %v", updateErr)
	}
	got, err := os.ReadFile(calls)
	if err != nil || string(got) != "configure --system --yes\n" {
		t.Fatalf("candidate configuration call = %q, %v", got, err)
	}
}
