//go:build rustinterop && !unix

package controllerservice

import (
	"net/http"
	"testing"
)

func testRustBackupRestore(t *testing.T, _ *http.Client, _, _, _ string) {
	t.Skip("native controller lifecycle locking requires a Unix host")
}
