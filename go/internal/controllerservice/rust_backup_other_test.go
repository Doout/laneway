//go:build rustinterop && !unix

package controllerservice

import "testing"

func testRustBackupRestore(t *testing.T, _ string) {
	t.Skip("native controller lifecycle locking requires a Unix host")
}
