// Package buildinfo exposes values injected into release binaries.
package buildinfo

// Version is replaced by scripts/package.sh through the Go linker. Source
// builds deliberately identify themselves as development builds.
var Version = "dev"
