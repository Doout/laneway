//go:build !linux && !darwin

package releaseupdate

import "os/exec"

func cosignPath() (string, error) { return exec.LookPath("cosign") }
