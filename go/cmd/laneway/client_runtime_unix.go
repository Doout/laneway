//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func nativeClientRuntime() (string, error) {
	if nativeClientCommands != "1" {
		return "", nil
	}
	source, err := os.Executable()
	if err != nil {
		return "", err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return "", err
	}
	runtime, err := rootlessRuntime(source)
	if err != nil {
		return "", nil
	}
	return runtime, nil
}

func tryNativeClient(args ...string) (bool, error) {
	runtime, err := nativeClientRuntime()
	if runtime == "" || err != nil {
		return false, err
	}
	return true, syscall.Exec(runtime, append([]string{runtime, "_client"}, args...), os.Environ())
}

// The protected system runtime is resolved and version-checked by the caller.
func execNativeConnect(executable string, args []string) error {
	environment := os.Environ()
	if runtime.GOOS == "linux" {
		environment = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "LANEWAY_PROFILE_DIR", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
			if value, present := os.LookupEnv(name); present {
				environment = append(environment, name+"="+value)
			}
		}
	}
	return syscall.Exec(executable, append([]string{executable, "_client", "connect"}, args...), environment)
}
