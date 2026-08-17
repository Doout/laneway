//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Doout/laneway/go/internal/adminauth"
	"github.com/Doout/laneway/go/internal/identity"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	administratorEffectiveUserID = os.Geteuid
	administratorTTYOpener       = func() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }
	administratorPasswordReader  = term.ReadPassword
)

func controllerAdministratorCommand() *cobra.Command {
	administrator := group("administrator", "Internal administrator lifecycle operations", runControllerAdministrator)
	administrator.AddCommand(
		forwarded("bootstrap", "Bootstrap the first administrator", "bootstrap", runControllerAdministrator),
		forwarded("recover", "Recover an administrator owner", "recover", runControllerAdministrator),
	)
	rootToken := group("root-token", "Internal root administrator token operations", runControllerAdministratorRootToken,
		forwarded("generate", "Create a protected candidate root token file", "generate", runControllerAdministratorRootToken),
		forwarded("authentication-check", "Check the exact root credential status", "authentication-check", runControllerAdministratorRootToken),
		forwarded("rotation-begin", "Record the start of root token rotation", "rotation-begin", runControllerAdministratorRootToken),
		forwarded("rotation-complete", "Record completed root token rotation", "rotation-complete", runControllerAdministratorRootToken),
	)
	administrator.AddCommand(rootToken)
	return administrator
}

func runControllerAdministrator(args []string) error {
	if administratorEffectiveUserID() != 0 {
		return errors.New("controller administrator lifecycle commands must run as root")
	}
	if len(args) == 0 {
		return errors.New("usage: laneway controller administrator <bootstrap|recover|root-token> ...")
	}
	switch args[0] {
	case "bootstrap", "recover":
		return runControllerAdministratorPasswordLifecycle(args[0], args[1:])
	case "root-token":
		return runControllerAdministratorRootToken(args[1:])
	default:
		return fmt.Errorf("unknown controller administrator command %q", args[0])
	}
}

func runControllerAdministratorPasswordLifecycle(action string, args []string) error {
	fs := flag.NewFlagSet("controller administrator "+action, flag.ContinueOnError)
	username := fs.String("username", "", "canonical administrator username")
	remote := addRemoteFlags(fs, false, true)
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if !adminauth.ValidateUsername(*username) {
		return errors.New("administrator lifecycle requires a valid --username")
	}
	client, err := remote.client()
	if err != nil {
		return err
	}
	preflightContext, cancelPreflight := commandContext()
	accepted, err := client.RootAuthenticationAccepted(preflightContext)
	cancelPreflight()
	if err != nil {
		return err
	}
	if !accepted {
		return errors.New("root administrator credential was rejected before administrator lifecycle input")
	}
	password, err := promptAdministratorPassword()
	if err != nil {
		return err
	}
	defer clear(password)
	ctx, cancel := commandContext()
	defer cancel()
	if action == "bootstrap" {
		return client.BootstrapFirstAdministrator(ctx, *username, password)
	}
	return client.RecoverAdministratorOwner(ctx, *username, password)
}

func promptAdministratorPassword() ([]byte, error) {
	tty, err := administratorTTYOpener()
	if err != nil {
		return nil, errors.New("administrator lifecycle requires a controlling terminal")
	}
	defer tty.Close()
	first, err := readAdministratorPassword(tty, "New administrator password: ")
	if err != nil {
		return nil, err
	}
	defer clear(first)
	if err := adminauth.ValidatePassword(first); err != nil {
		return nil, err
	}
	confirmation, err := readAdministratorPassword(tty, "Confirm administrator password: ")
	if err != nil {
		return nil, err
	}
	defer clear(confirmation)
	if err := adminauth.ValidatePassword(confirmation); err != nil {
		return nil, err
	}
	if !bytes.Equal(first, confirmation) {
		return nil, errors.New("administrator password confirmation did not match")
	}
	return append([]byte(nil), first...), nil
}

func readAdministratorPassword(tty *os.File, prompt string) ([]byte, error) {
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, errors.New("could not write administrator password prompt")
	}
	value, err := administratorPasswordReader(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		clear(value)
		return nil, errors.New("could not read administrator password from controlling terminal")
	}
	return value, nil
}

func runControllerAdministratorRootToken(args []string) error {
	if administratorEffectiveUserID() != 0 {
		return errors.New("controller administrator lifecycle commands must run as root")
	}
	if len(args) == 0 {
		return errors.New("usage: laneway controller administrator root-token <generate|authentication-check|rotation-begin|rotation-complete> ...")
	}
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("controller administrator root-token generate", flag.ContinueOnError)
		outFile := fs.String("out-file", "", "new protected file for the candidate root token")
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		if *outFile == "" || !filepath.IsAbs(*outFile) {
			return errors.New("root-token generate requires an absolute --out-file")
		}
		return generateProtectedRootToken(*outFile)

	case "authentication-check":
		fs := flag.NewFlagSet("controller administrator root-token authentication-check", flag.ContinueOnError)
		expect := fs.String("expect", "", "required result: accepted or rejected")
		remote := addRemoteFlags(fs, false, true)
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		if *expect != "accepted" && *expect != "rejected" {
			return errors.New("root-token authentication-check requires --expect accepted or --expect rejected")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		accepted, err := client.RootAuthenticationAccepted(ctx)
		if err != nil {
			return err
		}
		if accepted != (*expect == "accepted") {
			return errors.New("root administrator credential did not have the required authentication status")
		}
		return nil

	case "rotation-begin", "rotation-complete":
		fs := flag.NewFlagSet("controller administrator root-token "+args[0], flag.ContinueOnError)
		rotationText := fs.String("rotation-id", "", "non-secret root token rotation correlation ID")
		remote := addRemoteFlags(fs, false, true)
		if err := parseNoArgs(fs, args[1:]); err != nil {
			return err
		}
		rotationID, err := identity.ParseID(*rotationText)
		if err != nil {
			return errors.New("root-token rotation requires a canonical nonzero --rotation-id")
		}
		client, err := remote.client()
		if err != nil {
			return err
		}
		ctx, cancel := commandContext()
		defer cancel()
		if args[0] == "rotation-begin" {
			return client.BeginRootTokenRotation(ctx, rotationID)
		}
		return client.CompleteRootTokenRotation(ctx, rotationID)

	default:
		return fmt.Errorf("unknown controller administrator root-token command %q", args[0])
	}
}

func generateProtectedRootToken(path string) error {
	parent := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(parent) {
		return errors.New("root token output parent must be a real directory without symbolic links")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("root token output parent must be a protected directory with mode 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("root token output parent must be owned by root")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("root token output path must not already exist")
	}
	raw := make([]byte, 32)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("could not generate root administrator credential")
	}
	token := make([]byte, hex.EncodedLen(len(raw))+1)
	defer clear(token)
	hex.Encode(token, raw)
	token[len(token)-1] = '\n'
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("could not create protected root token output")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chown(0, 0); err != nil {
		return errors.New("could not protect root token output owner")
	}
	if err := file.Chmod(0o600); err != nil {
		return errors.New("could not protect root token output mode")
	}
	if written, err := file.Write(token); err != nil || written != len(token) {
		return errors.New("could not write protected root token output")
	}
	if err := file.Sync(); err != nil {
		return errors.New("could not make protected root token output durable")
	}
	if err := file.Close(); err != nil {
		return errors.New("could not close protected root token output")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return errors.New("could not open protected root token directory")
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return errors.New("could not make protected root token directory durable")
	}
	if err := directory.Close(); err != nil {
		return errors.New("could not close protected root token directory")
	}
	remove = false
	return nil
}
