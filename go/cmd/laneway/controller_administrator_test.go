//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func installAdministratorPromptFixture(t *testing.T, values ...[]byte) (string, [][]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalOpen, originalRead := administratorTTYOpener, administratorPasswordReader
	administratorTTYOpener = func() (*os.File, error) { return os.OpenFile(path, os.O_RDWR, 0) }
	index := 0
	administratorPasswordReader = func(int) ([]byte, error) {
		if index >= len(values) {
			return nil, errors.New("unexpected password read")
		}
		value := values[index]
		index++
		return value, nil
	}
	t.Cleanup(func() {
		administratorTTYOpener = originalOpen
		administratorPasswordReader = originalRead
	})
	return path, values
}

func TestAdministratorPasswordPromptIsTTYOnlyAndClearsInputs(t *testing.T) {
	first := []byte("  private password  ")
	confirmation := append([]byte(nil), first...)
	path, inputs := installAdministratorPromptFixture(t, first, confirmation)
	password, err := promptAdministratorPassword()
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "  private password  " {
		t.Fatalf("password was transformed: %q", password)
	}
	for _, input := range inputs {
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("terminal password buffer was not cleared")
		}
	}
	prompt, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(prompt, password) || !bytes.Contains(prompt, []byte("New administrator password:")) ||
		!bytes.Contains(prompt, []byte("Confirm administrator password:")) {
		t.Fatalf("unexpected terminal prompt contents: %q", prompt)
	}
	clear(password)
}

func TestAdministratorPasswordPromptFailsClosed(t *testing.T) {
	first := []byte("a private password")
	confirmation := []byte("a different password")
	_, inputs := installAdministratorPromptFixture(t, first, confirmation)
	if password, err := promptAdministratorPassword(); err == nil || password != nil {
		t.Fatal("mismatched password confirmation was accepted")
	}
	for _, input := range inputs {
		if !bytes.Equal(input, make([]byte, len(input))) {
			t.Fatal("failed terminal password buffer was not cleared")
		}
	}

	originalOpen := administratorTTYOpener
	administratorTTYOpener = func() (*os.File, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { administratorTTYOpener = originalOpen })
	if password, err := promptAdministratorPassword(); err == nil || password != nil {
		t.Fatal("administrator password input succeeded without a controlling terminal")
	}
}

func TestControllerAdministratorRejectsPrivilegeAndSecretFlagsBeforeTTY(t *testing.T) {
	originalUID, originalOpen := administratorEffectiveUserID, administratorTTYOpener
	t.Cleanup(func() {
		administratorEffectiveUserID = originalUID
		administratorTTYOpener = originalOpen
	})
	opened := false
	administratorTTYOpener = func() (*os.File, error) {
		opened = true
		return nil, errors.New("must not open")
	}
	administratorEffectiveUserID = func() int { return 1000 }
	if err := runControllerAdministrator([]string{"bootstrap", "--username", "owner"}); err == nil {
		t.Fatal("non-root administrator lifecycle command succeeded")
	}
	if opened {
		t.Fatal("non-root administrator lifecycle command opened the terminal")
	}
	administratorEffectiveUserID = func() int { return 0 }
	for _, args := range [][]string{
		{"bootstrap", "--username", "owner", "--password", "forbidden"},
		{"recover", "--username", "owner", "--grant", "forbidden"},
		{"recover", "--username", "Owner"},
	} {
		if err := runControllerAdministrator(args); err == nil {
			t.Fatalf("unsafe administrator arguments were accepted: %q", args)
		}
		if opened {
			t.Fatalf("unsafe administrator arguments opened the terminal: %q", args)
		}
	}
}
