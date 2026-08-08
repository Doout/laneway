//go:build !linux

package nodeapp

func lockProcessPrivileges() error { return nil }
