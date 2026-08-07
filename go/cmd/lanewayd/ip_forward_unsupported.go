//go:build !linux

package main

import "context"

type daemonIPForwardManager struct{}

func newDaemonIPForwardManager() *daemonIPForwardManager                       { return &daemonIPForwardManager{} }
func (*daemonIPForwardManager) Apply(context.Context, ipForwardFamilies) error { return nil }
func (*daemonIPForwardManager) Close() error                                   { return nil }
