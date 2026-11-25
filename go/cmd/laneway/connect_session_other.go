//go:build !linux

package main

func preflightConnectSessionHelper() error { return connectPlatformPreflight() }
