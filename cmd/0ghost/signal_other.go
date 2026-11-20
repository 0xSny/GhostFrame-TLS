//go:build !linux

package main

func startFirewallSignalWatcher(_ <-chan struct{}, _ func()) {}
