//go:build linux

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func startFirewallSignalWatcher(stopCh <-chan struct{}, onReload func()) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-stopCh:
				return
			case <-ch:
				if onReload != nil {
					onReload()
				}
			}
		}
	}()
}
