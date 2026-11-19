//go:build !windows

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
)

func main() {
	cfgFlag := flag.String("config", "", "path to client config.json")
	autoConnect := flag.Bool("connect", true, "automatically connect tunnel on startup")
	noSysProxy := flag.Bool("no-sysproxy", false, "disable system proxy modifications")
	lowMem := flag.Bool("low-mem", false, "enable low-memory mode (4MB stream windows)")
	flag.Parse()

	if *noSysProxy {
		client.SetNoSysProxy(true)
	}
	if *lowMem {
		gft.SetLowMemMode(true)
		debug.SetMemoryLimit(24 << 20)
	}

	cfgPath := resolveConfigPath(*cfgFlag)
	eng, err := client.NewEngine(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghostframe init failed: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	if err := eng.StartServers(); err != nil {
		fmt.Fprintf(os.Stderr, "ghostframe start servers failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("GhostFrame v3.2 headless client listening (config: %s)\n", cfgPath)

	if *autoConnect {
		if err := eng.Connect(); err != nil {
			fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("Shutting down GhostFrame headless client...")
}
