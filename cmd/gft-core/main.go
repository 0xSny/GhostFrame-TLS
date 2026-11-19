package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
)

const version = "v3.4.0"

func main() {
	cfgFlag := flag.String("config", "", "optional path to client.json (e.g. /etc/gft/client.json)")
	linkFlag := flag.String("link", "", "gft3:// node URI (runs directly without a config file)")
	socksFlag := flag.String("socks", "", "override SOCKS5 listen address (e.g. 0.0.0.0:10808)")
	httpFlag := flag.String("http", "", "override HTTP proxy listen address (e.g. 127.0.0.1:10809)")
	routeFlag := flag.String("route", "", "routing mode: rule, global, or direct")
	transFlag := flag.String("transport", "", "transport preference: auto, rtc, or tcp")
	lowMem := flag.Bool("low-mem", false, "enable low-memory router mode (<35MB RSS, 4MB stream windows, ideal for Phicomm N1/S905D)")
	noSysProxy := flag.Bool("no-sysproxy", false, "disable real system proxy modifications (sandbox mode)")
	showVer := flag.Bool("version", false, "print gft-core version and hardware capabilities")
	flag.Parse()

	if *showVer {
		fmt.Printf("gft-core %s (%s/%s chacha20_priority=%v)\n",
			version, runtime.GOOS, runtime.GOARCH, gft.PrioritizeChaCha20())
		return
	}

	// Headless daemon defaults to sandboxed no-sysproxy when invoked on routers/non-desktop or with -no-sysproxy.
	if *noSysProxy || runtime.GOOS != "windows" {
		client.SetNoSysProxy(true)
	}
	if *lowMem {
		gft.SetLowMemMode(true)
		debug.SetMemoryLimit(24 << 20)
	}

	eng, err := client.NewEngine(*cfgFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gft-core init failed: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	if *linkFlag != "" {
		if _, err := eng.ImportLink(*linkFlag, true); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -link URI: %v\n", err)
			os.Exit(1)
		}
	}
	if *socksFlag != "" || *httpFlag != "" {
		eng.OverrideListenAddrs(*socksFlag, *httpFlag)
	}
	if *routeFlag != "" {
		if err := eng.SetRouteMode(client.RouteMode(*routeFlag)); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -route: %v\n", err)
			os.Exit(1)
		}
	}
	if *transFlag != "" {
		if err := eng.SetTransport(*transFlag); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -transport: %v\n", err)
			os.Exit(1)
		}
	}

	if err := eng.StartServers(); err != nil {
		fmt.Fprintf(os.Stderr, "gft-core start failed: %v\n", err)
		os.Exit(1)
	}

	st := eng.Status()
	fmt.Printf("gft-core %s started (arch=%s/%s chacha20=%v low_mem=%v socks=%v http=%v)\n",
		version, runtime.GOOS, runtime.GOARCH, gft.PrioritizeChaCha20(), gft.IsLowMemMode(), st["socks_addr"], st["http_addr"])

	if err := eng.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "gft-core initial connect error: %v (will continue running/retrying)\n", err)
	} else {
		st = eng.Status()
		fmt.Printf("gft-core connected via %v (RTT=%vms)\n", st["active_transport"], st["ping_ms"])
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("gft-core shutting down cleanly...")
}
