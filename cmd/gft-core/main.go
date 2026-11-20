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

var version = "v4.0.26-LTS"

func main() {
	cfgFlag := flag.String("config", "", "optional path to client.json (e.g. /etc/kestrel/client.json)")
	linkFlag := flag.String("link", "", "ksl4:// (or gft3://) node URI (runs directly without a config file)")
	socksFlag := flag.String("socks", "", "override SOCKS5 listen address (e.g. 0.0.0.0:10808)")
	httpFlag := flag.String("http", "", "override HTTP proxy listen address (e.g. 127.0.0.1:10809)")
	routeFlag := flag.String("route", "", "routing mode: rule, global, or direct")
	transFlag := flag.String("transport", "", "transport preference: auto, rtc, or tcp")
	upMbpsFlag := flag.Int("up-mbps", -1, "Smart-Brutal target upload Mbps override (>=0, 0=Auto-Probe)")
	downMbpsFlag := flag.Int("down-mbps", -1, "Smart-Brutal target download Mbps override (>=0, 0=Auto-Probe)")
	lowMem := flag.Bool("low-mem", false, "enable low-memory router mode (<35MB RSS, 4MB stream windows, ideal for Phicomm N1/S905D)")
	noSysProxy := flag.Bool("no-sysproxy", false, "disable real system proxy modifications (sandbox mode)")
	showVer := flag.Bool("version", false, "print kestrel-core version and hardware capabilities")
	flag.Parse()

	if *showVer {
		fmt.Printf("kestrel-core %s (%s/%s chacha20_priority=%v)\n",
			version, runtime.GOOS, runtime.GOARCH, gft.PrioritizeChaCha20())
		return
	}

	// Headless daemon defaults to sandboxed no-sysproxy when invoked on routers/non-desktop or with -no-sysproxy.
	if *noSysProxy || runtime.GOOS != "windows" {
		client.SetNoSysProxy(true)
	}
	if *lowMem {
		gft.SetLowMemMode(true)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		if *lowMem {
			debug.SetMemoryLimit(64 << 20)
		} else {
			debug.SetMemoryLimit(256 << 20)
		}
	}

	eng, err := client.NewEngine(*cfgFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kestrel-core init failed: %v\n", err)
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
	if *upMbpsFlag >= 0 || *downMbpsFlag >= 0 {
		cur := eng.Status()
		upVal, _ := cur["up_mbps"].(int)
		downVal, _ := cur["down_mbps"].(int)
		if *upMbpsFlag >= 0 {
			upVal = *upMbpsFlag
		}
		if *downMbpsFlag >= 0 {
			downVal = *downMbpsFlag
		}
		if err := eng.SetBandwidthLimits(upVal, downVal); err != nil {
			fmt.Fprintf(os.Stderr, "invalid bandwidth flags: %v\n", err)
			os.Exit(1)
		}
	}

	if err := eng.StartServers(); err != nil {
		fmt.Fprintf(os.Stderr, "kestrel-core start failed: %v\n", err)
		os.Exit(1)
	}

	st := eng.Status()
	fmt.Printf("kestrel-core %s started (arch=%s/%s chacha20=%v low_mem=%v socks=%v http=%v hop=%v up_mbps=%v down_mbps=%v)\n",
		version, runtime.GOOS, runtime.GOARCH, gft.PrioritizeChaCha20(), gft.IsLowMemMode(), st["socks_addr"], st["http_addr"], st["hop_range"], st["up_mbps"], st["down_mbps"])

	if err := eng.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "kestrel-core initial connect error: %v (will continue running/retrying)\n", err)
	} else {
		st = eng.Status()
		fmt.Printf("kestrel-core connected via %v (rtc_port=%v ping=%vms pacing=%.1fMbps fec_recovered=%v)\n",
			st["active_transport"], st["rtc_port"], st["ping_ms"], st["pacing_mbps"], st["fec_recovered"])
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	fmt.Println("kestrel-core shutting down cleanly...")
}
