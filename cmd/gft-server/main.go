package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/server"
	"ghostframe/internal/sni"
	"ghostframe/internal/tui"
)

const version = "v3.4.1"

func main() {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
	if strings.EqualFold(base, "gft") && (len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-")) {
		runMenu(os.Args[1:])
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gft-server <run|init|link|menu|show-card|sni-test|version> [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "menu":
		runMenu(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "link":
		fs := flag.NewFlagSet("link", flag.ExitOnError)
		conf := fs.String("config", tui.DefaultConfigPath, "config file")
		_ = fs.Parse(os.Args[2:])
		c, err := server.LoadConfig(*conf)
		if err != nil {
			log.Fatal(err)
		}
		p := gft.DefaultParams()
		if c.Params != nil && c.Params.Validate() == nil {
			p = *c.Params
		}
		fmt.Println(c.Link(p).Encode())
	case "show-card":
		fs := flag.NewFlagSet("show-card", flag.ExitOnError)
		conf := fs.String("config", tui.DefaultConfigPath, "config file")
		_ = fs.Parse(os.Args[2:])
		if err := tui.ShowDeliveryCard(*conf, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "sni-test":
		runSNITest(os.Args[2:])
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		conf := fs.String("config", tui.DefaultConfigPath, "config file")
		_ = fs.Parse(os.Args[2:])
		c, err := server.LoadConfig(*conf)
		if err != nil {
			log.Fatal(err)
		}
		logger := log.New(os.Stderr, "gft ", log.LstdFlags)
		s, err := server.New(c, logger)
		if err != nil {
			log.Fatal(err)
		}
		s.SetConfigPath(*conf)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := s.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "version", "-v", "--version":
		fmt.Printf("gft-server %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runMenu(args []string) {
	fs := flag.NewFlagSet("menu", flag.ExitOnError)
	conf := fs.String("config", tui.DefaultConfigPath, "config file")
	_ = fs.Parse(args)
	ctrl := tui.NewController(*conf)
	if err := ctrl.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "gft menu error: %v\n", err)
		os.Exit(1)
	}
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	confDir := fs.String("conf-dir", "/etc/gft", "config directory")
	stateDir := fs.String("state-dir", "/var/lib/gft", "state directory")
	host := fs.String("host", "", "public host or domain (auto-detected if omitted)")
	sniFlag := fs.String("sni", "", "TLS server name (empty or 'auto' selects lowest-latency non-CDN origin)")
	autoSNI := fs.Bool("auto-sni", false, "concurrently probe non-CDN regional pools and randomize among Top-5")
	listen := fs.String("listen", ":443", "listen address")
	certMode := fs.String("cert-mode", "self_signed_90d", "certificate mode: acme, file, self_signed_90d")
	certFile := fs.String("cert-file", "", "TLS certificate path for cert-mode=file")
	keyFile := fs.String("key-file", "", "TLS private key path for cert-mode=file")
	acmeDomains := fs.String("acme-domains", "", "comma-separated ACME domains")
	acmeEmail := fs.String("acme-email", "", "ACME contact email")
	fallbackMode := fs.String("fallback-mode", "", "fallback mode: mirror, reverse_proxy, or builtin_blog")
	fallbackTarget := fs.String("fallback-target", "", "reverse proxy target URL (e.g. http://127.0.0.1:8080)")
	camouflageTarget := fs.String("camouflage", "", "Pre-TLS transparent camouflage mirror target (host:port)")
	hopRange := fs.String("hop-range", "", "optional UDP port hopping range advertised in gft3:// link (e.g. 20000-30000)")
	_ = fs.Parse(args)

	pubHost := strings.TrimSpace(*host)
	if pubHost == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		pubHost = sni.DetectSelfPublicIP(ctx)
		cancel()
	}
	if pubHost == "" {
		log.Fatal("-host required (auto-detect failed)")
	}

	chosenSNI := strings.TrimSpace(*sniFlag)
	if *autoSNI || chosenSNI == "" || chosenSNI == "auto" {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		pick, _, serr := sni.AutoSelectSNI(ctx, pubHost)
		cancel()
		if serr == nil && pick.Domain != "" {
			chosenSNI = pick.Domain
		}
	}

	var domains []string
	if *acmeDomains != "" {
		for _, d := range strings.Split(*acmeDomains, ",") {
			if t := strings.TrimSpace(d); t != "" {
				domains = append(domains, t)
			}
		}
	}
	sec, err := server.InitWithOptions(server.InitOptions{
		ConfDir:          *confDir,
		StateDir:         *stateDir,
		Host:             pubHost,
		SNI:              chosenSNI,
		Listen:           *listen,
		CertMode:         *certMode,
		CertFile:         *certFile,
		KeyFile:          *keyFile,
		ACMEDomains:      domains,
		ACMEEmail:        *acmeEmail,
		FallbackMode:     *fallbackMode,
		FallbackTarget:   *fallbackTarget,
		CamouflageTarget: *camouflageTarget,
		HopRange:         *hopRange,
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(sec)
}

func runSNITest(args []string) {
	fs := flag.NewFlagSet("sni-test", flag.ExitOnError)
	selfIP := fs.String("self-ip", "", "VPS public IP to exclude from candidates")
	jsonOut := fs.Bool("json", false, "output JSON array")
	_ = fs.Parse(args)

	ip := *selfIP
	if ip == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ip = sni.DetectSelfPublicIP(ctx)
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	results := sni.ProbeAll(ctx, nil, sni.ProbeOptions{SelfPublicIP: ip})
	cancel()

	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(results)
		return
	}

	qualified := sni.QualifiedSorted(results)
	fmt.Printf("Qualified non-CDN TLS 1.3 + H2 origins (%d / %d tested):\n", len(qualified), len(results))
	fmt.Printf("%-28s %-12s %-8s %-10s %s\n", "DOMAIN", "REGION", "RTT", "PROTOCOL", "ISSUER")
	for _, r := range qualified {
		warn := ""
		if r.LatencyWarn {
			warn = " (>50ms)"
		}
		fmt.Printf("%-28s %-12s %4dms%-3s %-10s %s\n",
			r.Domain, r.Region, r.HandshakeRTT.Milliseconds(), warn, r.Protocol, r.CertIssuer)
	}
}
