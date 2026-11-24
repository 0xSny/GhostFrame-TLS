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
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/server"
	"ghostframe/internal/sni"
	"ghostframe/internal/tui"
)

var version = tui.CurrentVersion

func main() {
	base := strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
	if (strings.EqualFold(base, "ksl") || strings.EqualFold(base, "gft")) && (len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-")) {
		runMenu(os.Args[1:])
		return
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kestrel-server <run|init|link|menu|upgrade|rollback|show-card|sni-test|reselect-sni|version> [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "menu":
		runMenu(os.Args[2:])
	case "upgrade":
		runUpgrade(os.Args[2:])
	case "rollback":
		runRollback(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "link":
		fs := flag.NewFlagSet("link", flag.ExitOnError)
		conf := fs.String("config", tui.DefaultConfigPath, "config file")
		_ = fs.Parse(os.Args[2:])
		cfgPath := resolveServerConfigPath(*conf)
		c, err := server.LoadConfig(cfgPath)
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
		if err := tui.ShowDeliveryCard(resolveServerConfigPath(*conf), os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "sni-test":
		runSNITest(os.Args[2:])
	case "reselect-sni":
		runReselectSNI(os.Args[2:])
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		conf := fs.String("config", tui.DefaultConfigPath, "config file")
		_ = fs.Parse(os.Args[2:])
		cfgPath := resolveServerConfigPath(*conf)
		c, err := server.LoadConfig(cfgPath)
		if err != nil {
			log.Fatal(err)
		}
		if os.Getenv("GOMEMLIMIT") == "" {
			debug.SetMemoryLimit(int64(c.EffectiveMaxMemoryMB()) << 20)
		}
		logger := log.New(os.Stderr, "ksl ", log.LstdFlags)
		s, err := server.New(c, logger)
		if err != nil {
			log.Fatal(err)
		}
		s.SetConfigPath(cfgPath)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := s.Run(ctx); err != nil {
			log.Fatal(err)
		}
	case "version", "-v", "--version":
		fmt.Printf("kestrel-server %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func resolveServerConfigPath(path string) string {
	if path == tui.DefaultConfigPath {
		if _, err := os.Stat(path); err != nil {
			const legacy = "/etc/gft/server.json"
			if _, err2 := os.Stat(legacy); err2 == nil {
				return legacy
			}
		}
	}
	return path
}

func runMenu(args []string) {
	fs := flag.NewFlagSet("menu", flag.ExitOnError)
	conf := fs.String("config", tui.DefaultConfigPath, "config file")
	_ = fs.Parse(args)
	ctrl := tui.NewController(resolveServerConfigPath(*conf))
	if err := ctrl.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ksl menu error: %v\n", err)
		os.Exit(1)
	}
}

func runUpgrade(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	ver := fs.String("version", "latest", "target release tag or 'latest'")
	mirror := fs.String("mirror", os.Getenv("KSL_MIRROR"), "optional GitHub mirror/proxy URL prefix")
	force := fs.Bool("force", false, "reinstall even if remote version matches current")
	conf := fs.String("config", tui.DefaultConfigPath, "config file")
	_ = fs.Parse(args)

	ctrl := tui.NewController(resolveServerConfigPath(*conf))
	res, err := ctrl.PerformOTAUpgrade(tui.UpgradeOptions{
		TargetVersion: *ver,
		MirrorPrefix:  *mirror,
		Force:         *force,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ksl upgrade error: %v\n", err)
		os.Exit(1)
	}
	if res.AlreadyLatest {
		fmt.Printf("Kestrel server is already up to date (%s).\n", res.ToVersion)
		return
	}
	fmt.Printf("Upgraded Kestrel server: %s -> %s (SHA-256: %s)\n", res.FromVersion, res.ToVersion, res.SHA256)
}

func runRollback(args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	conf := fs.String("config", tui.DefaultConfigPath, "config file")
	_ = fs.Parse(args)

	ctrl := tui.NewController(*conf)
	res, err := ctrl.PerformOTARollback(tui.UpgradeOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ksl rollback error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Rolled back Kestrel server to: %s (from %s)\n", res.RestoredBanner, res.BackupPath)
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	confDir := fs.String("conf-dir", "/etc/kestrel", "config directory")
	stateDir := fs.String("state-dir", "/var/lib/kestrel", "state directory")
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
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		pick, all, serr := sni.AutoSelectSNI(ctx, pubHost)
		cancel()
		if serr == nil && pick.Domain != "" {
			chosenSNI = pick.Domain
			q := sni.QualifiedSorted(all)
			fmt.Fprintf(os.Stderr, "[auto-sni] selected nearest low-latency origin: %s (region=%s, rtt=%dms, qualified=%d/%d)\n",
				pick.Domain, pick.Region, pick.HandshakeRTT.Milliseconds(), len(q), len(all))
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
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
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

func runReselectSNI(args []string) {
	fs := flag.NewFlagSet("reselect-sni", flag.ExitOnError)
	conf := fs.String("config", tui.DefaultConfigPath, "config file")
	sniOverride := fs.String("sni", "", "optional explicit SNI domain (auto-probes nearest lowest-latency origin if empty)")
	_ = fs.Parse(args)

	cfgPath := resolveServerConfigPath(*conf)
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	oldSNI := cfg.SNI
	if target := strings.TrimSpace(*sniOverride); target != "" {
		if _, err := server.RotateSNI(cfgPath, target); err != nil {
			log.Fatalf("rotate sni failed: %v", err)
		}
		fmt.Printf("[sni] updated SNI: %s -> %s (SPKI Pin preserved)\n", oldSNI, target)
		return
	}
	selfIP := strings.TrimSpace(cfg.PublicHost)
	if selfIP == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		selfIP = sni.DetectSelfPublicIP(ctx)
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	pick, all, err := sni.AutoSelectSNI(ctx, selfIP)
	cancel()
	if err != nil || pick.Domain == "" {
		log.Fatalf("auto-sni probe failed: %v", err)
	}
	if _, err := server.RotateSNI(cfgPath, pick.Domain); err != nil {
		log.Fatalf("rotate sni failed: %v", err)
	}
	q := sni.QualifiedSorted(all)
	fmt.Printf("[auto-sni] updated SNI: %s -> %s (region=%s, rtt=%dms, qualified=%d/%d, SPKI Pin preserved)\n",
		oldSNI, pick.Domain, pick.Region, pick.HandshakeRTT.Milliseconds(), len(q), len(all))
}
