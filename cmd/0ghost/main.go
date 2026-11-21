package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
	"ghostframe/internal/tproxy"
)

var gatewayVersion = "v4.0.34-LTS"

type GatewayService struct {
	cfgPath string
	engine  *client.Engine

	mu        sync.RWMutex
	gwCfg     tproxy.GatewayConfig
	dnsSrv    *tproxy.SplitDNSServer
	tcpSrv    *tproxy.TCPServer
	udpSrv    *tproxy.UDPServer
	fwActive  bool
	fwBackend string
	fwErr     string
	conflicts tproxy.ConflictReport
	lanIface  string
	lanIP     string
	gwIP      string

	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewGatewayService(cfgPath, webOverride string) (*GatewayService, error) {
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine(cfgPath)
	if err != nil {
		return nil, err
	}

	gwCfg := tproxy.DefaultGatewayConfig()
	if raw := eng.GatewayConfigRaw(); len(raw) > 0 {
		_ = json.Unmarshal(raw, &gwCfg)
	}
	gwCfg.Normalize()
	if strings.TrimSpace(webOverride) != "" {
		gwCfg.WebAddr = strings.TrimSpace(webOverride)
	}

	// Explicitly expose SOCKS5 & HTTP on all LAN interfaces (0.0.0.0:10808 / 0.0.0.0:10809).
	eng.OverrideListenAddrs("0.0.0.0:10808", "0.0.0.0:10809")
	_ = eng.SetRouteMode(mapGatewayToRouteMode(gwCfg.GatewayMode))
	_ = eng.SetEnableIPv6(gwCfg.EnableIPv6)

	// Apply Linux kernel SO_MARK anti-loop tag globally across all GFT/client outbound dials.
	netbind.SetOutboundMark(gwCfg.FWMark)

	// Save normalized gateway config back without dropping nodes.
	if b, merr := json.Marshal(gwCfg); merr == nil {
		_ = eng.SetGatewayConfigRaw(b)
	}

	iface, lanIP, gwIP := tproxy.DetectLANEnvironment()
	s := &GatewayService{
		cfgPath:  cfgPath,
		engine:   eng,
		gwCfg:    gwCfg,
		lanIface: iface,
		lanIP:    lanIP,
		gwIP:     gwIP,
		stopCh:   make(chan struct{}),
	}
	return s, nil
}

func mapGatewayToRouteMode(m tproxy.GatewayMode) client.RouteMode {
	switch m {
	case tproxy.ModeGlobal:
		return client.RouteGlobal
	case tproxy.ModePort:
		return client.RouteCore
	default:
		return client.RouteRule
	}
}

func (s *GatewayService) getGatewayConfig() tproxy.GatewayConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.gwCfg
	cp.DeviceIPs = append([]string(nil), s.gwCfg.DeviceIPs...)
	cp.DirectDNS = append([]string(nil), s.gwCfg.DirectDNS...)
	return cp
}

func (s *GatewayService) effectiveDirectDNS(cfg tproxy.GatewayConfig) []string {
	var list []string
	if len(cfg.DirectDNS) > 0 {
		list = append(list, cfg.DirectDNS...)
	} else if s.gwIP != "" {
		list = append(list, s.gwIP)
	}
	return list
}

func (s *GatewayService) Start() {
	cfg := s.getGatewayConfig()

	// 1. Check third-party transparent proxy conflicts before binding ports or mounting firewall.
	rep := tproxy.DetectConflicts()
	if rep.HasConflict {
		if cfg.AutoYieldConflicts {
			s.engine.Logf("[KestrelBox] 检测到冲突代理 (%d 项)，正在安全停用并让路...", len(rep.Items))
			rep = tproxy.ResolveConflicts()
			for _, act := range rep.Actions {
				s.engine.Logf("[KestrelBox] %s", act)
			}
			time.Sleep(350 * time.Millisecond)
		} else {
			s.engine.Logf("[KestrelBox] 检测到冲突代理，自动接管未开启；已暂停透明防火墙挂载以防止死锁")
		}
	}
	s.mu.Lock()
	s.conflicts = rep
	s.mu.Unlock()

	// 2. Start explicit LAN proxy servers (:10808 / :10809).
	if err := s.engine.StartServers(); err != nil {
		s.engine.Logf("[KestrelBox] 局域网显式代理端口启动告警: %v", err)
	} else {
		s.engine.Logf("[KestrelBox] 局域网代理已监听 SOCKS5 0.0.0.0:10808 / HTTP 0.0.0.0:10809")
	}

	// 3. Start Split-DNS (:7853 dual-stack so both LAN nft redirect and local host queries succeed),
	// TPROXY TCP (:10880), and TPROXY UDP (:10881).
	dnsSrv := tproxy.NewSplitDNSServer(
		fmt.Sprintf(":%d", cfg.DNSPort),
		s.engine,
		s.effectiveDirectDNS(cfg),
		cfg.FilterAAAA,
		func() tproxy.GatewayMode { return s.getGatewayConfig().GatewayMode },
	)
	if err := dnsSrv.Start(); err != nil {
		s.engine.Logf("[KestrelBox] Split-DNS 启动失败: %v", err)
	} else {
		s.engine.Logf("[KestrelBox] Split-DNS 已监听 :%d", cfg.DNSPort)
	}

	tcpSrv, err := tproxy.NewTCPServer(
		fmt.Sprintf("127.0.0.1:%d", cfg.TCPPort),
		s.engine,
		func() tproxy.GatewayMode { return s.getGatewayConfig().GatewayMode },
	)
	if err == nil {
		if serr := tcpSrv.Start(); serr != nil {
			s.engine.Logf("[KestrelBox] TCP TPROXY 启动告警: %v", serr)
		} else {
			s.engine.Logf("[KestrelBox] TCP 透明接管已监听 127.0.0.1:%d (ipv6=%v)", cfg.TCPPort, tcpSrv.HasIPv6())
		}
	}

	udpSrv, err := tproxy.NewUDPServer(
		fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort),
		s.engine,
		func() tproxy.GatewayMode { return s.getGatewayConfig().GatewayMode },
	)
	if err == nil {
		if serr := udpSrv.Start(); serr != nil {
			s.engine.Logf("[KestrelBox] UDP TPROXY 启动告警: %v", serr)
		} else {
			s.engine.Logf("[KestrelBox] UDP TPROXY 已监听 127.0.0.1:%d (ipv6=%v)", cfg.UDPPort, udpSrv.HasIPv6())
		}
	}

	s.mu.Lock()
	s.dnsSrv = dnsSrv
	s.tcpSrv = tcpSrv
	s.udpSrv = udpSrv
	s.mu.Unlock()

	// 4. Connect configured node if available, otherwise wait cleanly on standby.
	st := s.engine.Status()
	if host, _ := st["node_host"].(string); strings.TrimSpace(host) != "" {
		go func() {
			if err := s.engine.Connect(); err != nil {
				s.engine.Logf("[KestrelBox] 节点连接失败: %v", err)
			}
			s.SyncFirewall()
		}()
	} else {
		s.engine.Logf("[KestrelBox] 当前无可用节点，处于纯净待机模式（可访问 :19080 控制台粘贴 ksl4:// 或 gft3:// 链接）")
		s.SyncFirewall()
	}

	go s.watchLoop()
	startFirewallSignalWatcher(s.stopCh, func() {
		s.engine.Logf("[KestrelBox] 收到热插拔重载信号 (SIGUSR1)，正在自愈重挂防火墙规则...")
		s.SyncFirewall()
	})
}

func (s *GatewayService) watchLoop() {
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	lastConnected := false
	healthTick := 0
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			connected := s.engine.IsConnected()
			if connected != lastConnected {
				lastConnected = connected
				healthTick = 0
				s.SyncFirewall()
				continue
			}
			healthTick++
			if healthTick >= 3 { // Every 12s verify fw4/iptables & ip-rule integrity
				healthTick = 0
				cfg := s.getGatewayConfig()
				s.mu.RLock()
				active := s.fwActive
				s.mu.RUnlock()
				if active && connected && cfg.GatewayMode != tproxy.ModePort {
					if !tproxy.CheckFirewallHealthy(cfg.GatewayMode, 1, 100, cfg.EnableIPv6) {
						s.engine.Logf("[KestrelBox] 巡检发现防火墙规则或策略路由异常脱落，立即自动修复...")
						s.SyncFirewall()
					}
				}
			}
		}
	}
}

// SyncFirewall mounts or cleanly tears down `table inet ghost0` based on active node connection,
// gateway mode, and conflict state so LAN traffic is never blackholed when idle or in Port mode.
func (s *GatewayService) SyncFirewall() {
	cfg := s.getGatewayConfig()
	rep := tproxy.DetectConflicts()
	connected := s.engine.IsConnected()

	s.mu.Lock()
	s.conflicts = rep
	s.mu.Unlock()

	if cfg.GatewayMode == tproxy.ModePort || !connected || (rep.HasConflict && !cfg.AutoYieldConflicts) {
		tproxy.CleanupFirewall(1, 100)
		s.mu.Lock()
		s.fwActive = false
		if cfg.GatewayMode == tproxy.ModePort {
			s.fwBackend = "none (port-only)"
			s.fwErr = ""
		} else if rep.HasConflict && !cfg.AutoYieldConflicts {
			s.fwBackend = "paused (conflict detected)"
			s.fwErr = "检测到冲突透明代理，已安全让路未挂载防火墙"
		} else {
			s.fwBackend = "standby (node disconnected)"
			s.fwErr = ""
		}
		s.mu.Unlock()
		return
	}

	if rep.HasConflict && cfg.AutoYieldConflicts {
		rep = tproxy.ResolveConflicts()
		s.mu.Lock()
		s.conflicts = rep
		s.mu.Unlock()
	}

	_, webPortStr, _ := net.SplitHostPort(cfg.WebAddr)
	webPort, _ := strconv.Atoi(webPortStr)
	if webPort <= 0 {
		webPort = 19080
	}

	spec := tproxy.FirewallSpec{
		Mode:         cfg.GatewayMode,
		DeviceMode:   cfg.DeviceMode,
		DeviceIPs:    cfg.DeviceIPs,
		VPSIPs:       s.engine.NodeHostIPs(),
		VPSIPv6s:     s.engine.NodeHostIPv6s(),
		DirectDNS:    s.effectiveDirectDNS(cfg),
		TCPPort:      cfg.TCPPort,
		UDPPort:      cfg.UDPPort,
		DNSPort:      cfg.DNSPort,
		WebPort:      webPort,
		SocksPort:    10808,
		HTTPPort:     10809,
		FWMark:       cfg.FWMark,
		TProxyMark:   1,
		RouteTable:   100,
		PreferTProxy:  true,
		EnableIPv6:    cfg.EnableIPv6,
		FilterAAAA:    !cfg.EnableIPv6,
		LANMasquerade: cfg.LANMasquerade,
	}

	backend, err := tproxy.ApplyFirewall(spec)
	s.mu.Lock()
	if err != nil {
		s.fwActive = false
		s.fwBackend = "error"
		s.fwErr = err.Error()
		s.engine.Logf("[KestrelBox] 防火墙挂载失败: %v", err)
	} else {
		s.fwActive = true
		s.fwBackend = backend
		s.fwErr = ""
		s.engine.Logf("[KestrelBox] 透明防火墙已就绪 [%s] (mode=%s, devices=%s)", backend, cfg.GatewayMode, cfg.DeviceMode)
	}
	s.mu.Unlock()
}

func (s *GatewayService) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		tproxy.CleanupFirewall(1, 100)
		s.mu.Lock()
		if s.tcpSrv != nil {
			s.tcpSrv.Close()
		}
		if s.udpSrv != nil {
			s.udpSrv.Close()
		}
		if s.dnsSrv != nil {
			s.dnsSrv.Close()
		}
		s.fwActive = false
		s.mu.Unlock()
		if s.engine != nil {
			s.engine.Close()
		}
	})
}

type streamAsNetConn struct {
	gft.DataStream
}

func (streamAsNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (streamAsNetConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (streamAsNetConn) SetDeadline(time.Time) error        { return nil }
func (streamAsNetConn) SetReadDeadline(time.Time) error    { return nil }
func (streamAsNetConn) SetWriteDeadline(time.Time) error   { return nil }

func (s *GatewayService) ProbeDualConnectivity() map[string]any {
	var (
		directOK   bool
		directMs   int64
		directInfo string

		tunnelOK   bool
		tunnelMs   int64
		tunnelCode int
		tunnelInfo string
	)

	// 1. Direct CN connectivity check via SO_MARK=0xff dialer.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		targets := []struct {
			host string
			path string
		}{
			{"connectivitycheck.platform.hicloud.com:80", "/generate_204"},
			{"connect.rom.miui.com:80", "/generate_204"},
		}
		d := s.engine.DirectDialer(4 * time.Second)
		for _, tgt := range targets {
			t0 := time.Now()
			c, err := d.Dial("tcp", tgt.host)
			if err != nil {
				continue
			}
			_ = c.SetDeadline(time.Now().Add(4 * time.Second))
			req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tgt.path, strings.Split(tgt.host, ":")[0])
			_, _ = c.Write([]byte(req))
			buf := make([]byte, 256)
			n, _ := c.Read(buf)
			_ = c.Close()
			if n > 0 {
				ms := time.Since(t0).Milliseconds()
				if ms <= 0 {
					ms = 1
				}
				line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
				directOK = true
				directMs = ms
				directInfo = line
				return
			}
		}
		directInfo = "直连探测超时"
	}()

	go func() {
		defer wg.Done()
		if !s.engine.IsConnected() {
			tunnelInfo = "隧道未连接"
			return
		}
		t0 := time.Now()
		st, err := s.engine.TunnelStream("cp.cloudflare.com:443")
		if err != nil {
			tunnelInfo = err.Error()
			return
		}
		defer st.Close()
		tc := tls.Client(streamAsNetConn{DataStream: st}, &tls.Config{ServerName: "cp.cloudflare.com", MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(6 * time.Second))
		if err := tc.Handshake(); err != nil {
			tunnelInfo = "TLS: " + err.Error()
			return
		}
		req := "GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: KestrelBox-Probe\r\nConnection: close\r\n\r\n"
		if _, err := tc.Write([]byte(req)); err != nil {
			tunnelInfo = err.Error()
			return
		}
		respBytes, _ := io.ReadAll(io.LimitReader(tc, 1024))
		_ = tc.Close()
		ms := time.Since(t0).Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		firstLine := strings.SplitN(string(respBytes), "\r\n", 2)[0]
		code := 0
		if parts := strings.Fields(firstLine); len(parts) >= 2 {
			code, _ = strconv.Atoi(parts[1])
		}
		tunnelMs = ms
		tunnelCode = code
		tunnelInfo = firstLine
		tunnelOK = code >= 200 && code < 400
	}()

	wg.Wait()
	return map[string]any{
		"direct_ok":   directOK,
		"direct_ms":   directMs,
		"direct_info": directInfo,
		"tunnel_ok":   tunnelOK,
		"tunnel_ms":   tunnelMs,
		"tunnel_info": tunnelInfo,
		"tunnel_code": tunnelCode,
	}
}

func (s *GatewayService) Snapshot() map[string]any {
	st := s.engine.Status()
	cfg := s.getGatewayConfig()

	s.mu.RLock()
	fwActive := s.fwActive
	fwBackend := s.fwBackend
	fwErr := s.fwErr
	conflicts := s.conflicts
	dnsSrv := s.dnsSrv
	tcpSrv := s.tcpSrv
	udpSrv := s.udpSrv
	lanIface := s.lanIface
	lanIP := s.lanIP
	gwIP := s.gwIP
	s.mu.RUnlock()

	var tcpConns, udpConns, dnsQ, dnsDir, dnsTun, dnsRej uint64
	if tcpSrv != nil {
		tcpConns = tcpSrv.Count()
	}
	if udpSrv != nil {
		udpConns = udpSrv.Count()
	}
	if dnsSrv != nil {
		dnsQ, dnsDir, dnsTun, dnsRej = dnsSrv.Counters()
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	sysUsed, sysTotal, cpuPct := tproxy.ReadSystemStats()

	tpStats := tproxy.Stats{
		FirewallActive:  fwActive,
		FirewallBackend: fwBackend,
		LanIface:        lanIface,
		LanIP:           lanIP,
		GatewayIP:       gwIP,
		TCPConns:        tcpConns,
		UDPConns:        udpConns,
		DNSQueries:      dnsQ,
		DNSDirectHits:   dnsDir,
		DNSTunnelHits:   dnsTun,
		DNSRejectHits:   dnsRej,
		Conflicts:       conflicts,
	}

	st["gateway_version"] = gatewayVersion
	st["gateway_mode"] = string(cfg.GatewayMode)
	st["device_mode"] = string(cfg.DeviceMode)
	st["device_ips"] = cfg.DeviceIPs
	st["direct_dns"] = cfg.DirectDNS
	st["enable_ipv6"] = cfg.EnableIPv6
	st["filter_aaaa"] = !cfg.EnableIPv6
	st["lan_masquerade"] = cfg.LANMasquerade
	st["auto_yield_conflicts"] = cfg.AutoYieldConflicts
	st["web_password_enabled"] = strings.TrimSpace(cfg.WebPassword) != ""
	st["custom_rules"] = s.engine.CustomRules()
	st["tproxy_stats"] = tpStats
	st["fw_err"] = fwErr
	st["go_mem_alloc_mb"] = float64(ms.Alloc) / (1024 * 1024)
	st["go_mem_sys_mb"] = float64(ms.Sys) / (1024 * 1024)
	st["sys_mem_used_mb"] = sysUsed
	st["sys_mem_total_mb"] = sysTotal
	st["sys_cpu_pct"] = cpuPct
	st["logs"] = s.engine.Logs()
	return st
}

func main() {
	cfgPath := flag.String("config", "/etc/kbox/config.json", "path to KestrelBox unified config file")
	webAddr := flag.String("web", "", "override Web console listen address (default 0.0.0.0:19080)")
	cleanupOnly := flag.Bool("cleanup", false, "atomically clean KestrelBox firewall tables/routes and exit")
	flag.Parse()

	if *cleanupOnly {
		tproxy.CleanupFirewall(1, 100)
		fmt.Println("KestrelBox firewall rules cleaned.")
		return
	}

	resolvedCfg := *cfgPath
	if resolvedCfg == "/etc/kbox/config.json" {
		if _, err := os.Stat(resolvedCfg); err != nil {
			if _, err2 := os.Stat("/etc/0ghost/config.json"); err2 == nil {
				resolvedCfg = "/etc/0ghost/config.json"
			}
		}
	}

	// N1 S905D (2GB RAM) side-router memory tuning + full v4.0 LTS dual-track RTC.
	debug.SetMemoryLimit(128 << 20)
	debug.SetGCPercent(40)
	gft.SetLowMemMode(false)

	svc, err := NewGatewayService(resolvedCfg, *webAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KestrelBox init error: %v\n", err)
		os.Exit(1)
	}
	defer svc.Stop()

	svc.Start()

	mux := svc.BuildHTTPMux()
	srv := &http.Server{
		Addr:              svc.getGatewayConfig().WebAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		svc.engine.Logf("[KestrelBox] Web 控制台已监听 http://%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			svc.engine.Logf("[KestrelBox] Web 控制台异常退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
	svc.Stop()
}
