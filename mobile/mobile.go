package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
)

// Version is the mobile runtime identifier (overridable via -ldflags -X).
var Version = "v4.2.6"

const (
	defaultSocksPort = 10808
	defaultHTTPPort  = 10809
	maxMobileLogs    = 80
)

type mobileStartConfig struct {
	LinkURI      string   `json:"link_uri"`
	SocksPort    int      `json:"socks_port"`
	HTTPPort     int      `json:"http_port"`
	RouteMode    string   `json:"route_mode"`
	Transport    string   `json:"transport,omitempty"`
	UpMbps       *int     `json:"up_mbps,omitempty"`
	DownMbps     *int     `json:"down_mbps,omitempty"`
	AsyncConnect bool     `json:"async_connect,omitempty"`
	EnableIPv6   bool     `json:"enable_ipv6,omitempty"`
	CustomRules  []string `json:"custom_rules,omitempty"`
}

type parsedLinkInfo struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	Verify    string `json:"verify"`
	Transport string `json:"transport"`
	HopRange  string `json:"hop_range,omitempty"`
	UpMbps    int    `json:"up_mbps,omitempty"`
	DownMbps  int    `json:"down_mbps,omitempty"`
	Remark    string `json:"remark,omitempty"`
	URI       string `json:"uri"`
}

type jsonEnvelope struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

var (
	mu              sync.Mutex
	initialized     bool
	dataDirState    string
	tunnelExtState  bool
	engineInst      *client.Engine
	lastConfigRaw   string
	lastConnectErr  string
	scrubberStopCh  chan struct{}
	reconnectStopCh chan struct{}
	reconnectWakeCh chan struct{}
)

func init() {
	client.SetLocalMgmtHandler(handleLocalMgmt)
}

// InitCore configures mobile runtime guardrails before starting the engine.
// When isTunnelExt is true (50MB iOS PacketTunnel extension cap), memory is tightly
// bounded (18MB limit, GCPercent=20, 15s Darwin MADV_FREE physical memory scrubber,
// LowMemMode=true -> 4MB/8MB windows, 16KB copy buffers, 512KB UDP buffers, single RTC
// session). Companion app mode (isTunnelExt=false) allows 96MB and full dual-RTC striping.
func InitCore(dataDir string, isTunnelExt bool) {
	mu.Lock()
	defer mu.Unlock()
	initCoreLocked(dataDir, isTunnelExt)
}

func stopMemScrubberLocked() {
	if scrubberStopCh != nil {
		close(scrubberStopCh)
		scrubberStopCh = nil
	}
}

func startMemScrubberLocked() {
	if scrubberStopCh != nil {
		return
	}
	ch := make(chan struct{})
	scrubberStopCh = ch
	go func(stop <-chan struct{}) {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapSys > ms.HeapReleased && (ms.HeapSys-ms.HeapReleased) > (6<<20) {
					debug.FreeOSMemory()
				}
			}
		}
	}(ch)
}

func stopReconnectLoopLocked() {
	if reconnectStopCh != nil {
		close(reconnectStopCh)
		reconnectStopCh = nil
	}
	reconnectWakeCh = nil
}

func initCoreLocked(dataDir string, isTunnelExt bool) {
	client.SetNoSysProxy(true)
	client.SetLocalMgmtHandler(handleLocalMgmt)

	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "kestrel-mobile")
	}
	_ = os.MkdirAll(dir, 0o700)

	dataDirState = dir
	tunnelExtState = isTunnelExt
	initialized = true

	if isTunnelExt {
		debug.SetMemoryLimit(18 << 20)
		debug.SetGCPercent(20)
		gft.SetLowMemMode(true)
		netbind.SetDirectBindEnabled(true)
		startMemScrubberLocked()
	} else {
		stopMemScrubberLocked()
		debug.SetMemoryLimit(96 << 20)
		debug.SetGCPercent(50)
		gft.SetLowMemMode(false)
		netbind.SetDirectBindEnabled(true)
	}
}

// SocketProtector mirrors netbind.SocketProtector so gomobile exports a clean
// Java/Kotlin interface for Android VpnService.protect(fd).
type SocketProtector interface {
	ProtectFD(fd int32) bool
}

// SetSocketProtector registers (or clears with nil) a platform VPN socket protector.
func SetSocketProtector(p SocketProtector) {
	if p == nil {
		netbind.SetSocketProtector(nil)
		return
	}
	netbind.SetSocketProtector(p)
}

// StartEngine starts the local SOCKS5/HTTP listeners and dials the configured GhostFrame server.
func StartEngine(configJSON string) error {
	return startEngineWithOptions(configJSON, false)
}

func reloadEngineFromHTTP(configJSON string) error {
	return startEngineWithOptions(configJSON, true)
}

// ReloadEngineJSON hot-reloads the running engine configuration while keeping an active
// TUN stack attached (used by iOS and Android live settings/route updates).
func ReloadEngineJSON(configJSON string) string {
	return marshalEnvelope(startEngineWithOptions(configJSON, true), nil)
}

func startEngineWithOptions(configJSON string, preserveTUN bool) error {
	var cfg mobileStartConfig
	if err := json.Unmarshal([]byte(strings.TrimSpace(configJSON)), &cfg); err != nil {
		return fmt.Errorf("mobile: invalid config json: %w", err)
	}
	uri := strings.TrimSpace(cfg.LinkURI)
	if uri == "" {
		return errors.New("mobile: missing link_uri")
	}
	link, err := gft.ParseLink(uri)
	if err != nil {
		return fmt.Errorf("mobile: invalid node link: %w", err)
	}

	if t := strings.ToLower(strings.TrimSpace(cfg.Transport)); t != "" {
		link.Transport = t
	}
	if cfg.UpMbps != nil && *cfg.UpMbps >= 0 {
		link.UpMbps = *cfg.UpMbps
	}
	if cfg.DownMbps != nil && *cfg.DownMbps >= 0 {
		link.DownMbps = *cfg.DownMbps
	}
	if err := link.Validate(); err != nil {
		return fmt.Errorf("mobile: invalid link parameters: %w", err)
	}

	socksPort := cfg.SocksPort
	if socksPort <= 0 || socksPort > 65535 {
		socksPort = defaultSocksPort
	}
	httpPort := cfg.HTTPPort
	if httpPort <= 0 || httpPort > 65535 {
		httpPort = defaultHTTPPort
	}
	if socksPort == httpPort {
		return errors.New("mobile: socks_port and http_port must be different")
	}

	routeMode := client.RouteMode(strings.ToLower(strings.TrimSpace(cfg.RouteMode)))
	if routeMode == "" {
		routeMode = client.RouteRule
	}

	mu.Lock()
	if !initialized {
		initCoreLocked("", false)
	}
	isTunnel := tunnelExtState
	if isTunnel {
		startMemScrubberLocked()
	}
	stopReconnectLoopLocked()
	oldEngine := engineInst
	engineInst = nil
	dir := dataDirState
	lastConfigRaw = configJSON
	mu.Unlock()

	var savedWriter TunPacketWriter
	var savedMTU int
	if oldEngine != nil {
		if preserveTUN {
			savedWriter, savedMTU = detachTUNForReload()
		} else {
			StopTUN()
		}
		oldEngine.Close()
	} else if preserveTUN {
		savedWriter, savedMTU = peekLastTUN()
	}

	client.SetNoSysProxy(true)
	eng, err := client.NewEngine(filepath.Join(dir, "mobile_runtime.json"))
	if err != nil {
		return fmt.Errorf("mobile: init engine failed: %w", err)
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	eng.OverrideListenAddrs(socksAddr, httpAddr)

	if err := eng.SetRouteMode(routeMode); err != nil {
		eng.Close()
		return fmt.Errorf("mobile: invalid route_mode: %w", err)
	}
	_ = eng.SetEnableIPv6(cfg.EnableIPv6)
	if cfg.CustomRules != nil {
		if err := eng.SetCustomRules(cfg.CustomRules); err != nil {
			eng.Logf("[Mobile] apply custom rules warning: %v", err)
		}
	}
	if err := eng.SetLink(link); err != nil {
		eng.Close()
		return fmt.Errorf("mobile: apply link failed: %w", err)
	}
	if isTunnel && routeMode != client.RouteCore {
		eng.SetDirectDNSBypass(true)
	}
	if err := eng.StartServers(); err != nil {
		eng.Close()
		return fmt.Errorf("mobile: start local proxy failed: %w", err)
	}

	restoreTUNIfNeeded := func() {
		if !preserveTUN || savedWriter == nil {
			return
		}
		if routeMode == client.RouteCore {
			StopTUN()
			return
		}
		if tunErr := StartTUN(savedWriter, savedMTU); tunErr != nil {
			eng.Logf("[TUN] reload restore warning: %v", tunErr)
		}
	}

	mu.Lock()
	engineInst = eng
	lastConnectErr = ""
	if cfg.AsyncConnect {
		stopCh := make(chan struct{})
		wakeCh := make(chan struct{}, 1)
		reconnectStopCh = stopCh
		reconnectWakeCh = wakeCh
		mu.Unlock()
		restoreTUNIfNeeded()
		go connectWithRetryAsync(eng, stopCh, wakeCh)
		return nil
	}
	mu.Unlock()

	if err := eng.Connect(); err != nil {
		mu.Lock()
		lastConnectErr = err.Error()
		if engineInst == eng {
			engineInst = nil
		}
		mu.Unlock()
		eng.Close()
		return fmt.Errorf("mobile: tunnel connect failed: %w", err)
	}
	restoreTUNIfNeeded()
	return nil
}

func connectWithRetryAsync(eng *client.Engine, stopCh <-chan struct{}, wakeCh <-chan struct{}) {
	backoff := 2 * time.Second
	const maxBackoff = 15 * time.Second
	attempt := 0

	for {
		attempt++
		mu.Lock()
		stillActive := (engineInst == eng)
		mu.Unlock()
		if !stillActive {
			return
		}

		if err := eng.Connect(); err == nil {
			mu.Lock()
			if engineInst == eng {
				lastConnectErr = ""
			}
			mu.Unlock()
			return
		} else {
			mu.Lock()
			if engineInst == eng {
				lastConnectErr = err.Error()
			}
			mu.Unlock()
			eng.Logf("[Mobile] Connect attempt %d failed (retry in %s): %v", attempt, backoff, err)
		}

		timer := time.NewTimer(backoff)
		select {
		case <-stopCh:
			timer.Stop()
			return
		case <-wakeCh:
			timer.Stop()
			backoff = 2 * time.Second
		case <-timer.C:
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// StartEngineJSON wraps StartEngine into a JSON envelope {"ok":bool,"error":string} for Swift callers.
func StartEngineJSON(configJSON string) string {
	return marshalEnvelope(StartEngine(configJSON), nil)
}

// StopEngine stops the active GhostFrame engine and reclaims Go heap pages back to iOS.
func StopEngine() error {
	StopTUN()

	mu.Lock()
	eng := engineInst
	engineInst = nil
	lastConnectErr = ""
	isTunnel := tunnelExtState
	stopReconnectLoopLocked()
	stopMemScrubberLocked()
	mu.Unlock()

	if eng != nil {
		eng.Close()
	}
	if isTunnel || eng != nil {
		runtime.GC()
		debug.FreeOSMemory()
	}
	return nil
}

// StopEngineJSON wraps StopEngine into a JSON envelope {"ok":bool,"error":string} for Swift callers.
func StopEngineJSON() string {
	return marshalEnvelope(StopEngine(), nil)
}

// OnNetworkChanged notifies netbind and the running engine of a Wi-Fi / Cellular transition.
func OnNetworkChanged(ifaceName string) {
	netbind.SetPreferredInterface(strings.TrimSpace(ifaceName))
	netbind.ResetNAT64Cache()
	mu.Lock()
	eng := engineInst
	wakeCh := reconnectWakeCh
	mu.Unlock()
	if eng != nil {
		if eng.IsConnected() {
			eng.OnSystemWake()
		} else if wakeCh != nil {
			select {
			case wakeCh <- struct{}{}:
			default:
			}
		}
	}
}

// GetStatusJSON returns a combined JSON status + memory + rolling log snapshot.
func GetStatusJSON() string {
	mu.Lock()
	eng := engineInst
	isTunnel := tunnelExtState
	cachedErr := lastConnectErr
	mu.Unlock()

	var status map[string]any
	var logs []client.LogEntry
	if eng != nil {
		status = eng.Status()
		if curErr, _ := status["last_err"].(string); curErr == "" && cachedErr != "" {
			if st, _ := status["state"].(string); st != string(client.StateConnected) {
				status["last_err"] = cachedErr
			}
		}
		allLogs := eng.Logs()
		if len(allLogs) > maxMobileLogs {
			allLogs = allLogs[len(allLogs)-maxMobileLogs:]
		}
		logs = allLogs
	} else {
		status = map[string]any{
			"version":          Version,
			"state":            string(client.StateDisconnected),
			"last_err":         cachedErr,
			"active_transport": "",
			"transport_pref":   "rtc",
			"route_mode":       string(client.RouteRule),
			"rtc_ports":        [2]int{0, 0},
			"socks_addr":       fmt.Sprintf("127.0.0.1:%d", defaultSocksPort),
			"http_addr":        fmt.Sprintf("127.0.0.1:%d", defaultHTTPPort),
		}
		logs = []client.LogEntry{}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	physIface := netbind.DetectPhysicalInterface()
	if physIface == "" {
		physIface = netbind.PreferredInterface()
	}

	status["is_tunnel_ext"] = isTunnel
	status["low_mem_mode"] = gft.IsLowMemMode()
	status["netbind_enabled"] = netbind.DirectBindEnabled()
	status["physical_iface"] = physIface
	status["mem_alloc_mb"] = float64(ms.Alloc) / (1024 * 1024)
	status["mem_sys_mb"] = float64(ms.Sys) / (1024 * 1024)
	if ts := currentTUNStats(); ts != nil {
		status["tun_active"] = ts.Active
		status["tun_stats"] = ts
	} else {
		status["tun_active"] = false
	}
	status["logs"] = logs

	b, err := json.Marshal(status)
	if err != nil {
		return fmt.Sprintf(`{"version":%q,"state":"error","last_err":"status marshal failed"}`, Version)
	}
	return string(b)
}

// GetDiagnosticSnapshot returns an anonymized diagnostic report string.
func GetDiagnosticSnapshot() string {
	mu.Lock()
	eng := engineInst
	isTunnel := tunnelExtState
	mu.Unlock()

	if eng != nil {
		return eng.BuildDiagnosticSnapshot()
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	phys := netbind.DetectPhysicalInterface()
	if phys == "" {
		phys = netbind.PreferredInterface()
	}
	return fmt.Sprintf(
		"Kestrel Mobile Diagnostic (%s)\nState: disconnected\nTunnelExtension: %v\nLowMemMode: %v\nPhysicalInterface: %s\nMemAllocMB: %.2f\nMemSysMB: %.2f\n",
		Version,
		isTunnel,
		gft.IsLowMemMode(),
		phys,
		float64(ms.Alloc)/(1024*1024),
		float64(ms.Sys)/(1024*1024),
	)
}

// ClearLogs clears recorded rolling logs in the active engine.
func ClearLogs() {
	mu.Lock()
	eng := engineInst
	mu.Unlock()
	if eng != nil {
		eng.ClearLogs()
	}
}

// GetRuleStatsJSON returns the current KSLR rule bundle capacities as an envelope JSON.
func GetRuleStatsJSON() string {
	mu.Lock()
	eng := engineInst
	dir := dataDirState
	mu.Unlock()
	if eng != nil {
		return marshalEnvelope(nil, eng.RuleStats())
	}
	r := client.NewRouterWithDataDir(dir)
	return marshalEnvelope(nil, r.Stats())
}

// UpdateRuleBundleJSON downloads and hot-reloads rules_bundle.zlib (empty URL uses default Spittingjiu/Ghost release).
func UpdateRuleBundleJSON(rawURL string) string {
	mu.Lock()
	eng := engineInst
	dir := dataDirState
	mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	if eng != nil {
		st, err := eng.UpdateRuleBundle(ctx, rawURL)
		return marshalEnvelope(err, st)
	}
	tmpEng, err := client.NewEngine("")
	if err != nil {
		return marshalEnvelope(err, nil)
	}
	defer tmpEng.Close()
	tmpEng.SetRuleDataDir(dir)
	st, uerr := tmpEng.UpdateRuleBundle(ctx, rawURL)
	return marshalEnvelope(uerr, st)
}

// ParseLinkJSON validates a gft3:// or gft2:// URI and returns safe metadata as JSON.
func ParseLinkJSON(uri string) (string, error) {
	link, err := gft.ParseLink(strings.TrimSpace(uri))
	if err != nil {
		return "", err
	}
	remark := strings.TrimSpace(link.Remark)
	if remark == "" {
		remark = fmt.Sprintf("%s:%d", link.Host, link.Port)
	}
	info := parsedLinkInfo{
		Host:      link.Host,
		Port:      link.Port,
		SNI:       link.SNI,
		Verify:    link.EffectiveVerify(),
		Transport: link.EffectiveTransport(),
		HopRange:  link.HopRange,
		UpMbps:    link.UpMbps,
		DownMbps:  link.DownMbps,
		Remark:    remark,
		URI:       link.Encode(),
	}
	b, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseLinkEnvelopeJSON wraps ParseLinkJSON into {"ok":bool,"data":object,"error":string} for Swift callers.
func ParseLinkEnvelopeJSON(uri string) string {
	raw, err := ParseLinkJSON(uri)
	if err != nil {
		return marshalEnvelope(err, nil)
	}
	var obj json.RawMessage = json.RawMessage(raw)
	return marshalEnvelope(nil, obj)
}

// BuildShadowrocketAddURL constructs a Shadowrocket deep-link pointing to 127.0.0.1:<socksPort> with UDP enabled.
func BuildShadowrocketAddURL(socksPort int, remark string) string {
	if socksPort <= 0 || socksPort > 65535 {
		socksPort = defaultSocksPort
	}
	name := strings.TrimSpace(remark)
	if name == "" {
		name = "Kestrel Local"
	}
	raw := fmt.Sprintf(":@127.0.0.1:%d", socksPort)
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	return fmt.Sprintf("shadowrocket://add/socks://%s?remarks=%s&udp=1", encoded, url.QueryEscape(name))
}

// BuildBypassRule formats an anti-loopback DIRECT rule for Shadowrocket / Surge / Clash configs.
func BuildBypassRule(serverHost string) string {
	host := strings.TrimSpace(serverHost)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return fmt.Sprintf("IP-CIDR,%s/32,DIRECT", ip.To4().String())
		}
		return fmt.Sprintf("IP-CIDR6,%s/128,DIRECT", ip.String())
	}
	return fmt.Sprintf("DOMAIN,%s,DIRECT", host)
}

// ResolveHostIPsJSON resolves host via physical-interface-bound DirectLookupHostIPs (1.5s timeout),
// bypassing iOS utun Fake-IP DNS (198.18.0.1) so PacketTunnelProvider never blocks in getaddrinfo.
func ResolveHostIPsJSON(host string) string {
	clean := strings.TrimSpace(strings.Trim(host, "[]"))
	out := struct {
		V4 []string `json:"v4"`
		V6 []string `json:"v6"`
	}{}
	if clean != "" {
		if ip := net.ParseIP(clean); ip != nil {
			if !netbind.IsFakeIP(ip) {
				if ip4 := ip.To4(); ip4 != nil {
					out.V4 = append(out.V4, ip4.String())
				} else {
					out.V6 = append(out.V6, ip.String())
				}
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			ips, err := netbind.DirectLookupHostIPs(ctx, clean)
			cancel()
			if err == nil {
				for _, ip := range ips {
					if ip == nil || netbind.IsFakeIP(ip) {
						continue
					}
					if ip4 := ip.To4(); ip4 != nil {
						out.V4 = append(out.V4, ip4.String())
					} else {
						out.V6 = append(out.V6, ip.String())
					}
				}
			}
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return `{"v4":[],"v6":[]}`
	}
	return string(b)
}

func handleLocalMgmt(method, path string, body []byte) (int, string, []byte) {
	switch path {
	case "/_ksl/ping", "/_gft/ping":
		return 200, "application/json; charset=utf-8", []byte(`{"ok":true,"pong":true}`)
	case "/_ksl/status", "/_gft/status":
		return 200, "application/json; charset=utf-8", []byte(GetStatusJSON())
	case "/_ksl/diag", "/_gft/diag":
		return 200, "text/plain; charset=utf-8", []byte(GetDiagnosticSnapshot())
	case "/_ksl/clear-logs", "/_gft/clear-logs":
		ClearLogs()
		return 200, "application/json; charset=utf-8", []byte(`{"ok":true}`)
	case "/_ksl/rule-stats":
		return 200, "application/json; charset=utf-8", []byte(GetRuleStatsJSON())
	case "/_ksl/update-rules":
		if strings.ToUpper(strings.TrimSpace(method)) != "POST" {
			return 405, "application/json; charset=utf-8", []byte(`{"ok":false,"error":"method not allowed"}`)
		}
		var req struct {
			URL string `json:"url"`
		}
		if len(body) > 0 {
			_ = json.Unmarshal(body, &req)
		}
		return 200, "application/json; charset=utf-8", []byte(UpdateRuleBundleJSON(req.URL))
	case "/_ksl/ipv6":
		if strings.ToUpper(strings.TrimSpace(method)) != "POST" {
			return 405, "application/json; charset=utf-8", []byte(`{"ok":false,"error":"method not allowed"}`)
		}
		var req struct {
			EnableIPv6 bool `json:"enable_ipv6"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return 400, "application/json; charset=utf-8", []byte(`{"ok":false,"error":"invalid json"}`)
		}
		mu.Lock()
		eng := engineInst
		mu.Unlock()
		if eng != nil {
			_ = eng.SetEnableIPv6(req.EnableIPv6)
		}
		return 200, "application/json; charset=utf-8", []byte(GetStatusJSON())
	case "/_ksl/reload", "/_gft/reload":
		if strings.ToUpper(strings.TrimSpace(method)) != "POST" {
			return 405, "application/json; charset=utf-8", []byte(`{"ok":false,"error":"method not allowed"}`)
		}
		return 200, "application/json; charset=utf-8", []byte(marshalEnvelope(reloadEngineFromHTTP(string(body)), nil))
	default:
		return 404, "application/json; charset=utf-8", []byte(`{"ok":false,"error":"not found"}`)
	}
}

func marshalEnvelope(err error, data any) string {
	env := jsonEnvelope{OK: err == nil, Data: data}
	if err != nil {
		env.Error = err.Error()
	}
	b, merr := json.Marshal(env)
	if merr != nil {
		return `{"ok":false,"error":"json marshal failed"}`
	}
	return string(b)
}
