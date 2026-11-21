package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
)

// Version is the canonical release identifier (overridable via -ldflags -X).
var Version = "v4.0.31-LTS"

type ConnState string

const (
	StateDisconnected ConnState = "disconnected"
	StateConnecting   ConnState = "connecting"
	StateConnected    ConnState = "connected"
	StateError        ConnState = "error"
)

// ClientConfig holds saved client preferences, nodes, and routing mode.
type ClientConfig struct {
	Link          *gft.Link       `json:"link,omitempty"`
	Nodes         []*gft.Link     `json:"nodes,omitempty"`
	ActiveNode    int             `json:"active_node,omitempty"`
	RouteMode     RouteMode       `json:"route_mode,omitempty"` // "rule" (default), "global", "direct"
	SocksAddr     string          `json:"socks_addr"`
	HTTPAddr      string          `json:"http_addr"`
	SysProxy      bool            `json:"sys_proxy"`
	CustomRules   []string        `json:"custom_rules,omitempty"`
	RuleBundleURL string          `json:"rule_bundle_url,omitempty"`
	Gateway       json.RawMessage `json:"gateway,omitempty"`
}

// LogEntry is a single line in the client rolling log.
type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// TrafficPoint holds bandwidth at a specific time.
type TrafficPoint struct {
	Time int64  `json:"t"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// PingSummary holds a manual probe result.
type PingSummary struct {
	RTTMs     int64
	Transport string
}

// Engine coordinates GFT v3 ApexScheduler, CN/Domain Router, SOCKS5 (TCP+UDP),
// HTTP proxy, and crash-safe Windows system proxy.
type Engine struct {
	mu              sync.RWMutex
	portSwapMu      sync.Mutex
	cfgPath            string
	ruleDataDir        string
	proxyBackupPath    string
	config          ClientConfig
	state           ConnState
	lastErr         string
	sched           *gft.ApexScheduler
	connectingSched *gft.ApexScheduler
	connectGen      uint64
	paramStore      *gft.ParamStore
	router          *Router
	tunnelDNS          *TunnelDNSResolver
	smartCache         *smartRouteCache
	recentRoutes       *recentRouteRing
	directCNResolveFn  DirectCNDNSFunc
	tunnelDNSResolveFn TunnelDNSFunc
	socksSrv          *SOCKS5Server
	httpSrv         *HTTPProxyServer
	sysProxyApplied bool
	proxyDrifted    atomic.Bool
	directDNSBypass atomic.Bool

	// Stats
	prevUp     uint64
	prevDown   uint64
	curUpBps   uint64
	curDownBps uint64
	pingMs     int64
	history    []TrafficPoint

	// Fixed-capacity 1000-entry rolling ring log
	logRing *LogRingBuffer

	stopStats chan struct{}
	stopOnce  sync.Once
	statsOnce sync.Once
}

// directStreamConn adapts a direct net.Conn to gft.DataStream for Rule/Direct routing.
type directStreamConn struct {
	net.Conn
	target string
}

func (d *directStreamConn) CloseWrite() error {
	if cw, ok := d.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (d *directStreamConn) RemoteTarget() string { return d.target }

// NewEngine initializes the client engine and recovers any crash-orphaned system proxy.
func NewEngine(cfgPath string) (*Engine, error) {
	backupPath := ""
	ruleDir := ""
	if cfgPath != "" {
		ruleDir = filepath.Dir(cfgPath)
		backupPath = filepath.Join(ruleDir, "sysproxy_backup.json")
	}

	e := &Engine{
		cfgPath:         cfgPath,
		ruleDataDir:     ruleDir,
		proxyBackupPath: backupPath,
		state:           StateDisconnected,
		paramStore:      gft.NewParamStore(gft.DefaultParams()),
		router:          NewRouterWithDataDir(ruleDir),
		tunnelDNS:       NewTunnelDNSResolver(),
		smartCache:      newSmartRouteCache(smartRouteCacheCap),
		recentRoutes:    newRecentRouteRing(defaultRecentRouteCap),
		history:         make([]TrafficPoint, 0, 60),
		logRing:         NewLogRingBuffer(defaultLogRingCap),
		stopStats:       make(chan struct{}),
		config: ClientConfig{
			RouteMode: RouteRule,
			SocksAddr: "127.0.0.1:10808",
			HTTPAddr:  "127.0.0.1:10809",
			SysProxy:  false,
		},
	}

	if cfgPath != "" {
		if data, err := os.ReadFile(cfgPath); err == nil {
			data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
			_ = json.Unmarshal(data, &e.config)
		}
	}

	if len(e.config.Nodes) == 0 && e.config.Link != nil {
		e.config.Nodes = []*gft.Link{e.config.Link}
		e.config.ActiveNode = 0
	}
	if e.config.ActiveNode < 0 || e.config.ActiveNode >= len(e.config.Nodes) {
		e.config.ActiveNode = 0
	}
	if len(e.config.Nodes) > 0 {
		e.config.Link = e.config.Nodes[e.config.ActiveNode]
	}
	if e.config.RouteMode == "" {
		e.config.RouteMode = RouteRule
	} else if e.config.RouteMode == RouteDirect {
		e.config.RouteMode = RouteCore
	}
	e.config.SysProxy = e.config.RouteMode != RouteCore

	if active := e.activeLinkLocked(); active != nil && active.Params != nil {
		e.paramStore.Set(*active.Params)
	}

	var combinedRules []CustomRule
	if cfgPath != "" {
		rulesFile := filepath.Join(filepath.Dir(cfgPath), "rules.txt")
		combinedRules = append(combinedRules, LoadCustomRulesFile(rulesFile)...)
	}
	if len(e.config.CustomRules) > 0 {
		combinedRules = append(combinedRules, ParseCustomRules(e.config.CustomRules)...)
	}
	if len(combinedRules) > 0 {
		e.router.SetCustomRules(combinedRules)
	}

	if recovered, rerr := RecoverSystemProxyIfDirtyFor(e.proxyBackupPath, e.config.HTTPAddr); recovered {
		if rerr == nil {
			e.Logf("Recovered pre-crash Windows system proxy settings cleanly")
		} else {
			e.Logf("System proxy recovery warning: %v", rerr)
		}
	}

	e.socksSrv = NewSOCKS5Server(e.config.SocksAddr, e)
	e.httpSrv = NewHTTPProxyServer(e.config.HTTPAddr, e)
	return e, nil
}

func (e *Engine) activeLinkLocked() *gft.Link {
	if len(e.config.Nodes) > 0 && e.config.ActiveNode >= 0 && e.config.ActiveNode < len(e.config.Nodes) {
		return e.config.Nodes[e.config.ActiveNode]
	}
	return e.config.Link
}

// OverrideListenAddrs updates the local SOCKS5/HTTP listener addresses prior to StartServers.
func (e *Engine) OverrideListenAddrs(socksAddr, httpAddr string) {
	e.mu.Lock()
	if socksAddr != "" {
		e.config.SocksAddr = socksAddr
		e.socksSrv = NewSOCKS5Server(socksAddr, e)
	}
	if httpAddr != "" {
		e.config.HTTPAddr = httpAddr
		e.httpSrv = NewHTTPProxyServer(httpAddr, e)
	}
	e.mu.Unlock()
}

// StartServers binds and listens on local SOCKS5 and HTTP proxy ports.
func (e *Engine) StartServers() error {
	if err := e.socksSrv.Start(); err != nil {
		return fmt.Errorf("socks5 listen on %s: %w", e.config.SocksAddr, err)
	}
	e.Logf("SOCKS5 (TCP + UDP ASSOCIATE) listening on %s", e.config.SocksAddr)

	if err := e.httpSrv.Start(); err != nil {
		_ = e.socksSrv.Close()
		return fmt.Errorf("http proxy listen on %s: %w", e.config.HTTPAddr, err)
	}
	e.Logf("HTTP proxy listening on %s", e.config.HTTPAddr)

	e.statsOnce.Do(func() { go e.statsLoop() })
	return nil
}

// StartServersAutoFallback starts local proxy listeners, automatically switching to an
// available idle port pair if the configured ports are already occupied by another process.
func (e *Engine) StartServersAutoFallback() error {
	firstErr := e.StartServers()
	if firstErr == nil {
		return nil
	}

	e.mu.RLock()
	origSocks := e.config.SocksAddr
	origHTTP := e.config.HTTPAddr
	e.mu.RUnlock()

	sHost := splitHostOrDefault(origSocks)
	hHost := splitHostOrDefault(origHTTP)
	candidates := [][2]int{{10808, 10809}, {10818, 10819}, {17890, 17891}, {20808, 20809}, {27890, 27891}}

	tryPair := func(sAddr, hAddr string) bool {
		if sAddr == origSocks && hAddr == origHTTP {
			return false
		}
		e.OverrideListenAddrs(sAddr, hAddr)
		if err := e.StartServers(); err == nil {
			e.Logf("端口 %s / %s 已被占用，已自动切换至空闲端口 %s / %s", origSocks, origHTTP, sAddr, hAddr)
			_ = e.SaveConfig()
			return true
		}
		return false
	}

	for _, pair := range candidates {
		sAddr := net.JoinHostPort(sHost, strconv.Itoa(pair[0]))
		hAddr := net.JoinHostPort(hHost, strconv.Itoa(pair[1]))
		if tryPair(sAddr, hAddr) {
			return nil
		}
	}

	// Ephemeral port fallback if all preset pairs are occupied
	l1, e1 := net.Listen("tcp", net.JoinHostPort(sHost, "0"))
	l2, e2 := net.Listen("tcp", net.JoinHostPort(hHost, "0"))
	if e1 == nil && e2 == nil {
		p1 := l1.Addr().(*net.TCPAddr).Port
		p2 := l2.Addr().(*net.TCPAddr).Port
		_ = l1.Close()
		_ = l2.Close()
		if p1 != p2 && tryPair(net.JoinHostPort(sHost, strconv.Itoa(p1)), net.JoinHostPort(hHost, strconv.Itoa(p2))) {
			return nil
		}
	} else {
		if l1 != nil {
			_ = l1.Close()
		}
		if l2 != nil {
			_ = l2.Close()
		}
	}

	e.OverrideListenAddrs(origSocks, origHTTP)
	return firstErr
}

func splitHostOrDefault(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "127.0.0.1"
	}
	return host
}

// SetProxyPorts validates socksPort and httpPort, atomically pre-binds any changed
// listeners before closing old ones, persists client.json, and updates active
// Windows system proxy without overwriting sysproxy_backup.json.
func (e *Engine) SetProxyPorts(socksPort, httpPort int) error {
	if socksPort < 1024 || socksPort > 65535 {
		return fmt.Errorf("SOCKS5 端口必须在 1024-65535 之间 (%d)", socksPort)
	}
	if httpPort < 1024 || httpPort > 65535 {
		return fmt.Errorf("HTTP 端口必须在 1024-65535 之间 (%d)", httpPort)
	}
	if socksPort == httpPort {
		return fmt.Errorf("SOCKS5 与 HTTP 端口不能相同 (%d)", socksPort)
	}

	e.portSwapMu.Lock()
	defer e.portSwapMu.Unlock()

	e.mu.RLock()
	oldSocksAddr := e.config.SocksAddr
	oldHTTPAddr := e.config.HTTPAddr
	e.mu.RUnlock()

	socksHost := splitHostOrDefault(oldSocksAddr)
	httpHost := splitHostOrDefault(oldHTTPAddr)
	newSocksAddr := net.JoinHostPort(socksHost, strconv.Itoa(socksPort))
	newHTTPAddr := net.JoinHostPort(httpHost, strconv.Itoa(httpPort))

	var newSocksSrv *SOCKS5Server
	var newHTTPSrv *HTTPProxyServer

	if newSocksAddr != oldSocksAddr || e.socksSrv == nil || e.socksSrv.Addr() == nil {
		newSocksSrv = NewSOCKS5Server(newSocksAddr, e)
		if err := newSocksSrv.Start(); err != nil {
			return fmt.Errorf("SOCKS5 端口 %d 已被占用或无法监听: %w", socksPort, err)
		}
	}
	if newHTTPAddr != oldHTTPAddr || e.httpSrv == nil || e.httpSrv.Addr() == nil {
		newHTTPSrv = NewHTTPProxyServer(newHTTPAddr, e)
		if err := newHTTPSrv.Start(); err != nil {
			if newSocksSrv != nil {
				_ = newSocksSrv.Close()
			}
			return fmt.Errorf("HTTP 端口 %d 已被占用或无法监听: %w", httpPort, err)
		}
	}

	e.mu.Lock()
	var oldSocks *SOCKS5Server
	var oldHTTP *HTTPProxyServer
	if newSocksSrv != nil {
		oldSocks = e.socksSrv
		e.socksSrv = newSocksSrv
		e.config.SocksAddr = newSocksAddr
	}
	if newHTTPSrv != nil {
		oldHTTP = e.httpSrv
		e.httpSrv = newHTTPSrv
		e.config.HTTPAddr = newHTTPAddr
	}
	connected := e.state == StateConnected
	routeMode := e.config.RouteMode
	e.mu.Unlock()

	if oldSocks != nil {
		_ = oldSocks.Close()
	}
	if oldHTTP != nil {
		_ = oldHTTP.Close()
	}

	if err := e.SaveConfig(); err != nil {
		e.Logf("SaveConfig warning after port swap: %v", err)
	}

	if connected && routeMode != RouteCore {
		if err := SetSystemProxy(newHTTPAddr, true); err != nil {
			e.Logf("Failed to refresh system proxy to %s: %v", newHTTPAddr, err)
		} else {
			e.mu.Lock()
			e.sysProxyApplied = true
			e.mu.Unlock()
			e.Logf("System proxy smoothly switched to %s", newHTTPAddr)
		}
	}

	e.Logf("Proxy ports hot-swapped cleanly: SOCKS5 %s / HTTP %s", newSocksAddr, newHTTPAddr)
	return nil
}

// SaveConfig writes current client configuration to disk cleanly.
func (e *Engine) SaveConfig() error {
	e.mu.RLock()
	cfgCopy := e.config
	cfgPath := e.cfgPath
	e.mu.RUnlock()
	if cfgPath == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(cfgPath), 0o755)
	b, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, b, 0o600)
}

// SetLink replaces or sets the active node.
func (e *Engine) SetLink(l *gft.Link) error {
	e.mu.Lock()
	if l != nil {
		if len(e.config.Nodes) == 0 {
			e.config.Nodes = []*gft.Link{l}
			e.config.ActiveNode = 0
		} else {
			e.config.Nodes[e.config.ActiveNode] = l
		}
		e.config.Link = l
		if l.Params != nil {
			e.paramStore.Set(*l.Params)
		}
	}
	e.mu.Unlock()
	return e.SaveConfig()
}

// ImportLink adds (or updates duplicate host:port:psk) a gft3/gft2 node link and selects it.
func (e *Engine) ImportLink(uri string, switchTo bool) (int, error) {
	link, err := gft.ParseLink(uri)
	if err != nil {
		return -1, err
	}
	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Host, link.Port)
	}
	e.mu.Lock()
	idx := -1
	for i, existing := range e.config.Nodes {
		if existing != nil && existing.Host == link.Host && existing.Port == link.Port && existing.PSK == link.PSK {
			e.config.Nodes[i] = link
			idx = i
			break
		}
	}
	if idx < 0 {
		e.config.Nodes = append(e.config.Nodes, link)
		idx = len(e.config.Nodes) - 1
	}
	if switchTo || len(e.config.Nodes) == 1 {
		e.config.ActiveNode = idx
		e.config.Link = link
		if link.Params != nil {
			e.paramStore.Set(*link.Params)
		}
	}
	e.mu.Unlock()
	if err := e.SaveConfig(); err != nil {
		return idx, err
	}
	e.Logf("Imported node #%d: %s (%s:%d)", idx+1, link.Remark, link.Host, link.Port)
	return idx, nil
}

// SelectNode switches active node losslessly (make-before-break when already connected):
// the existing tunnel stays up until the new node's handshake succeeds, keeping system proxy
// untouched and rolling back cleanly to the working node if the new node fails to connect.
func (e *Engine) SelectNode(idx int) error {
	e.mu.Lock()
	if idx < 0 || idx >= len(e.config.Nodes) || e.config.Nodes[idx] == nil {
		e.mu.Unlock()
		return errors.New("node index out of range")
	}
	targetLink := e.config.Nodes[idx]
	targetName := targetLink.Remark
	if targetName == "" {
		targetName = fmt.Sprintf("%s:%d", targetLink.Host, targetLink.Port)
	}
	wasConnected := e.state == StateConnected || e.state == StateConnecting
	activeSched := e.sched
	oldConnSched := e.connectingSched

	if !wasConnected {
		e.config.ActiveNode = idx
		e.config.Link = targetLink
		if targetLink.Params != nil {
			e.paramStore.Set(*targetLink.Params)
		}
		e.mu.Unlock()
		e.Logf("Switched active node to #%d (%s)", idx+1, targetName)
		return e.SaveConfig()
	}

	if idx == e.config.ActiveNode && e.state == StateConnected && activeSched != nil {
		e.mu.Unlock()
		return e.SaveConfig()
	}

	targetParams := gft.DefaultParams()
	if targetLink.Params != nil && targetLink.Params.Validate() == nil {
		targetParams = *targetLink.Params
	} else {
		targetParams = e.paramStore.Get()
	}
	nextStore := gft.NewParamStore(targetParams)
	newSched := gft.NewApexScheduler(targetLink, nextStore, gft.DefaultPoolSize, e.Logf)

	e.connectGen++
	gen := e.connectGen
	e.connectingSched = newSched
	e.mu.Unlock()

	if oldConnSched != nil && oldConnSched != activeSched {
		go oldConnSched.Close()
	}

	if activeSched != nil {
		e.Logf("Hot-switching to #%d (%s:%d) without dropping current tunnel...", idx+1, targetLink.Host, targetLink.Port)
	} else {
		e.Logf("Connecting to #%d (%s:%d)...", idx+1, targetLink.Host, targetLink.Port)
	}

	if err := newSched.Start(8 * time.Second); err != nil {
		newSched.Close()
		e.mu.Lock()
		if e.connectingSched == newSched {
			e.connectingSched = nil
		}
		keptActive := e.sched != nil && e.connectGen == gen
		if !keptActive && e.connectGen == gen && activeSched == nil {
			e.config.ActiveNode = idx
			e.config.Link = targetLink
			e.state = StateError
			e.lastErr = err.Error()
		}
		e.mu.Unlock()
		if keptActive {
			e.Logf("Node #%d (%s) handshake failed (%v); kept existing tunnel active", idx+1, targetName, err)
			return fmt.Errorf("目标节点 %s 连接失败，已保留原节点连接: %w", targetName, err)
		}
		return err
	}

	st := newSched.Stats()
	e.mu.Lock()
	if e.connectingSched == newSched {
		e.connectingSched = nil
	}
	if e.connectGen != gen || e.state == StateDisconnected {
		e.mu.Unlock()
		newSched.Close()
		return errors.New("node switch cancelled")
	}
	prevSched := e.sched
	e.sched = newSched
	e.state = StateConnected
	e.lastErr = ""
	e.pingMs = st.RTTMs
	e.config.ActiveNode = idx
	e.config.Link = targetLink
	if targetLink.Params != nil {
		e.paramStore.Set(*targetLink.Params)
	}
	mode := e.config.RouteMode
	httpAddr := e.config.HTTPAddr
	e.config.SysProxy = mode != RouteCore
	needSysProxy := mode != RouteCore && !e.sysProxyApplied
	e.mu.Unlock()

	if err := e.SaveConfig(); err != nil {
		e.Logf("SaveConfig warning after lossless node switch: %v", err)
	}
	if needSysProxy {
		if serr := EnableSystemProxyWithBackup(httpAddr, e.proxyBackupPath); serr != nil {
			e.Logf("Failed to enable system proxy: %v", serr)
		} else {
			e.mu.Lock()
			e.sysProxyApplied = true
			e.mu.Unlock()
		}
	}

	if prevSched != nil && prevSched != newSched {
		go func(old *gft.ApexScheduler) {
			select {
			case <-e.stopStats:
			case <-time.After(400 * time.Millisecond):
			}
			old.Close()
		}(prevSched)
	}

	e.Logf("Losslessly switched to #%d (%s) via [%s] (RTT=%dms)", idx+1, targetName, st.Mode, st.RTTMs)
	return nil
}

// DeleteNode deletes a saved node by index.
func (e *Engine) DeleteNode(idx int) error {
	e.mu.Lock()
	if idx < 0 || idx >= len(e.config.Nodes) {
		e.mu.Unlock()
		return errors.New("node index out of range")
	}
	wasActive := idx == e.config.ActiveNode
	e.config.Nodes = append(e.config.Nodes[:idx], e.config.Nodes[idx+1:]...)
	if len(e.config.Nodes) == 0 {
		e.config.ActiveNode = 0
		e.config.Link = nil
	} else if e.config.ActiveNode >= len(e.config.Nodes) {
		e.config.ActiveNode = len(e.config.Nodes) - 1
		e.config.Link = e.config.Nodes[e.config.ActiveNode]
	} else {
		e.config.Link = e.config.Nodes[e.config.ActiveNode]
	}
	e.mu.Unlock()
	if wasActive {
		e.Disconnect()
	}
	return e.SaveConfig()
}

// RenameNode updates the display remark of a saved node by index and persists config.
func (e *Engine) RenameNode(idx int, remark string) error {
	clean := strings.TrimSpace(remark)
	if runes := []rune(clean); len(runes) > 64 {
		clean = string(runes[:64])
	}
	e.mu.Lock()
	if idx < 0 || idx >= len(e.config.Nodes) {
		e.mu.Unlock()
		return errors.New("node index out of range")
	}
	n := e.config.Nodes[idx]
	if clean == "" && n != nil {
		clean = fmt.Sprintf("%s:%d", n.Host, n.Port)
	}
	if n != nil {
		n.Remark = clean
	}
	if idx == e.config.ActiveNode && e.config.Link != nil {
		e.config.Link.Remark = clean
	}
	e.mu.Unlock()
	e.Logf("Renamed node #%d -> %s", idx+1, clean)
	return e.SaveConfig()
}

// SetRouteMode sets the unified routing/proxy mode ("rule", "global", "core"; legacy "direct" -> "core").
func (e *Engine) SetRouteMode(mode RouteMode) error {
	if mode == RouteDirect {
		mode = RouteCore
	}
	switch mode {
	case RouteRule, RouteGlobal, RouteCore:
	default:
		return fmt.Errorf("invalid route mode: %q", mode)
	}
	e.mu.Lock()
	e.config.RouteMode = mode
	wantSysProxy := mode != RouteCore
	e.config.SysProxy = wantSysProxy
	connected := e.state == StateConnected
	httpAddr := e.config.HTTPAddr
	wasApplied := e.sysProxyApplied
	e.mu.Unlock()

	if connected {
		if wantSysProxy {
			if err := EnableSystemProxyWithBackup(httpAddr, e.proxyBackupPath); err != nil {
				e.Logf("Failed to enable system proxy: %v", err)
			} else {
				e.mu.Lock()
				e.sysProxyApplied = true
				e.mu.Unlock()
				e.Logf("System proxy enabled (%s)", httpAddr)
			}
		} else if wasApplied {
			_ = DisableAndRestoreSystemProxy(e.proxyBackupPath)
			e.mu.Lock()
			e.sysProxyApplied = false
			e.mu.Unlock()
			e.Logf("Core mode: system proxy restored cleanly (ports listening)")
		}
	}

	e.Logf("Route mode changed to: %s", mode)
	return e.SaveConfig()
}

// IsConnected returns whether the tunnel is active.
func (e *Engine) IsConnected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.state == StateConnected && e.sched != nil
}

// RouteDecision decides whether hostport should bypass or traverse GhostFrame,
// running a 350ms CN DNS GeoIP probe only for unknown candidate domains in Rule mode.
func (e *Engine) RouteDecision(hostport string) RouteAction {
	act, _, _ := e.DecideSmartRoute(hostport, hostport)
	return act
}

// TunnelDNS returns the client's encrypted over-tunnel DNS LRU resolver.
func (e *Engine) TunnelDNS() *TunnelDNSResolver { return e.tunnelDNS }

// SetRuleDataDir sets the directory used to persist and load hot-updated rules_bundle.zlib.
func (e *Engine) SetRuleDataDir(dir string) {
	clean := strings.TrimSpace(dir)
	e.mu.Lock()
	e.ruleDataDir = clean
	e.mu.Unlock()
	if clean != "" {
		if b := LoadCompactRuleBundleFromDir(clean); b != nil && b.Source == "local" {
			e.router.SetCompactBundle(b)
			if e.smartCache != nil {
				e.smartCache.Clear()
			}
		}
	}
}

// RuleDataDir returns the directory storing hot-updated rules_bundle.zlib.
func (e *Engine) RuleDataDir() string {
	e.mu.RLock()
	dir := e.ruleDataDir
	e.mu.RUnlock()
	return dir
}

// RuleStats returns current routing table capacities and hit counters.
func (e *Engine) RuleStats() RuleStats {
	return e.router.Stats()
}

// ShouldSniffSNI reports whether target is a raw non-private IP on a TLS port eligible
// for 30ms ClientHello SNI sniffing under Rule mode.
func (e *Engine) ShouldSniffSNI(target string) bool {
	e.mu.RLock()
	mode := e.config.RouteMode
	e.mu.RUnlock()
	if mode != RouteRule {
		return false
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !gft.IsTLSSniffPort(port) {
		return false
	}
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast()
}

// OpenTargetStream opens either a direct TCP connection or a multiplexed GFT stream
// per Router policy (never leaking overseas DNS queries locally).
func (e *Engine) OpenTargetStream(target string, first []byte) (gft.DataStream, RouteAction, error) {
	return e.OpenTargetStreamWithRoute(target, target, first)
}

var errRouteRejected = errors.New("connection blocked by custom REJECT rule")

// SetDirectDNSBypass enables direct public CN DNS resolution (223.5.5.5 / 119.29.29.29)
// for ActionDirect connections so TUN Fake-IP system DNS (198.18.0.1) never causes self-resolution loops.
func (e *Engine) SetDirectDNSBypass(enabled bool) {
	e.directDNSBypass.Store(enabled)
}

// DirectDialer returns a net.Dialer bound to the physical interface and, when TUN Fake-IP DNS is active,
// configured with a direct CN DNS resolver bypassing the TUN virtual DNS server.
func (e *Engine) DirectDialer(timeout time.Duration) net.Dialer {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	d := net.Dialer{Timeout: timeout, Control: netbind.Control}
	if e.directDNSBypass.Load() {
		d.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				nd := net.Dialer{Timeout: 3 * time.Second, Control: netbind.Control}
				candidates := make([]string, 0, 3)
				for _, host := range []string{"223.5.5.5", "119.29.29.29"} {
					if ua, err := netbind.ResolveUDPAddr(ctx, host, 53); err == nil && ua != nil {
						candidates = append(candidates, ua.String())
					} else {
						candidates = append(candidates, net.JoinHostPort(host, "53"))
					}
				}
				if netbind.IsPureIPv6Physical() {
					candidates = append(candidates, "[2400:3200::1]:53", "[2402:4e00::]:53")
				}
				var lastErr error
				for _, addr := range candidates {
					if c, err := nd.DialContext(ctx, "udp", addr); err == nil {
						return c, nil
					} else {
						lastErr = err
					}
				}
				return nil, lastErr
			},
		}
	}
	return d
}

// OpenTargetStreamWithRoute classifies routing using routeTarget (e.g. sniffed TLS SNI)
// while opening the connection to dialTarget without local DNS leakage on known overseas hosts.
func (e *Engine) OpenTargetStreamWithRoute(dialTarget, routeTarget string, first []byte) (gft.DataStream, RouteAction, error) {
	e.mu.RLock()
	state := e.state
	sched := e.sched
	e.mu.RUnlock()

	if state != StateConnected || sched == nil {
		return nil, ActionProxy, errNoActiveSession
	}
	act, resolvedDial, _ := e.DecideSmartRoute(dialTarget, routeTarget)
	if act == ActionReject {
		return nil, ActionReject, errRouteRejected
	}
	if act == ActionDirect {
		dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
		dialTargetDirect := netbind.ResolveTCPTarget(dctx, resolvedDial)
		dcancel()
		d := e.DirectDialer(8 * time.Second)
		c, err := d.Dial("tcp", dialTargetDirect)
		if err != nil {
			return nil, ActionDirect, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		if len(first) > 0 {
			if _, werr := c.Write(first); werr != nil {
				_ = c.Close()
				return nil, ActionDirect, werr
			}
		}
		return &directStreamConn{Conn: c, target: resolvedDial}, ActionDirect, nil
	}
	st, err := sched.OpenStream(dialTarget, first)
	return st, ActionProxy, err
}

// OpenStreamWithOptionalSNISniff performs 30ms TLS SNI sniffing when target is a raw public IP
// under Rule mode, calling sendAck prior to reading the ClientHello when sniffing applies.
func (e *Engine) OpenStreamWithOptionalSNISniff(c net.Conn, target string, sendAck func() error) (st gft.DataStream, act RouteAction, rc net.Conn, ackSent bool, err error) {
	rc = c
	if e.ShouldSniffSNI(target) {
		if err = sendAck(); err != nil {
			return nil, ActionProxy, rc, false, err
		}
		ackSent = true
		_ = rc.SetDeadline(time.Time{})
		var sni string
		sni, rc = gft.SniffTLSSNI(rc, 30*time.Millisecond)
		routeTarget := target
		if sni != "" {
			if _, portStr, splitErr := net.SplitHostPort(target); splitErr == nil {
				routeTarget = net.JoinHostPort(sni, portStr)
			}
		}
		st, act, err = e.OpenTargetStreamWithRoute(target, routeTarget, nil)
		return st, act, rc, ackSent, err
	}
	st, act, err = e.OpenTargetStream(target, nil)
	return st, act, rc, false, err
}

// OpenUDPAssociation opens a GFT UDP association (QUIC Datagrams or TCP Mux fallback).
func (e *Engine) OpenUDPAssociation() (gft.UDPAssociation, error) {
	e.mu.RLock()
	state := e.state
	sched := e.sched
	e.mu.RUnlock()
	if state != StateConnected || sched == nil {
		return nil, errNoActiveSession
	}
	return sched.OpenUDP()
}

// TunnelStream opens a single encrypted proxy stream directly to target (used for health probes / gateway services).
func (e *Engine) TunnelStream(target string) (gft.DataStream, error) {
	e.mu.RLock()
	state := e.state
	sched := e.sched
	e.mu.RUnlock()
	if state != StateConnected || sched == nil {
		return nil, errNoActiveSession
	}
	return sched.OpenStream(target, nil)
}

// ForwardRawDNSThroughTunnel sends a raw RFC 1035 DNS packet over the active GhostFrame UDP
// association to upstream resolvers (1.1.1.1:53 / 8.8.8.8:53) without any local DNS query.
func (e *Engine) ForwardRawDNSThroughTunnel(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("dns: short query packet")
	}
	assoc, err := e.OpenUDPAssociation()
	if err != nil {
		return nil, err
	}
	defer assoc.Close()

	txID := [2]byte{query[0], query[1]}
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	var lastErr error
	for _, srv := range servers {
		if err := assoc.SendTo(srv, query); err != nil {
			lastErr = err
			continue
		}
		timer := time.NewTimer(2200 * time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
				lastErr = context.DeadlineExceeded
				goto nextDNS
			case pkt, ok := <-assoc.Recv():
				if !ok {
					timer.Stop()
					lastErr = errors.New("dns: assoc closed")
					goto nextDNS
				}
				if len(pkt.Data) >= 12 && pkt.Data[0] == txID[0] && pkt.Data[1] == txID[1] {
					timer.Stop()
					out := make([]byte, len(pkt.Data))
					copy(out, pkt.Data)
					return out, nil
				}
			}
		}
	nextDNS:
	}
	if lastErr == nil {
		lastErr = errors.New("dns: no tunnel response")
	}
	return nil, lastErr
}

// SetHopRange updates the active node's UDP port hopping range (e.g. "20000-45000") and reconnects if active.
func (e *Engine) SetHopRange(hopRange string) error {
	hr := strings.TrimSpace(hopRange)
	e.mu.Lock()
	l := e.activeLinkLocked()
	if l == nil {
		e.mu.Unlock()
		return errors.New("no active node configured")
	}
	l.HopRange = hr
	shouldReconnect := e.state == StateConnected || e.state == StateConnecting || e.state == StateError
	e.mu.Unlock()
	if err := e.SaveConfig(); err != nil {
		return err
	}
	e.Logf("Port hopping range updated: %q", hr)
	if shouldReconnect {
		e.Disconnect()
		go func() { _ = e.Connect() }()
	}
	return nil
}

// SetCustomRules updates, compiles, and persists user-defined custom routing rules.
func (e *Engine) SetCustomRules(lines []string) error {
	cp := make([]string, 0, len(lines))
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			cp = append(cp, ln)
		}
	}
	parsed := ParseCustomRules(cp)
	e.mu.Lock()
	e.config.CustomRules = cp
	e.router.SetCustomRules(parsed)
	e.mu.Unlock()
	if e.smartCache != nil {
		e.smartCache.Clear()
	}
	e.Logf("Custom rules updated (%d active entries)", len(parsed))
	return e.SaveConfig()
}

// CustomRules returns a copy of configured custom routing lines.
func (e *Engine) CustomRules() []string {
	e.mu.RLock()
	out := make([]string, len(e.config.CustomRules))
	copy(out, e.config.CustomRules)
	e.mu.RUnlock()
	return out
}

// GatewayConfigRaw returns a copy of any raw gateway config stored in config.json.
func (e *Engine) GatewayConfigRaw() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.config.Gateway) == 0 {
		return nil
	}
	cp := make([]byte, len(e.config.Gateway))
	copy(cp, e.config.Gateway)
	return cp
}

// SetGatewayConfigRaw updates and persists the raw gateway configuration block inside config.json.
func (e *Engine) SetGatewayConfigRaw(raw json.RawMessage) error {
	e.mu.Lock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	e.config.Gateway = cp
	e.mu.Unlock()
	return e.SaveConfig()
}

// NodeHostIPs returns unique IPv4 literal addresses for all configured VPS nodes
// (resolving hostnames using DirectDialer so firewall bypass never hijacks node dials).
func (e *Engine) NodeHostIPs() []string {
	e.mu.RLock()
	hosts := make([]string, 0, len(e.config.Nodes)+1)
	if e.config.Link != nil && e.config.Link.Host != "" {
		hosts = append(hosts, e.config.Link.Host)
	}
	for _, n := range e.config.Nodes {
		if n != nil && n.Host != "" {
			hosts = append(hosts, n.Host)
		}
	}
	e.mu.RUnlock()

	seen := make(map[string]struct{})
	var ips []string
	for _, h := range hosts {
		clean := strings.Trim(strings.TrimSpace(h), "[]")
		if clean == "" {
			continue
		}
		if ip := net.ParseIP(clean); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				s := ip4.String()
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					ips = append(ips, s)
				}
			}
			continue
		}
		d := e.DirectDialer(3 * time.Second)
		res := d.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, err := res.LookupIPAddr(ctx, clean)
		cancel()
		if err == nil {
			for _, a := range addrs {
				if ip4 := a.IP.To4(); ip4 != nil {
					s := ip4.String()
					if _, ok := seen[s]; !ok {
						seen[s] = struct{}{}
						ips = append(ips, s)
					}
				}
			}
		}
	}
	return ips
}

// Connect starts the ApexScheduler (QUIC Dual-Track + uTLS SessionPool).
func (e *Engine) Connect() error {
	e.mu.Lock()
	if e.state == StateConnected || e.state == StateConnecting {
		e.mu.Unlock()
		return nil
	}
	l := e.activeLinkLocked()
	if l == nil {
		e.state = StateError
		e.lastErr = "no node configured"
		e.mu.Unlock()
		return errors.New("no node configured")
	}
	e.state = StateConnecting
	e.lastErr = ""
	e.connectGen++
	gen := e.connectGen
	sched := gft.NewApexScheduler(l, e.paramStore, gft.DefaultPoolSize, e.Logf)
	e.connectingSched = sched
	e.mu.Unlock()

	e.Logf("Connecting to %s:%d (transport=%s, route=%s, Apex Dual-Track)...",
		l.Host, l.Port, l.EffectiveTransport(), e.config.RouteMode)

	if err := sched.Start(8 * time.Second); err != nil {
		sched.Close()
		e.mu.Lock()
		if e.connectingSched == sched {
			e.connectingSched = nil
		}
		if e.connectGen != gen || e.state != StateConnecting {
			e.mu.Unlock()
			return nil
		}
		e.state = StateError
		e.lastErr = err.Error()
		e.mu.Unlock()
		e.Logf("Connection failed: %v", err)
		return err
	}

	st := sched.Stats()
	e.mu.Lock()
	if e.connectingSched == sched {
		e.connectingSched = nil
	}
	if e.connectGen != gen || e.state != StateConnecting {
		e.mu.Unlock()
		sched.Close()
		return nil
	}
	e.sched = sched
	e.state = StateConnected
	e.lastErr = ""
	e.pingMs = st.RTTMs
	mode := e.config.RouteMode
	httpAddr := e.config.HTTPAddr
	socksAddr := e.config.SocksAddr
	e.config.SysProxy = mode != RouteCore
	e.mu.Unlock()

	e.Logf("Connected via [%s] (RTT=%dms, conns=%d)", st.Mode, st.RTTMs, st.ActiveConns)

	if mode != RouteCore {
		if err := EnableSystemProxyWithBackup(httpAddr, e.proxyBackupPath); err != nil {
			e.Logf("Failed to enable system proxy: %v", err)
		} else {
			e.mu.Lock()
			e.sysProxyApplied = true
			e.mu.Unlock()
			e.Logf("System proxy enabled with crash-safe backup (%s)", httpAddr)
		}
	} else {
		e.Logf("Core mode active: local proxy ready (%s / %s), system proxy untouched", socksAddr, httpAddr)
	}
	return nil
}

// Disconnect stops the ApexScheduler and restores system proxy cleanly.
func (e *Engine) Disconnect() {
	e.mu.Lock()
	if e.state != StateConnected && e.state != StateConnecting {
		e.mu.Unlock()
		return
	}
	e.state = StateDisconnected
	e.connectGen++
	connSched := e.connectingSched
	e.connectingSched = nil
	sched := e.sched
	e.sched = nil
	wasApplied := e.sysProxyApplied
	e.sysProxyApplied = false
	e.mu.Unlock()

	if connSched != nil {
		connSched.Close()
	}
	if sched != nil {
		sched.Close()
	}
	if wasApplied {
		_ = DisableAndRestoreSystemProxy(e.proxyBackupPath)
		e.Logf("System proxy restored cleanly")
	}
	e.Logf("Disconnected from node")
}

func (e *Engine) statsLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	tickCount := 0
	for {
		select {
		case <-e.stopStats:
			return
		case <-t.C:
			tickCount++
			if tickCount%15 == 0 {
				e.checkSysProxyDrift()
			}
			e.mu.Lock()
			var curUp, curDown uint64
			if e.sched != nil {
				st := e.sched.Stats()
				curUp = st.TotalUp
				curDown = st.TotalDown
				if st.RTTMs > 0 {
					e.pingMs = st.RTTMs
				}
			}
			var upDelta, downDelta uint64
			if curUp >= e.prevUp {
				upDelta = curUp - e.prevUp
			}
			if curDown >= e.prevDown {
				downDelta = curDown - e.prevDown
			}
			e.prevUp = curUp
			e.prevDown = curDown
			e.curUpBps = upDelta
			e.curDownBps = downDelta

			pt := TrafficPoint{Time: time.Now().Unix(), Up: upDelta, Down: downDelta}
			if len(e.history) >= 60 {
				e.history = append(e.history[1:], pt)
			} else {
				e.history = append(e.history, pt)
			}
			e.mu.Unlock()
		}
	}
}

func (e *Engine) checkSysProxyDrift() {
	e.mu.RLock()
	connected := e.state == StateConnected
	wantProxy := e.config.SysProxy
	applied := e.sysProxyApplied
	httpAddr := e.config.HTTPAddr
	e.mu.RUnlock()

	if !connected || !wantProxy || !applied || IsMockSysProxy() {
		e.proxyDrifted.Store(false)
		return
	}
	cur, err := QueryFullSystemProxy()
	if err != nil {
		return
	}
	drifted := !cur.Enabled || !strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(httpAddr))
	prev := e.proxyDrifted.Swap(drifted)
	if drifted && !prev {
		e.Logf("[SysProxy] Proxy drift detected (system proxy changed outside GhostFrame)")
	}
}

// OnSystemWake resets stale RTT estimators and probes live tunnels after sleep/resume or network change.
func (e *Engine) OnSystemWake() {
	e.mu.RLock()
	sched := e.sched
	connected := e.state == StateConnected
	e.mu.RUnlock()
	if connected && sched != nil {
		sched.OnSystemWake()
	}
	e.checkSysProxyDrift()
}

// RestoreSystemProxySync synchronously restores pre-session system proxy during WM_QUERYENDSESSION/shutdown.
func (e *Engine) RestoreSystemProxySync() {
	e.mu.Lock()
	applied := e.sysProxyApplied
	backupPath := e.proxyBackupPath
	e.sysProxyApplied = false
	e.proxyDrifted.Store(false)
	e.mu.Unlock()
	if applied || backupPath != "" {
		_ = DisableAndRestoreSystemProxy(backupPath)
	}
}

// RebindSystemProxy re-applies the local GhostFrame system proxy after external drift.
func (e *Engine) RebindSystemProxy() error {
	e.mu.RLock()
	httpAddr := e.config.HTTPAddr
	backupPath := e.proxyBackupPath
	e.mu.RUnlock()
	if err := EnableSystemProxyWithBackup(httpAddr, backupPath); err != nil {
		return err
	}
	e.mu.Lock()
	e.sysProxyApplied = true
	e.mu.Unlock()
	e.proxyDrifted.Store(false)
	e.Logf("[SysProxy] System proxy rebound cleanly (%s)", httpAddr)
	return nil
}

// SetSysProxyToggle toggles the Windows system proxy setting with backup/restore.
func (e *Engine) SetSysProxyToggle(enable bool) error {
	e.mu.Lock()
	e.config.SysProxy = enable
	connected := e.state == StateConnected
	httpAddr := e.config.HTTPAddr
	e.mu.Unlock()

	_ = e.SaveConfig()

	if connected {
		if enable {
			if err := EnableSystemProxyWithBackup(httpAddr, e.proxyBackupPath); err != nil {
				e.Logf("SetSystemProxy failed: %v", err)
				return err
			}
			e.proxyDrifted.Store(false)
			e.Logf("System proxy enabled (%s)", httpAddr)
		} else {
			_ = DisableAndRestoreSystemProxy(e.proxyBackupPath)
			e.proxyDrifted.Store(false)
			e.Logf("System proxy restored cleanly")
		}
	}
	return nil
}

// Logf records a log entry in the fixed 1000-entry ring buffer.
func (e *Engine) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Message: msg,
	}
	if e.logRing != nil {
		e.logRing.Push(entry)
	}
}

// PingNow performs an explicit user-triggered RTT probe (never background polling!).
func (e *Engine) PingNow() (PingSummary, error) {
	e.mu.RLock()
	sched := e.sched
	l := e.activeLinkLocked()
	e.mu.RUnlock()

	if sched != nil {
		st := sched.Stats()
		if st.RTTMs > 0 {
			e.mu.Lock()
			e.pingMs = st.RTTMs
			e.mu.Unlock()
			e.Logf("In-band RTT [%s]: %dms", st.Mode, st.RTTMs)
			return PingSummary{RTTMs: st.RTTMs, Transport: st.Mode}, nil
		}
	}
	if l == nil {
		return PingSummary{}, errors.New("no node configured")
	}
	pr, err := gft.Ping(context.Background(), l, 5*time.Second)
	if err != nil {
		e.Logf("Manual ping failed: %v", err)
		return PingSummary{}, err
	}
	ms := pr.KnockRTT.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	e.mu.Lock()
	e.pingMs = ms
	e.mu.Unlock()
	e.Logf("Manual ping OK: Handshake=%v RTT=%dms", pr.Handshake.Round(time.Millisecond), ms)
	return PingSummary{RTTMs: ms, Transport: "uTLS-" + l.EffectiveFP()}, nil
}

// SetTransport updates the active node's preferred transport ("auto", "rtc", "tcp").
// Legacy "quic" values are normalized seamlessly to "rtc".
func (e *Engine) SetTransport(mode string) error {
	switch mode {
	case "", "auto", "tcp", "rtc":
	case "quic":
		mode = "rtc"
	default:
		return fmt.Errorf("invalid transport mode: %s", mode)
	}
	e.mu.Lock()
	if l := e.activeLinkLocked(); l != nil {
		l.Transport = mode
	}
	shouldReconnect := e.state == StateConnected || e.state == StateConnecting || e.state == StateError
	e.mu.Unlock()
	_ = e.SaveConfig()
	e.Logf("Transport preference updated to: %s", mode)
	if shouldReconnect {
		e.Disconnect()
		go func() { _ = e.Connect() }()
	}
	return nil
}

// SetBandwidthLimits configures Smart-Brutal upload/download target Mbps (0 = Auto-Probe)
// on the active node and applies live updates immediately if connected.
func (e *Engine) SetBandwidthLimits(upMbps, downMbps int) error {
	if upMbps < 0 || upMbps > 65535 || downMbps < 0 || downMbps > 65535 {
		return errors.New("带宽目标必须在 0-65535 Mbps 之间")
	}
	e.mu.Lock()
	l := e.activeLinkLocked()
	if l == nil {
		e.mu.Unlock()
		return errors.New("未选择节点")
	}
	l.UpMbps = upMbps
	l.DownMbps = downMbps
	sched := e.sched
	e.mu.Unlock()

	if sched != nil {
		sched.UpdateBandwidth(upMbps, downMbps)
	}
	e.Logf("Smart-Brutal 带宽设置已更新: 上行=%d Mbps 下行=%d Mbps (0=自动探测)", upMbps, downMbps)
	return e.SaveConfig()
}

// NodeSummary describes a configured server node for UI rendering.
type NodeSummary struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Verify    string `json:"verify"`
	Transport string `json:"transport"`
	HopRange  string `json:"hop_range,omitempty"`
}

// ClearLogs clears recorded client log entries.
func (e *Engine) ClearLogs() {
	if e.logRing != nil {
		e.logRing.Clear()
	}
}

// Status returns the full UI status snapshot.
func (e *Engine) Status() map[string]any {
	e.mu.RLock()
	state := e.state
	lastErr := e.lastErr
	sched := e.sched
	upBps := e.curUpBps
	downBps := e.curDownBps
	pingMs := e.pingMs
	routeMode := e.config.RouteMode
	sysProxy := e.config.SysProxy
	socksAddr := e.config.SocksAddr
	httpAddr := e.config.HTTPAddr
	activeIdx := e.config.ActiveNode
	histCopy := make([]TrafficPoint, len(e.history))
	copy(histCopy, e.history)

	nodes := make([]NodeSummary, 0, len(e.config.Nodes))
	for i, n := range e.config.Nodes {
		if n == nil {
			continue
		}
		name := n.Remark
		if name == "" {
			name = fmt.Sprintf("%s:%d", n.Host, n.Port)
		}
		nodes = append(nodes, NodeSummary{
			Index:     i,
			Name:      name,
			Host:      n.Host,
			Port:      n.Port,
			Verify:    n.EffectiveVerify(),
			Transport: n.EffectiveTransport(),
			HopRange:  n.HopRange,
		})
	}
	l := e.activeLinkLocked()
	e.mu.RUnlock()

	var totalUp, totalDown, fecRecovered, hopCount, rekeyCount uint64
	activeMode := ""
	hopState := ""
	var rtcPorts [2]int
	var srttMs, minRTTMs int64
	var rtcPort, activeConns, activeStreams int
	var lossPct, pacingMbps float64
	if sched != nil {
		st := sched.Stats()
		totalUp = st.TotalUp
		totalDown = st.TotalDown
		activeMode = st.Mode
		rtcPort = st.RTCPort
		rtcPorts = st.RTCPorts
		hopCount = st.HopCount
		hopState = st.HopState
		rekeyCount = st.RekeyCount
		srttMs = st.SRTTMs
		minRTTMs = st.MinRTTMs
		fecRecovered = st.FECRecovered
		lossPct = st.LossRate * 100.0
		pacingMbps = st.PacingMbps
		activeConns = st.ActiveConns
		activeStreams = st.ActiveStreams
		if st.RTTMs > 0 {
			pingMs = st.RTTMs
		}
		if lastErr == "" && st.LastErr != "" && state != StateConnected {
			lastErr = st.LastErr
		}
	}

	var nodeName, nodeHost, tPref, verifyMode, hopRange string
	var nodePort, upMbps, downMbps int
	if l != nil {
		nodeName = l.Remark
		if nodeName == "" {
			nodeName = fmt.Sprintf("%s:%d", l.Host, l.Port)
		}
		nodeHost = l.Host
		nodePort = l.Port
		tPref = l.EffectiveTransport()
		verifyMode = l.EffectiveVerify()
		hopRange = l.HopRange
		upMbps = l.UpMbps
		downMbps = l.DownMbps
	}
	if tPref == "" {
		tPref = "auto"
	}

	return map[string]any{
		"version":          Version,
		"state":            string(state),
		"last_err":         lastErr,
		"active_transport": activeMode,
		"transport_pref":   tPref,
		"route_mode":       string(routeMode),
		"rule_stats":       e.router.Stats(),
		"custom_rules":     e.CustomRules(),
		"recent_routes":    e.RecentRoutes(),
		"verify_mode":      verifyMode,
		"hop_range":        hopRange,
		"rtc_port":         rtcPort,
		"rtc_ports":        rtcPorts,
		"hop_count":        hopCount,
		"hop_state":        hopState,
		"rekey_count":      rekeyCount,
		"srtt_ms":          srttMs,
		"min_rtt_ms":       minRTTMs,
		"fec_recovered":    fecRecovered,
		"loss_pct":         lossPct,
		"pacing_mbps":      pacingMbps,
		"up_mbps":          upMbps,
		"down_mbps":        downMbps,
		"active_conns":     activeConns,
		"active_streams":   activeStreams,
		"ping_ms":          pingMs,
		"up_bps":           upBps,
		"down_bps":         downBps,
		"total_up":         totalUp,
		"total_down":       totalDown,
		"history":          histCopy,
		"sys_proxy":        sysProxy,
		"proxy_drifted":    e.proxyDrifted.Load(),
		"socks_addr":       socksAddr,
		"http_addr":        httpAddr,
		"node_name":        nodeName,
		"node_host":        nodeHost,
		"node_port":        nodePort,
		"active_node":      activeIdx,
		"nodes":            nodes,
		"link_uri":         e.LinkURI(),
		"clash_yaml":       e.ClashYAML(),
	}
}

// Logs returns recent log lines.
func (e *Engine) Logs() []LogEntry {
	if e.logRing == nil {
		return nil
	}
	return e.logRing.Entries()
}

// LinkURI returns the active node's gft3:// link.
func (e *Engine) LinkURI() string {
	e.mu.RLock()
	l := e.activeLinkLocked()
	e.mu.RUnlock()
	if l == nil {
		return ""
	}
	return l.Encode()
}

// ClashYAML outputs Clash Meta / Clash Verge compatible SOCKS5 (TCP+UDP) config.
func (e *Engine) ClashYAML() string {
	e.mu.RLock()
	l := e.activeLinkLocked()
	socks := e.config.SocksAddr
	e.mu.RUnlock()
	if l == nil {
		return "# No node configured"
	}
	host, portStr, err := net.SplitHostPort(socks)
	if err != nil {
		host, portStr = "127.0.0.1", "10808"
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	port, _ := strconv.Atoi(portStr)
	if port <= 0 {
		port = 10808
	}
	name := l.Remark
	if name == "" {
		name = "Kestrel-Apex"
	}
	return fmt.Sprintf(`proxies:
  - name: "%s"
    type: socks5
    server: %s
    port: %d
    udp: true`, name, host, port)
}

// Close shuts down local proxy listeners, active tunnel, and restores system proxy if applied.
func (e *Engine) Close() {
	e.stopOnce.Do(func() { close(e.stopStats) })
	e.Disconnect()
	e.mu.Lock()
	socksSrv := e.socksSrv
	httpSrv := e.httpSrv
	e.socksSrv = nil
	e.httpSrv = nil
	e.mu.Unlock()
	if socksSrv != nil {
		_ = socksSrv.Close()
	}
	if httpSrv != nil {
		_ = httpSrv.Close()
	}
	_, _ = RecoverSystemProxyIfDirty(e.proxyBackupPath)
}
