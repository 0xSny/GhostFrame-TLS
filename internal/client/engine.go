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
var Version = "v4.2.2"

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
	AutoConnect   bool            `json:"auto_connect,omitempty"`
	EnableIPv6    bool            `json:"enable_ipv6,omitempty"`
	CloseToTray   *bool           `json:"close_to_tray,omitempty"`
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

// ErrSwitchCancelled is returned by SelectNode when superseded by a newer switch, Connect, or Disconnect.
var ErrSwitchCancelled = errors.New("node switch cancelled")

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
	activeSchedLink *gft.Link
	connectingSched *gft.ApexScheduler
	connectGen      uint64
	switchingNode   int
	switchingName   string
	paramStore      *gft.ParamStore
	router          *Router
	tunnelDNS          *TunnelDNSResolver
	smartCache         *smartRouteCache
	recentRoutes       *recentRouteRing
	trafficTracker     *targetTrafficTracker
	directCNResolveFn  DirectCNDNSFunc
	tunnelDNSResolveFn TunnelDNSFunc
	fakeIPLookupMu     sync.RWMutex
	fakeIPLookupFn     func(net.IP) (string, bool)
	systemLookupIPFn   func(context.Context, string, string) ([]net.IP, error)
	socksSrv           *SOCKS5Server
	httpSrv            *HTTPProxyServer
	sysProxyApplied    bool
	proxyDrifted       atomic.Bool
	directDNSBypass     atomic.Bool
	enableIPv6          atomic.Bool
	lastAntiLoopTCPLogNs atomic.Int64
	lastAntiLoopUDPLogNs atomic.Int64
	antiLoopBlocked      atomic.Uint64
	nodeHostsGen         atomic.Uint64

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
		switchingNode:   -1,
		paramStore:      gft.NewParamStore(gft.DefaultParams()),
		router:          NewRouterWithDataDir(ruleDir),
		tunnelDNS:       NewTunnelDNSResolver(),
		smartCache:      newSmartRouteCache(smartRouteCacheCap),
		recentRoutes:    newRecentRouteRing(defaultRecentRouteCap),
		trafficTracker:  newTargetTrafficTracker(),
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
	e.enableIPv6.Store(e.config.EnableIPv6)
	e.router.SetEnableIPv6(e.config.EnableIPv6)
	e.mu.Lock()
	gen := e.syncRouterNodeHostsLocked()
	e.mu.Unlock()
	go e.refreshRouterNodeIPsAsync(gen)

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
		gen := e.syncRouterNodeHostsLocked()
		e.mu.Unlock()
		go e.refreshRouterNodeIPsAsync(gen)
		return e.SaveConfig()
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
	gen := e.syncRouterNodeHostsLocked()
	e.mu.Unlock()
	go e.refreshRouterNodeIPsAsync(gen)
	if err := e.SaveConfig(); err != nil {
		return idx, err
	}
	e.Logf("Imported node #%d: %s (%s:%d)", idx+1, link.Remark, link.Host, link.Port)
	return idx, nil
}

func sliceIndexLink(nodes []*gft.Link, target *gft.Link) int {
	for i, n := range nodes {
		if n == target {
			return i
		}
	}
	return -1
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
		e.connectGen++
		e.connectingSched = nil
		e.switchingNode = -1
		e.switchingName = ""
		if e.state == StateError {
			e.state = StateDisconnected
		}
		e.lastErr = ""
		e.config.ActiveNode = idx
		e.config.Link = targetLink
		if targetLink.Params != nil {
			e.paramStore.Set(*targetLink.Params)
		}
		e.mu.Unlock()
		if oldConnSched != nil && oldConnSched != activeSched {
			go oldConnSched.Close()
		}
		e.Logf("Switched active node to #%d (%s)", idx+1, targetName)
		return e.SaveConfig()
	}

	// Only skip if already connected to the exact same link object AND no pending switch needs cancellation.
	if idx == e.config.ActiveNode && e.state == StateConnected && activeSched != nil && e.activeSchedLink == targetLink && oldConnSched == nil {
		e.mu.Unlock()
		return e.SaveConfig()
	}

	// Clicking the currently active node while another switch handshake is in flight cancels the pending switch.
	if idx == e.config.ActiveNode && e.state == StateConnected && activeSched != nil && e.activeSchedLink == targetLink && oldConnSched != nil {
		e.connectGen++
		e.connectingSched = nil
		e.switchingNode = -1
		e.switchingName = ""
		e.lastErr = ""
		e.mu.Unlock()
		if oldConnSched != activeSched {
			go oldConnSched.Close()
		}
		e.Logf("Cancelled pending node switch; kept #%d (%s) active", idx+1, targetName)
		return nil
	}

	targetParams := gft.DefaultParams()
	if targetLink.Params != nil && targetLink.Params.Validate() == nil {
		targetParams = *targetLink.Params
	} else {
		targetParams = e.paramStore.Get()
	}
	targetParams.SNIRTTMs = 0
	nextStore := gft.NewParamStore(targetParams)
	newSched := gft.NewApexScheduler(targetLink, nextStore, gft.EffectivePoolSize(), e.Logf)

	e.connectGen++
	gen := e.connectGen
	e.connectingSched = newSched
	e.switchingNode = idx
	e.switchingName = targetName
	e.lastErr = ""
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
		superseded := e.connectGen != gen || e.state == StateDisconnected
		if e.connectGen == gen {
			e.switchingNode = -1
			e.switchingName = ""
		}
		keptActive := !superseded && e.sched != nil
		if !superseded && !keptActive {
			if curIdx := sliceIndexLink(e.config.Nodes, targetLink); curIdx >= 0 {
				e.config.ActiveNode = curIdx
				e.config.Link = targetLink
			}
			e.state = StateError
			e.lastErr = err.Error()
		}
		e.mu.Unlock()
		if superseded {
			return ErrSwitchCancelled
		}
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
	newIdx := sliceIndexLink(e.config.Nodes, targetLink)
	if e.connectGen != gen || e.state == StateDisconnected || newIdx < 0 {
		if e.connectGen == gen {
			e.switchingNode = -1
			e.switchingName = ""
		}
		e.mu.Unlock()
		newSched.Close()
		return ErrSwitchCancelled
	}
	prevSched := e.sched
	e.sched = newSched
	e.activeSchedLink = targetLink
	e.state = StateConnected
	e.lastErr = ""
	e.pingMs = st.RTTMs
	e.prevUp = st.TotalUp
	e.prevDown = st.TotalDown
	e.switchingNode = -1
	e.switchingName = ""
	e.config.ActiveNode = newIdx
	e.config.Link = targetLink
	e.config.AutoConnect = true
	e.paramStore = nextStore
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

	e.Logf("Losslessly switched to #%d (%s) via [%s] (RTT=%dms)", newIdx+1, targetName, st.Mode, st.RTTMs)
	return nil
}

// DeleteNode deletes a saved node by index without corrupting ActiveNode ordering.
func (e *Engine) DeleteNode(idx int) error {
	e.mu.Lock()
	if idx < 0 || idx >= len(e.config.Nodes) {
		e.mu.Unlock()
		return errors.New("node index out of range")
	}
	wasActive := idx == e.config.ActiveNode
	var cancelConnSched *gft.ApexScheduler
	e.config.Nodes = append(e.config.Nodes[:idx], e.config.Nodes[idx+1:]...)
	if len(e.config.Nodes) == 0 {
		e.config.ActiveNode = 0
		e.config.Link = nil
		e.config.AutoConnect = false
		e.switchingNode = -1
		e.switchingName = ""
	} else {
		if idx < e.config.ActiveNode {
			e.config.ActiveNode--
		}
		if e.config.ActiveNode >= len(e.config.Nodes) {
			e.config.ActiveNode = len(e.config.Nodes) - 1
		}
		e.config.Link = e.config.Nodes[e.config.ActiveNode]
		if e.switchingNode == idx {
			e.connectGen++
			e.switchingNode = -1
			e.switchingName = ""
			cancelConnSched = e.connectingSched
			e.connectingSched = nil
		} else if idx < e.switchingNode {
			e.switchingNode--
		}
	}
	gen := e.syncRouterNodeHostsLocked()
	e.mu.Unlock()
	go e.refreshRouterNodeIPsAsync(gen)
	if cancelConnSched != nil {
		go cancelConnSched.Close()
	}
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
	if idx == e.switchingNode {
		e.switchingName = clean
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

// ShouldAutoConnect reports whether the previous desktop session ended with an active tunnel
// and an active node is configured to automatically resume on startup.
func (e *Engine) ShouldAutoConnect() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.AutoConnect && e.activeLinkLocked() != nil
}

// SetAutoConnect updates whether future startups should automatically reconnect the tunnel/proxy.
func (e *Engine) SetAutoConnect(on bool) error {
	e.mu.Lock()
	changed := e.config.AutoConnect != on
	e.config.AutoConnect = on
	e.mu.Unlock()
	if changed {
		return e.SaveConfig()
	}
	return nil
}

// CloseToTray reports whether clicking the window close button minimizes to the tray (default true)
// rather than exiting Kestrel Pro completely.
func (e *Engine) CloseToTray() bool {
	e.mu.RLock()
	v := e.config.CloseToTray
	e.mu.RUnlock()
	return v == nil || *v
}

// SetCloseToTray configures whether closing the main window minimizes to tray or exits the app.
func (e *Engine) SetCloseToTray(toTray bool) error {
	e.mu.Lock()
	val := toTray
	e.config.CloseToTray = &val
	e.mu.Unlock()
	if toTray {
		e.Logf("主窗口关闭行为已设为: 缩小到右下角托盘")
	} else {
		e.Logf("主窗口关闭行为已设为: 直接退出全部关闭")
	}
	return e.SaveConfig()
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
	if e.IsNodeHost(target) {
		return false
	}
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

// syncRouterNodeHostsLocked registers configured literal node hosts/IPs into e.router immediately.
func (e *Engine) syncRouterNodeHostsLocked() uint64 {
	gen := e.nodeHostsGen.Add(1)
	if e.router == nil {
		return gen
	}
	hosts := make([]string, 0, len(e.config.Nodes)+1)
	if e.config.Link != nil && e.config.Link.Host != "" {
		hosts = append(hosts, e.config.Link.Host)
	}
	for _, n := range e.config.Nodes {
		if n != nil && n.Host != "" {
			hosts = append(hosts, n.Host)
		}
	}
	e.router.SetNodeBypassHosts(hosts)
	return gen
}

func (e *Engine) refreshRouterNodeIPsAsync(gen uint64) {
	if e.router == nil {
		return
	}
	if e.nodeHostsGen.Load() != gen {
		return
	}
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

	hosts = append(hosts, e.NodeHostIPs()...)
	hosts = append(hosts, e.NodeHostIPv6s()...)
	if e.nodeHostsGen.Load() == gen {
		e.router.SetNodeBypassHosts(hosts)
	}
}

// IsNodeHost reports whether target matches any configured proxy node IP or hostname.
func (e *Engine) IsNodeHost(target string) bool {
	return e.router != nil && e.router.IsNodeHost(target)
}

func (e *Engine) logAntiLoopThrottled(proto, target string) {
	e.antiLoopBlocked.Add(1)
	now := time.Now().UnixNano()
	slot := &e.lastAntiLoopTCPLogNs
	if proto == "UDP" {
		slot = &e.lastAntiLoopUDPLogNs
	}
	prev := slot.Load()
	if now-prev >= int64(5*time.Second) && slot.CompareAndSwap(prev, now) {
		e.Logf("[Anti-Loop] Rejected %s loopback proxy request targeting configured node %s", proto, target)
	}
}

// AntiLoopBlockedCount returns the number of rejected node-self-loop requests.
func (e *Engine) AntiLoopBlockedCount() uint64 {
	return e.antiLoopBlocked.Load()
}

// RecordTargetTraffic updates cumulative per-target upload/download statistics and emits
// a [TrafficAlert] kernel log whenever a single destination uploads > 20 MB within 10 seconds.
func (e *Engine) RecordTargetTraffic(target string, upBytes, downBytes uint64) {
	if e.trafficTracker == nil {
		return
	}
	if alert := e.trafficTracker.Record(target, upBytes, downBytes); alert != "" {
		e.Logf("%s", alert)
	}
}

// TopUploadTargets returns the top-N destinations sorted by cumulative uploaded bytes descending.
func (e *Engine) TopUploadTargets(limit int) []TargetTrafficStat {
	if e.trafficTracker == nil {
		return nil
	}
	return e.trafficTracker.TopUpload(limit)
}

// OpenTargetStream opens either a direct TCP connection or a multiplexed GFT stream
// per Router policy (never leaking overseas DNS queries locally).
func (e *Engine) OpenTargetStream(target string, first []byte) (gft.DataStream, RouteAction, error) {
	return e.OpenTargetStreamWithRoute(target, target, first)
}

var (
	errRouteRejected      = errors.New("connection blocked by custom REJECT rule")
	errNodeLoopRejected   = errors.New("connection rejected: target matches configured proxy node (anti-loop)")
	errIPv6DisabledClient = errors.New("IPv6 is disabled by client switch")
)

// IPv6Enabled reports whether IPv6 dual-stack routing & resolution is enabled.
func (e *Engine) IPv6Enabled() bool {
	return e.enableIPv6.Load()
}

// SetEnableIPv6 toggles client IPv6 dual-stack routing/dialing, flushes DNS/smart-route caches, and persists config.
func (e *Engine) SetEnableIPv6(enabled bool) error {
	e.mu.Lock()
	e.config.EnableIPv6 = enabled
	e.enableIPv6.Store(enabled)
	if e.router != nil {
		e.router.SetEnableIPv6(enabled)
	}
	e.mu.Unlock()
	if e.smartCache != nil {
		e.smartCache.Clear()
	}
	if e.tunnelDNS != nil {
		e.tunnelDNS.Clear()
	}
	stateWord := "关闭 (仅 IPv4 / 防泄露)"
	if enabled {
		stateWord = "开启 (IPv4 + IPv6 双栈)"
	}
	e.Logf("IPv6 双栈分流开关已%s", stateWord)
	return e.SaveConfig()
}

// SetDirectDNSBypass enables direct public CN DNS resolution (223.5.5.5 / 119.29.29.29)
// for ActionDirect connections so TUN Fake-IP system DNS (198.18.0.1) never causes self-resolution loops.
func (e *Engine) SetDirectDNSBypass(enabled bool) {
	e.directDNSBypass.Store(enabled)
}

// DirectDNSBypassEnabled reports whether direct physical DNS bypass is active on this Engine.
func (e *Engine) DirectDNSBypassEnabled() bool {
	return e.directDNSBypass.Load()
}

// SetFakeIPLookupFunc registers a reverse-lookup callback (e.g. from tunstack.FakeIPPool)
// so any direct outbound path receiving a Fake-IP can recover its original hostname before dialing.
func (e *Engine) SetFakeIPLookupFunc(fn func(net.IP) (string, bool)) {
	e.fakeIPLookupMu.Lock()
	e.fakeIPLookupFn = fn
	e.fakeIPLookupMu.Unlock()
}

// RecoverFakeIPTarget checks whether target uses a Fake-IP (198.18.0.0/15 or fd18:c612::/64).
// If so, it attempts to recover the mapped domain via fakeIPLookupFn and returns netbind.ErrFakeIPBlocked
// if the Fake-IP cannot be recovered. Non-Fake-IP targets are returned unchanged.
func (e *Engine) RecoverFakeIPTarget(target string) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return trimmed, nil
	}
	host := trimmed
	port := ""
	hasPort := false
	if h, p, err := net.SplitHostPort(trimmed); err == nil {
		host = h
		port = p
		hasPort = true
	}
	cleanHost := strings.Trim(strings.TrimSpace(host), "[]")
	if idx := strings.IndexByte(cleanHost, '%'); idx >= 0 {
		cleanHost = cleanHost[:idx]
	}
	ip := net.ParseIP(cleanHost)
	if ip == nil || !netbind.IsFakeIP(ip) {
		return target, nil
	}
	e.fakeIPLookupMu.RLock()
	fn := e.fakeIPLookupFn
	e.fakeIPLookupMu.RUnlock()
	if fn != nil {
		if realHost, ok := fn(ip); ok && realHost != "" {
			if hasPort {
				return net.JoinHostPort(realHost, port), nil
			}
			return realHost, nil
		}
	}
	return "", netbind.ErrFakeIPBlocked
}

// DirectDialer returns a net.Dialer bound to the physical interface and, when TUN Fake-IP DNS is active,
// configured with the physical-interface-bound pure-Go direct DNS resolver bypassing mDNSResponder.
func (e *Engine) DirectDialer(timeout time.Duration) net.Dialer {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	d := net.Dialer{Timeout: timeout, Control: netbind.Control}
	if e.directDNSBypass.Load() {
		d.Resolver = netbind.DirectResolver()
	}
	return d
}

func (e *Engine) lookupSystemIPs(ctx context.Context, network, host string) ([]net.IP, error) {
	e.fakeIPLookupMu.RLock()
	fn := e.systemLookupIPFn
	e.fakeIPLookupMu.RUnlock()
	if fn != nil {
		return fn(ctx, network, host)
	}
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

func (e *Engine) resolveDirectTCPCandidates(ctx context.Context, addr string) ([]netbind.DirectEndpoint, error) {
	allowIPv6 := e.IPv6Enabled()
	if e.directDNSBypass.Load() {
		return netbind.ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
	}

	h, pStr, splitErr := net.SplitHostPort(strings.TrimSpace(addr))
	if splitErr != nil {
		return netbind.ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
	}
	portNum, perr := strconv.Atoi(pStr)
	if perr != nil || portNum <= 0 || portNum > 65535 {
		return netbind.ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
	}
	rawHost := strings.TrimSpace(strings.Trim(h, "[]"))
	if idx := strings.IndexByte(rawHost, '%'); idx >= 0 {
		rawHost = rawHost[:idx]
	}
	if rawHost == "" || strings.EqualFold(rawHost, "localhost") || net.ParseIP(rawHost) != nil {
		return netbind.ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
	}

	fam := "ip4"
	if allowIPv6 {
		fam = "ip"
	}
	sysIPs, sysErr := e.lookupSystemIPs(ctx, fam, rawHost)
	if sysErr == nil && len(sysIPs) > 0 {
		var v4List, v6List []net.IP
		seen := make(map[string]struct{}, len(sysIPs))
		sawFake := false
		for _, ip := range sysIPs {
			if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if netbind.IsFakeIP(ip) {
				sawFake = true
				continue
			}
			k := ip.String()
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			if ip4 := ip.To4(); ip4 != nil {
				v4List = append(v4List, ip4)
			} else if allowIPv6 {
				v6List = append(v6List, ip)
			}
		}
		if !sawFake && (len(v4List) > 0 || len(v6List) > 0) {
			eps := make([]netbind.DirectEndpoint, 0, len(v4List)+len(v6List))
			for _, ip4 := range v4List {
				eps = append(eps, netbind.DirectEndpoint{
					DialNet: "tcp4",
					Addr:    net.JoinHostPort(ip4.String(), pStr),
				})
			}
			for _, ip6 := range v6List {
				eps = append(eps, netbind.DirectEndpoint{
					DialNet: "tcp6",
					Addr:    net.JoinHostPort(ip6.String(), pStr),
				})
			}
			return eps, nil
		}
	}

	// Fallback to physical-interface direct DNS (223.5.5.5 / 119.29.29.29) when system DNS
	// fails, returns empty/polluted answers, or returns Fake-IPs.
	return netbind.ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
}

// DirectDialContext dials addr directly over the physical interface, recovering Fake-IP targets
// via reverse lookup (or rejecting unmapped Fake-IPs with netbind.ErrFakeIPBlocked). On desktop
// platforms (!DirectDNSBypassEnabled), system DNS is preferred first with automatic fallback to
// DirectLookupHostIPs and multi-IP sequential dialing tolerance across returned CDN endpoints.
func (e *Engine) DirectDialContext(ctx context.Context, _ string, addr string) (net.Conn, error) {
	recovered, err := e.RecoverFakeIPTarget(addr)
	if err != nil {
		return nil, err
	}
	resolveCtx := ctx
	var cancel context.CancelFunc
	if resolveCtx == nil {
		resolveCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	} else if _, hasDeadline := resolveCtx.Deadline(); !hasDeadline {
		resolveCtx, cancel = context.WithTimeout(resolveCtx, 3*time.Second)
	}
	eps, rerr := e.resolveDirectTCPCandidates(resolveCtx, recovered)
	if cancel != nil {
		cancel()
	}
	if rerr != nil {
		if errors.Is(rerr, netbind.ErrIPv6Disabled) {
			return nil, errIPv6DisabledClient
		}
		return nil, rerr
	}
	if ctx == nil {
		var dcancel context.CancelFunc
		ctx, dcancel = context.WithTimeout(context.Background(), 8*time.Second)
		defer dcancel()
	}
	d := e.DirectDialer(8 * time.Second)
	var lastErr error
	for i, ep := range eps {
		if ctx.Err() != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		}
		attemptCtx := ctx
		var acancel context.CancelFunc
		if i < len(eps)-1 {
			perTry := 2500 * time.Millisecond
			if dl, ok := ctx.Deadline(); ok {
				rem := time.Until(dl)
				if rem <= 0 {
					if lastErr != nil {
						return nil, lastErr
					}
					return nil, context.DeadlineExceeded
				}
				share := rem / time.Duration(len(eps)-i)
				if share < 1200*time.Millisecond {
					share = minDuration(rem, 1200*time.Millisecond)
				}
				if share < perTry {
					perTry = share
				}
			}
			attemptCtx, acancel = context.WithTimeout(ctx, perTry)
		}
		conn, derr := d.DialContext(attemptCtx, ep.DialNet, ep.Addr)
		if acancel != nil {
			acancel()
		}
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// CanStaticDirect reports whether target is explicitly permitted for direct dialing under static
// RouteRule entries (LAN IPs, CN CIDRs, builtin CN domains, or custom DIRECT rules) without
// requiring an active remote tunnel session.
func (e *Engine) CanStaticDirect(target string) bool {
	e.mu.RLock()
	mode := e.config.RouteMode
	e.mu.RUnlock()
	if mode != RouteRule {
		return false
	}
	if recovered, err := e.RecoverFakeIPTarget(target); err == nil && recovered != "" {
		target = recovered
	}
	if e.IsNodeHost(target) {
		return false
	}
	act, _, unknown := e.router.evaluateStatic(mode, target)
	return !unknown && act == ActionDirect
}

func (e *Engine) dialDirectTrackedStream(resolvedDial, metricTarget string, first []byte) (gft.DataStream, RouteAction, error) {
	dctx, dcancel := context.WithTimeout(context.Background(), 8*time.Second)
	c, err := e.DirectDialContext(dctx, "tcp", resolvedDial)
	dcancel()
	if err != nil {
		if errors.Is(err, errIPv6DisabledClient) || errors.Is(err, netbind.ErrFakeIPBlocked) {
			return nil, ActionReject, err
		}
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
		e.RecordTargetTraffic(metricTarget, uint64(len(first)), 0)
	}
	return &trackedDataStream{
		DataStream: &directStreamConn{Conn: c, target: resolvedDial},
		eng:        e,
		target:     metricTarget,
	}, ActionDirect, nil
}

// OpenTargetStreamWithRoute classifies routing using routeTarget (e.g. sniffed TLS SNI)
// while opening the connection to dialTarget without local DNS leakage on known overseas hosts.
func (e *Engine) OpenTargetStreamWithRoute(dialTarget, routeTarget string, first []byte) (gft.DataStream, RouteAction, error) {
	if recovered, rerr := e.RecoverFakeIPTarget(dialTarget); rerr != nil {
		return nil, ActionReject, rerr
	} else if recovered != dialTarget {
		if routeTarget == "" || routeTarget == dialTarget {
			routeTarget = recovered
		}
		dialTarget = recovered
	}
	if routeTarget != "" {
		if recoveredRoute, rerr := e.RecoverFakeIPTarget(routeTarget); rerr == nil {
			routeTarget = recoveredRoute
		}
	}

	if e.IsNodeHost(dialTarget) || (routeTarget != "" && e.IsNodeHost(routeTarget)) {
		e.logAntiLoopThrottled("TCP", dialTarget)
		return nil, ActionReject, errNodeLoopRejected
	}

	metricTarget := strings.TrimSpace(routeTarget)
	if metricTarget == "" {
		metricTarget = dialTarget
	}

	e.mu.RLock()
	state := e.state
	sched := e.sched
	mode := e.config.RouteMode
	e.mu.RUnlock()

	if state != StateConnected || sched == nil {
		if mode == RouteRule {
			effTarget := routeTarget
			if effTarget == "" {
				effTarget = dialTarget
			}
			act, reason, unknown := e.router.evaluateStatic(mode, effTarget)
			if !unknown {
				act, reason = e.router.RecordDecision(act, reason)
				if e.recentRoutes != nil {
					e.recentRoutes.Push(dialTarget, effTarget, act, reason)
				}
				if act == ActionReject {
					return nil, ActionReject, errRouteRejected
				}
				if act == ActionDirect {
					return e.dialDirectTrackedStream(dialTarget, metricTarget, first)
				}
			}
		}
		return nil, ActionProxy, errNoActiveSession
	}
	act, resolvedDial, reason := e.DecideSmartRoute(dialTarget, routeTarget)
	if act == ActionReject {
		if reason == "anti-loop:node-host" {
			e.logAntiLoopThrottled("TCP", dialTarget)
			return nil, ActionReject, errNodeLoopRejected
		}
		return nil, ActionReject, errRouteRejected
	}
	if act == ActionDirect {
		return e.dialDirectTrackedStream(resolvedDial, metricTarget, first)
	}
	proxyDial := selectProxyDialTarget(dialTarget, routeTarget)
	st, err := sched.OpenStream(proxyDial, first)
	if err != nil {
		return nil, ActionProxy, err
	}
	if len(first) > 0 {
		e.RecordTargetTraffic(metricTarget, uint64(len(first)), 0)
	}
	return &trackedDataStream{
		DataStream: st,
		eng:        e,
		target:     metricTarget,
	}, ActionProxy, nil
}

// selectProxyDialTarget prefers a sniffed domain in routeTarget over a raw IP dialTarget
// when opening an ActionProxy tunnel stream, so stale or GFW-poisoned client IPs never fail remotely.
func selectProxyDialTarget(dialTarget, routeTarget string) string {
	dHost, _, dErr := net.SplitHostPort(dialTarget)
	rHost, _, rErr := net.SplitHostPort(routeTarget)
	if dErr == nil && rErr == nil && net.ParseIP(strings.Trim(dHost, "[]")) != nil {
		cleanR := strings.TrimSpace(rHost)
		if cleanR != "" && net.ParseIP(strings.Trim(cleanR, "[]")) == nil && !strings.ContainsAny(cleanR, " /\\") {
			return routeTarget
		}
	}
	return dialTarget
}

// OpenStreamWithOptionalSNISniff performs 30ms TLS SNI sniffing when target is a raw public IP
// under Rule mode, calling sendAck prior to reading the ClientHello when sniffing applies.
func (e *Engine) OpenStreamWithOptionalSNISniff(c net.Conn, target string, sendAck func() error) (st gft.DataStream, act RouteAction, rc net.Conn, ackSent bool, err error) {
	rc = c
	if e.IsNodeHost(target) {
		e.logAntiLoopThrottled("TCP", target)
		return nil, ActionReject, rc, false, errNodeLoopRejected
	}
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
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resolvedIPs, err := netbind.DirectLookupHostIPs(ctx, clean)
		cancel()
		if err != nil && !e.directDNSBypass.Load() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
			addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx2, clean)
			cancel2()
			if lerr == nil {
				for _, a := range addrs {
					resolvedIPs = append(resolvedIPs, a.IP)
				}
				err = nil
			}
		}
		if err == nil {
			for _, rip := range resolvedIPs {
				if netbind.IsFakeIP(rip) {
					continue
				}
				if ip4 := rip.To4(); ip4 != nil {
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

// NodeHostIPv6s returns unique IPv6 literal addresses for all configured VPS nodes
// (used for host/gateway firewall bypass when IPv6 dual-stack TPROXY is active).
func (e *Engine) NodeHostIPv6s() []string {
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
			if ip.To4() == nil {
				s := ip.String()
				if _, ok := seen[s]; !ok {
					seen[s] = struct{}{}
					ips = append(ips, s)
				}
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resolvedIPs, err := netbind.DirectLookupHostIPs(ctx, clean)
		cancel()
		if err != nil && !e.directDNSBypass.Load() {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
			addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx2, clean)
			cancel2()
			if lerr == nil {
				for _, a := range addrs {
					resolvedIPs = append(resolvedIPs, a.IP)
				}
				err = nil
			}
		}
		if err == nil {
			for _, rip := range resolvedIPs {
				if netbind.IsFakeIP(rip) {
					continue
				}
				if rip.To4() == nil && rip.To16() != nil {
					s := rip.String()
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
	pInit := e.paramStore.Get()
	pInit.SNIRTTMs = 0
	e.paramStore.Set(pInit)
	sched := gft.NewApexScheduler(l, e.paramStore, gft.EffectivePoolSize(), e.Logf)
	e.connectingSched = sched
	e.mu.Unlock()

	e.Logf("Connecting to %s:%d (transport=%s, route=%s, Apex Dual-Track)...",
		l.Host, l.Port, l.EffectiveTransport(), e.config.RouteMode)
	e.mu.RLock()
	nodeGen := e.nodeHostsGen.Load()
	e.mu.RUnlock()
	go e.refreshRouterNodeIPsAsync(nodeGen)

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
	e.activeSchedLink = l
	e.state = StateConnected
	e.lastErr = ""
	e.pingMs = st.RTTMs
	e.prevUp = 0
	e.prevDown = 0
	mode := e.config.RouteMode
	httpAddr := e.config.HTTPAddr
	socksAddr := e.config.SocksAddr
	e.config.SysProxy = mode != RouteCore
	needSaveAuto := !e.config.AutoConnect
	e.config.AutoConnect = true
	e.mu.Unlock()

	if needSaveAuto {
		_ = e.SaveConfig()
	}

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
	e.disconnectWithWait(0)
}

func (e *Engine) disconnectWithWait(maxSchedWait time.Duration) {
	e.mu.Lock()
	if e.state != StateConnected && e.state != StateConnecting {
		e.mu.Unlock()
		return
	}
	e.state = StateDisconnected
	e.connectGen++
	e.switchingNode = -1
	e.switchingName = ""
	e.prevUp = 0
	e.prevDown = 0
	e.curUpBps = 0
	e.curDownBps = 0
	connSched := e.connectingSched
	e.connectingSched = nil
	sched := e.sched
	e.sched = nil
	e.activeSchedLink = nil
	wasApplied := e.sysProxyApplied
	e.sysProxyApplied = false
	e.mu.Unlock()

	if wasApplied {
		_ = DisableAndRestoreSystemProxy(e.proxyBackupPath)
		e.Logf("System proxy restored cleanly")
	}
	closeScheds := func() {
		if connSched != nil {
			connSched.Close()
		}
		if sched != nil {
			sched.Close()
		}
	}
	if maxSchedWait > 0 && (connSched != nil || sched != nil) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			closeScheds()
		}()
		select {
		case <-done:
		case <-time.After(maxSchedWait):
		}
	} else {
		closeScheds()
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
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ms, mode, perr := sched.ProbeNow(ctx)
		cancel()
		if perr == nil && ms > 0 {
			e.mu.Lock()
			e.pingMs = ms
			e.mu.Unlock()
			e.Logf("Live RTT [%s]: %dms", mode, ms)
			return PingSummary{RTTMs: ms, Transport: mode}, nil
		}
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

// NodePingResult reports the latency probe result for a specific saved node index.
type NodePingResult struct {
	Index     int    `json:"index"`
	RTTMs     int64  `json:"rtt_ms"`
	Transport string `json:"transport,omitempty"`
	Error     string `json:"error,omitempty"`
}

// PingNode probes the saved node at idx without switching the active node or dropping the current session.
func (e *Engine) PingNode(ctx context.Context, idx int) NodePingResult {
	res := NodePingResult{Index: idx, RTTMs: -1}
	e.mu.RLock()
	var l *gft.Link
	if idx >= 0 && idx < len(e.config.Nodes) && e.config.Nodes[idx] != nil {
		cp := *e.config.Nodes[idx]
		l = &cp
	}
	activeIdx := e.config.ActiveNode
	sched := e.sched
	e.mu.RUnlock()

	if l == nil {
		res.Error = "node index out of range"
		return res
	}
	if idx == activeIdx && sched != nil {
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ms, mode, perr := sched.ProbeNow(pctx)
		cancel()
		if perr == nil && ms > 0 {
			res.RTTMs = ms
			res.Transport = mode
			return res
		}
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	pr, err := gft.Ping(pctx, l, 5*time.Second)
	cancel()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	ms := pr.KnockRTT.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	res.RTTMs = ms
	res.Transport = "uTLS-" + l.EffectiveFP()
	return res
}

// PingAllNodes probes all configured nodes concurrently (up to 6 parallel workers).
func (e *Engine) PingAllNodes(ctx context.Context) []NodePingResult {
	e.mu.RLock()
	n := len(e.config.Nodes)
	e.mu.RUnlock()
	if n == 0 {
		return nil
	}
	results := make([]NodePingResult, n)
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = NodePingResult{Index: idx, RTTMs: -1, Error: ctx.Err().Error()}
				return
			}
			results[idx] = e.PingNode(ctx, idx)
		}(i)
	}
	wg.Wait()
	return results
}

// SetTransport updates the active node's preferred transport ("rtc" for UDP-first, "tcp" for TCP-first).
// Legacy "", "auto", "quic", "udp", "udp_first" normalize to "rtc"; "tcp_first" normalizes to "tcp".
func (e *Engine) SetTransport(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto", "quic", "rtc", "udp", "udp_first":
		mode = "rtc"
	case "tcp", "tcp_first":
		mode = "tcp"
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
	SNI       string `json:"sni,omitempty"`
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

// TrayStatus returns a lightweight status snapshot for periodic tray icon/tooltip updates
// without serializing Clash YAML, node lists, or recent route logs.
func (e *Engine) TrayStatus() map[string]any {
	e.mu.RLock()
	state := e.state
	sched := e.sched
	pingMs := e.pingMs
	l := e.activeLinkLocked()
	e.mu.RUnlock()

	activeMode := ""
	if sched != nil {
		st := sched.Stats()
		activeMode = st.Mode
		if st.RTTMs > 0 {
			pingMs = st.RTTMs
		}
	}

	var nodeName, tPref string
	if l != nil {
		nodeName = l.Remark
		if nodeName == "" {
			nodeName = fmt.Sprintf("%s:%d", l.Host, l.Port)
		}
		tPref = l.EffectiveTransport()
	}
	if tPref == "" {
		tPref = "rtc"
	}

	return map[string]any{
		"state":            string(state),
		"active_transport": activeMode,
		"transport_pref":   tPref,
		"ping_ms":          pingMs,
		"node_name":        nodeName,
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
	switchingNode := e.switchingNode
	switchingName := e.switchingName
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
			SNI:       n.SNI,
			Verify:    n.EffectiveVerify(),
			Transport: n.EffectiveTransport(),
			HopRange:  n.HopRange,
		})
	}
	l := e.activeLinkLocked()
	paramStore := e.paramStore
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

	var nodeName, nodeHost, nodeSNI, tPref, verifyMode, hopRange string
	var nodePort, upMbps, downMbps int
	var sniRTTMs int64
	if l != nil {
		nodeName = l.Remark
		if nodeName == "" {
			nodeName = fmt.Sprintf("%s:%d", l.Host, l.Port)
		}
		nodeHost = l.Host
		nodePort = l.Port
		nodeSNI = l.SNI
		tPref = l.EffectiveTransport()
		verifyMode = l.EffectiveVerify()
		hopRange = l.HopRange
		upMbps = l.UpMbps
		downMbps = l.DownMbps
	}
	if state == StateConnected && paramStore != nil {
		sniRTTMs = paramStore.Get().SNIRTTMs
	}
	if tPref == "" {
		tPref = "rtc"
	}

	return map[string]any{
		"version":          Version,
		"state":            string(state),
		"last_err":         lastErr,
		"switching_node":   switchingNode,
		"switching_name":   switchingName,
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
		"enable_ipv6":      e.IPv6Enabled(),
		"close_to_tray":    e.CloseToTray(),
		"proxy_drifted":    e.proxyDrifted.Load(),
		"socks_addr":       socksAddr,
		"http_addr":        httpAddr,
		"node_name":        nodeName,
		"node_host":        nodeHost,
		"node_port":        nodePort,
		"sni":              nodeSNI,
		"sni_rtt_ms":       sniRTTMs,
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

// LinkURI returns the active node's ksl4:// / gft3:// link.
func (e *Engine) LinkURI() string {
	e.mu.RLock()
	l := e.activeLinkLocked()
	e.mu.RUnlock()
	if l == nil {
		return ""
	}
	return l.Encode()
}

// LinkURIForNode returns the shareable URI for node idx (falling back to LinkURI if idx < 0).
func (e *Engine) LinkURIForNode(idx int) string {
	if idx < 0 {
		return e.LinkURI()
	}
	e.mu.RLock()
	var l *gft.Link
	if idx < len(e.config.Nodes) && e.config.Nodes[idx] != nil {
		cp := *e.config.Nodes[idx]
		l = &cp
	}
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
	e.disconnectWithWait(1200 * time.Millisecond)
	_, _ = RecoverSystemProxyIfDirty(e.proxyBackupPath)
}
