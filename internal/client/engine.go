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
	"sync"
	"time"

	"ghostframe/internal/gft"
)

type ConnState string

const (
	StateDisconnected ConnState = "disconnected"
	StateConnecting   ConnState = "connecting"
	StateConnected    ConnState = "connected"
	StateError        ConnState = "error"
)

// ClientConfig holds saved client preferences, nodes, and routing mode.
type ClientConfig struct {
	Link       *gft.Link   `json:"link,omitempty"`
	Nodes      []*gft.Link `json:"nodes,omitempty"`
	ActiveNode int         `json:"active_node,omitempty"`
	RouteMode  RouteMode   `json:"route_mode,omitempty"` // "rule" (default), "global", "direct"
	SocksAddr  string      `json:"socks_addr"`
	HTTPAddr   string      `json:"http_addr"`
	SysProxy   bool        `json:"sys_proxy"`
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
	mu               sync.RWMutex
	portSwapMu       sync.Mutex
	cfgPath          string
	proxyBackupPath  string
	config           ClientConfig
	state            ConnState
	lastErr          string
	sched            *gft.ApexScheduler
	connectingSched  *gft.ApexScheduler
	connectGen       uint64
	paramStore       *gft.ParamStore
	router           *Router
	socksSrv         *SOCKS5Server
	httpSrv          *HTTPProxyServer
	sysProxyApplied  bool

	// Stats
	prevUp     uint64
	prevDown   uint64
	curUpBps   uint64
	curDownBps uint64
	pingMs     int64
	history    []TrafficPoint

	// Rolling log
	logMu sync.Mutex
	logs  []LogEntry

	stopStats chan struct{}
	stopOnce  sync.Once
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
	if cfgPath != "" {
		backupPath = filepath.Join(filepath.Dir(cfgPath), "sysproxy_backup.json")
	}

	e := &Engine{
		cfgPath:         cfgPath,
		proxyBackupPath: backupPath,
		state:           StateDisconnected,
		paramStore:      gft.NewParamStore(gft.DefaultParams()),
		router:          NewRouter(),
		history:         make([]TrafficPoint, 0, 60),
		logs:            make([]LogEntry, 0, 200),
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

	if recovered, rerr := RecoverSystemProxyIfDirty(e.proxyBackupPath); recovered {
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

	go e.statsLoop()
	return nil
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

	if newSocksAddr != oldSocksAddr || e.socksSrv == nil {
		newSocksSrv = NewSOCKS5Server(newSocksAddr, e)
		if err := newSocksSrv.Start(); err != nil {
			return fmt.Errorf("SOCKS5 端口 %d 已被占用或无法监听: %w", socksPort, err)
		}
	}
	if newHTTPAddr != oldHTTPAddr || e.httpSrv == nil {
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

// SelectNode switches active node (disconnecting any running session first).
func (e *Engine) SelectNode(idx int) error {
	e.Disconnect()
	e.mu.Lock()
	if idx < 0 || idx >= len(e.config.Nodes) {
		e.mu.Unlock()
		return errors.New("node index out of range")
	}
	e.config.ActiveNode = idx
	e.config.Link = e.config.Nodes[idx]
	if e.config.Link != nil && e.config.Link.Params != nil {
		e.paramStore.Set(*e.config.Link.Params)
	}
	name := ""
	if e.config.Link != nil {
		name = e.config.Link.Remark
	}
	e.mu.Unlock()
	e.Logf("Switched active node to #%d (%s)", idx+1, name)
	return e.SaveConfig()
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

// RouteDecision decides whether hostport should bypass or traverse GhostFrame.
func (e *Engine) RouteDecision(hostport string) RouteAction {
	e.mu.RLock()
	mode := e.config.RouteMode
	e.mu.RUnlock()
	return e.router.Decide(mode, hostport)
}

// OpenTargetStream opens either a direct TCP connection or a multiplexed GFT stream
// per Router policy (never leaking overseas DNS queries locally).
func (e *Engine) OpenTargetStream(target string, first []byte) (gft.DataStream, RouteAction, error) {
	e.mu.RLock()
	state := e.state
	sched := e.sched
	mode := e.config.RouteMode
	e.mu.RUnlock()

	if state != StateConnected || sched == nil {
		return nil, ActionProxy, errNoActiveSession
	}
	act := e.router.Decide(mode, target)
	if act == ActionDirect {
		c, err := net.DialTimeout("tcp", target, 8*time.Second)
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
		return &directStreamConn{Conn: c, target: target}, ActionDirect, nil
	}
	st, err := sched.OpenStream(target, first)
	return st, ActionProxy, err
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
	for {
		select {
		case <-e.stopStats:
			return
		case <-t.C:
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
			e.Logf("System proxy enabled (%s)", httpAddr)
		} else {
			_ = DisableAndRestoreSystemProxy(e.proxyBackupPath)
			e.Logf("System proxy restored cleanly")
		}
	}
	return nil
}

// Logf records a log entry.
func (e *Engine) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Message: msg,
	}
	e.logMu.Lock()
	if len(e.logs) >= 200 {
		e.logs = append(e.logs[1:], entry)
	} else {
		e.logs = append(e.logs, entry)
	}
	e.logMu.Unlock()
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

// SetTransport updates the active node's preferred transport ("auto", "tcp", "quic").
func (e *Engine) SetTransport(mode string) error {
	switch mode {
	case "", "auto", "tcp", "quic":
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
	e.logMu.Lock()
	e.logs = e.logs[:0]
	e.logMu.Unlock()
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

	var totalUp, totalDown uint64
	activeMode := ""
	var quicPort, activeConns, activeStreams int
	if sched != nil {
		st := sched.Stats()
		totalUp = st.TotalUp
		totalDown = st.TotalDown
		activeMode = st.Mode
		quicPort = st.QUICPort
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
	var nodePort int
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
	}
	if tPref == "" {
		tPref = "auto"
	}

	return map[string]any{
		"state":            string(state),
		"last_err":         lastErr,
		"active_transport": activeMode,
		"transport_pref":   tPref,
		"route_mode":       string(routeMode),
		"verify_mode":      verifyMode,
		"hop_range":        hopRange,
		"quic_port":        quicPort,
		"active_conns":     activeConns,
		"active_streams":   activeStreams,
		"ping_ms":          pingMs,
		"up_bps":           upBps,
		"down_bps":         downBps,
		"total_up":         totalUp,
		"total_down":       totalDown,
		"history":          histCopy,
		"sys_proxy":        sysProxy,
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
	e.logMu.Lock()
	defer e.logMu.Unlock()
	cp := make([]LogEntry, len(e.logs))
	copy(cp, e.logs)
	return cp
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
		name = "GhostFrame-Apex"
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
