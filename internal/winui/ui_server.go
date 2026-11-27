//go:build windows

package winui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/qr"
	"ghostframe/internal/wininstall"
)

//go:embed ui_assets/index.html
var indexHTMLTemplate string

type toastState struct {
	Text    string `json:"text"`
	Err     bool   `json:"err"`
	Success bool   `json:"success"`
	Seq     uint64 `json:"seq"`
}

type updateUIState struct {
	Status     string                    `json:"status"` // "idle", "checking", "up_to_date", "available", "downloading", "applying", "error"
	Latest     *client.ClientReleaseInfo `json:"latest,omitempty"`
	Downloaded int64                     `json:"downloaded"`
	Total      int64                     `json:"total"`
	Pct        int                       `json:"pct"`
	Error      string                    `json:"error,omitempty"`
	CheckedAt  string                    `json:"checked_at,omitempty"`
}

// uiServer serves the Porcelain & Slate Light WebView2 UI over a strictly authenticated
// 127.0.0.1 loopback listener and dispatches all mutating Engine calls off the Win32 UI thread.
type uiServer struct {
	eng         *client.Engine
	hwnd        uintptr
	token       string
	listener    net.Listener
	srv         *http.Server
	addr        string
	onTraySync  func()
	onQuitMu    sync.Mutex
	onQuitFn    func()
	switchSeq   atomic.Uint64
	rulesUpdate atomic.Bool

	updAvail atomic.Bool
	updTag   atomic.Value
	updMu    sync.Mutex
	updState updateUIState

	toastMu    sync.Mutex
	toast      toastState
	toastUntil time.Time
	toastSeq   atomic.Uint64
}

func generateSessionToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func startUIServer(eng *client.Engine, hwnd uintptr, onTraySync func()) (*uiServer, error) {
	tok, err := generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("generate UI session token: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen UI loopback: %w", err)
	}
	s := &uiServer{
		eng:        eng,
		hwnd:       hwnd,
		token:      tok,
		listener:   ln,
		addr:       ln.Addr().String(),
		onTraySync: onTraySync,
		updState:   updateUIState{Status: "idle"},
	}
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = s.srv.Serve(ln)
	}()
	if !client.IsMockSysProxy() {
		go func() {
			time.Sleep(8 * time.Second)
			s.runUpdateCheck(true)
		}()
	}
	return s, nil
}

func (s *uiServer) SetQuitFn(fn func()) {
	s.onQuitMu.Lock()
	s.onQuitFn = fn
	s.onQuitMu.Unlock()
}

func (s *uiServer) triggerQuit() {
	s.onQuitMu.Lock()
	fn := s.onQuitFn
	s.onQuitMu.Unlock()
	if fn != nil {
		fn()
	}
}

func (s *uiServer) URL() string {
	return fmt.Sprintf("http://%s/?token=%s", s.addr, s.token)
}

func (s *uiServer) Token() string {
	return s.token
}

func (s *uiServer) SetHWND(hwnd uintptr) {
	s.hwnd = hwnd
}

func (s *uiServer) Close() {
	if s == nil {
		return
	}
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
		_ = s.srv.Shutdown(ctx)
		cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *uiServer) setToast(msg string, isErr bool) {
	seq := s.toastSeq.Add(1)
	s.toastMu.Lock()
	s.toast = toastState{
		Text:    msg,
		Err:     isErr,
		Success: !isErr && strings.Contains(msg, "已"),
		Seq:     seq,
	}
	s.toastUntil = time.Now().Add(3 * time.Second)
	s.toastMu.Unlock()
}

func (s *uiServer) setToastSuccess(msg string) {
	seq := s.toastSeq.Add(1)
	s.toastMu.Lock()
	s.toast = toastState{
		Text:    msg,
		Err:     false,
		Success: true,
		Seq:     seq,
	}
	s.toastUntil = time.Now().Add(3 * time.Second)
	s.toastMu.Unlock()
}

func (s *uiServer) currentToast() *toastState {
	now := time.Now()
	s.toastMu.Lock()
	defer s.toastMu.Unlock()
	if s.toast.Text == "" || now.After(s.toastUntil) {
		return nil
	}
	cp := s.toast
	return &cp
}

func (s *uiServer) notifyTray() {
	if s.onTraySync != nil {
		s.onTraySync()
	}
}

func (s *uiServer) tokenValid(candidate string) bool {
	if len(candidate) != len(s.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.token)) == 1
}

func (s *uiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tok := r.URL.Query().Get("token")
		if !s.tokenValid(tok) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		html := strings.Replace(indexHTMLTemplate, "__KESTREL_TOKEN__", s.token, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
		return
	}

	if !s.tokenValid(r.Header.Get("X-Kestrel-Token")) {
		writeJSONError(w, http.StatusForbidden, "forbidden: invalid session token")
		return
	}

	switch r.URL.Path {
	case "/api/status":
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleStatus(w, r)
	case "/api/connect":
		s.requirePost(w, r, s.handleConnect)
	case "/api/disconnect":
		s.requirePost(w, r, s.handleDisconnect)
	case "/api/ping":
		s.requirePost(w, r, s.handlePing)
	case "/api/nodes/ping":
		s.requirePost(w, r, s.handleNodePing)
	case "/api/nodes/ping-all":
		s.requirePost(w, r, s.handleNodesPingAll)
	case "/api/nodes/select":
		s.requirePost(w, r, s.handleNodeSelect)
	case "/api/nodes/rename":
		s.requirePost(w, r, s.handleNodeRename)
	case "/api/nodes/delete":
		s.requirePost(w, r, s.handleNodeDelete)
	case "/api/nodes/import":
		s.requirePost(w, r, s.handleNodesImport)
	case "/api/nodes/qr":
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleNodeQR(w, r)
	case "/api/mode/route":
		s.requirePost(w, r, s.handleSetRouteMode)
	case "/api/mode/transport":
		s.requirePost(w, r, s.handleSetTransport)
	case "/api/mode/ipv6":
		s.requirePost(w, r, s.handleSetIPv6)
	case "/api/proxy/rebind":
		s.requirePost(w, r, s.handleRebindProxy)
	case "/api/proxy/toggle":
		s.requirePost(w, r, s.handleToggleSysProxy)
	case "/api/settings/ports":
		s.requirePost(w, r, s.handleSetPorts)
	case "/api/settings/params":
		s.requirePost(w, r, s.handleSetParams)
	case "/api/settings/close-behavior":
		s.requirePost(w, r, s.handleSetCloseBehavior)
	case "/api/rules/append":
		s.requirePost(w, r, s.handleAppendRule)
	case "/api/rules/set":
		s.requirePost(w, r, s.handleSetRules)
	case "/api/rules/update":
		s.requirePost(w, r, s.handleUpdateRules)
	case "/api/logs/clear":
		s.requirePost(w, r, s.handleClearLogs)
	case "/api/diagnostic":
		s.requirePost(w, r, s.handleDiagnostic)
	case "/api/clipboard":
		s.handleClipboard(w, r)
	case "/api/app/info":
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleAppInfo(w, r)
	case "/api/app/install-system":
		s.requirePost(w, r, s.handleInstallSystem)
	case "/api/settings/autostart":
		s.requirePost(w, r, s.handleSetAutostart)
	case "/api/update/check":
		s.requirePost(w, r, s.handleUpdateCheck)
	case "/api/update/apply":
		s.requirePost(w, r, s.handleUpdateApply)
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

func (s *uiServer) requirePost(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	fn(w, r)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{
		"ok":    false,
		"error": msg,
	})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(dst)
}

func (s *uiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	st := s.eng.StatusForTab(tab)
	if tab == "routes" {
		st["top_uploads"] = s.eng.TopUploadTargets(20)
		st["logs"] = s.eng.Logs()
	}
	st["rules_updating"] = s.rulesUpdate.Load()
	st["update_available"] = s.updAvail.Load()
	if tag, _ := s.updTag.Load().(string); tag != "" {
		st["latest_version"] = tag
	}
	if tab == "settings" {
		st["app_install"] = wininstall.QueryStatus("")
		st["update_state"] = s.snapshotUpdateState()
	}
	if t := s.currentToast(); t != nil {
		st["toast"] = t
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *uiServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	seq := s.switchSeq.Add(1)
	go func() {
		if err := s.eng.Connect(); err != nil {
			if s.switchSeq.Load() != seq {
				return
			}
			s.setToast("连接失败: "+err.Error(), true)
		} else {
			if s.switchSeq.Load() != seq {
				return
			}
			s.setToastSuccess("安全隧道已建立")
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	s.switchSeq.Add(1)
	go func() {
		_ = s.eng.SetAutoConnect(false)
		s.eng.Disconnect()
		s.setToast("已断开安全隧道", false)
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handlePing(w http.ResponseWriter, r *http.Request) {
	pr, err := s.eng.PingNow()
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.setToastSuccess(fmt.Sprintf("测速成功: %dms (%s)", pr.RTTMs, pr.Transport))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"rtt_ms":    pr.RTTMs,
		"transport": pr.Transport,
	})
}

func (s *uiServer) handleNodePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Index int `json:"index"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	res := s.eng.PingNode(r.Context(), req.Index)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"result": res,
	})
}

func (s *uiServer) handleNodesPingAll(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	results := s.eng.PingAllNodes(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"results": results,
	})
}

func (s *uiServer) switchNodeAsync(idx int, importedCount int) {
	seq := s.switchSeq.Add(1)
	go func() {
		st := s.eng.Status()
		curState := client.ConnState(strVal(st["state"]))
		wasLive := curState == client.StateConnected || curState == client.StateConnecting
		if wasLive && importedCount == 0 {
			s.setToast("正在无损切换节点...", false)
		}
		if err := s.eng.SelectNode(idx); err != nil {
			if errors.Is(err, client.ErrSwitchCancelled) || s.switchSeq.Load() != seq {
				return
			}
			s.setToast("切换节点失败: "+err.Error(), true)
		} else {
			if s.switchSeq.Load() != seq {
				return
			}
			if importedCount > 0 {
				s.setToastSuccess(fmt.Sprintf("已导入 %d 个节点并热切换生效", importedCount))
			} else if wasLive && s.eng.IsConnected() {
				s.setToastSuccess("已无损切换节点（连接不断开）")
			} else {
				s.setToastSuccess("已切换并保存节点")
			}
		}
		s.notifyTray()
	}()
}

func (s *uiServer) handleNodeSelect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Index int `json:"index"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	s.switchNodeAsync(req.Index, 0)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleNodeRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Index  int    `json:"index"`
		Remark string `json:"remark"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.eng.RenameNode(req.Index, strings.TrimSpace(req.Remark)); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setToastSuccess("节点备注已更新")
	s.notifyTray()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *uiServer) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Index int `json:"index"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	go func() {
		if err := s.eng.DeleteNode(req.Index); err != nil {
			s.setToast("删除节点失败: "+err.Error(), true)
		} else {
			s.setToast("已删除节点", false)
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleNodesImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	raw := strings.TrimSpace(req.Text)
	if raw == "" {
		writeJSONError(w, http.StatusBadRequest, "请输入 ksl4:// 或 gft3:// 节点链接")
		return
	}
	lines := strings.Split(raw, "\n")
	imported := 0
	firstIdx := -1
	var lastErr error
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || (!strings.HasPrefix(ln, "ksl4://") && !strings.HasPrefix(ln, "gft3://") && !strings.HasPrefix(ln, "gft2://") && !strings.HasPrefix(ln, "gft://")) {
			continue
		}
		idx, err := s.eng.ImportLink(ln, imported == 0)
		if err != nil {
			lastErr = err
			continue
		}
		if imported == 0 {
			firstIdx = idx
		}
		imported++
	}
	if imported == 0 {
		idx, err := s.eng.ImportLink(raw, true)
		if err != nil {
			if lastErr != nil {
				err = lastErr
			}
			writeJSONError(w, http.StatusBadRequest, "导入失败: "+err.Error())
			return
		}
		firstIdx = idx
		imported = 1
	}

	st := s.eng.Status()
	curState := client.ConnState(strVal(st["state"]))
	if firstIdx >= 0 && (curState == client.StateConnected || curState == client.StateConnecting) {
		s.setToast(fmt.Sprintf("已导入 %d 个节点，正在无损切换...", imported), false)
		s.switchNodeAsync(firstIdx, imported)
	} else {
		s.setToastSuccess(fmt.Sprintf("已成功导入 %d 个节点并激活", imported))
		s.notifyTray()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"imported":    imported,
		"first_index": firstIdx,
	})
}

func (s *uiServer) handleNodeQR(w http.ResponseWriter, r *http.Request) {
	idx := -1
	if q := r.URL.Query().Get("index"); q != "" {
		if parsed, err := strconv.Atoi(q); err == nil {
			idx = parsed
		}
	}
	uri := s.eng.LinkURIForNode(idx)
	if uri == "" {
		writeJSONError(w, http.StatusNotFound, "当前没有可生成二维码的节点")
		return
	}
	svg, err := qr.RenderSVG(uri)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成二维码失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":  true,
		"uri": uri,
		"svg": svg,
	})
}

func (s *uiServer) handleSetRouteMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	var targetMode client.RouteMode
	var label string
	switch strings.ToLower(strings.TrimSpace(req.Mode)) {
	case string(client.RouteRule):
		targetMode = client.RouteRule
		label = "Rule (智能分流)"
	case string(client.RouteGlobal):
		targetMode = client.RouteGlobal
		label = "Global (全局代理)"
	case string(client.RouteCore):
		targetMode = client.RouteCore
		label = "Core (仅开放本地端口)"
	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported route mode")
		return
	}
	go func() {
		if err := s.eng.SetRouteMode(targetMode); err != nil {
			s.setToast("切换运行模式失败: "+err.Error(), true)
		} else {
			s.setToastSuccess("运行模式已切换: " + label)
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleSetTransport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transport string `json:"transport"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	t := strings.ToLower(strings.TrimSpace(req.Transport))
	var label string
	switch t {
	case "", "auto", "quic", "rtc", "udp", "udp_first":
		t = "rtc"
		label = "UDP 优先"
	case "tcp", "tcp_first":
		t = "tcp"
		label = "TCP 优先"
	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported transport mode")
		return
	}
	go func() {
		if err := s.eng.SetTransport(t); err != nil {
			s.setToast("切换传输内核失败: "+err.Error(), true)
		} else {
			s.setToastSuccess("传输内核已切换: " + label)
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleSetIPv6(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	go func() {
		if err := s.eng.SetEnableIPv6(req.Enabled); err != nil {
			s.setToast("切换 IPv6 失败: "+err.Error(), true)
		} else if req.Enabled {
			s.setToastSuccess("已开启 IPv6 双栈分流")
		} else {
			s.setToast("已关闭 IPv6 (防泄露纯 IPv4 模式)", false)
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleRebindProxy(w http.ResponseWriter, r *http.Request) {
	go func() {
		if err := s.eng.RebindSystemProxy(); err != nil {
			s.setToast("重绑系统代理失败: "+err.Error(), true)
		} else {
			s.setToastSuccess("已重新接管 Windows 系统代理")
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleToggleSysProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	go func() {
		if err := s.eng.SetSysProxyToggle(req.Enabled); err != nil {
			s.setToast("系统代理切换失败: "+err.Error(), true)
		} else if req.Enabled {
			s.setToastSuccess("已启用 Windows 系统代理接管")
		} else {
			s.setToast("已恢复系统代理直连状态", false)
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleSetPorts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SocksPort int `json:"socks_port"`
		HTTPPort  int `json:"http_port"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.SocksPort < 1024 || req.SocksPort > 65535 {
		writeJSONError(w, http.StatusBadRequest, "SOCKS5 端口需在 1024-65535 之间")
		return
	}
	if req.HTTPPort < 1024 || req.HTTPPort > 65535 {
		writeJSONError(w, http.StatusBadRequest, "HTTP 端口需在 1024-65535 之间")
		return
	}
	if req.SocksPort == req.HTTPPort {
		writeJSONError(w, http.StatusBadRequest, "SOCKS5 与 HTTP 端口不能相同")
		return
	}
	go func() {
		if err := s.eng.SetProxyPorts(req.SocksPort, req.HTTPPort); err != nil {
			s.setToast("端口切换失败: "+err.Error(), true)
		} else {
			s.setToastSuccess(fmt.Sprintf("本地端口已热切换: SOCKS5 :%d / HTTP :%d", req.SocksPort, req.HTTPPort))
		}
		s.notifyTray()
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleSetParams(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UpMbps   int    `json:"up_mbps"`
		DownMbps int    `json:"down_mbps"`
		HopRange string `json:"hop_range"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.UpMbps < 0 || req.UpMbps > 65535 || req.DownMbps < 0 || req.DownMbps > 65535 {
		writeJSONError(w, http.StatusBadRequest, "带宽限速范围需在 0-65535 Mbps (0=自动)")
		return
	}
	if err := s.eng.SetBandwidthLimits(req.UpMbps, req.DownMbps); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	curHop := strVal(s.eng.Status()["hop_range"])
	nextHop := strings.TrimSpace(req.HopRange)
	if nextHop != curHop {
		go func() {
			if err := s.eng.SetHopRange(nextHop); err != nil {
				s.setToast("端口跃迁范围更新失败: "+err.Error(), true)
			} else {
				s.setToastSuccess("已更新 Smart-Brutal 与端口跃迁参数")
			}
			s.notifyTray()
		}()
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
		return
	}
	s.setToastSuccess("传输限速参数已保存并应用")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *uiServer) handleSetCloseBehavior(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CloseToTray bool `json:"close_to_tray"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.eng.SetCloseToTray(req.CloseToTray); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.CloseToTray {
		s.setToastSuccess("关闭行为已设为：缩小到右下角托盘")
	} else {
		s.setToastSuccess("关闭行为已设为：直接全部退出关闭")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"close_to_tray": req.CloseToTray,
	})
}

func (s *uiServer) handleAppendRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule string `json:"rule"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.eng.AppendCustomRule(req.Rule); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setToastSuccess("已添加并置顶自定义规则: " + strings.TrimSpace(req.Rule))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"custom_rules": s.eng.CustomRules(),
	})
}

func (s *uiServer) handleSetRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Lines []string `json:"lines"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.eng.SetCustomRules(req.Lines); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved := s.eng.CustomRules()
	s.setToastSuccess(fmt.Sprintf("已保存并生效 %d 条自定义规则", len(saved)))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"custom_rules": saved,
	})
}

func (s *uiServer) handleUpdateRules(w http.ResponseWriter, r *http.Request) {
	if !s.rulesUpdate.CompareAndSwap(false, true) {
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true, "already_running": true})
		return
	}
	s.setToast("正在拉取最新 10万+ KSLR 规则库...", false)
	go func() {
		defer s.rulesUpdate.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		st, err := s.eng.UpdateRuleBundle(ctx, "")
		cancel()
		if err != nil {
			s.setToast("规则库更新失败: "+err.Error(), true)
		} else {
			s.setToastSuccess(fmt.Sprintf("KSLR 规则库已更新: %d 条域名 (0指针)", st.BuiltinDomains))
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}

func (s *uiServer) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	s.eng.ClearLogs()
	s.setToast("运行日志已清空", false)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *uiServer) handleDiagnostic(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IncludeRawTargets bool `json:"include_raw_targets"`
	}
	if r.Body != nil {
		_ = decodeJSON(r, &req)
	}
	type diagRes struct {
		path   string
		copied bool
		text   string
		err    error
	}
	ch := make(chan diagRes, 1)
	go func(includeRaw bool) {
		outPath, copied, text, err := s.eng.ExportDiagnosticSnapshotWithOptions(s.hwnd, client.DiagnosticOptions{
			IncludeRawTargets: includeRaw,
		})
		ch <- diagRes{path: outPath, copied: copied, text: text, err: err}
	}(req.IncludeRawTargets)
	res := <-ch
	if res.err != nil && res.text == "" {
		writeJSONError(w, http.StatusInternalServerError, res.err.Error())
		return
	}
	msg := "已生成脱敏诊断快照"
	if res.copied {
		msg += "并复制到剪贴板"
	}
	s.setToastSuccess(msg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"path":   res.path,
		"copied": res.copied,
		"text":   res.text,
	})
}

func (s *uiServer) handleClipboard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		txt := GetClipboardText(s.hwnd)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"text": txt,
		})
	case http.MethodPost:
		var req struct {
			Text string `json:"text"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if !SetClipboardText(s.hwnd, req.Text) {
			writeJSONError(w, http.StatusInternalServerError, "写入系统剪贴板失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *uiServer) snapshotUpdateState() updateUIState {
	s.updMu.Lock()
	cp := s.updState
	s.updMu.Unlock()
	return cp
}

func (s *uiServer) runUpdateCheck(silent bool) (*client.ClientReleaseInfo, error) {
	s.updMu.Lock()
	if s.updState.Status == "downloading" || s.updState.Status == "applying" {
		cur := s.updState.Latest
		s.updMu.Unlock()
		return cur, nil
	}
	s.updState.Status = "checking"
	s.updState.Error = ""
	s.updMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	info, err := s.eng.CheckClientUpdate(ctx, client.UpdateCheckOptions{})
	cancel()

	s.updMu.Lock()
	defer s.updMu.Unlock()
	s.updState.CheckedAt = time.Now().Format("15:04:05")
	if err != nil {
		if silent {
			s.updState.Status = "idle"
		} else {
			s.updState.Status = "error"
			s.updState.Error = err.Error()
		}
		return nil, err
	}
	s.updState.Latest = info
	if info.HasUpdate {
		s.updState.Status = "available"
		s.updAvail.Store(true)
		s.updTag.Store(info.TagName)
	} else {
		s.updState.Status = "up_to_date"
		s.updAvail.Store(false)
		s.updTag.Store(info.TagName)
	}
	return info, nil
}

func (s *uiServer) handleAppInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"version":      client.Version,
		"app_install":  wininstall.QueryStatus(""),
		"update_state": s.snapshotUpdateState(),
	})
}

func (s *uiServer) handleSetAutostart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	exe, _ := os.Executable()
	if wininstall.IsInstalledBinary(exe) {
		exe = wininstall.InstalledExePath()
	}
	if err := wininstall.SetAutoStart(exe, req.Enabled); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Enabled {
		s.setToastSuccess("已开启 Windows 开机自动启动（后台托盘运行）")
	} else {
		s.setToast("已关闭开机自动启动", false)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"auto_start": wininstall.IsAutoStartEnabled(),
	})
}

func (s *uiServer) handleInstallSystem(w http.ResponseWriter, r *http.Request) {
	curExe, err := os.Executable()
	if err != nil || curExe == "" {
		writeJSONError(w, http.StatusInternalServerError, "无法获取当前程序路径")
		return
	}
	targetExe := wininstall.InstalledExePath()
	if strings.EqualFold(filepath.Dir(curExe), filepath.Dir(targetExe)) {
		if err := wininstall.RegisterWindowsApp(curExe, client.Version, true, wininstall.IsAutoStartEnabled()); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.setToastSuccess("已刷新系统快捷方式与开始菜单检索注册")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "relaunching": false, "app_install": wininstall.QueryStatus(curExe)})
		return
	}

	f, err := os.Open(curExe)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取当前程序失败: "+err.Error())
		return
	}
	err = wininstall.InstallFromReader(f, targetExe, client.Version, wininstall.InstallOptions{
		CreateDesktop:   true,
		AutoStart:       wininstall.IsAutoStartEnabled(),
		LegacyConfigDir: filepath.Dir(curExe),
	})
	_ = f.Close()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "安装到系统失败: "+err.Error())
		return
	}

	s.setToastSuccess("已安装至系统并注册开始菜单，正在切换启动...")
	_ = wininstall.LaunchAfterExit(targetExe, os.Getpid())
	go func() {
		time.Sleep(350 * time.Millisecond)
		s.triggerQuit()
	}()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"relaunching": true,
		"target_exe":  targetExe,
	})
}

func (s *uiServer) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	info, err := s.runUpdateCheck(false)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	if info.HasUpdate {
		s.setToastSuccess("发现新版本 " + info.TagName)
	} else {
		s.setToast("当前已是最新版本 ("+client.Version+")", false)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"update_state": s.snapshotUpdateState(),
	})
}

func (s *uiServer) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	s.updMu.Lock()
	if s.updState.Status == "downloading" || s.updState.Status == "applying" {
		s.updMu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true, "already_running": true})
		return
	}
	info := s.updState.Latest
	s.updMu.Unlock()

	if info == nil || !info.HasUpdate {
		var err error
		info, err = s.runUpdateCheck(false)
		if err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
		if !info.HasUpdate {
			s.setToast("当前已是最新版本 ("+client.Version+")", false)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "up_to_date": true})
			return
		}
	}

	curExe, err := os.Executable()
	if err != nil || curExe == "" {
		writeJSONError(w, http.StatusInternalServerError, "无法定位当前程序路径")
		return
	}

	s.updMu.Lock()
	s.updState.Status = "downloading"
	s.updState.Downloaded = 0
	s.updState.Total = info.AssetSize
	s.updState.Pct = 0
	s.updState.Error = ""
	s.updMu.Unlock()

	s.setToast("正在从 GitHub 拉取 "+info.TagName+"...", false)
	go func(rel *client.ClientReleaseInfo, exePath string) {
		staged := exePath + ".new"
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		err := s.eng.DownloadAndVerifyClientUpdate(ctx, rel, staged, client.UpdateCheckOptions{}, func(dl, tot int64) {
			pct := 0
			if tot > 0 {
				pct = int((dl * 100) / tot)
				if pct > 100 {
					pct = 100
				}
			}
			s.updMu.Lock()
			s.updState.Downloaded = dl
			s.updState.Total = tot
			s.updState.Pct = pct
			s.updMu.Unlock()
		})
		cancel()

		if err != nil {
			s.updMu.Lock()
			s.updState.Status = "error"
			s.updState.Error = err.Error()
			s.updMu.Unlock()
			s.setToast("更新下载失败: "+err.Error(), true)
			return
		}

		s.updMu.Lock()
		s.updState.Status = "applying"
		s.updState.Pct = 100
		s.updMu.Unlock()

		if err := wininstall.ScheduleSelfReplaceAndRestart(staged, exePath, rel.TagName, os.Getpid(), nil); err != nil {
			s.updMu.Lock()
			s.updState.Status = "error"
			s.updState.Error = "启动升级脚本失败: " + err.Error()
			s.updMu.Unlock()
			s.setToast("应用更新失败: "+err.Error(), true)
			return
		}

		s.setToastSuccess("已校验 " + rel.TagName + "，正在自动重启更新...")
		time.Sleep(400 * time.Millisecond)
		s.triggerQuit()
	}(info, curExe)

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "async": true})
}
