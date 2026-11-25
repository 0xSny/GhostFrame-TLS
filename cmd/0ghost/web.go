package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/tproxy"
)

//go:embed web/index.html
var webFS embed.FS

func (s *GatewayService) BuildHTTPMux() http.Handler {
	mux := http.NewServeMux()

	serveIndex := func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "console asset missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}

	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/console", serveIndex)

	mux.HandleFunc("/api/auth/info", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.getGatewayConfig()
		required := strings.TrimSpace(cfg.WebPassword) != ""
		writeJSON(w, http.StatusOK, map[string]any{
			"auth_required": required,
			"authenticated": !required || s.isAuthorizedRequest(r, cfg.WebPassword),
		})
	})

	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		cfg := s.getGatewayConfig()
		want := strings.TrimSpace(cfg.WebPassword)
		if want != "" && subtle.ConstantTimeCompare([]byte(req.Password), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "口令错误"})
			return
		}
		if want != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "kbox_auth",
				Value:    computeWebAuthToken(want),
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400 * 7,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Snapshot())
	})

	mux.HandleFunc("/api/connect", postOnly(func(w http.ResponseWriter, r *http.Request) {
		go func() {
			if err := s.engine.Connect(); err != nil {
				s.engine.Logf("[KestrelBox] 连接失败: %v", err)
			}
			s.SyncFirewall()
		}()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/disconnect", postOnly(func(w http.ResponseWriter, r *http.Request) {
		s.engine.Disconnect()
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/import", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URI string `json:"uri"`
		}
		if err := readJSON(r, &req); err != nil {
			s.engine.Logf("[KestrelBox] 节点导入请求解析失败: %v", err)
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		uris := extractNodeURIs(req.URI)
		wasConnected := s.engine.IsConnected()
		imported := 0
		firstIdx := -1
		var lastErr error
		for _, u := range uris {
			// When already connected, avoid mutating ActiveNode before make-before-break SelectNode completes.
			switchNow := !wasConnected && imported == 0
			idx, err := s.engine.ImportLink(u, switchNow)
			if err != nil {
				lastErr = err
			} else {
				if firstIdx < 0 {
					firstIdx = idx
				}
				imported++
			}
		}
		if imported == 0 {
			msg := "未发现有效 ksl4:// 或 gft3:// 节点链接"
			if lastErr != nil {
				msg = lastErr.Error()
			}
			s.engine.Logf("[KestrelBox] 节点导入失败: %s", msg)
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": msg})
			return
		}
		go func(idx int, hadConn bool) {
			if hadConn && idx >= 0 {
				if err := s.engine.SelectNode(idx); err != nil {
					s.engine.Logf("[KestrelBox] 新节点自动切换失败（已保留原连接，可稍后手动点击切换）: %v", err)
				}
			} else if !s.engine.IsConnected() {
				if err := s.engine.Connect(); err != nil {
					s.engine.Logf("[KestrelBox] 新节点自动连接失败: %v", err)
				}
			}
			s.SyncFirewall()
		}(firstIdx, wasConnected)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "imported": imported, "active_index": firstIdx})
	}))

	mux.HandleFunc("/api/node/select", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Index int `json:"index"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		go func(idx int) {
			if err := s.engine.SelectNode(idx); err != nil {
				s.engine.Logf("[KestrelBox] 切换节点失败: %v", err)
				return
			}
			if !s.engine.IsConnected() {
				_ = s.engine.Connect()
			}
			s.SyncFirewall()
		}(req.Index)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/node/delete", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Index int `json:"index"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := s.engine.DeleteNode(req.Index); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/node/rename", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Index  int    `json:"index"`
			Remark string `json:"remark"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := s.engine.RenameNode(req.Index, req.Remark); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/settings", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			GatewayMode        *string  `json:"gateway_mode"`
			DeviceMode         *string  `json:"device_mode"`
			DeviceIPs          []string `json:"device_ips"`
			HasDeviceIPs       bool     `json:"has_device_ips"`
			DirectDNS          []string `json:"direct_dns"`
			HasDirectDNS       bool     `json:"has_direct_dns"`
			EnableIPv6         *bool    `json:"enable_ipv6"`
			FilterAAAA         *bool    `json:"filter_aaaa"`
			LANMasquerade      *bool    `json:"lan_masquerade"`
			AutoYieldConflicts *bool    `json:"auto_yield_conflicts"`
			WebPassword        *string  `json:"web_password"`
			HasWebPassword     bool     `json:"has_web_password"`
			Transport          *string  `json:"transport"`
			HopRange           *string  `json:"hop_range"`
			UpMbps             *int     `json:"up_mbps"`
			DownMbps           *int     `json:"down_mbps"`
			CustomRules        []string `json:"custom_rules"`
			HasCustomRules     bool     `json:"has_custom_rules"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}

		s.mu.Lock()
		cfg := s.gwCfg
		if req.GatewayMode != nil {
			cfg.GatewayMode = tproxy.GatewayMode(strings.ToLower(strings.TrimSpace(*req.GatewayMode)))
		}
		if req.DeviceMode != nil {
			cfg.DeviceMode = tproxy.DeviceMode(strings.ToLower(strings.TrimSpace(*req.DeviceMode)))
		}
		if req.HasDeviceIPs {
			var clean []string
			for _, ip := range req.DeviceIPs {
				t := strings.TrimSpace(ip)
				if net.ParseIP(t) != nil {
					clean = append(clean, t)
				} else if _, _, perr := net.ParseCIDR(t); perr == nil {
					clean = append(clean, t)
				}
			}
			cfg.DeviceIPs = clean
		}
		if req.HasDirectDNS {
			var cleanDNS []string
			for _, d := range req.DirectDNS {
				if t := strings.TrimSpace(d); t != "" {
					cleanDNS = append(cleanDNS, t)
				}
			}
			cfg.DirectDNS = cleanDNS
		}
		ipv6Changed := req.EnableIPv6 != nil || req.FilterAAAA != nil
		if req.EnableIPv6 != nil {
			cfg.EnableIPv6 = *req.EnableIPv6
			cfg.FilterAAAA = !cfg.EnableIPv6
		} else if req.FilterAAAA != nil {
			cfg.FilterAAAA = *req.FilterAAAA
			cfg.EnableIPv6 = !cfg.FilterAAAA
		}
		if req.LANMasquerade != nil {
			cfg.LANMasquerade = *req.LANMasquerade
		}
		if req.AutoYieldConflicts != nil {
			cfg.AutoYieldConflicts = *req.AutoYieldConflicts
		}
		if req.HasWebPassword && req.WebPassword != nil {
			cfg.WebPassword = strings.TrimSpace(*req.WebPassword)
		}
		cfg.Normalize()
		s.gwCfg = cfg
		dnsSrv := s.dnsSrv
		s.mu.Unlock()

		if b, err := json.Marshal(cfg); err == nil {
			_ = s.engine.SetGatewayConfigRaw(b)
		}
		_ = s.engine.SetEnableIPv6(cfg.EnableIPv6)
		_ = s.engine.SetRouteMode(mapGatewayToRouteMode(cfg.GatewayMode))
		if dnsSrv != nil {
			dnsSrv.UpdateConfig(s.effectiveDirectDNS(cfg), !cfg.EnableIPv6)
			if ipv6Changed {
				dnsSrv.ClearCache()
			}
		}

		if req.HasCustomRules {
			_ = s.engine.SetCustomRules(req.CustomRules)
			if dnsSrv != nil {
				dnsSrv.ClearCache()
			}
		}
		if req.UpMbps != nil && req.DownMbps != nil {
			if err := s.engine.SetBandwidthLimits(*req.UpMbps, *req.DownMbps); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
		reconnectingAsync := false
		if req.Transport != nil {
			wasConnected := s.engine.IsConnected()
			if err := s.engine.SetTransport(strings.ToLower(strings.TrimSpace(*req.Transport))); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			if wasConnected {
				reconnectingAsync = true
			}
		}
		if req.HopRange != nil {
			wasConnected := s.engine.IsConnected()
			if err := s.engine.SetHopRange(*req.HopRange); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			if wasConnected {
				reconnectingAsync = true
			}
		}

		if reconnectingAsync {
			s.syncAfterReconnect(12 * time.Second)
		} else {
			s.SyncFirewall()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	mux.HandleFunc("/api/conflicts/resolve", postOnly(func(w http.ResponseWriter, r *http.Request) {
		rep := tproxy.ResolveConflicts()
		for _, act := range rep.Actions {
			s.engine.Logf("[KestrelBox] %s", act)
		}
		_ = s.engine.StartServers()
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, rep)
	}))

	mux.HandleFunc("/api/test", postOnly(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.ProbeDualConnectivity())
	}))

	mux.HandleFunc("/api/rules/quick", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host   string `json:"host"`
			Action string `json:"action"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		host := strings.TrimSpace(strings.Trim(strings.ToLower(req.Host), "[]"))
		act := strings.ToUpper(strings.TrimSpace(req.Action))
		if host == "" || (act != "DIRECT" && act != "PROXY" && act != "REJECT") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid host or action"})
			return
		}
		ruleType := "DOMAIN-SUFFIX"
		ruleVal := host
		if net.ParseIP(host) != nil {
			ruleType = "IP-CIDR"
			if strings.Contains(host, ":") {
				ruleVal = host + "/128"
			} else {
				ruleVal = host + "/32"
			}
		}
		ruleLine := ruleType + "," + ruleVal + "," + act
		if err := s.engine.AppendCustomRule(ruleLine); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": ruleLine, "custom_rules": s.engine.CustomRules()})
	}))

	mux.HandleFunc("/api/rules/update", postOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		_ = readJSON(r, &req)
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		st, err := s.engine.UpdateRuleBundle(ctx, req.URL)
		cancel()
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error(), "rule_stats": st})
			return
		}
		s.mu.RLock()
		dnsSrv := s.dnsSrv
		s.mu.RUnlock()
		if dnsSrv != nil {
			dnsSrv.ClearCache()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule_stats": st})
	}))

	mux.HandleFunc("/api/logs/clear", postOnly(func(w http.ResponseWriter, r *http.Request) {
		s.engine.ClearLogs()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))

	// Apply DNS-rebinding Host validation, same-origin CSRF checks, optional password gate,
	// and /0ghost prefix stripping uniformly.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")

		rNorm := r
		if strings.HasPrefix(r.URL.Path, "/kbox") {
			r2 := r.Clone(r.Context())
			trimmed := strings.TrimPrefix(r.URL.Path, "/kbox")
			if trimmed == "" {
				trimmed = "/"
			}
			r2.URL.Path = trimmed
			rNorm = r2
		} else if strings.HasPrefix(r.URL.Path, "/0ghost") {
			r2 := r.Clone(r.Context())
			trimmed := strings.TrimPrefix(r.URL.Path, "/0ghost")
			if trimmed == "" {
				trimmed = "/"
			}
			r2.URL.Path = trimmed
			rNorm = r2
		}

		if !s.isAllowedHostHeader(rNorm.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		if strings.HasPrefix(rNorm.URL.Path, "/api/") {
			if !s.isSameOriginAPIRequest(rNorm) {
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "cross-origin request blocked"})
				return
			}
			if rNorm.URL.Path != "/api/auth/info" && rNorm.URL.Path != "/api/auth/login" {
				cfg := s.getGatewayConfig()
				if !s.isAuthorizedRequest(rNorm, cfg.WebPassword) {
					writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "authentication required"})
					return
				}
			}
		}

		mux.ServeHTTP(w, rNorm)
	})
}

func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func extractHostname(hostport string) string {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(strings.ToLower(host), "[]")
	}
	return strings.Trim(strings.ToLower(h), "[]")
}

func (s *GatewayService) isAllowedHostHeader(hostHdr string) bool {
	host := extractHostname(hostHdr)
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home") {
		return true
	}
	// Single-label local router hostname (e.g. "istoreos", "openwrt") has no dot.
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
		s.mu.RLock()
		lanIP := s.lanIP
		s.mu.RUnlock()
		return lanIP != "" && ip.String() == lanIP
	}
	return false
}

func (s *GatewayService) isSameOriginAPIRequest(r *http.Request) bool {
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs == "cross-site" {
		return false
	}
	reqHost := extractHostname(r.Host)
	checkOriginURL := func(raw string) bool {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return false
		}
		origHost := extractHostname(u.Host)
		if origHost == reqHost {
			return true
		}
		// Treat localhost and 127.0.0.1 as equivalent only when reqHost is loopback,
		// and allow router LAN IP <-> localhost when proxied through uhttpd on 127.0.0.1.
		origIP := net.ParseIP(origHost)
		reqIP := net.ParseIP(reqHost)
		if (reqHost == "127.0.0.1" || reqHost == "localhost" || (reqIP != nil && reqIP.IsLoopback())) &&
			s.isAllowedHostHeader(u.Host) {
			return true
		}
		if origIP != nil && reqIP != nil && origIP.Equal(reqIP) {
			return true
		}
		return false
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		return checkOriginURL(origin)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if ref := r.Header.Get("Referer"); ref != "" {
			return checkOriginURL(ref)
		}
	}
	return true
}

func computeWebAuthToken(secret string) string {
	mac := hmac.New(sha256.New, []byte("ghost0-web-session-v1"))
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *GatewayService) isAuthorizedRequest(r *http.Request, password string) bool {
	want := strings.TrimSpace(password)
	if want == "" {
		return true
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		tok := strings.TrimSpace(auth[7:])
		if subtle.ConstantTimeCompare([]byte(tok), []byte(want)) == 1 {
			return true
		}
	}
	if hdr := strings.TrimSpace(r.Header.Get("X-Ghost-Token")); hdr != "" {
		if subtle.ConstantTimeCompare([]byte(hdr), []byte(want)) == 1 {
			return true
		}
	}
	if c, err := r.Cookie("kbox_auth"); err == nil && c.Value != "" {
		expectedTok := computeWebAuthToken(want)
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(expectedTok)) == 1 {
			return true
		}
	}
	return false
}

func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var nodeSchemeRe = regexp.MustCompile(`(?i)(?:ksl4|gft3|gft2|gft)://`)

func cleanInvisibleImportChars(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	repl := strings.NewReplacer(
		"\ufeff", "",
		"\u200b", "",
		"\u200c", "",
		"\u200d", "",
		"\u00a0", " ",
	)
	return repl.Replace(s)
}

func isBase64URLByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == '='
}

// extractNodeURIs extracts one or more ksl4:// / gft3:// / gft2:// / gft:// links from raw pasted text,
// tolerating terminal line wraps, embedded spaces/newlines inside base64 payloads, surrounding CLI flags,
// quotes, and batch multi-link pastes.
func extractNodeURIs(raw string) []string {
	cleaned := strings.TrimSpace(cleanInvisibleImportChars(raw))
	if cleaned == "" {
		return nil
	}
	locs := nodeSchemeRe.FindAllStringIndex(cleaned, -1)
	if len(locs) == 0 {
		return []string{cleaned}
	}
	out := make([]string, 0, len(locs))
	for i, loc := range locs {
		segEnd := len(cleaned)
		if i+1 < len(locs) {
			segEnd = locs[i+1][0]
		}
		seg := cleaned[loc[0]:segEnd]
		schemeLen := loc[1] - loc[0]
		scheme := strings.ToLower(seg[:schemeLen])
		rest := seg[schemeLen:]

		// Fast path: contiguous token up to quote/whitespace already parses cleanly.
		tok := rest
		if end := strings.IndexAny(tok, "\"'`<> \t\r\n"); end >= 0 {
			tok = tok[:end]
		}
		fast := scheme + strings.TrimSpace(tok)
		if _, err := gft.ParseLink(fast); err == nil {
			out = append(out, fast)
			continue
		}

		// Recovery path: reassemble terminal-wrapped base64url payload across newlines/spaces/box borders.
		var payload strings.Builder
		pos := 0
		for pos < len(rest) {
			c := rest[pos]
			if isBase64URLByte(c) {
				payload.WriteByte(c)
				pos++
				continue
			}
			if c == ' ' || c == '\t' || c == '\n' {
				// If the accumulated payload is already a complete valid link, stop before trailing prose.
				if payload.Len() >= 24 {
					if _, err := gft.ParseLink(scheme + payload.String()); err == nil {
						break
					}
				}
				pos++
				continue
			}
			// Skip UTF-8 box-drawing vertical bar "│" (0xE2 0x94 0x82) if terminal table wrapped the link.
			if pos+2 < len(rest) && rest[pos] == 0xE2 && rest[pos+1] == 0x94 && rest[pos+2] == 0x82 {
				pos += 3
				continue
			}
			break
		}
		cand := scheme + payload.String()
		if pos < len(rest) && rest[pos] == '#' {
			rem := rest[pos+1:]
			if end := strings.IndexAny(rem, "\"'`<>\n"); end >= 0 {
				rem = rem[:end]
			}
			rem = strings.TrimSpace(rem)
			if rem != "" {
				cand += "#" + rem
			}
		}
		if _, err := gft.ParseLink(cand); err == nil {
			out = append(out, cand)
		} else {
			out = append(out, fast)
		}
	}
	return out
}

func extractNodeURI(raw string) string {
	uris := extractNodeURIs(raw)
	if len(uris) == 0 {
		return ""
	}
	return uris[0]
}
