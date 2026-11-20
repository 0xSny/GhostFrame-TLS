package main

import (
	"embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

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

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Snapshot())
	})

	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		go func() {
			if err := s.engine.Connect(); err != nil {
				s.engine.Logf("[0Ghost] 连接失败: %v", err)
			}
			s.SyncFirewall()
		}()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.engine.Disconnect()
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			URI string `json:"uri"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		imported := 0
		var lastErr error
		for _, ln := range strings.Split(strings.ReplaceAll(req.URI, "\r\n", "\n"), "\n") {
			u := strings.TrimSpace(ln)
			if u == "" {
				continue
			}
			if _, err := s.engine.ImportLink(u, imported == 0); err != nil {
				lastErr = err
			} else {
				imported++
			}
		}
		if imported == 0 {
			msg := "未发现有效 gft3:// 或 gft2:// 节点链接"
			if lastErr != nil {
				msg = lastErr.Error()
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": msg})
			return
		}
		go func() {
			if !s.engine.IsConnected() {
				_ = s.engine.Connect()
			}
			s.SyncFirewall()
		}()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "imported": imported})
	})

	mux.HandleFunc("/api/node/select", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Index int `json:"index"`
		}
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := s.engine.SelectNode(req.Index); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		go func() {
			_ = s.engine.Connect()
			s.SyncFirewall()
		}()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/node/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
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
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GatewayMode        *string  `json:"gateway_mode"`
			DeviceMode         *string  `json:"device_mode"`
			DeviceIPs          []string `json:"device_ips"`
			HasDeviceIPs       bool     `json:"has_device_ips"`
			DirectDNS          []string `json:"direct_dns"`
			HasDirectDNS       bool     `json:"has_direct_dns"`
			FilterAAAA         *bool    `json:"filter_aaaa"`
			AutoYieldConflicts *bool    `json:"auto_yield_conflicts"`
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
		if req.FilterAAAA != nil {
			cfg.FilterAAAA = *req.FilterAAAA
		}
		if req.AutoYieldConflicts != nil {
			cfg.AutoYieldConflicts = *req.AutoYieldConflicts
		}
		cfg.Normalize()
		s.gwCfg = cfg
		dnsSrv := s.dnsSrv
		s.mu.Unlock()

		if b, err := json.Marshal(cfg); err == nil {
			_ = s.engine.SetGatewayConfigRaw(b)
		}
		_ = s.engine.SetRouteMode(mapGatewayToRouteMode(cfg.GatewayMode))
		if dnsSrv != nil {
			dnsSrv.UpdateConfig(s.effectiveDirectDNS(cfg), cfg.FilterAAAA)
		}

		if req.HasCustomRules {
			_ = s.engine.SetCustomRules(req.CustomRules)
		}
		if req.UpMbps != nil && req.DownMbps != nil {
			if err := s.engine.SetBandwidthLimits(*req.UpMbps, *req.DownMbps); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
		if req.Transport != nil {
			if err := s.engine.SetTransport(strings.ToLower(strings.TrimSpace(*req.Transport))); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
		if req.HopRange != nil {
			if err := s.engine.SetHopRange(*req.HopRange); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}

		s.SyncFirewall()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/api/conflicts/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rep := tproxy.ResolveConflicts()
		for _, act := range rep.Actions {
			s.engine.Logf("[0Ghost] %s", act)
		}
		_ = s.engine.StartServers()
		s.SyncFirewall()
		writeJSON(w, http.StatusOK, rep)
	})

	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, s.ProbeDualConnectivity())
	})

	mux.HandleFunc("/api/logs/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.engine.ClearLogs()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Support both direct root access (:19080/) and uhttpd reverse-proxy (/0ghost/).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/0ghost") {
			r2 := r.Clone(r.Context())
			trimmed := strings.TrimPrefix(r.URL.Path, "/0ghost")
			if trimmed == "" {
				trimmed = "/"
			}
			r2.URL.Path = trimmed
			mux.ServeHTTP(w, r2)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
