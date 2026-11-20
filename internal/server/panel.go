package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"ghostframe/internal/gft"
	"ghostframe/internal/qr"
)

const (
	sessionCookieName  = "ksl_session"
	sessionTTL         = 24 * time.Hour
	panelMaxLoginFails = 5
	panelLockoutDur    = 10 * time.Minute
)

type panelSession struct {
	token   string
	created time.Time
	expires time.Time
}

type loginAttempt struct {
	fails       int
	lockedUntil time.Time
}

// Panel implements the hidden management web console and its REST APIs.
type Panel struct {
	srv      *Server
	mu       sync.Mutex
	sessions map[string]panelSession
	loginMu  sync.Mutex
	failures map[string]*loginAttempt // IP -> failure/lockout state
}

func newPanel(s *Server) *Panel {
	return &Panel{
		srv:      s,
		sessions: make(map[string]panelSession),
		failures: make(map[string]*loginAttempt),
	}
}

func (p *Panel) sweep() {
	p.mu.Lock()
	now := time.Now()
	for k, v := range p.sessions {
		if now.After(v.expires) {
			delete(p.sessions, k)
		}
	}
	p.mu.Unlock()

	p.loginMu.Lock()
	for ip, att := range p.failures {
		if att == nil || (!att.lockedUntil.IsZero() && now.After(att.lockedUntil)) {
			delete(p.failures, ip)
		}
	}
	if len(p.failures) > 2000 {
		p.failures = make(map[string]*loginAttempt)
	}
	p.loginMu.Unlock()
}

func (p *Panel) isAuth(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sess, ok := p.sessions[cookie.Value]
	if !ok || time.Now().After(sess.expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sess.token), []byte(cookie.Value)) == 1
}

func (p *Panel) createSession() string {
	b := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, b)
	token := hex.EncodeToString(b)
	p.mu.Lock()
	p.sessions[token] = panelSession{
		token:   token,
		created: time.Now(),
		expires: time.Now().Add(sessionTTL),
	}
	p.mu.Unlock()
	return token
}

func (p *Panel) serve(w http.ResponseWriter, r *http.Request, sub string) {
	sub = strings.TrimPrefix(sub, "/")
	if sub == "" || sub == "index.html" {
		// Handle optional query key login: ?key=PASSWORD (guarded by 5-fail 10m lockout)
		if key := r.URL.Query().Get("key"); key != "" {
			ip := reqIP(r)
			if p.checkLockedOut(ip, time.Now()) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(p.srv.cfg.PanelHash), []byte(key)); err == nil {
				p.clearLoginFailure(ip)
				token := p.createSession()
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    token,
					Path:     p.srv.cfg.PanelPath,
					HttpOnly: true,
					Secure:   r.TLS != nil,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   int(sessionTTL / time.Second),
				})
				http.Redirect(w, r, p.srv.cfg.PanelPath+"/", http.StatusFound)
				return
			}
			p.recordLoginFailure(ip, time.Now())
		}

		if !p.isAuth(r) {
			notFound(w)
			return
		}
		w.Header().Set("Server", serverHeader)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(panelHTML)
		return
	}

	// API Routing
	if strings.HasPrefix(sub, "api/") {
		p.serveAPI(w, r, strings.TrimPrefix(sub, "api/"))
		return
	}

	notFound(w)
}

func reqIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (p *Panel) serveAPI(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Server", serverHeader)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// Login is the only public API on the secret path
	if action == "login" && r.Method == http.MethodPost {
		p.handleLogin(w, r)
		return
	}

	// All other APIs require active session
	if !p.isAuth(r) {
		notFound(w)
		return
	}

	// CSRF + Origin validation on mutating methods
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && action != "login" {
		if !validSameOrigin(r) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden: invalid origin"})
			return
		}
		cookie, _ := r.Cookie(sessionCookieName)
		csrf := r.Header.Get("X-CSRF-Token")
		if csrf == "" || cookie == nil || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookie.Value)) != 1 {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden: missing or invalid csrf"})
			return
		}
	}

	switch action {
	case "session":
		cookie, _ := r.Cookie(sessionCookieName)
		token := ""
		if cookie != nil {
			token = cookie.Value
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "csrf": token})
		return
	case "logout":
		if r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    "",
				Path:     p.srv.cfg.PanelPath,
				HttpOnly: true,
				Secure:   r.TLS != nil,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   -1,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
	case "stats":
		p.handleStats(w, r)
		return
	case "conns":
		p.handleConns(w, r)
		return
	case "audit":
		p.handleAudit(w, r)
		return
	case "ban":
		if r.Method == http.MethodPost {
			p.handleBan(w, r)
			return
		}
	case "params":
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			p.handleUpdateParams(w, r)
			return
		} else if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(p.srv.params.Get())
			return
		}
	case "link":
		p.handleLink(w, r)
		return
	case "rtc":
		if r.Method == http.MethodGet || r.Method == http.MethodPut || r.Method == http.MethodPost {
			p.handleRTC(w, r)
			return
		}
	}

	notFound(w)
}

func validSameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (p *Panel) checkLockedOut(ip string, now time.Time) bool {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	att := p.failures[ip]
	if att == nil {
		return false
	}
	if !att.lockedUntil.IsZero() {
		if now.Before(att.lockedUntil) {
			return true
		}
		att.fails = 0
		att.lockedUntil = time.Time{}
	}
	return false
}

func (p *Panel) recordLoginFailure(ip string, now time.Time) {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	att := p.failures[ip]
	if att == nil {
		att = &loginAttempt{}
		p.failures[ip] = att
	}
	att.fails++
	if att.fails >= panelMaxLoginFails {
		att.lockedUntil = now.Add(panelLockoutDur)
	}
}

func (p *Panel) clearLoginFailure(ip string) {
	p.loginMu.Lock()
	delete(p.failures, ip)
	p.loginMu.Unlock()
}

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := reqIP(r)
	now := time.Now()
	if p.checkLockedOut(ip, now) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "too many failed attempts, locked for 10m"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid payload"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(p.srv.cfg.PanelHash), []byte(req.Password))
	if err != nil {
		p.recordLoginFailure(ip, now)
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
		return
	}

	// Login Success: Reset fail counter
	p.clearLoginFailure(ip)

	token := p.createSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     p.srv.cfg.PanelPath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL / time.Second),
	})

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"token": token,
		"csrf":  token,
	})
}

func (p *Panel) handleStats(w http.ResponseWriter, r *http.Request) {
	p.srv.smu.Lock()
	activeCount := len(p.srv.sessions)
	p.srv.smu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snap := p.srv.stats.Snapshot()

	p.srv.cfgMu.RLock()
	hopRange := p.srv.cfg.HopRange
	upMbps := p.srv.cfg.UpMbps
	downMbps := p.srv.cfg.DownMbps
	pubHost := p.srv.cfg.PublicHost
	listen := p.srv.cfg.Listen
	sni := p.srv.cfg.SNI
	remark := strings.TrimSpace(p.srv.cfg.Remark)
	rtcCfgEnabled := !p.srv.cfg.DisableRTC && !p.srv.cfg.DisableQUIC
	p.srv.cfgMu.RUnlock()

	rtcEnabled := rtcCfgEnabled && p.srv.UDPAddr() != nil
	rtcActive := p.srv.rtcActive.Load()

	res := map[string]any{
		"version":     Version,
		"uptime_sec":  int64(time.Since(p.srv.started).Seconds()),
		"active":      activeCount,
		"rtc_active":  rtcActive,
		"rtc_enabled": rtcEnabled,
		"hop_range":   hopRange,
		"up_mbps":     upMbps,
		"down_mbps":   downMbps,
		"public_host": pubHost,
		"listen":      listen,
		"sni":         sni,
		"remark":      remark,
		"traffic":     snap,
		"system": map[string]any{
			"alloc_mb":   m.Alloc / 1024 / 1024,
			"sys_mb":     m.Sys / 1024 / 1024,
			"goroutines": runtime.NumGoroutine(),
		},
	}
	_ = json.NewEncoder(w).Encode(res)
}

type connInfo struct {
	ID       uint64 `json:"id"`
	IP       string `json:"ip"`
	Duration int64  `json:"duration_sec"`
	UpBytes  uint64 `json:"up_bytes"`
	DownByte uint64 `json:"down_bytes"`
}

func (p *Panel) handleConns(w http.ResponseWriter, r *http.Request) {
	p.srv.smu.Lock()
	list := make([]connInfo, 0, len(p.srv.sessions))
	now := time.Now()
	for _, e := range p.srv.sessions {
		list = append(list, connInfo{
			ID:       e.ID,
			IP:       e.IP,
			Duration: int64(now.Sub(e.Since).Seconds()),
			UpBytes:  e.Sess.UpBytes.Load(),
			DownByte: e.Sess.DownBytes.Load(),
		})
	}
	p.srv.smu.Unlock()
	_ = json.NewEncoder(w).Encode(list)
}

func (p *Panel) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries := p.srv.audit.List()
	_ = json.NewEncoder(w).Encode(entries)
}

func (p *Panel) handleBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Banned bool   `json:"banned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid payload"})
		return
	}
	ok := p.srv.audit.SetBan(req.IP, req.Banned)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok})
}

func (p *Panel) handleUpdateParams(w http.ResponseWriter, r *http.Request) {
	var q gft.Params
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad json"})
		return
	}
	if err := q.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	p.srv.params.Set(q)
	p.srv.saveParams(q)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "params": q})
}

func parsePanelHopRange(spec string) (string, error) {
	hr := strings.TrimSpace(spec)
	if hr == "" {
		return "", nil
	}
	parts := strings.Split(hr, "-")
	if len(parts) != 2 {
		return "", &jsonError{msg: "hop_range must be empty or min-max (1024 <= min < max <= 65535)"}
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 1024 || hi > 65535 || lo >= hi {
		return "", &jsonError{msg: "hop_range must satisfy 1024 <= min < max <= 65535"}
	}
	return strconv.Itoa(lo) + "-" + strconv.Itoa(hi), nil
}

type jsonError struct{ msg string }

func (e *jsonError) Error() string { return e.msg }

func (p *Panel) handleRTC(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		p.srv.cfgMu.RLock()
		res := map[string]any{
			"rtc_enabled": !p.srv.cfg.DisableRTC && !p.srv.cfg.DisableQUIC && p.srv.UDPAddr() != nil,
			"rtc_active":  p.srv.rtcActive.Load(),
			"hop_range":   p.srv.cfg.HopRange,
			"up_mbps":     p.srv.cfg.UpMbps,
			"down_mbps":   p.srv.cfg.DownMbps,
			"tx_mbps":     p.srv.cfg.TxMbps,
			"remark":      strings.TrimSpace(p.srv.cfg.Remark),
		}
		p.srv.cfgMu.RUnlock()
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	var req struct {
		HopRange string  `json:"hop_range"`
		UpMbps   int     `json:"up_mbps"`
		DownMbps int     `json:"down_mbps"`
		Remark   *string `json:"remark,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad json"})
		return
	}
	normHop, err := parsePanelHopRange(req.HopRange)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	if req.UpMbps < 0 || req.UpMbps > 65535 || req.DownMbps < 0 || req.DownMbps > 65535 {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "up_mbps and down_mbps must be 0..65535"})
		return
	}

	curParams := p.srv.params.Get()
	p.srv.cfgMu.Lock()
	oldHop := p.srv.cfg.HopRange
	oldUp := p.srv.cfg.UpMbps
	oldDown := p.srv.cfg.DownMbps
	oldRemark := p.srv.cfg.Remark
	p.srv.cfg.HopRange = normHop
	p.srv.cfg.UpMbps = req.UpMbps
	p.srv.cfg.DownMbps = req.DownMbps
	if req.Remark != nil {
		rem := strings.TrimSpace(*req.Remark)
		if runes := []rune(rem); len(runes) > 64 {
			rem = string(runes[:64])
		}
		p.srv.cfg.Remark = rem
	}
	if p.srv.cfgPath != "" {
		if err := SaveConfigAtomic(p.srv.cfgPath, p.srv.cfg); err != nil {
			p.srv.cfg.HopRange = oldHop
			p.srv.cfg.UpMbps = oldUp
			p.srv.cfg.DownMbps = oldDown
			p.srv.cfg.Remark = oldRemark
			p.srv.cfgMu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
	}
	newRemark := p.srv.cfg.Remark
	linkObj := p.srv.cfg.Link(curParams)
	p.srv.cfgMu.Unlock()

	uri := linkObj.Encode()
	qrSVG, _ := qr.RenderSVG(uri)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"hop_range": normHop,
		"up_mbps":   req.UpMbps,
		"down_mbps": req.DownMbps,
		"remark":    newRemark,
		"uri":       uri,
		"qr_svg":    qrSVG,
	})
}

func (p *Panel) handleLink(w http.ResponseWriter, r *http.Request) {
	curParams := p.srv.params.Get()
	p.srv.cfgMu.RLock()
	linkObj := p.srv.cfg.Link(curParams)
	rawPSK := p.srv.cfg.PSK
	pin := p.srv.cfg.Pin
	p.srv.cfgMu.RUnlock()

	uri := linkObj.Encode()
	qrSVG, _ := qr.RenderSVG(uri)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"uri":     uri,
		"link":    linkObj,
		"qr_svg":  qrSVG,
		"raw_psk": rawPSK,
		"pin":     pin,
	})
}

var _ = subtle.ConstantTimeCompare
