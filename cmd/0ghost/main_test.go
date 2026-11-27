package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ghostframe/internal/gft"
	"ghostframe/internal/tproxy"
)

func TestGatewayConsoleRoutesAndSettings(t *testing.T) {
	svc, err := NewGatewayService("", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewGatewayService failed: %v", err)
	}
	defer svc.Stop()

	mux := svc.BuildHTTPMux()

	// Verify embedded cyber-dark console HTML serves on / with allowed Host header
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19080/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	html := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(html, "KestrelBox") {
		t.Fatalf("expected HTTP 200 HTML console, got code=%d", rec.Code)
	}
	// Guard against Document.prototype.importNode() collision inside inline HTML event attributes.
	if strings.Contains(html, `onclick="importNode(`) || strings.Contains(html, `;importNode()`) {
		t.Fatalf("inline HTML event handler must not call unqualified importNode() (shadows Document.prototype.importNode)")
	}

	// Verify /api/status JSON structure (requires bootstrap token)
	tok := svc.BootstrapToken()
	reqSt := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19080/api/status", nil)
	reqSt.Header.Set("Authorization", "Bearer "+tok)
	recSt := httptest.NewRecorder()
	mux.ServeHTTP(recSt, reqSt)
	if recSt.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recSt.Code)
	}
	var snap map[string]any
	if err := json.Unmarshal(recSt.Body.Bytes(), &snap); err != nil {
		t.Fatalf("invalid status json: %v", err)
	}
	if snap["gateway_mode"] != "rule" {
		t.Fatalf("expected default gateway_mode rule, got %v", snap["gateway_mode"])
	}

	// Verify device filter + custom rules + lan_masquerade update via POST /api/settings
	body := `{"gateway_mode":"rule","device_mode":"only","device_ips":["192.168.1.60"],"has_device_ips":true,"lan_masquerade":true,"custom_rules":["DOMAIN-SUFFIX,ads.example,REJECT"],"has_custom_rules":true}`
	reqSet := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19080/api/settings", strings.NewReader(body))
	reqSet.Header.Set("Origin", "http://127.0.0.1:19080")
	reqSet.Header.Set("Authorization", "Bearer "+tok)
	recSet := httptest.NewRecorder()
	mux.ServeHTTP(recSet, reqSet)
	if recSet.Code != http.StatusOK {
		t.Fatalf("settings update failed: %d %s", recSet.Code, recSet.Body.String())
	}
	cfg := svc.getGatewayConfig()
	if cfg.DeviceMode != "only" || len(cfg.DeviceIPs) != 1 || cfg.DeviceIPs[0] != "192.168.1.60" || !cfg.LANMasquerade {
		t.Fatalf("unexpected updated gateway config: %+v", cfg)
	}

	// Import a node (also verifying accidental CLI wrapper around ksl4:// is cleanly stripped) and verify POST /api/node/rename updates node remark
	nodeURI := (&gft.Link{V: 3, Host: "n1.example", Port: 443, SNI: "ftp.jaist.ac.jp", PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Verify: "ca", Remark: "OldNode"}).Encode()
	impBody := `{"uri":"kestrel-core -low-mem -socks 0.0.0.0:10808 -link \"` + nodeURI + `\""}`
	reqImp := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19080/api/import", strings.NewReader(impBody))
	reqImp.Header.Set("Origin", "http://127.0.0.1:19080")
	reqImp.Header.Set("Authorization", "Bearer "+tok)
	recImp := httptest.NewRecorder()
	mux.ServeHTTP(recImp, reqImp)
	if recImp.Code != http.StatusOK {
		t.Fatalf("node import failed: %d %s", recImp.Code, recImp.Body.String())
	}

	reqRen := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19080/api/node/rename", strings.NewReader(`{"index":0,"remark":"N1-Renamed"}`))
	reqRen.Header.Set("Origin", "http://127.0.0.1:19080")
	reqRen.Header.Set("Authorization", "Bearer "+tok)
	recRen := httptest.NewRecorder()
	mux.ServeHTTP(recRen, reqRen)
	if recRen.Code != http.StatusOK {
		t.Fatalf("node rename failed: %d %s", recRen.Code, recRen.Body.String())
	}

	reqSt2 := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19080/api/status", nil)
	reqSt2.Header.Set("Authorization", "Bearer "+tok)
	recSt2 := httptest.NewRecorder()
	mux.ServeHTTP(recSt2, reqSt2)
	var renSnap map[string]any
	if err := json.Unmarshal(recSt2.Body.Bytes(), &renSnap); err != nil {
		t.Fatalf("invalid status json after rename: %v", err)
	}
	if renSnap["node_name"] != "N1-Renamed" {
		t.Fatalf("expected renamed node_name=N1-Renamed, got %v", renSnap["node_name"])
	}
	// Status must NEVER leak link_uri or PSK.
	if _, hasLink := renSnap["link_uri"]; hasLink || strings.Contains(recSt2.Body.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") || strings.Contains(recSt2.Body.String(), "gft3://") {
		t.Fatalf("status leaked share link or PSK: %s", recSt2.Body.String())
	}
	// Authorized export returns the share link.
	reqExp := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19080/api/node/export", strings.NewReader(`{"index":0}`))
	reqExp.Header.Set("Origin", "http://127.0.0.1:19080")
	reqExp.Header.Set("Authorization", "Bearer "+tok)
	recExp := httptest.NewRecorder()
	mux.ServeHTTP(recExp, reqExp)
	if recExp.Code != http.StatusOK || !strings.Contains(recExp.Body.String(), `"link_uri":"`) {
		t.Fatalf("authorized /api/node/export failed: %d %s", recExp.Code, recExp.Body.String())
	}
}

func TestGatewayWebSecurityHardening(t *testing.T) {
	// Scenario 1: Fresh install — defaults to 127.0.0.1:19080, requires bootstrap admin.token, rejects LAN bind without password.
	freshDir := t.TempDir()
	svc, err := NewGatewayService(filepath.Join(freshDir, "config.json"), "")
	if err != nil {
		t.Fatalf("NewGatewayService failed: %v", err)
	}
	defer svc.Stop()
	if svc.getGatewayConfig().WebAddr != "127.0.0.1:19080" {
		t.Fatalf("expected fresh install WebAddr 127.0.0.1:19080, got %s", svc.getGatewayConfig().WebAddr)
	}
	tokBytes, err := os.ReadFile(filepath.Join(freshDir, "admin.token"))
	if err != nil || strings.TrimSpace(string(tokBytes)) != svc.BootstrapToken() {
		t.Fatalf("expected persisted admin.token matching BootstrapToken, err=%v", err)
	}
	mux := svc.BuildHTTPMux()

	// Unauthenticated /api/status must be 401 even on fresh install.
	reqFreshUnauth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19080/api/status", nil)
	recFreshUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recFreshUnauth, reqFreshUnauth)
	if recFreshUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on fresh unauthenticated /api/status, got %d", recFreshUnauth.Code)
	}

	// 1. Reject DNS rebinding (external public Host header)
	reqRebind := httptest.NewRequest(http.MethodGet, "http://attacker.evil.com:19080/api/status", nil)
	recRebind := httptest.NewRecorder()
	mux.ServeHTTP(recRebind, reqRebind)
	if recRebind.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for DNS rebinding Host, got %d", recRebind.Code)
	}

	// 2. Reject cross-origin CSRF POST
	reqCSRF := httptest.NewRequest(http.MethodPost, "http://192.168.1.1:19080/api/connect", nil)
	reqCSRF.Header.Set("Origin", "https://evil.site")
	recCSRF := httptest.NewRecorder()
	mux.ServeHTTP(recCSRF, reqCSRF)
	if recCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST, got %d", recCSRF.Code)
	}

	// Reject enabling allow_lan_web while web_password is empty.
	reqLAN := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19080/api/settings", strings.NewReader(`{"allow_lan_web":true}`))
	reqLAN.Header.Set("Origin", "http://127.0.0.1:19080")
	reqLAN.Header.Set("Authorization", "Bearer "+svc.BootstrapToken())
	recLAN := httptest.NewRecorder()
	mux.ServeHTTP(recLAN, reqLAN)
	if recLAN.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when enabling allow_lan_web without password, got %d", recLAN.Code)
	}

	// 3. Enforce WebPassword via cookie login + bearer auth (also Scenario 4: LuCI /kbox/ reverse proxy)
	setPwd := `{"web_password":"secret-n1","has_web_password":true,"allow_lan_web":true}`
	reqSet := httptest.NewRequest(http.MethodPost, "http://192.168.1.1:19080/kbox/api/settings", strings.NewReader(setPwd))
	reqSet.Header.Set("Origin", "http://192.168.1.1:19080")
	reqSet.Header.Set("Authorization", "Bearer "+svc.BootstrapToken())
	recSet := httptest.NewRecorder()
	mux.ServeHTTP(recSet, reqSet)
	if recSet.Code != http.StatusOK {
		t.Fatalf("failed setting web_password: %d %s", recSet.Code, recSet.Body.String())
	}

	reqUnauth := httptest.NewRequest(http.MethodGet, "http://192.168.1.1:19080/kbox/api/status", nil)
	recUnauth := httptest.NewRecorder()
	mux.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when unauthenticated, got %d", recUnauth.Code)
	}

	reqLogin := httptest.NewRequest(http.MethodPost, "http://192.168.1.1:19080/kbox/api/auth/login", strings.NewReader(`{"password":"secret-n1"}`))
	reqLogin.Header.Set("Origin", "http://192.168.1.1:19080")
	recLogin := httptest.NewRecorder()
	mux.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d", recLogin.Code)
	}
	cookies := recLogin.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected auth cookie after login")
	}

	reqAuth := httptest.NewRequest(http.MethodGet, "http://192.168.1.1:19080/kbox/api/status", nil)
	reqAuth.AddCookie(cookies[0])
	recAuth := httptest.NewRecorder()
	mux.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected authenticated /kbox/api/status 200, got %d", recAuth.Code)
	}

	// Scenario 2: Legacy empty-password migration (web_addr: 0.0.0.0:19080 with empty web_password -> clamped to 127.0.0.1:19080).
	migDir := t.TempDir()
	migCfgPath := filepath.Join(migDir, "config.json")
	_ = os.WriteFile(migCfgPath, []byte(`{"gateway":{"web_addr":"0.0.0.0:19080","web_password":""}}`), 0o600)
	migSvc, err := NewGatewayService(migCfgPath, "")
	if err != nil {
		t.Fatalf("legacy migration NewGatewayService failed: %v", err)
	}
	defer migSvc.Stop()
	if migSvc.getGatewayConfig().WebAddr != "127.0.0.1:19080" {
		t.Fatalf("expected legacy empty-password WebAddr clamped to 127.0.0.1:19080, got %s", migSvc.getGatewayConfig().WebAddr)
	}

	// Scenario 3: Existing password with LAN bind keeps 0.0.0.0:19080.
	pwdDir := t.TempDir()
	pwdCfgPath := filepath.Join(pwdDir, "config.json")
	_ = os.WriteFile(pwdCfgPath, []byte(`{"gateway":{"web_addr":"0.0.0.0:19080","web_password":"keep-lan"}}`), 0o600)
	pwdSvc, err := NewGatewayService(pwdCfgPath, "")
	if err != nil {
		t.Fatalf("existing-password NewGatewayService failed: %v", err)
	}
	defer pwdSvc.Stop()
	if pwdSvc.getGatewayConfig().WebAddr != "0.0.0.0:19080" {
		t.Fatalf("expected existing-password WebAddr preserved as 0.0.0.0:19080, got %s", pwdSvc.getGatewayConfig().WebAddr)
	}
}

func TestProbeDualConnectivityConcurrentSafe(t *testing.T) {
	svc, err := NewGatewayService("", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewGatewayService failed: %v", err)
	}
	defer svc.Stop()

	res := svc.ProbeDualConnectivity()
	if res["tunnel_info"] != "隧道未连接" {
		t.Fatalf("expected disconnected tunnel_info message, got %v", res["tunnel_info"])
	}
	if _, ok := res["direct_ok"].(bool); !ok {
		t.Fatalf("expected boolean direct_ok in probe result: %v", res)
	}
}

func TestShouldSelfHealFirewall(t *testing.T) {
	if !shouldSelfHealFirewall(true, tproxy.ModeRule, false, "standby (node disconnected)") {
		t.Fatal("expected self-heal when connected in rule mode and firewall is standby/inactive")
	}
	if !shouldSelfHealFirewall(true, tproxy.ModeGlobal, false, "error") {
		t.Fatal("expected self-heal when connected in global mode after firewall error")
	}
	if shouldSelfHealFirewall(true, tproxy.ModeRule, false, "paused (conflict detected)") {
		t.Fatal("must not override conflict pause without user resolution")
	}
	if shouldSelfHealFirewall(true, tproxy.ModePort, false, "none (port-only)") {
		t.Fatal("must not mount firewall in port-only mode")
	}
	if shouldSelfHealFirewall(false, tproxy.ModeRule, false, "standby (node disconnected)") {
		t.Fatal("must not self-heal while disconnected")
	}
	if shouldSelfHealFirewall(true, tproxy.ModeRule, true, "nftables") {
		t.Fatal("must not trigger redundant sync when firewall is already active")
	}
}

func TestExtractNodeURIsAndWrappedImport(t *testing.T) {
	l1 := (&gft.Link{V: 4, Host: "10.0.0.1", Port: 443, SNI: "ftp.jaist.ac.jp", PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Verify: "ca", Remark: "LA-GIA"}).Encode()
	l2 := (&gft.Link{V: 4, Host: "10.0.0.2", Port: 443, SNI: "mirrors.mit.edu", PSK: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", Verify: "ca", Remark: "JP-SoftBank"}).Encode()

	// 1. Terminal-wrapped link across multiple lines with spaces and trailing terminal prose
	wrapped := "通用导入链接:\n" + l1[:42] + "\r\n  " + l1[42:96] + "   \n" + l1[96:] + "\nkestrel-core -low-mem"
	got := extractNodeURIs(wrapped)
	if len(got) != 1 {
		t.Fatalf("expected 1 extracted URI from wrapped text, got %d: %#v", len(got), got)
	}
	parsed, err := gft.ParseLink(got[0])
	if err != nil || parsed.Host != "10.0.0.1" || parsed.Remark != "LA-GIA" {
		t.Fatalf("wrapped link parse failed: parsed=%+v err=%v raw=%q", parsed, err, got[0])
	}

	// 2. Two links pasted together (even concatenated with zero-width space or no newline)
	batch := "\ufeff" + strings.ToUpper(l1[:7]) + l1[7:] + "\n" + l2
	gotBatch := extractNodeURIs(batch)
	if len(gotBatch) != 2 {
		t.Fatalf("expected 2 extracted URIs from batch paste, got %d", len(gotBatch))
	}
	if p1, err := gft.ParseLink(gotBatch[0]); err != nil || p1.Host != "10.0.0.1" {
		t.Fatalf("batch[0] parse failed: %+v %v", p1, err)
	}
	if p2, err := gft.ParseLink(gotBatch[1]); err != nil || p2.Host != "10.0.0.2" {
		t.Fatalf("batch[1] parse failed: %+v %v", p2, err)
	}

	// 3. End-to-end HTTP POST /api/import with terminal-wrapped VPS copy
	svc, err := NewGatewayService("", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewGatewayService failed: %v", err)
	}
	defer svc.Stop()
	mux := svc.BuildHTTPMux()
	payload, _ := json.Marshal(map[string]string{"uri": wrapped})
	req := httptest.NewRequest(http.MethodPost, "http://192.168.1.75/kbox/api/import", strings.NewReader(string(payload)))
	req.Header.Set("Origin", "http://192.168.1.75")
	req.Header.Set("Authorization", "Bearer "+svc.BootstrapToken())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrapped /kbox/api/import failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
}
