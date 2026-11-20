package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayConsoleRoutesAndSettings(t *testing.T) {
	svc, err := NewGatewayService("", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewGatewayService failed: %v", err)
	}
	defer svc.Stop()

	mux := svc.BuildHTTPMux()

	// Verify embedded cyber-dark console HTML serves on /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "0Ghost") {
		t.Fatalf("expected HTTP 200 HTML console, got code=%d", rec.Code)
	}

	// Verify /api/status JSON structure
	reqSt := httptest.NewRequest(http.MethodGet, "/api/status", nil)
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

	// Verify device filter + custom rules update via POST /api/settings
	body := `{"gateway_mode":"rule","device_mode":"only","device_ips":["192.168.1.60"],"has_device_ips":true,"custom_rules":["DOMAIN-SUFFIX,ads.example,REJECT"],"has_custom_rules":true}`
	reqSet := httptest.NewRequest(http.MethodPost, "/api/settings", strings.NewReader(body))
	recSet := httptest.NewRecorder()
	mux.ServeHTTP(recSet, reqSet)
	if recSet.Code != http.StatusOK {
		t.Fatalf("settings update failed: %d %s", recSet.Code, recSet.Body.String())
	}
	cfg := svc.getGatewayConfig()
	if cfg.DeviceMode != "only" || len(cfg.DeviceIPs) != 1 || cfg.DeviceIPs[0] != "192.168.1.60" {
		t.Fatalf("unexpected updated gateway config: %+v", cfg)
	}
}
