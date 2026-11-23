//go:build windows

package winui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
)

func TestUIServerAuthAndEndpoints(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cfg.json")
	eng, err := client.NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	uri := (&gft.Link{
		V:      3,
		Host:   "example.com",
		Port:   443,
		SNI:    "example.com",
		PSK:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify: "ca",
		Remark: "HK-Edge",
	}).Encode()
	if _, err := eng.ImportLink(uri, true); err != nil {
		t.Fatal(err)
	}
	eng.RecordTargetTraffic("upload-heavy.example.com:443", 25*1024*1024, 1024)

	srv, err := startUIServer(eng, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	base := "http://" + srv.addr

	// 1. Root page without valid token must return 403 Forbidden.
	rNoTok, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = rNoTok.Body.Close()
	if rNoTok.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing root token, got %d", rNoTok.StatusCode)
	}

	// 2. Root page with valid token serves Porcelain Light UI without waveform charts.
	rOK, err := http.Get(srv.URL())
	if err != nil {
		t.Fatal(err)
	}
	var htmlBuf bytes.Buffer
	_, _ = htmlBuf.ReadFrom(rOK.Body)
	_ = rOK.Body.Close()
	if rOK.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", rOK.StatusCode)
	}
	html := htmlBuf.String()
	if !strings.Contains(html, srv.Token()) || !strings.Contains(html, "#F4F6F9") {
		t.Fatal("rendered HTML missing injected session token or Porcelain palette")
	}
	if strings.Contains(html, "TrafficWaveform") {
		t.Fatal("desktop UI must not contain TrafficWaveform chart")
	}

	// 3. API without X-Kestrel-Token must return 403.
	rAPINoTok, err := http.Get(base + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = rAPINoTok.Body.Close()
	if rAPINoTok.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without X-Kestrel-Token, got %d", rAPINoTok.StatusCode)
	}

	// 4. GET /api/status?tab=routes returns status + top_uploads without history field.
	req, _ := http.NewRequest(http.MethodGet, base+"/api/status?tab=routes", nil)
	req.Header.Set("X-Kestrel-Token", srv.Token())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&st)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status endpoint returned %d", resp.StatusCode)
	}
	if _, hasHist := st["history"]; hasHist {
		t.Fatal("status endpoint must omit 60s history points")
	}
	ups, _ := st["top_uploads"].([]any)
	if len(ups) == 0 {
		t.Fatal("expected top_uploads populated on routes tab")
	}

	// 5. GET /api/nodes/qr?index=0 renders SVG QR via qr.RenderSVG.
	qrReq, _ := http.NewRequest(http.MethodGet, base+"/api/nodes/qr?index=0", nil)
	qrReq.Header.Set("X-Kestrel-Token", srv.Token())
	qrResp, err := http.DefaultClient.Do(qrReq)
	if err != nil {
		t.Fatal(err)
	}
	var qrBody map[string]any
	_ = json.NewDecoder(qrResp.Body).Decode(&qrBody)
	_ = qrResp.Body.Close()
	if svg, _ := qrBody["svg"].(string); !strings.Contains(svg, "<svg") {
		t.Fatalf("expected valid SVG QR output, got %q", svg)
	}

	// 6. Async mode switch / rule append / diagnostic snapshot all work without blocking.
	appendReq, _ := http.NewRequest(http.MethodPost, base+"/api/rules/append", strings.NewReader(`{"rule":"DOMAIN-SUFFIX,corp.example.cn,DIRECT"}`))
	appendReq.Header.Set("X-Kestrel-Token", srv.Token())
	aResp, err := http.DefaultClient.Do(appendReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = aResp.Body.Close()
	if aResp.StatusCode != http.StatusOK {
		t.Fatalf("append rule failed: %d", aResp.StatusCode)
	}
	if !eng.CanStaticDirect("app.corp.example.cn:443") {
		t.Fatal("expected CanStaticDirect true after appending custom DIRECT rule")
	}

	routeReq, _ := http.NewRequest(http.MethodPost, base+"/api/mode/route", strings.NewReader(`{"mode":"global"}`))
	routeReq.Header.Set("X-Kestrel-Token", srv.Token())
	start := time.Now()
	rmResp, err := http.DefaultClient.Do(routeReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = rmResp.Body.Close()
	if rmResp.StatusCode != http.StatusAccepted || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("expected fast async 202 for /api/mode/route, got %d in %v", rmResp.StatusCode, time.Since(start))
	}

	diagReq, _ := http.NewRequest(http.MethodPost, base+"/api/diagnostic", nil)
	diagReq.Header.Set("X-Kestrel-Token", srv.Token())
	dResp, err := http.DefaultClient.Do(diagReq)
	if err != nil {
		t.Fatal(err)
	}
	var diagBody map[string]any
	_ = json.NewDecoder(dResp.Body).Decode(&diagBody)
	_ = dResp.Body.Close()
	if dResp.StatusCode != http.StatusOK || !strings.Contains(strVal(diagBody["text"]), "Kestrel Pro Diagnostic Snapshot") {
		t.Fatalf("diagnostic export failed: status=%d body=%v", dResp.StatusCode, diagBody)
	}
}

func TestWebView2HostInitializationSmoke(t *testing.T) {
	if _, err := findEmbeddedWebViewDLL(); err != nil {
		t.Skipf("Edge WebView2 runtime unavailable in test environment: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	_, _, _ = pCoInitializeEx.Call(0, coinitApartmentThreaded)
	defer pCoUninitialize.Call()

	hInst, _, _ := pGetModuleHandleW.Call(0)
	cls := utf16Ptr("KestrelWV2TestWndClass")
	wcx := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		LpfnWndProc:   pDefWindowProcW.Addr(),
		HInstance:     hInst,
		LpszClassName: cls,
	}
	_, _, _ = pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcx)))
	runtime.KeepAlive(&wcx)
	runtime.KeepAlive(cls)

	hwnd, _, err := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(utf16Ptr("WV2Test"))),
		wsOverlappedWindow,
		0, 0, 640, 480,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		t.Fatalf("CreateWindowExW failed: %v", err)
	}
	defer func() {
		_, _, _ = user32.NewProc("DestroyWindow").Call(hwnd)
	}()

	cfgPath := filepath.Join(t.TempDir(), "cfg.json")
	eng, err := client.NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	srv, err := startUIServer(eng, hwnd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	wv, err := newWebView2Host(hwnd, srv.URL(), func(reason string) {
		t.Logf("WebView2 async failure callback: %s", reason)
	})
	if err != nil {
		t.Fatalf("newWebView2Host failed: %v", err)
	}
	defer wv.Close()

	pPeek := user32.NewProc("PeekMessageW")
	deadline := time.Now().Add(8 * time.Second)
	var msg msgW
	for time.Now().Before(deadline) {
		wv.mu.Lock()
		ready := wv.ready
		failed := wv.failed
		failErr := wv.failErr
		wv.mu.Unlock()
		if failed {
			t.Fatalf("WebView2 initialization reported error: %s", failErr)
		}
		if ready {
			break
		}
		for {
			r, _, _ := pPeek.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1) // PM_REMOVE=1
			if r == 0 {
				break
			}
			_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
		time.Sleep(15 * time.Millisecond)
	}

	wv.mu.Lock()
	ready := wv.ready
	ctrl := wv.ctrl
	wvPtr := wv.webview
	wv.mu.Unlock()
	if !ready || ctrl == 0 || wvPtr == 0 {
		t.Fatalf("WebView2 controller did not become ready in time (ready=%v ctrl=0x%x webview=0x%x)", ready, ctrl, wvPtr)
	}
	wv.Resize()
}
