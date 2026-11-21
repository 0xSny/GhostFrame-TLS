package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"ghostframe/internal/gft"
)

func waitForTCPAddr(t *testing.T, s *Server) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := s.TCPAddr(); a != nil {
			return a.String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start listening")
	return ""
}

func startTestServer(t *testing.T, opts InitOptions, disableQUIC bool, testPC net.PacketConn) (*Server, *Secrets, string, func()) {
	t.Helper()
	dir := t.TempDir()
	opts.ConfDir = filepath.Join(dir, "conf")
	opts.StateDir = filepath.Join(dir, "state")
	if opts.Host == "" {
		opts.Host = "127.0.0.1"
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:0"
	}
	sec, err := InitWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(filepath.Join(opts.ConfDir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisableQUIC = disableQUIC
	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if testPC != nil {
		srv.SetTestUDPConn(testPC)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	addr := waitForTCPAddr(t, srv)
	return srv, sec, addr, func() {
		cancel()
		<-done
	}
}

func TestServerInitNoIPInSANAnd90dValidity(t *testing.T) {
	dir := t.TempDir()
	sec, err := InitWithOptions(InitOptions{
		ConfDir:  filepath.Join(dir, "conf"),
		StateDir: filepath.Join(dir, "state"),
		Host:     "198.51.100.10",
		SNI:      "ftp.jaist.ac.jp",
		Listen:   ":443",
		CertMode: "self_signed_90d",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sec.Link, "ksl4://") {
		t.Fatalf("expected ksl4:// link, got %s", sec.Link)
	}
	certBytes, err := os.ReadFile(filepath.Join(dir, "conf", "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// Verify no IP SANs on self-signed cert
	cfg, _ := LoadConfig(filepath.Join(dir, "conf", "server.json"))
	kc, err := tls.X509KeyPair(certBytes, mustRead(t, cfg.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(kc.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Fatalf("certificate SAN must NOT expose IPAddresses, got %v", leaf.IPAddresses)
	}
	dur := leaf.NotAfter.Sub(leaf.NotBefore)
	if dur < 89*24*time.Hour || dur > 91*24*time.Hour {
		t.Fatalf("expected ~90 day validity, got %v", dur)
	}
}

func TestRotateSNIPreservesSPKIPin(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf")
	sec, err := InitWithOptions(InitOptions{
		ConfDir:  confDir,
		StateDir: filepath.Join(dir, "state"),
		Host:     "198.51.100.10",
		SNI:      "ftp.jaist.ac.jp",
		Listen:   ":443",
		CertMode: "self_signed_90d",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(confDir, "server.json")
	newPin, err := RotateSNI(cfgPath, "ftp.riken.jp")
	if err != nil {
		t.Fatal(err)
	}
	if newPin == "" || newPin != sec.Pin {
		t.Fatalf("expected identical SPKI Pin after RotateSNI: got %q want %q", newPin, sec.Pin)
	}
	c, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.SNI != "ftp.riken.jp" || c.CamouflageTarget != "ftp.riken.jp:443" {
		t.Fatalf("unexpected rotated config: %+v", c)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServerMirrorInspectorAndInternalPanelAndTCPEcho(t *testing.T) {
	// 1. Mock genuine upstream origin (camouflage target)
	camoSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Camo-Origin", "authentic-upstream")
		_, _ = w.Write([]byte("ORIGIN-CAMOUFLAGE-OK"))
	}))
	defer camoSrv.Close()
	camoAddr := strings.TrimPrefix(camoSrv.URL, "https://")

	// 2. Echo target behind AllowPrivateTargets for TCP tunnel verification
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_, _ = io.Copy(cc, cc)
			}(c)
		}
	}()

	AllowPrivateTargets = true
	defer func() { AllowPrivateTargets = false }()

	srv, sec, addr, stop := startTestServer(t, InitOptions{
		SNI:              "ftp.jaist.ac.jp",
		CertMode:         "self_signed_90d",
		FallbackMode:     "mirror",
		CamouflageTarget: camoAddr,
	}, true, nil)
	defer stop()

	// A. Active probe without stego SessionID MUST get the mock upstream cert + body via MirrorInspector
	probeCli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 4 * time.Second,
	}
	defer probeCli.CloseIdleConnections()
	resp, err := probeCli.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("probe mirror failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ORIGIN-CAMOUFLAGE-OK" || resp.Header.Get("X-Camo-Origin") != "authentic-upstream" {
		t.Fatalf("expected transparent reflection to camouflage upstream, got %q hdr=%v", body, resp.Header)
	}
	if len(srv.audit.List()) == 0 {
		t.Fatal("expected pre_tls_probe audit record")
	}

	// B. Authentic GFT v3 client connects over uTLS + RecordSplit + SessionID Stego -> echoes & reaches internal panel
	link, err := gft.ParseLink(sec.Link)
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(addr)
	link.Port = mustAtoi(portStr)
	link.Host = "127.0.0.1"

	ps := gft.NewParamStore(gft.DefaultParams())
	sess, _, err := gft.DialSession(context.Background(), link, ps, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("gft v3 dial failed: %v", err)
	}
	defer sess.Close()

	// Echo test via FastOutbound (read full echo before half-close to avoid Windows WFP half-close drop)
	st, err := sess.OpenStream(echoLn.Addr().String(), []byte("ping-"))
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 32*1024)
	_, _ = rand.Read(msg)
	go func() {
		_, _ = st.Write(msg)
	}()
	echoed := make([]byte, 5+len(msg))
	if _, err := io.ReadFull(st, echoed); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if !bytes.HasPrefix(echoed, []byte("ping-")) || !bytes.Equal(echoed[5:], msg) {
		t.Fatalf("echo mismatch len=%d", len(echoed))
	}

	// Internal stealth panel access over tunnel ("gft.internal.panel:80")
	pst, err := sess.OpenStream(internalPanelHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pst.Close()
	_, _ = io.WriteString(pst, "GET "+sec.PanelPath+"/?key="+sec.PanelPassword+" HTTP/1.1\r\nHost: gft.internal.panel\r\nConnection: close\r\n\r\n")
	httpResp, err := http.ReadResponse(bufio.NewReader(pst), nil)
	if err != nil {
		t.Fatalf("internal panel read failed: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK && httpResp.StatusCode != http.StatusFound {
		t.Fatalf("expected 200 or 302 on internal panel, got %d", httpResp.StatusCode)
	}
}

func TestServerSSRFBlocked(t *testing.T) {
	AllowPrivateTargets = false
	ob := NewFastOutbound()
	for _, tgt := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:22"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := ob.DialTCP(ctx, tgt)
		cancel()
		if err == nil {
			_ = c.Close()
			t.Fatalf("expected SSRF block for %s", tgt)
		}
	}
}

func TestServerHTTP2FallbackBlogAndPanelCSRF(t *testing.T) {
	_, sec, addr, stop := startTestServer(t, InitOptions{
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "builtin_blog",
	}, true, nil)
	defer stop()

	// 1. Public HTTP/2 fallback renders builtin blog cleanly
	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	defer tr2.CloseIdleConnections()
	cli := &http.Client{Transport: tr2, Timeout: 4 * time.Second}
	resp, err := cli.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("h2 blog get failed: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.ProtoMajor != 2 || len(b) == 0 {
		t.Fatalf("expected HTTP/2 200 blog, got status=%d proto=%s len=%d", resp.StatusCode, resp.Proto, len(b))
	}

	// 2. Panel login -> CSRF session -> missing CSRF 403 -> valid CSRF 200 + gft3:// link
	jar := &simpleJar{}
	pcli := &http.Client{
		Transport: tr2,
		Jar:       jar,
		Timeout:   20 * time.Second,
	}
	base := "https://" + addr + sec.PanelPath
	loginResp, err := pcli.Post(base+"/api/login", "application/json", strings.NewReader(`{"password":"`+sec.PanelPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		t.Fatalf("panel login status=%d", loginResp.StatusCode)
	}

	sessResp, err := pcli.Get(base + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	var sessData struct {
		OK   bool   `json:"ok"`
		CSRF string `json:"csrf"`
	}
	_ = json.NewDecoder(sessResp.Body).Decode(&sessData)
	sessResp.Body.Close()
	if !sessData.OK || sessData.CSRF == "" {
		t.Fatalf("expected csrf token from /api/session, got %+v", sessData)
	}

	// Reject without X-CSRF-Token
	noCSRF, err := pcli.Post(base+"/api/params", "application/json", strings.NewReader(`{"pmin":0,"pmax":64,"pprob":35,"hbmin":25000,"hbmax":55000}`))
	if err != nil {
		t.Fatal(err)
	}
	noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF token, got %d", noCSRF.StatusCode)
	}

	// Accept with X-CSRF-Token
	req, _ := http.NewRequest(http.MethodPut, base+"/api/params", strings.NewReader(`{"pmin":4,"pmax":64,"pprob":40,"hbmin":20000,"hbmax":50000}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sessData.CSRF)
	okResp, err := pcli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != 200 {
		t.Fatalf("expected 200 with CSRF token, got %d", okResp.StatusCode)
	}

	linkResp, err := pcli.Get(base + "/api/link")
	if err != nil {
		t.Fatal(err)
	}
	var linkData struct {
		URI string `json:"uri"`
	}
	_ = json.NewDecoder(linkResp.Body).Decode(&linkData)
	linkResp.Body.Close()
	if !strings.HasPrefix(linkData.URI, "ksl4://") {
		t.Fatalf("expected ksl4:// link from /api/link, got %s", linkData.URI)
	}
}

// ---- QUIC Server Integration Test via in-memory PacketConn ----

type srvMemAddr string

func (a srvMemAddr) Network() string { return "udp" }
func (a srvMemAddr) String() string  { return string(a) }

type srvMemPkt struct {
	data []byte
	from net.Addr
}

type srvMemPacketConn struct {
	local  srvMemAddr
	peer   *srvMemPacketConn
	recv   chan srvMemPkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	rDead  time.Time
}

func newSrvMemPair() (*srvMemPacketConn, *srvMemPacketConn) {
	a := &srvMemPacketConn{local: srvMemAddr("127.0.0.1:21001"), recv: make(chan srvMemPkt, 256), closed: make(chan struct{})}
	b := &srvMemPacketConn{local: srvMemAddr("127.0.0.1:21443"), recv: make(chan srvMemPkt, 256), closed: make(chan struct{})}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *srvMemPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	m.mu.Lock()
	dl := m.rDead
	m.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, net.ErrClosed
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-m.recv:
		n := copy(p, pkt.data)
		return n, pkt.from, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, context.DeadlineExceeded
	}
}

func (m *srvMemPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-m.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case m.peer.recv <- srvMemPkt{data: cp, from: m.local}:
	default:
	}
	return len(p), nil
}

func (m *srvMemPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *srvMemPacketConn) LocalAddr() net.Addr                { return m.local }
func (m *srvMemPacketConn) SetDeadline(t time.Time) error      { return m.SetReadDeadline(t) }
func (m *srvMemPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *srvMemPacketConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.rDead = t
	m.mu.Unlock()
	return nil
}

func TestServerRTCStealthStreamAndInternalPanel(t *testing.T) {
	cRaw, sRaw := newSrvMemPair()
	_, sec, _, stop := startTestServer(t, InitOptions{
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "mirror",
	}, false, sRaw)
	defer stop()

	link, err := gft.ParseLink(sec.Link)
	if err != nil {
		t.Fatal(err)
	}
	ps := gft.NewParamStore(gft.DefaultParams())
	rs, _, err := gft.DialRTCWithPacketConn(context.Background(), cRaw, false, sRaw.LocalAddr(), 443, link, ps, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	defer cRaw.Close()
	defer sRaw.Close()

	st, err := rs.OpenStream(internalPanelHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _ = io.WriteString(st, "GET "+sec.PanelPath+"/?key="+sec.PanelPassword+" HTTP/1.1\r\nHost: gft.internal.panel\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(st), nil)
	if err != nil {
		t.Fatalf("rtc internal panel failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 200 or 302 via RTC internal panel, got %d", resp.StatusCode)
	}
}

func TestWebPanelRTCConfigUpdateAndSVGQR(t *testing.T) {
	srv, sec, addr, stop := startTestServer(t, InitOptions{
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "builtin_blog",
	}, false, nil)
	defer stop()

	cfgPath := filepath.Join(t.TempDir(), "server.json")
	srv.SetConfigPath(cfgPath)

	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	defer tr2.CloseIdleConnections()

	jar := &simpleJar{}
	pcli := &http.Client{Transport: tr2, Jar: jar, Timeout: 20 * time.Second}
	base := "https://" + addr + sec.PanelPath

	loginResp, err := pcli.Post(base+"/api/login", "application/json", strings.NewReader(`{"password":"`+sec.PanelPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		t.Fatalf("login failed: status=%d", loginResp.StatusCode)
	}

	sessResp, err := pcli.Get(base + "/api/session")
	if err != nil {
		t.Fatal(err)
	}
	var sessData struct {
		OK   bool   `json:"ok"`
		CSRF string `json:"csrf"`
	}
	_ = json.NewDecoder(sessResp.Body).Decode(&sessData)
	sessResp.Body.Close()
	if !sessData.OK || sessData.CSRF == "" {
		t.Fatalf("missing csrf token: %+v", sessData)
	}

	// Verify /api/stats exposes v4.0.0-LTS RTC metadata
	stResp, err := pcli.Get(base + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	var stBody map[string]any
	_ = json.NewDecoder(stResp.Body).Decode(&stBody)
	stResp.Body.Close()
	if stBody["version"] != Version {
		t.Fatalf("expected stats version %s, got %v", Version, stBody["version"])
	}
	if en, _ := stBody["rtc_enabled"].(bool); !en {
		t.Fatalf("expected rtc_enabled=true, got %v", stBody["rtc_enabled"])
	}

	// Reject invalid hop_range
	badReq, _ := http.NewRequest(http.MethodPut, base+"/api/rtc", strings.NewReader(`{"hop_range":"80-90","up_mbps":30,"down_mbps":100}`))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("X-CSRF-Token", sessData.CSRF)
	badResp, err := pcli.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-range hop_range, got %d", badResp.StatusCode)
	}

	// Persist valid Kestrel-RTC config + remark via PUT /api/rtc
	req, _ := http.NewRequest(http.MethodPut, base+"/api/rtc", strings.NewReader(`{"hop_range":"20000-40000","up_mbps":30,"down_mbps":100,"remark":"Tokyo-VIP"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sessData.CSRF)
	okResp, err := pcli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var putData struct {
		OK       bool   `json:"ok"`
		HopRange string `json:"hop_range"`
		UpMbps   int    `json:"up_mbps"`
		DownMbps int    `json:"down_mbps"`
		Remark   string `json:"remark"`
		URI      string `json:"uri"`
		QRSVG    string `json:"qr_svg"`
	}
	_ = json.NewDecoder(okResp.Body).Decode(&putData)
	okResp.Body.Close()
	if okResp.StatusCode != 200 || !putData.OK || putData.HopRange != "20000-40000" || putData.UpMbps != 30 || putData.DownMbps != 100 || putData.Remark != "Tokyo-VIP" {
		t.Fatalf("unexpected PUT /api/rtc response status=%d body=%+v", okResp.StatusCode, putData)
	}
	if !strings.HasPrefix(putData.URI, "ksl4://") || !strings.HasSuffix(putData.URI, "#Tokyo-VIP") || !strings.Contains(putData.QRSVG, "<svg") {
		t.Fatalf("expected ksl4:// URI ending #Tokyo-VIP + inline SVG QR from PUT /api/rtc, got uri=%q", putData.URI)
	}

	// Verify atomic persistence to server.json
	persisted, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s) failed: %v", cfgPath, err)
	}
	if persisted.HopRange != "20000-40000" || persisted.UpMbps != 30 || persisted.DownMbps != 100 || persisted.Remark != "Tokyo-VIP" {
		t.Fatalf("persisted server.json mismatch: %+v", persisted)
	}

	// Verify /api/link reflects updated ksl4:// URI, remark, and SVG QR
	lResp, err := pcli.Get(base + "/api/link")
	if err != nil {
		t.Fatal(err)
	}
	var lData struct {
		URI   string `json:"uri"`
		QRSVG string `json:"qr_svg"`
	}
	_ = json.NewDecoder(lResp.Body).Decode(&lData)
	lResp.Body.Close()
	decoded, err := gft.ParseLink(lData.URI)
	if err != nil {
		t.Fatalf("ParseLink(%q) failed: %v", lData.URI, err)
	}
	if decoded.HopRange != "20000-40000" || decoded.UpMbps != 30 || decoded.DownMbps != 100 || decoded.Remark != "Tokyo-VIP" || !strings.Contains(lData.QRSVG, "<svg") {
		t.Fatalf("decoded link or QR mismatch: link=%+v hasSVG=%v", decoded, strings.Contains(lData.QRSVG, "<svg"))
	}

	// Toggle ipv6_enabled=false via PUT /api/rtc and verify persistence + live state
	v6Req, _ := http.NewRequest(http.MethodPut, base+"/api/rtc", strings.NewReader(`{"hop_range":"20000-40000","up_mbps":30,"down_mbps":100,"remark":"Tokyo-VIP","ipv6_enabled":false}`))
	v6Req.Header.Set("Content-Type", "application/json")
	v6Req.Header.Set("X-CSRF-Token", sessData.CSRF)
	v6Resp, err := pcli.Do(v6Req)
	if err != nil {
		t.Fatal(err)
	}
	var v6Data struct {
		OK          bool `json:"ok"`
		IPv6Enabled bool `json:"ipv6_enabled"`
	}
	_ = json.NewDecoder(v6Resp.Body).Decode(&v6Data)
	v6Resp.Body.Close()
	if v6Resp.StatusCode != 200 || !v6Data.OK || v6Data.IPv6Enabled {
		t.Fatalf("expected ipv6_enabled=false after PUT /api/rtc, got status=%d body=%+v", v6Resp.StatusCode, v6Data)
	}
	persistedV6, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s) failed: %v", cfgPath, err)
	}
	if !persistedV6.DisableIPv6 || persistedV6.IsIPv6Enabled() {
		t.Fatalf("expected persisted DisableIPv6=true, got %+v", persistedV6)
	}
}

func TestFastOutboundIPv6Toggle(t *testing.T) {
	ob := NewFastOutbound()
	ctx := context.Background()

	// Default: IPv6 outbound enabled.
	v4, v6, err := ob.ResolveHost(ctx, "2606:4700:4700::1111")
	if err != nil || len(v4) != 0 || len(v6) != 1 {
		t.Fatalf("expected default IPv6 literal allowed, got v4=%v v6=%v err=%v", v4, v6, err)
	}

	// Seed mixed v4+v6 cache entry to verify stripping and cache purge on toggle.
	ob.mu.Lock()
	ob.cache["dual.example.test"] = &dnsEntry{
		v4:      []net.IP{net.ParseIP("1.1.1.1").To4()},
		v6:      []net.IP{net.ParseIP("2606:4700:4700::1111")},
		expires: time.Now().Add(time.Minute),
	}
	ob.mu.Unlock()

	ob.SetDisableIPv6(true)
	if _, _, err := ob.ResolveHost(ctx, "2606:4700:4700::1111"); err != errIPv6Disabled {
		t.Fatalf("expected errIPv6Disabled for literal IPv6 when disabled, got %v", err)
	}

	ob.mu.RLock()
	cacheLen := len(ob.cache)
	ob.mu.RUnlock()
	if cacheLen != 0 {
		t.Fatalf("expected SetDisableIPv6 to clear DNS cache, len=%d", cacheLen)
	}

	// Re-seed dual entry while disabled: ResolveHost must suppress v6.
	ob.mu.Lock()
	ob.cache["dual.example.test"] = &dnsEntry{
		v4:      []net.IP{net.ParseIP("1.1.1.1").To4()},
		v6:      []net.IP{net.ParseIP("2606:4700:4700::1111")},
		expires: time.Now().Add(time.Minute),
	}
	ob.mu.Unlock()
	v4, v6, err = ob.ResolveHost(ctx, "dual.example.test")
	if err != nil || len(v4) != 1 || len(v6) != 0 {
		t.Fatalf("expected only v4 when IPv6 disabled, got v4=%v v6=%v err=%v", v4, v6, err)
	}

	// Re-enable IPv6: dual entry returns both again.
	ob.SetDisableIPv6(false)
	ob.mu.Lock()
	ob.cache["dual.example.test"] = &dnsEntry{
		v4:      []net.IP{net.ParseIP("1.1.1.1").To4()},
		v6:      []net.IP{net.ParseIP("2606:4700:4700::1111")},
		expires: time.Now().Add(time.Minute),
	}
	ob.mu.Unlock()
	v4, v6, err = ob.ResolveHost(ctx, "dual.example.test")
	if err != nil || len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("expected dual-stack when IPv6 re-enabled, got v4=%v v6=%v err=%v", v4, v6, err)
	}
}

type simpleJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *simpleJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	j.cookies = append(j.cookies, cookies...)
	j.mu.Unlock()
}

func (j *simpleJar) Cookies(_ *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies
}

func mustAtoi(s string) int {
	v := 0
	for _, c := range s {
		v = v*10 + int(c-'0')
	}
	return v
}
