package server

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type noopSink struct{ done chan struct{} }

func (n *noopSink) SendUDPReply(_ uint16, _ string, _ []byte) error { return nil }
func (n *noopSink) SessionDone() <-chan struct{}                    { return n.done }

func TestUDPMgrLRUEvictionAndIdleTimeout(t *testing.T) {
	AllowPrivateTargets = true
	defer func() { AllowPrivateTargets = false }()

	sink := &noopSink{done: make(chan struct{})}
	defer close(sink.done)
	ob := NewFastOutbound()
	mgr := newUDPManager(sink, false, ob, log.New(io.Discard, "", 0))
	defer mgr.closeAll()

	// Exceed MaxUDPAssocPerClient (256) with 300 distinct IDs -> oldest LRU entries must evict safely.
	for id := uint16(1); id <= 300; id++ {
		mgr.handleDatagramSink(sink, id, "127.0.0.1:9999", []byte("ping"))
	}

	mgr.mu.Lock()
	count := len(mgr.assocs)
	_, hasFirst := mgr.assocs[1]
	_, hasLatest := mgr.assocs[300]
	mgr.mu.Unlock()

	if count != MaxUDPAssocPerClient {
		t.Fatalf("expected UDP assoc table capped at %d, got %d", MaxUDPAssocPerClient, count)
	}
	if hasFirst {
		t.Fatal("expected oldest LRU assoc #1 to be evicted when exceeding 256 limit")
	}
	if !hasLatest {
		t.Fatal("expected latest assoc #300 to stay active")
	}

	// Verify DNS vs regular idle timestamp tagging (port 53 sets isDNS=true)
	mgr.handleDatagramSink(sink, 500, "127.0.0.1:53", []byte("dns"))
	mgr.mu.Lock()
	dnsAssoc := mgr.assocs[500]
	mgr.mu.Unlock()
	if dnsAssoc == nil || !dnsAssoc.isDNS.Load() {
		t.Fatal("expected port 53 association to be tagged isDNS=true for 12s short TTL")
	}
}

func TestPanelBruteForceLockoutAndOriginCSRF(t *testing.T) {
	srv, sec, addr, stop := startTestServer(t, InitOptions{
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "builtin_blog",
	}, false, nil)
	defer stop()

	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	defer tr2.CloseIdleConnections()

	jar := &simpleJar{}
	pcli := &http.Client{Transport: tr2, Jar: jar, Timeout: 10 * time.Second}
	base := "https://" + addr + sec.PanelPath

	// 5 bad passwords trigger 10-minute IP lockout returning HTTP 429 on 6th try
	for i := 0; i < 5; i++ {
		resp, err := pcli.Post(base+"/api/login", "application/json", strings.NewReader(`{"password":"wrong-password"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, resp.StatusCode)
		}
	}
	lockedResp, err := pcli.Post(base+"/api/login", "application/json", strings.NewReader(`{"password":"`+sec.PanelPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	lockedResp.Body.Close()
	if lockedResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 lockout after 5 failures even with valid password, got %d", lockedResp.StatusCode)
	}

	// Reset IP failure map directly to test Origin header CSRF validation cleanly
	srv.panel.clearLoginFailure(func() string { h, _, _ := net.SplitHostPort(addr); return h }())
	srv.panel.loginMu.Lock()
	clear(srv.panel.failures)
	srv.panel.loginMu.Unlock()

	loginOK, err := pcli.Post(base+"/api/login", "application/json", strings.NewReader(`{"password":"`+sec.PanelPassword+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginOK.Body.Close()
	if loginOK.StatusCode != http.StatusOK {
		t.Fatalf("login after unlock failed: %d", loginOK.StatusCode)
	}

	var csrf string
	for _, ck := range jar.cookies {
		if ck.Name == sessionCookieName {
			csrf = ck.Value
		}
	}
	if csrf == "" {
		t.Fatal("missing session cookie")
	}

	// Cross-site Origin must be rejected 403 even with X-CSRF-Token
	badReq, _ := http.NewRequest(http.MethodPost, base+"/api/params", bytes.NewReader([]byte(`{"pmin":0,"pmax":64,"pprob":35,"hbmin":25000,"hbmax":55000}`)))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("X-CSRF-Token", csrf)
	badReq.Header.Set("Origin", "https://evil.example")
	badResp, err := pcli.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin CSRF POST, got %d", badResp.StatusCode)
	}

	// Matching Origin succeeds
	goodReq, _ := http.NewRequest(http.MethodPost, base+"/api/params", bytes.NewReader([]byte(`{"pmin":0,"pmax":64,"pprob":35,"hbmin":25000,"hbmax":55000}`)))
	goodReq.Header.Set("Content-Type", "application/json")
	goodReq.Header.Set("X-CSRF-Token", csrf)
	goodReq.Header.Set("Origin", "https://"+addr)
	goodResp, err := pcli.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	goodResp.Body.Close()
	if goodResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for same-origin CSRF POST, got %d", goodResp.StatusCode)
	}
}

func TestSSRFBlockedSpecialRanges(t *testing.T) {
	blocked := []string{"198.18.0.1", "198.19.255.254", "100.64.0.1", "100.127.255.254", "127.0.0.1", "10.0.0.1"}
	for _, ipStr := range blocked {
		if !blockedIP(net.ParseIP(ipStr)) {
			t.Fatalf("expected SSRF filter to block %s", ipStr)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "198.20.0.1", "100.128.0.1"}
	for _, ipStr := range allowed {
		if blockedIP(net.ParseIP(ipStr)) {
			t.Fatalf("expected SSRF filter to allow public IP %s", ipStr)
		}
	}
}
