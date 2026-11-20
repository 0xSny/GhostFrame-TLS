package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/gft"
)

// mockServer creates an in-memory GFT server loop over a pipe.
func mockGFTLoop(t *testing.T) (*gft.Link, func()) {
	t.Helper()
	// Create an echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return nil, func() {
		_ = echoLn.Close()
	}
}

func TestSOCKS5HandshakeAndProxy(t *testing.T) {
	// Create a dummy engine
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	socks := NewSOCKS5Server("127.0.0.1:0", eng)
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()

	// 1. When disconnected, SOCKS5 CONNECT returns error
	c, err := net.Dial("tcp", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// SOCKS5 Greeting: 0x05, 0x01, 0x00
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("greeting reply: %v %v", err, rep)
	}

	// Request: CONNECT 127.0.0.1:80 (IPv4)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	_, _ = c.Write(req)
	var resp [10]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x05 { // Must return 0x05 (connection refused) because not connected
		t.Fatalf("expected 0x05 rejected, got %v", resp[1])
	}
}

func TestHTTPProxyRejectionWhenDisconnected(t *testing.T) {
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	hp := NewHTTPProxyServer("127.0.0.1:0", eng)
	if err := hp.Start(); err != nil {
		t.Fatal(err)
	}
	defer hp.Close()

	c, err := net.Dial("tcp", hp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// CONNECT request
	_, _ = c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", resp.StatusCode)
	}
}

func TestSystemProxyRegistryAndBackupRecovery(t *testing.T) {
	if !IsMockSysProxy() {
		t.Fatal("IsMockSysProxy() MUST be true under go test to protect host Windows Registry")
	}
	// Verify mock mutations stay strictly in-memory
	if err := SetSystemProxy("127.0.0.1:10809", true); err != nil {
		t.Fatal(err)
	}
	en, srv, err := GetSystemProxy()
	if err != nil || !en || srv != "127.0.0.1:10809" {
		t.Fatalf("unexpected mock state: enabled=%v server=%q err=%v", en, srv, err)
	}
	_ = SetSystemProxy("", false)

	dir := t.TempDir()
	backupPath := filepath.Join(dir, "sysproxy_backup.json")
	snap := ProxySnapshot{Enabled: false, Server: "", Override: ""}
	b, _ := json.Marshal(snap)
	if err := os.WriteFile(backupPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "client.json")
	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected NewEngine to recover and remove sysproxy_backup.json")
	}
}

func TestRouterZeroDNSLeakAndCNBypass(t *testing.T) {
	r := NewRouter()

	cases := []struct {
		mode   RouteMode
		target string
		want   RouteAction
	}{
		{RouteRule, "192.168.1.1:80", ActionDirect},
		{RouteRule, "10.0.0.1:443", ActionDirect},
		{RouteRule, "223.5.5.5:53", ActionDirect},
		{RouteRule, "114.114.114.114:53", ActionDirect},
		{RouteRule, "8.8.8.8:53", ActionProxy},
		{RouteRule, "1.1.1.1:443", ActionProxy},
		{RouteRule, "www.baidu.com:443", ActionDirect},
		{RouteRule, "tsinghua.edu.cn:443", ActionDirect},
		{RouteRule, "api.github.com:443", ActionProxy},
		{RouteRule, "nonexistent-overseas-test.invalid:443", ActionProxy},
		{RouteGlobal, "www.baidu.com:443", ActionProxy},
		{RouteGlobal, "127.0.0.1:8080", ActionDirect},
		{RouteCore, "api.github.com:443", ActionProxy},
		{RouteCore, "127.0.0.1:8080", ActionDirect},
		{RouteRule, "gft.internal.panel:80", ActionProxy},
	}
	for _, tc := range cases {
		if got := r.Decide(tc.mode, tc.target); got != tc.want {
			t.Fatalf("Decide(%s, %q) = %v, want %v", tc.mode, tc.target, got, tc.want)
		}
	}
}

func TestEngineMultiNodeRouteTransportAndClashYAML(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "client.json")
	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	l1 := (&gft.Link{V: 3, Host: "node1.example", Port: 443, SNI: "ftp.jaist.ac.jp", PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Verify: "ca", Remark: "NodeOne"}).Encode()
	l2 := (&gft.Link{V: 3, Host: "node2.example", Port: 443, SNI: "ftp.riken.jp", PSK: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", Verify: "ca", Remark: "NodeTwo"}).Encode()

	i1, err := eng.ImportLink(l1, true)
	if err != nil || i1 != 0 {
		t.Fatalf("ImportLink 1 failed: idx=%d err=%v", i1, err)
	}
	i2, err := eng.ImportLink(l2, true)
	if err != nil || i2 != 1 {
		t.Fatalf("ImportLink 2 failed: idx=%d err=%v", i2, err)
	}
	if err := eng.SetRouteMode(RouteGlobal); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetTransport("quic"); err != nil {
		t.Fatal(err)
	}
	if stT := eng.Status(); stT["transport_pref"] != "rtc" {
		t.Fatalf("expected legacy quic normalized to rtc, got %v", stT["transport_pref"])
	}
	if err := eng.SetBandwidthLimits(30, 100); err != nil {
		t.Fatal(err)
	}
	if stBW := eng.Status(); stBW["up_mbps"] != 30 || stBW["down_mbps"] != 100 {
		t.Fatalf("expected up_mbps=30 down_mbps=100, got up=%v down=%v", stBW["up_mbps"], stBW["down_mbps"])
	}
	yb := eng.ClashYAML()
	if !strings.Contains(yb, "type: socks5") || !strings.Contains(yb, "udp: true") || !strings.Contains(yb, "NodeTwo") {
		t.Fatalf("unexpected Clash Meta YAML:\n%s", yb)
	}

	if err := eng.RenameNode(1, "  Tokyo-Custom  "); err != nil {
		t.Fatalf("RenameNode failed: %v", err)
	}
	if stR := eng.Status(); stR["node_name"] != "Tokyo-Custom" {
		t.Fatalf("expected renamed node_name=Tokyo-Custom, got %v", stR["node_name"])
	}
	engReload, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatalf("reload engine failed: %v", err)
	}
	if stRL := engReload.Status(); stRL["node_name"] != "Tokyo-Custom" {
		engReload.Close()
		t.Fatalf("expected persisted node_name=Tokyo-Custom, got %v", stRL["node_name"])
	}
	engReload.Close()
	if err := eng.RenameNode(1, ""); err != nil {
		t.Fatalf("RenameNode fallback failed: %v", err)
	}
	if stRF := eng.Status(); stRF["node_name"] != "node2.example:443" {
		t.Fatalf("expected fallback node_name=node2.example:443, got %v", stRF["node_name"])
	}

	if err := eng.SelectNode(0); err != nil {
		t.Fatal(err)
	}
	st := eng.Status()
	if st["node_name"] != "NodeOne" || st["route_mode"] != "global" {
		t.Fatalf("unexpected status after SelectNode(0): %+v", st)
	}

	if err := eng.DeleteNode(1); err != nil {
		t.Fatal(err)
	}
	st2 := eng.Status()
	nodes, _ := st2["nodes"].([]NodeSummary)
	if len(nodes) != 1 || nodes[0].Name != "NodeOne" {
		t.Fatalf("expected 1 remaining node after DeleteNode(1), got %+v", st2["nodes"])
	}
}

func TestSOCKS5UDPAssociateRejectedWhenDisconnected(t *testing.T) {
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	socks := NewSOCKS5Server("127.0.0.1:0", eng)
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()

	c, err := net.Dial("tcp", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var rep [2]byte
	_, _ = io.ReadFull(c, rep[:])
	// CMD 0x03 UDP ASSOCIATE
	_, _ = c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	var resp [10]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x05 {
		t.Fatalf("expected 0x05 error when disconnected, got %d", resp[1])
	}
}

func TestUnifiedRouteCoreAndSysProxyLinkage(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(cfgPath, []byte(`{"route_mode":"direct"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if st := eng.Status(); st["route_mode"] != "core" {
		t.Fatalf("expected legacy 'direct' migrated to 'core', got %v", st["route_mode"])
	}

	if err := eng.SetRouteMode(RouteRule); err != nil {
		t.Fatal(err)
	}
	if !eng.Status()["sys_proxy"].(bool) {
		t.Fatalf("expected sys_proxy=true in Rule mode")
	}

	if err := eng.SetRouteMode(RouteCore); err != nil {
		t.Fatal(err)
	}
	if eng.Status()["sys_proxy"].(bool) {
		t.Fatalf("expected sys_proxy=false in Core mode")
	}
}

func TestHTTPProxyThrottledDisconnectLogAndSilentDirectFailure(t *testing.T) {
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	hp := NewHTTPProxyServer("127.0.0.1:0", eng)
	if err := hp.Start(); err != nil {
		t.Fatal(err)
	}
	defer hp.Close()

	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", hp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		_, _ = io.ReadAll(c)
		_ = c.Close()
	}

	// 4 immediate bursts while disconnected must produce at most 1 waiting log line
	logs := eng.Logs()
	waitCount := 0
	for _, l := range logs {
		if strings.Contains(l.Message, "Waiting for connection") {
			waitCount++
		}
	}
	if waitCount != 1 {
		t.Fatalf("expected 1 throttled waiting log line across 4 bursts, got %d (%+v)", waitCount, logs)
	}
}

func freeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestSetProxyPortsHotSwapAndAtomicRollback(t *testing.T) {
	if !IsMockSysProxy() {
		t.Fatal("IsMockSysProxy() must be true under go test")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.json")

	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Seed a dummy node so ClashYAML() outputs full YAML
	_ = eng.SetLink(&gft.Link{V: 3, Host: "198.51.100.10", Port: 443, PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Verify: "spki", Pin: strings.Repeat("a", 64), Remark: "TestNode"})

	s1 := freeTestPort(t)
	h1 := freeTestPort(t)
	for h1 == s1 {
		h1 = freeTestPort(t)
	}
	eng.OverrideListenAddrs(fmt.Sprintf("127.0.0.1:%d", s1), fmt.Sprintf("127.0.0.1:%d", h1))
	if err := eng.StartServers(); err != nil {
		t.Fatal(err)
	}
	_ = eng.SaveConfig()

	// 1. Validation rejections
	if err := eng.SetProxyPorts(80, h1); err == nil {
		t.Fatal("expected error for port < 1024")
	}
	if err := eng.SetProxyPorts(s1, s1); err == nil {
		t.Fatal("expected error for identical ports")
	}

	// 2. Atomic rollback when target HTTP port is already occupied
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busyLn.Close()
	busyPort := busyLn.Addr().(*net.TCPAddr).Port

	freeS := freeTestPort(t)
	if err := eng.SetProxyPorts(freeS, busyPort); err == nil {
		t.Fatalf("expected conflict error when HTTP port %d is occupied", busyPort)
	}
	// Verify freeS was rolled back (not leaked listening) and original s1/h1 still work
	if probe, perr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", freeS)); perr != nil {
		t.Fatalf("expected pre-bound SOCKS5 port %d to be closed on rollback: %v", freeS, perr)
	} else {
		_ = probe.Close()
	}
	if c, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h1), time.Second); derr != nil {
		t.Fatalf("original HTTP listener %d must remain intact on failed swap: %v", h1, derr)
	} else {
		_ = c.Close()
	}

	// 3. Hot swap while connected must update listeners, config, ClashYAML, and mock sysproxy
	//    without overwriting sysproxy_backup.json
	backupPath := filepath.Join(dir, "sysproxy_backup.json")
	origBackup := `{"enabled":false,"server":"127.0.0.1:9999","override":"orig","applied":"127.0.0.1:10809"}`
	if err := os.WriteFile(backupPath, []byte(origBackup), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.mu.Lock()
	eng.state = StateConnected
	eng.config.RouteMode = RouteRule
	eng.sysProxyApplied = true
	eng.mu.Unlock()

	s2 := freeTestPort(t)
	h2 := freeTestPort(t)
	for h2 == s2 || h2 == busyPort || s2 == busyPort {
		h2 = freeTestPort(t)
	}
	if err := eng.SetProxyPorts(s2, h2); err != nil {
		t.Fatalf("SetProxyPorts(%d, %d) failed: %v", s2, h2, err)
	}

	// Verify new ports accept TCP connections & old ports closed
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h2), time.Second)
	if err != nil {
		t.Fatalf("new HTTP port %d not accepting: %v", h2, err)
	}
	_ = c.Close()
	cs, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s2), time.Second)
	if err != nil {
		t.Fatalf("new SOCKS5 port %d not accepting: %v", s2, err)
	}
	_ = cs.Close()

	// Check ClashYAML updated
	if !strings.Contains(eng.ClashYAML(), fmt.Sprintf("port: %d", s2)) {
		t.Fatalf("ClashYAML did not reflect new port %d:\n%s", s2, eng.ClashYAML())
	}

	// Check mock sysproxy pointed to h2 and backup untouched
	en, srv, err := GetSystemProxy()
	if err != nil || !en || srv != fmt.Sprintf("127.0.0.1:%d", h2) {
		t.Fatalf("expected sysproxy updated to %d, got enabled=%v server=%q err=%v", h2, en, srv, err)
	}
	gotBackup, err := os.ReadFile(backupPath)
	if err != nil || string(gotBackup) != origBackup {
		t.Fatalf("sysproxy_backup.json was modified! got=%q", string(gotBackup))
	}

	// Check persisted client.json
	rawCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved ClientConfig
	if err := json.Unmarshal(rawCfg, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.SocksAddr != fmt.Sprintf("127.0.0.1:%d", s2) || saved.HTTPAddr != fmt.Sprintf("127.0.0.1:%d", h2) {
		t.Fatalf("saved config mismatch: socks=%q http=%q", saved.SocksAddr, saved.HTTPAddr)
	}
}

func TestStartServersAutoFallbackWhenPortsOccupied(t *testing.T) {
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	occSocks := ln1.Addr().String()
	occHTTP := ln2.Addr().String()
	eng.OverrideListenAddrs(occSocks, occHTTP)

	if err := eng.StartServersAutoFallback(); err != nil {
		t.Fatalf("expected auto fallback to succeed when configured ports are occupied: %v", err)
	}
	st := eng.Status()
	if st["socks_addr"] == occSocks || st["http_addr"] == occHTTP {
		t.Fatalf("expected fallback to new addresses, still got socks=%v http=%v", st["socks_addr"], st["http_addr"])
	}
}

var _ = time.Now
var _ = fmt.Sprintf
var _ = context.Background
