package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
	"ghostframe/internal/server"
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

func TestNAT64DirectCNProbeAndWireRespTTL(t *testing.T) {
	restore := netbind.SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("64:ff9b::192.0.0.170")}, nil
		},
		nil,
	)
	defer restore()

	var mu sync.Mutex
	var dialed []string
	setCNProbeTargetHook(func(network, addr string) {
		mu.Lock()
		dialed = append(dialed, network+"|"+addr)
		mu.Unlock()
	})
	defer setCNProbeTargetHook(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	_, _, _ = defaultDirectCNProbe(ctx, "example.cn")

	mu.Lock()
	joined := strings.Join(dialed, ",")
	mu.Unlock()
	if !strings.Contains(joined, "udp|[64:ff9b::df05:505]:53") ||
		!strings.Contains(joined, "udp|[64:ff9b::771d:1d1d]:53") ||
		!strings.Contains(joined, "udp|[2400:3200::1]:53") ||
		!strings.Contains(joined, "udp|[2402:4e00::]:53") {
		t.Fatalf("expected defaultDirectCNProbe to dial NAT64 64:ff9b + native IPv6 CN DNS over udp, got %q", joined)
	}
	if strings.Contains(joined, "udp4|") {
		t.Fatalf("unexpected hardcoded udp4 dial in defaultDirectCNProbe: %q", joined)
	}

	// Verify wireResp expires after 30s while ActionDirect stays cached for 10m.
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	wire := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	eng.smartCache.Put(smartRouteEntry{
		host:     "fresh-test.example",
		act:      ActionDirect,
		reason:   "direct:cn-dns",
		directIP: "223.5.5.5",
		wireResp: wire,
		wireAt:   time.Now().Add(-31 * time.Second),
	})
	act, gotWire, _ := eng.ResolveSmartDNS(RouteRule, "fresh-test.example", []byte{0xab, 0xcd})
	if act != ActionDirect {
		t.Fatalf("expected cached ActionDirect, got %v", act)
	}
	if gotWire != nil {
		t.Fatalf("expected stale wireResp (>30s) to be withheld so SplitDNSServer fetches fresh A record, got len=%d", len(gotWire))
	}
}

var _ = time.Now
var _ = fmt.Sprintf
var _ = context.Background

func startLocalTestServerForClient(t *testing.T, remark string) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	sec, err := server.InitWithOptions(server.InitOptions{
		ConfDir:      filepath.Join(dir, "conf"),
		StateDir:     filepath.Join(dir, "state"),
		Host:         "127.0.0.1",
		Listen:       "127.0.0.1:0",
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "builtin",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := server.LoadConfig(filepath.Join(dir, "conf", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DisableQUIC = true
	srv, err := server.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.TCPAddr(); a != nil {
			l, err := gft.ParseLink(sec.Link)
			if err != nil {
				cancel()
				<-done
				t.Fatal(err)
			}
			_, pStr, _ := net.SplitHostPort(a.String())
			fmt.Sscanf(pStr, "%d", &l.Port)
			l.Transport = "tcp"
			l.Remark = remark
			return l.Encode(), func() {
				cancel()
				<-done
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("local test server did not start")
	return "", nil
}

func TestSelectNodeMakeBeforeBreakLossless(t *testing.T) {
	SetNoSysProxy(true)
	uri1, stop1 := startLocalTestServerForClient(t, "NodeOne")
	defer stop1()
	uri2, stop2 := startLocalTestServerForClient(t, "NodeTwo")
	defer stop2()

	// Create a closed port URI for testing rollback on failed node switch.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()
	deadLink, err := gft.ParseLink(uri2)
	if err != nil {
		t.Fatal(err)
	}
	deadLink.Port = deadPort
	deadLink.Remark = "DeadNode"
	uriDead := deadLink.Encode()

	eng, err := NewEngine(filepath.Join(t.TempDir(), "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	if _, err := eng.ImportLink(uri1, true); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ImportLink(uri2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ImportLink(uriDead, false); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetRouteMode(RouteCore); err != nil {
		t.Fatal(err)
	}
	if err := eng.Connect(); err != nil {
		t.Fatalf("initial Connect failed: %v", err)
	}
	if !eng.IsConnected() {
		t.Fatal("expected connected state after initial Connect")
	}

	// Poll connection state continuously while performing lossless switch from Node 1 -> Node 2.
	var dropped atomic.Bool
	stopPoll := make(chan struct{})
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		for {
			select {
			case <-stopPoll:
				return
			default:
				if !eng.IsConnected() {
					dropped.Store(true)
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()

	if err := eng.SelectNode(1); err != nil {
		close(stopPoll)
		<-pollDone
		t.Fatalf("lossless SelectNode(1) failed: %v", err)
	}
	close(stopPoll)
	<-pollDone
	if dropped.Load() {
		t.Fatal("engine reported disconnected during make-before-break node switch")
	}
	st := eng.Status()
	if st["state"] != string(StateConnected) || st["node_name"] != "NodeTwo" || st["active_node"] != 1 {
		t.Fatalf("unexpected status after lossless switch: %+v", st)
	}

	// Switching to a dead node MUST return error while keeping NodeTwo connected and active.
	if err := eng.SelectNode(2); err == nil {
		t.Fatal("expected error switching to dead node")
	}
	stAfterFail := eng.Status()
	if !eng.IsConnected() || stAfterFail["state"] != string(StateConnected) || stAfterFail["node_name"] != "NodeTwo" || stAfterFail["active_node"] != 1 {
		t.Fatalf("expected rollback preserving NodeTwo connected, got %+v", stAfterFail)
	}
}

func TestEngineIPv6ToggleAndStrictReject(t *testing.T) {
	SetNoSysProxy(true)
	cfgPath := filepath.Join(t.TempDir(), "client.json")
	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Default EnableIPv6 is false for strict anti-leak safety.
	if eng.IPv6Enabled() {
		t.Fatal("expected EnableIPv6=false by default")
	}
	if en, _ := eng.Status()["enable_ipv6"].(bool); en {
		t.Fatalf("expected Status()[enable_ipv6]=false by default")
	}

	// While IPv6 is disabled, literal non-loopback IPv6 targets MUST be rejected in Rule and Global modes,
	// whereas loopback ::1 stays direct so local loopback tools aren't broken.
	if act, _, reason := eng.DecideSmartRoute("[2606:4700:4700::1111]:443", "[2606:4700:4700::1111]:443"); act != ActionReject || reason != "ipv6:disabled" {
		t.Fatalf("expected ActionReject(ipv6:disabled) for overseas IPv6 when disabled, got act=%v reason=%q", act, reason)
	}
	if act, _, reason := eng.DecideSmartRoute("[2408:8207:1::1]:443", "[2408:8207:1::1]:443"); act != ActionReject || reason != "ipv6:disabled" {
		t.Fatalf("expected ActionReject(ipv6:disabled) for CN IPv6 when disabled, got act=%v reason=%q", act, reason)
	}
	if err := eng.SetRouteMode(RouteGlobal); err != nil {
		t.Fatal(err)
	}
	if act, _, reason := eng.DecideSmartRoute("[2606:4700:4700::1111]:443", "[2606:4700:4700::1111]:443"); act != ActionReject || reason != "ipv6:disabled" {
		t.Fatalf("expected Global mode ActionReject(ipv6:disabled) when IPv6 disabled, got act=%v reason=%q", act, reason)
	}
	if act, _, _ := eng.DecideSmartRoute("[::1]:8080", "[::1]:8080"); act != ActionDirect {
		t.Fatalf("expected ::1 loopback ActionDirect, got %v", act)
	}

	// Enable IPv6: persists config and enables dual-stack Rule/Global routing.
	if err := eng.SetEnableIPv6(true); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetRouteMode(RouteRule); err != nil {
		t.Fatal(err)
	}
	if !eng.IPv6Enabled() {
		t.Fatal("expected IPv6Enabled=true after SetEnableIPv6(true)")
	}
	if act, _, reason := eng.DecideSmartRoute("[2408:8207:1::1]:443", "[2408:8207:1::1]:443"); act != ActionDirect || reason != "geoip:cn" {
		t.Fatalf("expected CN IPv6 ActionDirect(geoip:cn) when IPv6 enabled, got act=%v reason=%q", act, reason)
	}
	if act, _, reason := eng.DecideSmartRoute("[2606:4700:4700::1111]:443", "[2606:4700:4700::1111]:443"); act != ActionProxy || reason != "geoip:overseas" {
		t.Fatalf("expected overseas IPv6 ActionProxy(geoip:overseas) when IPv6 enabled, got act=%v reason=%q", act, reason)
	}

	// Reload from disk verifies persistence of EnableIPv6=true.
	eng2, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer eng2.Close()
	if !eng2.IPv6Enabled() {
		t.Fatal("expected EnableIPv6=true to persist across NewEngine reload")
	}
}

func TestAutoConnectPreservedOnCloseAndClearedOnUserDisconnect(t *testing.T) {
	SetNoSysProxy(true)
	defer applyMockSystemProxySnapshot(ProxySnapshot{})

	uri1, stop1 := startLocalTestServerForClient(t, "AutoResumeNode")
	defer stop1()

	cfgPath := filepath.Join(t.TempDir(), "client.json")
	eng, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.ImportLink(uri1, true); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetRouteMode(RouteRule); err != nil {
		t.Fatal(err)
	}
	if err := eng.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !eng.ShouldAutoConnect() {
		t.Fatal("expected ShouldAutoConnect=true after successful Connect")
	}
	if enabled, _, _ := GetSystemProxy(); !enabled {
		t.Fatal("expected mock system proxy enabled while connected in Rule mode")
	}

	// Software close cleans system proxy without clearing user's active AutoConnect intent.
	eng.Close()
	if enabled, _, _ := GetSystemProxy(); enabled {
		t.Fatal("expected dirty system proxy cleared after Close()")
	}

	reopened, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.ShouldAutoConnect() {
		reopened.Close()
		t.Fatal("expected ShouldAutoConnect=true preserved across software restart")
	}

	// Explicit user Disconnect clears AutoConnect so subsequent launch stays disconnected.
	if err := reopened.SetAutoConnect(false); err != nil {
		reopened.Close()
		t.Fatal(err)
	}
	reopened.Disconnect()
	reopened.Close()

	reopened2, err := NewEngine(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened2.Close()
	if reopened2.ShouldAutoConnect() {
		t.Fatal("expected ShouldAutoConnect=false after explicit user disconnect")
	}
}
