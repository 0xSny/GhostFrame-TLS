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
		{RouteDirect, "api.github.com:443", ActionDirect},
		{RouteDirect, "gft.internal.panel:80", ActionProxy},
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
	yb := eng.ClashYAML()
	if !strings.Contains(yb, "type: socks5") || !strings.Contains(yb, "udp: true") || !strings.Contains(yb, "NodeTwo") {
		t.Fatalf("unexpected Clash Meta YAML:\n%s", yb)
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

var _ = time.Now
var _ = fmt.Sprintf
var _ = context.Background
