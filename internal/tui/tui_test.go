package tui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/server"
)

func TestDisplayWidthAndBoxRightBorderAlignment(t *testing.T) {
	c := NewController("")
	c.Box = BoxStyle{UTF8: true, Color: true, Width: 76}
	cfg := &server.Config{
		Listen:       ":443",
		PublicHost:   "198.51.100.10",
		SNI:          "ftp.jaist.ac.jp",
		CertMode:     "self_signed_90d",
		FallbackMode: "mirror",
		HopRange:     "20000-30000",
	}
	snap := server.RuntimeSnapshot{
		TotalUp:      12 * 1024 * 1024,
		TotalDown:    256 * 1024 * 1024,
		UpBps:        64 * 1024,
		DownBps:      4 * 1024 * 1024,
		BlockedCount: 42,
	}
	frame := c.RenderDashboard(cfg, true, "bbr+fq", snap, 14*time.Millisecond)
	lines := strings.Split(strings.TrimSpace(frame), "\n")
	if len(lines) < 10 {
		t.Fatalf("unexpected short dashboard (%d lines)", len(lines))
	}
	wantW := DisplayWidth(lines[0])
	for i, ln := range lines {
		w := DisplayWidth(ln)
		if w != wantW {
			t.Fatalf("line %d width mismatch: got %d want %d\nline=%q", i, w, wantW, StripANSI(ln))
		}
	}
}

func TestPureGoQREncoderAndRenderer(t *testing.T) {
	uri := "gft3://eyJ2IjozLCJob3N0IjoiMTk4LjUxLjEwMC4xMCIsInBvcnQiOjQ0Mywic25pIjoiZnRwLmphaXN0LmFjLmpwIiwicHNrIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9IiwidmVyaWZ5Ijoic3BraSIsInBpbiI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYifQ#GFT"
	mat, err := EncodeQR(uri)
	if err != nil {
		t.Fatalf("EncodeQR failed: %v", err)
	}
	n := len(mat)
	if n < 29 || len(mat[0]) != n {
		t.Fatalf("invalid QR matrix size %dx%d", n, len(mat[0]))
	}
	if !mat[0][0] || !mat[3][3] || !mat[0][n-1] || !mat[n-1][0] {
		t.Fatalf("finder corner modules corrupted")
	}
	utfQR, err := RenderTerminalQR(uri, true)
	if err != nil || !strings.Contains(utfQR, "▀") {
		t.Fatalf("expected UTF-8 half-block QR output, got err=%v", err)
	}
	ascQR, err := RenderTerminalQR(uri, false)
	if err != nil || !strings.Contains(ascQR, "##") {
		t.Fatalf("expected ASCII QR output, got err=%v", err)
	}
}

func TestTransactionRunnerAutomaticRollbackOnPortConflict(t *testing.T) {
	tmp := t.TempDir()
	confDir := filepath.Join(tmp, "conf")
	_, err := server.InitWithOptions(server.InitOptions{
		ConfDir:  confDir,
		StateDir: filepath.Join(tmp, "state"),
		Host:     "198.51.100.10",
		SNI:      "ftp.jaist.ac.jp",
		Listen:   ":443",
		CertMode: "self_signed_90d",
		HopRange: "20000-21000",
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(confDir, "server.json")

	var fwApplied [2]string
	tx := NewTransactionRunner(cfgPath)
	tx.LockPath = filepath.Join(tmp, "menu.lock")
	tx.ProbeTimeout = 350 * time.Millisecond
	tx.RestartFn = func() error { return nil }
	tx.ActiveFn = func() bool { return true }
	tx.ApplyHopFn = func(hopRange string, port int) error {
		fwApplied[0] = fwApplied[1]
		fwApplied[1] = hopRange + ":" + string(rune('0'+port/1000))
		return nil
	}
	tx.PortProbeFn = func(port int) error {
		if port == 9999 {
			return errors.New("port 9999 failed startup health check (occupied)")
		}
		return nil
	}

	err = tx.Apply(func(c *server.Config) error {
		c.Listen = ":9999"
		c.SNI = "broken.example"
		c.HopRange = "25000-26000"
		return nil
	})
	if err == nil {
		t.Fatal("expected Apply to fail on port 9999 health probe and roll back")
	}

	after, rerr := server.LoadConfig(cfgPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if after.Listen != ":443" || after.SNI != "ftp.jaist.ac.jp" || after.HopRange != "20000-21000" {
		t.Fatalf("rollback failed to restore original config: %+v", after)
	}
	if !strings.HasPrefix(fwApplied[1], "20000-21000") {
		t.Fatalf("expected firewall hop rule restored cleanly, history=%v", fwApplied)
	}
	_ = gft.DefaultParams()
}

func TestParseProcNetUDPPortsAndApplyHopExemptions(t *testing.T) {
	procSample := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:53AF 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 00000000 0
   1: 00000000:9C3F 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12346 2 00000000 0
   2: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12347 2 00000000 0
   3: 00000000:7530 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12348 2 00000000 0`
	// 0x53AF = 21423, 0x9C3F = 39999, 0x01BB = 443, 0x7530 = 30000 (excluded self port)
	ports := ParseProcNetUDPPorts(procSample, 20000, 40000, 30000)
	if len(ports) != 2 || ports[0] != 21423 || ports[1] != 39999 {
		t.Fatalf("unexpected parsed proc udp ports: %v", ports)
	}

	ssSample := `State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
UNCONN 0      0            0.0.0.0:21423      0.0.0.0:*    users:(("sing-box",pid=620,fd=12))
UNCONN 0      0                  *:39999            *:*    users:(("smatrix",pid=619,fd=9))
UNCONN 0      0                  *:25555            *:*    users:(("gft-server",pid=999,fd=5))`
	ssPorts := ParseSSUDPOutput(ssSample, 20000, 40000, 443)
	if len(ssPorts) != 2 || ssPorts[0] != 21423 || ssPorts[1] != 39999 {
		t.Fatalf("unexpected parsed ss udp ports: %v", ssPorts)
	}

	// 1. Test iptables mode with >15 occupied ports (verifies multiport chunking <=15 AND RETURN before REDIRECT)
	var iptCalls []string
	manyPorts := make([]int, 17)
	for i := range manyPorts {
		manyPorts[i] = 21000 + i
	}
	fwIPT := &FirewallManager{
		HasCmdFn: func(name string) bool {
			return name == "iptables" || name == "netfilter-persistent"
		},
		DetectUDPFn: func(lo, hi, excludePort int) []int {
			return manyPorts
		},
		RunCmd: func(name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			if name == "iptables" && len(args) >= 4 && args[2] == "-C" {
				return nil, errors.New("not linked")
			}
			iptCalls = append(iptCalls, line)
			return nil, nil
		},
	}
	if err := fwIPT.ApplyHopRule("20000-40000", 443); err != nil {
		t.Fatalf("iptables ApplyHopRule failed: %v", err)
	}
	joined := strings.Join(iptCalls, "\n")
	retIdx := strings.Index(joined, "-m multiport --dports")
	redirIdx := strings.Index(joined, "-j REDIRECT --to-ports 443")
	if retIdx < 0 || redirIdx < 0 || retIdx >= redirIdx {
		t.Fatalf("expected multiport RETURN rule strictly before REDIRECT:\n%s", joined)
	}
	if !strings.Contains(joined, "-p udp --dport 21015,21016") && !strings.Contains(joined, "-m multiport --dports 21015,21016 -j RETURN") {
		t.Fatalf("expected second chunk for remaining 2 ports:\n%s", joined)
	}
	if !strings.Contains(joined, "netfilter-persistent save") {
		t.Fatalf("expected netfilter-persistent save call:\n%s", joined)
	}

	// 2. Test nftables mode emits RETURN set strictly before redirect
	var nftStdin string
	fwNFT := &FirewallManager{
		HasCmdFn: func(name string) bool { return name == "nft" },
		DetectUDPFn: func(lo, hi, excludePort int) []int {
			return []int{21423, 39999}
		},
		RunCmd: func(name string, args ...string) ([]byte, error) {
			if name == "nft" && len(args) == 3 && args[0] == "-f" && args[1] == "-" {
				nftStdin = args[2]
			}
			return nil, nil
		},
	}
	if err := fwNFT.ApplyHopRule("20000-40000", 443); err != nil {
		t.Fatalf("nft ApplyHopRule failed: %v", err)
	}
	nftRet := strings.Index(nftStdin, "udp dport { 21423, 39999 } return")
	nftRedir := strings.Index(nftStdin, "udp dport 20000-40000 redirect to :443")
	if nftRet < 0 || nftRedir < 0 || nftRet >= nftRedir {
		t.Fatalf("expected nft RETURN rule before REDIRECT, got:\n%s", nftStdin)
	}
}

func TestApplyKernelSysctlWritesAndExecutes(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "99-gft-rtc.conf")
	var cmds []string
	err := ApplyKernelSysctl(confPath, func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		return []byte("ok"), nil
	})
	if err != nil {
		t.Fatalf("ApplyKernelSysctl failed: %v", err)
	}
	raw, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "net.core.rmem_max = 33554432") || !strings.Contains(string(raw), "bbr") {
		t.Fatalf("unexpected sysctl content:\n%s", string(raw))
	}
	if len(cmds) != 2 || !strings.Contains(cmds[0], "sysctl -p "+confPath) || cmds[1] != "sysctl --system" {
		t.Fatalf("unexpected sysctl commands: %v", cmds)
	}
}
