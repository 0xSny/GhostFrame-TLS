package tui

import (
	"errors"
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
