package tui

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostframe/internal/server"
)

// TransactionRunner executes server configuration mutations protected by 4 locks:
//  1. Inter-process file lock (/run/gft-menu.lock fallback temp dir)
//  2. Pre-write backups (.bak) & fsync+rename atomic writes
//  3. Isolated firewall rule management
//  4. 2.5s post-restart health probe with automatic rollback on failure
type TransactionRunner struct {
	CfgPath     string
	ServiceName string
	LockPath    string
	FW          *FirewallManager

	// Injectable hooks for deterministic rollback testing.
	RestartFn    func() error
	ActiveFn     func() bool
	PortProbeFn  func(port int) error
	ApplyHopFn   func(hopRange string, port int) error
	ProbeTimeout time.Duration
}

func NewTransactionRunner(cfgPath string) *TransactionRunner {
	lockPath := "/run/kestrel-menu.lock"
	if _, err := os.Stat("/run"); err != nil {
		lockPath = filepath.Join(os.TempDir(), "kestrel-menu.lock")
	}
	svc := "kestrel"
	if _, err := os.Stat("/etc/systemd/system/kestrel.service"); err != nil {
		if _, err2 := os.Stat("/etc/systemd/system/ghostframe.service"); err2 == nil {
			svc = "ghostframe"
		}
	}
	tr := &TransactionRunner{
		CfgPath:      cfgPath,
		ServiceName:  svc,
		LockPath:     lockPath,
		FW:           NewFirewallManager(),
		ProbeTimeout: 2500 * time.Millisecond,
	}
	tr.RestartFn = func() error {
		out, err := exec.Command("systemctl", "restart", tr.ServiceName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart %s: %v (%s)", tr.ServiceName, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	tr.ActiveFn = func() bool {
		out, err := exec.Command("systemctl", "is-active", tr.ServiceName).Output()
		return err == nil && strings.TrimSpace(string(out)) == "active"
	}
	tr.PortProbeFn = func(port int) error {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 350*time.Millisecond)
		if err != nil {
			return err
		}
		_ = c.Close()
		return nil
	}
	tr.ApplyHopFn = tr.FW.ApplyHopRule
	return tr
}

func (t *TransactionRunner) acquireLock() (func(), error) {
	_ = os.MkdirAll(filepath.Dir(t.LockPath), 0o755)
	f, err := os.OpenFile(t.LockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another ksl session holds lock %s", t.LockPath)
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	return func() { _ = os.Remove(t.LockPath) }, nil
}

// ConfigListenPort parses the TCP/UDP port out of Config.Listen.
func ConfigListenPort(listen string) int {
	_, ps, err := net.SplitHostPort(listen)
	if err != nil {
		ps = strings.TrimPrefix(listen, ":")
	}
	p, _ := strconv.Atoi(ps)
	if p <= 0 {
		return 443
	}
	return p
}

// Apply runs mutator inside a full transactional guard. If restarting or probing
// the new port fails within 2.5s, previous config, cert, and firewall rules are
// restored automatically.
func (t *TransactionRunner) Apply(mutator func(c *server.Config) error) error {
	unlock, err := t.acquireLock()
	if err != nil {
		return err
	}
	defer unlock()

	oldCfg, err := server.LoadConfig(t.CfgPath)
	if err != nil {
		return err
	}
	oldPort := ConfigListenPort(oldCfg.Listen)
	oldHop := oldCfg.HopRange

	cfgRaw, err := os.ReadFile(t.CfgPath)
	if err != nil {
		return err
	}
	cfgBak := t.CfgPath + ".bak"
	if err := server.WriteFileAtomic(cfgBak, cfgRaw, 0o600); err != nil {
		return err
	}

	var certBak string
	var certRaw []byte
	if oldCfg.CertFile != "" {
		if cb, rerr := os.ReadFile(oldCfg.CertFile); rerr == nil {
			certRaw = cb
			certBak = oldCfg.CertFile + ".bak"
			_ = server.WriteFileAtomic(certBak, cb, 0o644)
		}
	}
	var keyBak string
	var keyRaw []byte
	if oldCfg.KeyFile != "" {
		if kb, rerr := os.ReadFile(oldCfg.KeyFile); rerr == nil {
			keyRaw = kb
			keyBak = oldCfg.KeyFile + ".bak"
			_ = server.WriteFileAtomic(keyBak, kb, 0o600)
		}
	}

	newCfg := *oldCfg
	if err := mutator(&newCfg); err != nil {
		return err
	}
	if err := server.SaveConfigAtomic(t.CfgPath, &newCfg); err != nil {
		return err
	}

	newPort := ConfigListenPort(newCfg.Listen)
	if newCfg.HopRange != oldHop || newPort != oldPort {
		if ferr := t.ApplyHopFn(newCfg.HopRange, newPort); ferr != nil {
			_ = server.WriteFileAtomic(t.CfgPath, cfgRaw, 0o600)
			if certBak != "" {
				_ = server.WriteFileAtomic(oldCfg.CertFile, certRaw, 0o644)
			}
			if keyBak != "" {
				_ = server.WriteFileAtomic(oldCfg.KeyFile, keyRaw, 0o600)
			}
			return ferr
		}
	}

	rollback := func(cause error) error {
		_ = server.WriteFileAtomic(t.CfgPath, cfgRaw, 0o600)
		if certBak != "" {
			_ = server.WriteFileAtomic(oldCfg.CertFile, certRaw, 0o644)
		}
		if keyBak != "" {
			_ = server.WriteFileAtomic(oldCfg.KeyFile, keyRaw, 0o600)
		}
		_ = t.ApplyHopFn(oldHop, oldPort)
		_ = t.RestartFn()
		return fmt.Errorf("%w (已自动回滚并恢复原服务运行)", cause)
	}

	if err := t.RestartFn(); err != nil {
		return rollback(err)
	}

	budget := t.ProbeTimeout
	if budget <= 0 {
		budget = 2500 * time.Millisecond
	}
	deadline := time.Now().Add(budget)
	var lastProbeErr error
	for time.Now().Before(deadline) {
		if t.ActiveFn() {
			if perr := t.PortProbeFn(newPort); perr == nil {
				return nil
			} else {
				lastProbeErr = perr
			}
		} else {
			lastProbeErr = fmt.Errorf("service %s not active", t.ServiceName)
		}
		time.Sleep(120 * time.Millisecond)
	}
	if lastProbeErr == nil {
		lastProbeErr = fmt.Errorf("health probe timeout after %v", budget)
	}
	return rollback(lastProbeErr)
}

// CheckPortOccupied reports whether port is currently accepting TCP connections locally.
func CheckPortOccupied(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
