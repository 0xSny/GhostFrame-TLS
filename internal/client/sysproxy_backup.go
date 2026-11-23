package client

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ProxySnapshot captures system proxy settings before GhostFrame modifies them.
type ProxySnapshot struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Override string `json:"override"`
	Applied  string `json:"applied,omitempty"`
}

var (
	sysProxyBackupMu sync.Mutex

	noSysProxy   atomic.Bool
	mockProxyMu  sync.Mutex
	mockProxyVal ProxySnapshot
)

// SetNoSysProxy enables or disables the in-memory system proxy sandbox lock.
// When enabled, Windows Registry Internet Settings are never read or modified.
func SetNoSysProxy(disable bool) {
	noSysProxy.Store(disable)
}

// WindowsProxyOverride lists all loopback, RFC1918, link-local, and local bypass ranges for WinINET.
const WindowsProxyOverride = "localhost;127.*;[::1];10.*;169.254.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// IsMockSysProxy returns true when any sandbox condition is active:
// Go test execution, -no-sysproxy flag, KSL_NO_SYSPROXY=1, or KSL_MOCK_SYSPROXY=1 (legacy GFT_* aliases supported).
func IsMockSysProxy() bool {
	return testing.Testing() ||
		noSysProxy.Load() ||
		os.Getenv("KSL_NO_SYSPROXY") == "1" ||
		os.Getenv("KSL_MOCK_SYSPROXY") == "1" ||
		os.Getenv("GFT_NO_SYSPROXY") == "1" ||
		os.Getenv("GFT_MOCK_SYSPROXY") == "1"
}

func setMockSystemProxy(addr string, enable bool) {
	mockProxyMu.Lock()
	mockProxyVal.Enabled = enable
	if enable && addr != "" {
		mockProxyVal.Server = addr
		mockProxyVal.Override = WindowsProxyOverride
	}
	mockProxyMu.Unlock()
}

func getMockSystemProxy() (bool, string, error) {
	mockProxyMu.Lock()
	defer mockProxyMu.Unlock()
	return mockProxyVal.Enabled, mockProxyVal.Server, nil
}

func queryMockSystemProxy() ProxySnapshot {
	mockProxyMu.Lock()
	defer mockProxyMu.Unlock()
	return mockProxyVal
}

func applyMockSystemProxySnapshot(snap ProxySnapshot) {
	mockProxyMu.Lock()
	mockProxyVal = snap
	mockProxyMu.Unlock()
}

// IsLocalLoopbackProxy reports whether a Windows proxy server string points to 127.0.0.1 / localhost / ::1.
func IsLocalLoopbackProxy(server string) bool {
	s := strings.TrimSpace(server)
	if s == "" {
		return false
	}
	parts := strings.Split(s, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			part = strings.TrimSpace(part[eq+1:])
		}
		part = strings.TrimPrefix(part, "http://")
		part = strings.TrimPrefix(part, "https://")
		part = strings.TrimPrefix(part, "socks5://")
		part = strings.TrimPrefix(part, "socks://")
		host := part
		if h, _, err := net.SplitHostPort(part); err == nil {
			host = h
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		if strings.EqualFold(host, "localhost") {
			return true
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

func extractLoopbackHostPort(server string) string {
	for _, part := range strings.Split(server, ";") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			part = strings.TrimSpace(part[eq+1:])
		}
		part = strings.TrimPrefix(part, "http://")
		part = strings.TrimPrefix(part, "https://")
		part = strings.TrimPrefix(part, "socks5://")
		part = strings.TrimPrefix(part, "socks://")
		if h, p, err := net.SplitHostPort(part); err == nil && p != "" {
			hh := strings.Trim(h, "[]")
			if strings.EqualFold(hh, "localhost") {
				return net.JoinHostPort("127.0.0.1", p)
			}
			if ip := net.ParseIP(hh); ip != nil && ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), p)
			}
		}
	}
	return ""
}

func isLoopbackProxyDead(server string) bool {
	hp := extractLoopbackHostPort(server)
	if hp == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", hp, 80*time.Millisecond)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

// EnableSystemProxyWithBackup saves the user's pre-existing system proxy into
// backupPath (if not already backed up) before enabling addr.
// Never records a dirty/stale GhostFrame loopback proxy as the clean baseline.
func EnableSystemProxyWithBackup(addr, backupPath string) error {
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	if backupPath != "" {
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			snap, qerr := QueryFullSystemProxy()
			if qerr == nil {
				if snap.Enabled && IsLocalLoopbackProxy(snap.Server) {
					if strings.EqualFold(strings.TrimSpace(snap.Server), strings.TrimSpace(addr)) || isLoopbackProxyDead(snap.Server) {
						snap.Enabled = false
						snap.Server = ""
					}
				}
				snap.Applied = addr
				_ = os.MkdirAll(filepath.Dir(backupPath), 0o755)
				if b, jerr := json.MarshalIndent(snap, "", "  "); jerr == nil {
					_ = os.WriteFile(backupPath, b, 0o600)
				}
			}
		}
	}
	if err := SetSystemProxy(addr, true); err != nil {
		return err
	}
	registerSysProxyBootRecovery(backupPath, addr)
	return nil
}

// DisableAndRestoreSystemProxy restores system proxy from backupPath (if present)
// and deletes the backup file; otherwise disables system proxy cleanly.
func DisableAndRestoreSystemProxy(backupPath string) error {
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	if backupPath != "" {
		if b, err := os.ReadFile(backupPath); err == nil {
			var snap ProxySnapshot
			if json.Unmarshal(b, &snap) == nil {
				if snap.Enabled && IsLocalLoopbackProxy(snap.Server) {
					if (snap.Applied != "" && strings.EqualFold(strings.TrimSpace(snap.Server), strings.TrimSpace(snap.Applied))) || isLoopbackProxyDead(snap.Server) {
						snap.Enabled = false
						snap.Server = ""
					}
				}
				if aerr := ApplySystemProxySnapshot(snap); aerr != nil {
					return aerr
				}
				_ = os.Remove(backupPath)
				clearSysProxyBootRecovery()
				return nil
			}
			_ = os.Remove(backupPath)
		}
	}
	if err := SetSystemProxy("", false); err != nil {
		return err
	}
	clearSysProxyBootRecovery()
	return nil
}

// RecoverSystemProxyIfDirty runs on startup to restore pre-crash proxy state if
// sysproxy_backup.json was left behind or an orphaned dead loopback proxy remains active.
func RecoverSystemProxyIfDirty(backupPath string) (bool, error) {
	return RecoverSystemProxyIfDirtyFor(backupPath, "")
}

// RecoverSystemProxyIfDirtyFor recovers either from a leftover backup file or, on power-loss,
// when the OS registry still points to a dead or expected local loopback proxy without a backup file.
func RecoverSystemProxyIfDirtyFor(backupPath, expectedHTTPAddr string) (bool, error) {
	if backupPath != "" {
		if _, err := os.Stat(backupPath); err == nil {
			rerr := DisableAndRestoreSystemProxy(backupPath)
			return true, rerr
		}
	}
	cur, qerr := QueryFullSystemProxy()
	if qerr == nil && cur.Enabled && IsLocalLoopbackProxy(cur.Server) {
		sameOwn := expectedHTTPAddr != "" && strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(expectedHTTPAddr))
		if sameOwn || isLoopbackProxyDead(cur.Server) {
			serr := SetSystemProxy("", false)
			clearSysProxyBootRecovery()
			return true, serr
		}
	}
	return false, nil
}
