package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmp, perm)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

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
// Fails before modifying OS proxy if querying or persisting the backup fails.
func EnableSystemProxyWithBackup(addr, backupPath string) error {
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	if backupPath != "" {
		_, statErr := os.Stat(backupPath)
		switch {
		case os.IsNotExist(statErr):
			snap, qerr := QueryFullSystemProxy()
			if qerr != nil {
				return fmt.Errorf("query system proxy before takeover: %w", qerr)
			}
			// Only clear if the OS proxy is already pointing at our own addr; never wipe third-party loopback proxies.
			if snap.Enabled && strings.EqualFold(strings.TrimSpace(snap.Server), strings.TrimSpace(addr)) {
				snap.Enabled = false
				snap.Server = ""
			}
			snap.Applied = addr
			b, jerr := json.MarshalIndent(snap, "", "  ")
			if jerr != nil {
				return jerr
			}
			if werr := writeFileAtomic(backupPath, b, 0o600); werr != nil {
				return fmt.Errorf("persist system proxy backup: %w", werr)
			}
		case statErr != nil:
			return fmt.Errorf("inspect system proxy backup: %w", statErr)
		default:
			raw, rerr := os.ReadFile(backupPath)
			if rerr != nil {
				return fmt.Errorf("read existing system proxy backup: %w", rerr)
			}
			var snap ProxySnapshot
			if jerr := json.Unmarshal(raw, &snap); jerr != nil {
				_ = os.Rename(backupPath, backupPath+".corrupt")
				return fmt.Errorf("corrupt system proxy backup preserved as %s.corrupt: %w", backupPath, jerr)
			}
			if !strings.EqualFold(strings.TrimSpace(snap.Applied), strings.TrimSpace(addr)) {
				snap.Applied = addr
				b, jerr := json.MarshalIndent(snap, "", "  ")
				if jerr != nil {
					return jerr
				}
				if werr := writeFileAtomic(backupPath, b, 0o600); werr != nil {
					return fmt.Errorf("update system proxy backup: %w", werr)
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

// UpdateSystemProxyBackupApplied updates the recorded Applied address after a live proxy port swap.
func UpdateSystemProxyBackupApplied(backupPath, newAddr string) error {
	if backupPath == "" {
		return nil
	}
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	raw, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap ProxySnapshot
	if jerr := json.Unmarshal(raw, &snap); jerr != nil {
		_ = os.Rename(backupPath, backupPath+".corrupt")
		return fmt.Errorf("corrupt system proxy backup preserved as %s.corrupt: %w", backupPath, jerr)
	}
	snap.Applied = newAddr
	b, jerr := json.MarshalIndent(snap, "", "  ")
	if jerr != nil {
		return jerr
	}
	if werr := writeFileAtomic(backupPath, b, 0o600); werr != nil {
		return werr
	}
	registerSysProxyBootRecovery(backupPath, newAddr)
	return nil
}

// DisableAndRestoreSystemProxy restores system proxy from backupPath (if present)
// only if the OS proxy is still owned by Kestrel, and deletes the backup file.
// Corrupt backups are preserved as .corrupt and return an error without touching OS proxy.
func DisableAndRestoreSystemProxy(backupPath string) error {
	return DisableAndRestoreSystemProxyFor(backupPath, "")
}

// DisableAndRestoreSystemProxyFor restores system proxy from backupPath if the OS proxy
// still matches snap.Applied or currentAppliedAddr.
func DisableAndRestoreSystemProxyFor(backupPath, currentAppliedAddr string) error {
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	if backupPath != "" {
		b, err := os.ReadFile(backupPath)
		switch {
		case err == nil:
			var snap ProxySnapshot
			if jerr := json.Unmarshal(b, &snap); jerr != nil {
				_ = os.Rename(backupPath, backupPath+".corrupt")
				return fmt.Errorf("corrupt system proxy backup preserved as %s.corrupt: %w", backupPath, jerr)
			}
			if snap.Applied != "" || currentAppliedAddr != "" {
				if cur, qerr := QueryFullSystemProxy(); qerr == nil {
					stillOwned := cur.Enabled && (
						(snap.Applied != "" && strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(snap.Applied))) ||
							(currentAppliedAddr != "" && strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(currentAppliedAddr))))
					if !stillOwned {
						// User manually changed or disabled the system proxy; preserve their current setting.
						_ = os.Remove(backupPath)
						clearSysProxyBootRecovery()
						return nil
					}
				}
			}
			if snap.Enabled && snap.Applied != "" && strings.EqualFold(strings.TrimSpace(snap.Server), strings.TrimSpace(snap.Applied)) {
				snap.Enabled = false
				snap.Server = ""
			}
			snap.Applied = ""
			if aerr := ApplySystemProxySnapshot(snap); aerr != nil {
				return aerr
			}
			_ = os.Remove(backupPath)
			clearSysProxyBootRecovery()
			return nil
		case !os.IsNotExist(err):
			return fmt.Errorf("read system proxy backup: %w", err)
		}
	}
	if err := SetSystemProxy("", false); err != nil {
		return err
	}
	clearSysProxyBootRecovery()
	return nil
}

// RecoverSystemProxyIfDirty runs on startup to restore pre-crash proxy state if
// sysproxy_backup.json was left behind or Kestrel's own loopback proxy remains active.
func RecoverSystemProxyIfDirty(backupPath string) (bool, error) {
	return RecoverSystemProxyIfDirtyFor(backupPath, "")
}

// RecoverSystemProxyIfDirtyFor recovers either from a leftover backup file or, when no backup
// file exists, only when the OS registry still points to expectedHTTPAddr.
func RecoverSystemProxyIfDirtyFor(backupPath, expectedHTTPAddr string) (bool, error) {
	if backupPath != "" {
		if _, err := os.Stat(backupPath); err == nil {
			rerr := DisableAndRestoreSystemProxy(backupPath)
			return true, rerr
		}
	}
	cur, qerr := QueryFullSystemProxy()
	if qerr == nil && cur.Enabled && expectedHTTPAddr != "" &&
		strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(expectedHTTPAddr)) {
		serr := SetSystemProxy("", false)
		clearSysProxyBootRecovery()
		return true, serr
	}
	return false, nil
}
