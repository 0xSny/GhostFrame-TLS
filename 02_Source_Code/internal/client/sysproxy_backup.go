package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
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

// IsMockSysProxy returns true when any sandbox condition is active:
// Go test execution, -no-sysproxy flag, GFT_NO_SYSPROXY=1, or GFT_MOCK_SYSPROXY=1.
func IsMockSysProxy() bool {
	return testing.Testing() ||
		noSysProxy.Load() ||
		os.Getenv("GFT_NO_SYSPROXY") == "1" ||
		os.Getenv("GFT_MOCK_SYSPROXY") == "1"
}

func setMockSystemProxy(addr string, enable bool) {
	mockProxyMu.Lock()
	mockProxyVal.Enabled = enable
	if enable && addr != "" {
		mockProxyVal.Server = addr
		mockProxyVal.Override = "localhost;127.*;10.*;172.16.*;192.168.*;<local>"
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

// EnableSystemProxyWithBackup saves the user's pre-existing system proxy into
// backupPath (if not already backed up) before enabling addr.
func EnableSystemProxyWithBackup(addr, backupPath string) error {
	sysProxyBackupMu.Lock()
	defer sysProxyBackupMu.Unlock()

	if backupPath != "" {
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			snap, err := QueryFullSystemProxy()
			if err == nil {
				snap.Applied = addr
				_ = os.MkdirAll(filepath.Dir(backupPath), 0o755)
				if b, jerr := json.MarshalIndent(snap, "", "  "); jerr == nil {
					_ = os.WriteFile(backupPath, b, 0o600)
				}
			}
		}
	}
	return SetSystemProxy(addr, true)
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
				if aerr := ApplySystemProxySnapshot(snap); aerr != nil {
					return aerr
				}
				_ = os.Remove(backupPath)
				return nil
			}
			_ = os.Remove(backupPath)
		}
	}
	return SetSystemProxy("", false)
}

// RecoverSystemProxyIfDirty runs on startup to restore pre-crash proxy state if
// sysproxy_backup.json was left behind by a non-graceful termination.
func RecoverSystemProxyIfDirty(backupPath string) (bool, error) {
	if backupPath == "" {
		return false, nil
	}
	if _, err := os.Stat(backupPath); err != nil {
		return false, nil
	}
	err := DisableAndRestoreSystemProxy(backupPath)
	return true, err
}
