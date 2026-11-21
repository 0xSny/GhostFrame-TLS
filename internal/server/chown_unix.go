//go:build !windows

package server

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func statUIDGID(path string) (uid, gid int, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

func resolveDesiredOwnerFromStats(fileUID, fileGID int, fileOK bool, dirUID, dirGID int, dirOK bool) (uid, gid int, shouldChown bool) {
	if fileOK && (fileUID > 0 || fileGID > 0) {
		return fileUID, fileGID, true
	}
	if dirOK && (dirUID > 0 || dirGID > 0) {
		return dirUID, dirGID, true
	}
	return 0, 0, false
}

func resolveDesiredOwner(targetPath string) (uid, gid int, shouldChown bool) {
	fuid, fgid, fok := statUIDGID(targetPath)
	duid, dgid, dok := statUIDGID(filepath.Dir(targetPath))
	return resolveDesiredOwnerFromStats(fuid, fgid, fok, duid, dgid, dok)
}

func preserveFileOwnership(tmpPath, targetPath string, perm os.FileMode) {
	if os.Geteuid() == 0 {
		if uid, gid, ok := resolveDesiredOwner(targetPath); ok {
			_ = os.Chown(tmpPath, uid, gid)
		}
	}
	_ = os.Chmod(tmpPath, perm)
}

// HealConfigDirOwnership restores service-user ownership on config/cert/key files
// inside a non-root owned config directory (e.g. /etc/kestrel owned by gft:gft)
// if a prior root-run TUI/CLI write left them owned by root:root.
func HealConfigDirOwnership(cfgPath string) {
	if os.Geteuid() != 0 || strings.TrimSpace(cfgPath) == "" {
		return
	}
	dir := filepath.Dir(cfgPath)
	duid, dgid, dok := statUIDGID(dir)
	if !dok || (duid == 0 && dgid == 0) {
		return
	}
	candidates := []string{
		cfgPath,
		cfgPath + ".bak",
		filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "cert.pem.bak"),
		filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "key.pem.bak"),
	}
	for _, p := range candidates {
		if fuid, fgid, fok := statUIDGID(p); fok && fuid == 0 && fgid == 0 {
			_ = os.Chown(p, duid, dgid)
		}
	}
}
