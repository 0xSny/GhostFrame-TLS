//go:build !windows

package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func checkAvailableDiskSpace(dir string, minBytes uint64) error {
	cur := filepath.Clean(dir)
	for {
		if _, err := os.Stat(cur); err == nil {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(cur, &st); err != nil {
		return fmt.Errorf("检查磁盘空间失败 (%s): %w", cur, err)
	}
	avail := uint64(st.Bavail) * uint64(st.Bsize)
	if avail < minBytes {
		return fmt.Errorf("可用磁盘空间不足 (%s 剩余 %d MiB，至少需要 %d MiB)",
			cur, avail/(1<<20), minBytes/(1<<20))
	}
	return nil
}

func reexecSelf(binaryPath string, args []string) error {
	if len(args) == 0 {
		args = []string{binaryPath}
	}
	return syscall.Exec(binaryPath, args, os.Environ())
}
