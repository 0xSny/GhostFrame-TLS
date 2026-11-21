//go:build windows

package server

import "os"

func preserveFileOwnership(tmpPath, _ string, perm os.FileMode) {
	_ = os.Chmod(tmpPath, perm)
}

// HealConfigDirOwnership is a no-op on Windows.
func HealConfigDirOwnership(_ string) {}
