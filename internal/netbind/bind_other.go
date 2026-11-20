//go:build !darwin

package netbind

import "syscall"

// DetectPhysicalInterface returns an empty string on non-Darwin platforms where physical interface pinning is disabled.
func DetectPhysicalInterface() string {
	return ""
}

// Control is a zero-cost no-op on Windows and Linux so desktop/server networking remains unchanged.
func Control(network, address string, c syscall.RawConn) error {
	return nil
}
