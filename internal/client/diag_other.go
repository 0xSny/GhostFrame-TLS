//go:build !windows

package client

func copyTextClipboardNative(_ uintptr, _ string) bool {
	return false
}
