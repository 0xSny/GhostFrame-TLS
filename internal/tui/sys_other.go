//go:build windows

package tui

func checkAvailableDiskSpace(_ string, _ uint64) error {
	return nil
}

func reexecSelf(_ string, _ []string) error {
	return nil
}
