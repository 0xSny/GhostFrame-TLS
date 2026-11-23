//go:build linux

package netbind

import (
	"syscall"
)

// DetectPhysicalInterface returns an empty string on Linux; side-router sockets rely on SO_MARK routing.
func DetectPhysicalInterface() string {
	return ""
}

// Control protects Android VpnService sockets (when SetSocketProtector is registered)
// and attaches Linux SO_MARK (when OutboundMark() > 0) to every non-loopback
// outbound TCP/UDP socket (Kestrel-RTC, lazy port-hopping, TCP-uTLS, and direct CN bypass),
// guaranteeing kernel-level anti-loop isolation in VPN and transparent gateway modes.
func Control(network, address string, c syscall.RawConn) error {
	if isLoopbackAddress(address) {
		return nil
	}
	mark := OutboundMark()
	hasProtector := HasSocketProtector()
	if mark <= 0 && !hasProtector {
		return nil
	}
	_ = c.Control(func(fd uintptr) {
		if hasProtector {
			_ = ProtectSocketFD(fd)
		}
		if mark > 0 {
			// Best-effort: ignore EPERM/EACCES when running unprivileged outside root/CAP_NET_ADMIN.
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}
	})
	return nil
}
