//go:build linux

package netbind

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// TuneTCPConn applies low-bufferbloat and rapid dead-peer detection options
// (TCP_NODELAY, TCP_NOTSENT_LOWAT, TCP_USER_TIMEOUT, and aggressive keepalives)
// on outer carrier TCP sockets so multi-TCP scheduling observes real kernel backpressure.
func TuneTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(15 * time.Second)
	raw, err := tc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		// Cap unsent kernel TCP buffer at 64KB so slow carrier sockets apply
		// immediate backpressure to user-space BondGroup health scheduling.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, 65536)
		// Fail stalled unacknowledged TCP writes in 15s instead of ~15m RTO default.
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 15000)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 15)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 5)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 3)
	})
}
