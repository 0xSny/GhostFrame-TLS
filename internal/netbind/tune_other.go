//go:build !linux

package netbind

import (
	"net"
	"time"
)

// TuneTCPConn enables TCP_NODELAY and TCP keepalives on non-Linux outer carrier sockets.
func TuneTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(15 * time.Second)
}
