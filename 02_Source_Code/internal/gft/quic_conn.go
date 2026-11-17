package gft

import (
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// DefaultQUICConfig returns hardened QUIC transport settings tuned for
// high-latency, lossy, or QoS-policed cross-border UDP networks.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           8 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     1024 * 1024,
		MaxStreamReceiveWindow:         8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 2 * 1024 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024 * 1024,
		InitialPacketSize:              1200,
		DisablePathMTUDiscovery:        true,
	}
}

// QUICStreamConn adapts a single bidirectional *quic.Stream and its parent
// *quic.Conn into a standard net.Conn for GFT Session/Knock/RewindConn reuse.
type QUICStreamConn struct {
	*quic.Stream
	Conn      *quic.Conn
	closeOnce sync.Once
}

// LocalAddr returns the local UDP address of the QUIC connection.
func (c *QUICStreamConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote UDP address of the QUIC connection.
func (c *QUICStreamConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// CloseWrite half-closes the outgoing QUIC stream direction.
func (c *QUICStreamConn) CloseWrite() error {
	return c.Stream.Close()
}

// Close terminates both the stream and the underlying QUIC connection.
func (c *QUICStreamConn) Close() error {
	c.closeOnce.Do(func() {
		c.Stream.CancelRead(0)
		_ = c.Stream.Close()
		_ = c.Conn.CloseWithError(0, "")
	})
	return nil
}
