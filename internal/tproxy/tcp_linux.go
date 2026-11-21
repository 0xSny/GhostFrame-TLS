//go:build linux

package tproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"ghostframe/internal/client"
	"golang.org/x/sys/unix"
)

var tcpCopyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

// TCPServer accepts Linux TPROXY and REDIRECT TCP flows on 127.0.0.1:<port>
// and forwards them through client.Engine after optional SNI/HTTP Host sniffing.
type TCPServer struct {
	addr     string
	listenIP string
	port     int
	engine    *client.Engine
	modeFn    func() GatewayMode
	listener  net.Listener
	listener6 net.Listener
	closed    chan struct{}
	closeMu  sync.Mutex
	conns    atomic.Uint64
}

// NewTCPServer creates a Linux transparent TCP listener (supports both TPROXY and REDIRECT).
func NewTCPServer(addr string, eng *client.Engine, modeFn func() GatewayMode) (*TCPServer, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return nil, errors.New("tproxy tcp: invalid port")
	}
	return &TCPServer{
		addr:     addr,
		listenIP: host,
		port:     p,
		engine:   eng,
		modeFn:   modeFn,
		closed:   make(chan struct{}),
	}, nil
}

// Start binds the IP_TRANSPARENT TCP listener and accepts connections.
func (s *TCPServer) Start() error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			_ = c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
					sockErr = err
				}
			})
			// Non-fatal if CAP_NET_ADMIN missing; REDIRECT still works on standard sockets.
			_ = sockErr
			return nil
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp4", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln
	go s.acceptLoop(ln)

	lc6 := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
			})
			return nil
		},
	}
	if ln6, err6 := lc6.Listen(context.Background(), "tcp6", net.JoinHostPort("::1", strconv.Itoa(s.port))); err6 == nil {
		s.listener6 = ln6
		go s.acceptLoop(ln6)
	}
	return nil
}

// HasIPv6 reports whether the IPv6 TCP TPROXY listener is active on [::1]:<port>.
func (s *TCPServer) HasIPv6() bool {
	return s.listener6 != nil
}

// Close stops accepting new connections.
func (s *TCPServer) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.listener6 != nil {
		_ = s.listener6.Close()
	}
}

// Count returns total accepted TCP transparent connections.
func (s *TCPServer) Count() uint64 {
	return s.conns.Load()
}

func (s *TCPServer) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				time.Sleep(25 * time.Millisecond)
				continue
			}
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
		s.conns.Add(1)
		go s.handleConn(c)
	}
}

func (s *TCPServer) handleConn(c net.Conn) {
	defer c.Close()

	dialTarget, ok := extractTCPOriginalDst(c, s.port)
	if !ok {
		return
	}

	var clientConn net.Conn = c
	routeTarget := dialTarget
	gwMode := ModeRule
	if s.modeFn != nil {
		gwMode = s.modeFn()
	}
	if gwMode == ModeRule {
		if domain, rewound := SniffTCPDomain(c, 25*time.Millisecond); rewound != nil {
			clientConn = rewound
			if domain != "" {
				if _, portStr, err := net.SplitHostPort(dialTarget); err == nil {
					routeTarget = net.JoinHostPort(domain, portStr)
				}
			}
		}
	}

	st, _, err := s.engine.OpenTargetStreamWithRoute(dialTarget, routeTarget, nil)
	if err != nil {
		return
	}
	defer st.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bufPtr := tcpCopyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(st, clientConn, *bufPtr)
		tcpCopyBufPool.Put(bufPtr)
		_ = st.CloseWrite()
	}()

	bufPtr := tcpCopyBufPool.Get().(*[]byte)
	_, _ = io.CopyBuffer(c, st, *bufPtr)
	tcpCopyBufPool.Put(bufPtr)
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	wg.Wait()
}

func extractTCPOriginalDst(c net.Conn, listenPort int) (string, bool) {
	// Under Linux TPROXY, c.LocalAddr() holds the true remote destination IP:Port (IPv4 or IPv6).
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok && ta != nil && ta.IP != nil {
		if ip4 := ta.IP.To4(); ip4 != nil {
			if !ip4.IsLoopback() || ta.Port != listenPort {
				return net.JoinHostPort(ip4.String(), strconv.Itoa(ta.Port)), true
			}
		} else if ip16 := ta.IP.To16(); ip16 != nil {
			if !ip16.IsLoopback() || ta.Port != listenPort {
				return net.JoinHostPort(ip16.String(), strconv.Itoa(ta.Port)), true
			}
		}
	}

	// Fallback for iptables/ip6tables/nftables REDIRECT: query SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST (80).
	const ip6tSOOriginalDst = 80
	sc, ok := c.(syscall.Conn)
	if !ok {
		return "", false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return "", false
	}
	var target string
	var got bool
	_ = raw.Control(func(fd uintptr) {
		var addr [16]byte
		addrLen := uint32(len(addr))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.SOL_IP,
			unix.SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr[0])),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno == 0 && addrLen >= 8 {
			port := binary.BigEndian.Uint16(addr[2:4])
			ip := net.IPv4(addr[4], addr[5], addr[6], addr[7])
			if !ip.IsLoopback() && port > 0 {
				target = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
				got = true
				return
			}
		}
		var addr6 [28]byte
		addr6Len := uint32(len(addr6))
		_, _, errno6 := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.SOL_IPV6,
			ip6tSOOriginalDst,
			uintptr(unsafe.Pointer(&addr6[0])),
			uintptr(unsafe.Pointer(&addr6Len)),
			0,
		)
		if errno6 == 0 && addr6Len >= 24 {
			port := binary.BigEndian.Uint16(addr6[2:4])
			ip := make(net.IP, net.IPv6len)
			copy(ip, addr6[8:24])
			if !ip.IsLoopback() && port > 0 {
				target = net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
				got = true
			}
		}
	})
	return target, got
}
