//go:build linux

package tproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
	"golang.org/x/sys/unix"
)

const (
	udpSessionIdle    = 45 * time.Second
	maxUDPNatSessions = 1024
)

var directReplyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

type udpTuple struct {
	isV6    bool
	srcIP   [16]byte
	srcPort uint16
	dstIP   [16]byte
	dstPort uint16
}

func (t udpTuple) srcNetIP() net.IP {
	if t.isV6 {
		ip := make(net.IP, 16)
		copy(ip, t.srcIP[:])
		return ip
	}
	return net.IPv4(t.srcIP[0], t.srcIP[1], t.srcIP[2], t.srcIP[3])
}

func (t udpTuple) dstNetIP() net.IP {
	if t.isV6 {
		ip := make(net.IP, 16)
		copy(ip, t.dstIP[:])
		return ip
	}
	return net.IPv4(t.dstIP[0], t.dstIP[1], t.dstIP[2], t.dstIP[3])
}

func (t udpTuple) replySockaddr() unix.Sockaddr {
	if t.isV6 {
		return &unix.SockaddrInet6{Port: int(t.srcPort), Addr: t.srcIP}
	}
	var a [4]byte
	copy(a[:], t.srcIP[:4])
	return &unix.SockaddrInet4{Port: int(t.srcPort), Addr: a}
}

type udpNatEntry struct {
	tuple    udpTuple
	srcAddr  *net.UDPAddr
	dstAddr  *net.UDPAddr
	dstStr   string
	assoc    gft.UDPAssociation
	direct   net.PacketConn
	replyFD  int
	lastUsed atomic.Int64
	closeFn  func()
}

// UDPServer accepts Linux TPROXY UDP packets via IP_TRANSPARENT + IP_RECVORIGDSTADDR
// (and optional IPV6_TRANSPARENT + IPV6_RECVORIGDSTADDR on [::1])
// and relays them via GFT UDPAssociation or direct 0xff-marked sockets.
type UDPServer struct {
	addr     string
	port     int
	engine   *client.Engine
	modeFn   func() GatewayMode
	fd       int
	fd6      int
	closed   chan struct{}
	closeMu  sync.Mutex
	mu       sync.Mutex
	sessions map[udpTuple]*udpNatEntry
	conns    atomic.Uint64
}

// NewUDPServer creates a Linux UDP TPROXY server bound to addr (e.g. "127.0.0.1:10881").
func NewUDPServer(addr string, eng *client.Engine, modeFn func() GatewayMode) (*UDPServer, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return nil, errors.New("tproxy udp: invalid port")
	}
	return &UDPServer{
		addr:     addr,
		port:     p,
		engine:   eng,
		modeFn:   modeFn,
		fd:       -1,
		fd6:      -1,
		closed:   make(chan struct{}),
		sessions: make(map[udpTuple]*udpNatEntry),
	}, nil
}

// Start opens the IP_TRANSPARENT + IP_RECVORIGDSTADDR UDP socket and starts the read + reaper loops.
func (s *UDPServer) Start() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
		_ = unix.Close(fd)
		return err
	}
	ua, err := net.ResolveUDPAddr("udp4", s.addr)
	if err != nil {
		_ = unix.Close(fd)
		return err
	}
	var sa unix.SockaddrInet4
	sa.Port = ua.Port
	if ip4 := ua.IP.To4(); ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	if err := unix.Bind(fd, &sa); err != nil {
		_ = unix.Close(fd)
		return err
	}
	s.fd = fd
	go s.readLoop(fd)

	// Optional IPv6 TPROXY UDP listener on [::1]:<port>
	if fd6, err6 := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP); err6 == nil {
		_ = unix.SetsockoptInt(fd6, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		_ = unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		if unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1) == nil &&
			unix.SetsockoptInt(fd6, unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1) == nil {
			sa6 := &unix.SockaddrInet6{Port: s.port, Addr: [16]byte{15: 1}}
			if unix.Bind(fd6, sa6) == nil {
				s.fd6 = fd6
				go s.readLoop6(fd6)
			} else {
				_ = unix.Close(fd6)
			}
		} else {
			_ = unix.Close(fd6)
		}
	}

	go s.reapLoop()
	return nil
}

// HasIPv6 reports whether the IPv6 UDP TPROXY listener is active on [::1]:<port>.
func (s *UDPServer) HasIPv6() bool {
	return s.fd6 >= 0
}

// Close closes the TPROXY UDP listener and all active NAT sessions.
func (s *UDPServer) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	if s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
	if s.fd6 >= 0 {
		_ = unix.Close(s.fd6)
		s.fd6 = -1
	}
	s.mu.Lock()
	for k, ent := range s.sessions {
		delete(s.sessions, k)
		if ent.closeFn != nil {
			ent.closeFn()
		}
	}
	s.mu.Unlock()
}

// Count returns total unique UDP transparent flows created.
func (s *UDPServer) Count() uint64 {
	return s.conns.Load()
}

func (s *UDPServer) readLoop(fd int) {
	buf := make([]byte, 64*1024)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, fromSA, err := unix.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		if n <= 0 || oobn <= 0 {
			continue
		}
		srcSA, ok := fromSA.(*unix.SockaddrInet4)
		if !ok || srcSA.Port <= 0 {
			continue
		}
		dstIP, dstPort, ok := parseOrigDstAddr(oob[:oobn])
		if !ok || dstPort == 0 {
			continue
		}
		// Never forward loopback/self-loop packets.
		if net.IP(dstIP[:]).IsLoopback() {
			continue
		}

		var tup udpTuple
		copy(tup.srcIP[:4], srcSA.Addr[:])
		tup.srcPort = uint16(srcSA.Port)
		copy(tup.dstIP[:4], dstIP[:])
		tup.dstPort = dstPort

		ent := s.getOrCreateSession(tup)
		if ent == nil {
			continue
		}
		ent.lastUsed.Store(time.Now().UnixNano())
		payload := buf[:n]
		if ent.assoc != nil {
			_ = ent.assoc.SendTo(ent.dstStr, payload)
		} else if ent.direct != nil {
			_, _ = ent.direct.WriteTo(payload, ent.dstAddr)
		}
	}
}

func (s *UDPServer) readLoop6(fd int) {
	buf := make([]byte, 64*1024)
	oob := make([]byte, 1024)
	for {
		n, oobn, _, fromSA, err := unix.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		if n <= 0 || oobn <= 0 {
			continue
		}
		if s.engine != nil && !s.engine.IPv6Enabled() {
			continue
		}
		srcSA, ok := fromSA.(*unix.SockaddrInet6)
		if !ok || srcSA.Port <= 0 {
			continue
		}
		dstIP, dstPort, ok := parseOrigDstAddr6(oob[:oobn])
		if !ok || dstPort == 0 {
			continue
		}
		if net.IP(dstIP[:]).IsLoopback() {
			continue
		}

		tup := udpTuple{
			isV6:    true,
			srcIP:   srcSA.Addr,
			srcPort: uint16(srcSA.Port),
			dstIP:   dstIP,
			dstPort: dstPort,
		}
		ent := s.getOrCreateSession(tup)
		if ent == nil {
			continue
		}
		ent.lastUsed.Store(time.Now().UnixNano())
		payload := buf[:n]
		if ent.assoc != nil {
			_ = ent.assoc.SendTo(ent.dstStr, payload)
		} else if ent.direct != nil {
			_, _ = ent.direct.WriteTo(payload, ent.dstAddr)
		}
	}
}

func (s *UDPServer) getOrCreateSession(tup udpTuple) *udpNatEntry {
	s.mu.Lock()
	if ent, ok := s.sessions[tup]; ok {
		s.mu.Unlock()
		return ent
	}
	s.mu.Unlock()

	srcIP := tup.srcNetIP()
	dstIP := tup.dstNetIP()
	dstStr := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(tup.dstPort)))
	gwMode := ModeRule
	if s.modeFn != nil {
		gwMode = s.modeFn()
	}

	act := client.ActionProxy
	if gwMode == ModeRule {
		act = s.engine.RouteDecision(dstStr)
	}
	if act == client.ActionReject {
		return nil
	}

	replyFD, err := openTransparentReplySocket(tup)
	if err != nil {
		return nil
	}

	ent := &udpNatEntry{
		tuple:   tup,
		srcAddr: &net.UDPAddr{IP: srcIP, Port: int(tup.srcPort)},
		dstAddr: &net.UDPAddr{IP: dstIP, Port: int(tup.dstPort)},
		dstStr:  dstStr,
		replyFD: replyFD,
	}
	ent.lastUsed.Store(time.Now().UnixNano())

	if act == client.ActionDirect {
		lc := net.ListenConfig{Control: netbind.Control}
		listenNet, listenAddr := "udp4", ":0"
		if tup.isV6 {
			listenNet, listenAddr = "udp6", "[::]:0"
		}
		pc, err := lc.ListenPacket(context.Background(), listenNet, listenAddr)
		if err != nil {
			_ = unix.Close(replyFD)
			return nil
		}
		ent.direct = pc
		ent.closeFn = func() {
			_ = pc.Close()
			_ = unix.Close(replyFD)
		}
		go s.pumpDirectReplies(ent)
	} else {
		assoc, err := s.engine.OpenUDPAssociation()
		if err != nil {
			_ = unix.Close(replyFD)
			return nil
		}
		ent.assoc = assoc
		ent.closeFn = func() {
			_ = assoc.Close()
			_ = unix.Close(replyFD)
		}
		go s.pumpTunnelReplies(ent)
	}

	var evicted *udpNatEntry
	s.mu.Lock()
	if existing, ok := s.sessions[tup]; ok {
		s.mu.Unlock()
		ent.closeFn()
		return existing
	}
	if len(s.sessions) >= maxUDPNatSessions {
		var oldestKey udpTuple
		var oldestTS int64
		first := true
		for k, candidate := range s.sessions {
			ts := candidate.lastUsed.Load()
			if first || ts < oldestTS {
				first = false
				oldestTS = ts
				oldestKey = k
				evicted = candidate
			}
		}
		if evicted != nil {
			delete(s.sessions, oldestKey)
		}
	}
	s.sessions[tup] = ent
	s.mu.Unlock()
	if evicted != nil && evicted.closeFn != nil {
		evicted.closeFn()
	}
	s.conns.Add(1)
	return ent
}

func (s *UDPServer) pumpTunnelReplies(ent *udpNatEntry) {
	defer s.removeSession(ent.tuple)
	dstSA := ent.tuple.replySockaddr()
	for {
		select {
		case <-s.closed:
			return
		case <-ent.assoc.Done():
			return
		case pkt, ok := <-ent.assoc.Recv():
			if !ok {
				return
			}
			ent.lastUsed.Store(time.Now().UnixNano())
			_ = unix.Sendto(ent.replyFD, pkt.Data, 0, dstSA)
		}
	}
}

func (s *UDPServer) pumpDirectReplies(ent *udpNatEntry) {
	defer s.removeSession(ent.tuple)
	dstSA := ent.tuple.replySockaddr()

	sc, ok := ent.direct.(syscall.Conn)
	if !ok {
		for {
			bp := directReplyBufPool.Get().(*[]byte)
			n, _, err := ent.direct.ReadFrom(*bp)
			if err != nil {
				directReplyBufPool.Put(bp)
				return
			}
			ent.lastUsed.Store(time.Now().UnixNano())
			_ = unix.Sendto(ent.replyFD, (*bp)[:n], 0, dstSA)
			directReplyBufPool.Put(bp)
		}
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return
	}
	for {
		var readErr error
		ctrlErr := rawConn.Read(func(rfd uintptr) bool {
			bp := directReplyBufPool.Get().(*[]byte)
			buf := *bp
			n, _, rerr := unix.Recvfrom(int(rfd), buf, unix.MSG_DONTWAIT)
			if rerr != nil {
				directReplyBufPool.Put(bp)
				if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK || rerr == unix.EINTR {
					return false
				}
				readErr = rerr
				return true
			}
			ent.lastUsed.Store(time.Now().UnixNano())
			_ = unix.Sendto(ent.replyFD, buf[:n], 0, dstSA)
			directReplyBufPool.Put(bp)
			return true
		})
		if ctrlErr != nil || readErr != nil {
			return
		}
	}
}

func (s *UDPServer) removeSession(tup udpTuple) {
	s.mu.Lock()
	ent, ok := s.sessions[tup]
	if ok {
		delete(s.sessions, tup)
	}
	s.mu.Unlock()
	if ok && ent.closeFn != nil {
		ent.closeFn()
	}
}

func (s *UDPServer) reapLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case now := <-t.C:
			cutoff := now.Add(-udpSessionIdle).UnixNano()
			var stale []*udpNatEntry
			s.mu.Lock()
			for k, ent := range s.sessions {
				if ent.lastUsed.Load() < cutoff {
					delete(s.sessions, k)
					stale = append(stale, ent)
				}
			}
			s.mu.Unlock()
			for _, ent := range stale {
				if ent.closeFn != nil {
					ent.closeFn()
				}
			}
		}
	}
}

func openTransparentReplySocket(tup udpTuple) (int, error) {
	if tup.isV6 {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
		if err != nil {
			return -1, err
		}
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1)
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		if mark := netbind.OutboundMark(); mark > 0 {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
		}
		sa := &unix.SockaddrInet6{
			Port: int(tup.dstPort),
			Addr: tup.dstIP,
		}
		if err := unix.Bind(fd, sa); err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	// Tag reply packet with FWMark (0xff) so mangle_output never re-intercepts it.
	if mark := netbind.OutboundMark(); mark > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	}
	var srcIP4 [4]byte
	copy(srcIP4[:], tup.dstIP[:4])
	sa := &unix.SockaddrInet4{
		Port: int(tup.dstPort),
		Addr: srcIP4,
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func parseOrigDstAddr(oob []byte) ([4]byte, uint16, bool) {
	var zero [4]byte
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return zero, 0, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_ORIGDSTADDR && len(m.Data) >= 8 {
			family := binary.LittleEndian.Uint16(m.Data[0:2])
			if family == unix.AF_INET {
				port := binary.BigEndian.Uint16(m.Data[2:4])
				var ip [4]byte
				copy(ip[:], m.Data[4:8])
				return ip, port, true
			}
		}
	}
	return zero, 0, false
}

func parseOrigDstAddr6(oob []byte) ([16]byte, uint16, bool) {
	var zero [16]byte
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return zero, 0, false
	}
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR && len(m.Data) >= 24 {
			family := binary.LittleEndian.Uint16(m.Data[0:2])
			if family == unix.AF_INET6 {
				port := binary.BigEndian.Uint16(m.Data[2:4])
				var ip [16]byte
				copy(ip[:], m.Data[8:24])
				return ip, port, true
			}
		}
	}
	return zero, 0, false
}

var _ = unsafe.Sizeof(0)
