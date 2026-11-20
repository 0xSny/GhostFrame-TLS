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

const udpSessionIdle = 45 * time.Second

type udpTuple struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
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
// and relays them via GFT UDPAssociation or direct 0xff-marked sockets.
type UDPServer struct {
	addr     string
	port     int
	engine   *client.Engine
	modeFn   func() GatewayMode
	fd       int
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
	go s.reapLoop()
	return nil
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

		tup := udpTuple{
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

	dstStr := net.JoinHostPort(net.IP(tup.dstIP[:]).String(), strconv.Itoa(int(tup.dstPort)))
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

	replyFD, err := openTransparentReplySocket(tup.dstIP, tup.dstPort)
	if err != nil {
		return nil
	}

	ent := &udpNatEntry{
		tuple:   tup,
		srcAddr: &net.UDPAddr{IP: net.IP(tup.srcIP[:]), Port: int(tup.srcPort)},
		dstAddr: &net.UDPAddr{IP: net.IP(tup.dstIP[:]), Port: int(tup.dstPort)},
		dstStr:  dstStr,
		replyFD: replyFD,
	}
	ent.lastUsed.Store(time.Now().UnixNano())

	if act == client.ActionDirect {
		lc := net.ListenConfig{Control: netbind.Control}
		pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
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

	s.mu.Lock()
	if existing, ok := s.sessions[tup]; ok {
		s.mu.Unlock()
		ent.closeFn()
		return existing
	}
	s.sessions[tup] = ent
	s.mu.Unlock()
	s.conns.Add(1)
	return ent
}

func (s *UDPServer) pumpTunnelReplies(ent *udpNatEntry) {
	defer s.removeSession(ent.tuple)
	var dstSA unix.SockaddrInet4
	dstSA.Addr = ent.tuple.srcIP
	dstSA.Port = int(ent.tuple.srcPort)
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
			_ = unix.Sendto(ent.replyFD, pkt.Data, 0, &dstSA)
		}
	}
}

func (s *UDPServer) pumpDirectReplies(ent *udpNatEntry) {
	defer s.removeSession(ent.tuple)
	var dstSA unix.SockaddrInet4
	dstSA.Addr = ent.tuple.srcIP
	dstSA.Port = int(ent.tuple.srcPort)
	buf := make([]byte, 64*1024)
	for {
		n, _, err := ent.direct.ReadFrom(buf)
		if err != nil {
			return
		}
		ent.lastUsed.Store(time.Now().UnixNano())
		_ = unix.Sendto(ent.replyFD, buf[:n], 0, &dstSA)
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

func openTransparentReplySocket(srcIP [4]byte, srcPort uint16) (int, error) {
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
	sa := &unix.SockaddrInet4{
		Port: int(srcPort),
		Addr: srcIP,
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

var _ = unsafe.Sizeof(0)
