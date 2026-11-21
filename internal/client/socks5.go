package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/netbind"
)

// SOCKS5Server handles SOCKS5 CONNECT (0x01) and UDP ASSOCIATE (0x03) requests.
type SOCKS5Server struct {
	addr     string
	engine   *Engine
	listener net.Listener
	closed   chan struct{}
	mu       sync.Mutex
}

// NewSOCKS5Server creates a new SOCKS5 server instance.
func NewSOCKS5Server(addr string, eng *Engine) *SOCKS5Server {
	return &SOCKS5Server{
		addr:   addr,
		engine: eng,
		closed: make(chan struct{}),
	}
}

// Start begins listening and serving connections.
func (s *SOCKS5Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-s.closed:
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			go s.handleConn(c)
		}
	}()
	return nil
}

// Addr returns the listener address.
func (s *SOCKS5Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Close stops the server.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func readSOCKS5Target(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", errors.New("unsupported atyp")
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *SOCKS5Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil || head[0] != 0x05 {
		return
	}
	nmethods := int(head[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var reqHead [4]byte
	if _, err := io.ReadFull(c, reqHead[:]); err != nil || reqHead[0] != 0x05 {
		return
	}

	target, err := readSOCKS5Target(c, reqHead[3])
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	switch reqHead[1] {
	case 0x01: // CONNECT
		if !s.engine.IsConnected() {
			_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		sendOK := func() error {
			_, werr := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return werr
		}
		st, act, rc, ackSent, err := s.engine.OpenStreamWithOptionalSNISniff(c, target, sendOK)
		c = rc
		if err != nil {
			if act == ActionProxy {
				s.engine.Logf("[SOCKS5] CONNECT %s failed: %v", target, err)
			}
			if !ackSent {
				_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}
			return
		}
		defer st.Close()

		if !ackSent {
			if err := sendOK(); err != nil {
				return
			}
		}
		_ = c.SetDeadline(time.Time{})
		gft.Relay(st, c, relayIdleTimeout())

	case 0x03: // UDP ASSOCIATE (RFC 1928)
		s.handleUDPAssociate(c)

	default:
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (s *SOCKS5Server) handleUDPAssociate(ctrl net.Conn) {
	if !s.engine.IsConnected() {
		_, _ = ctrl.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	bindIP := "127.0.0.1"
	if la, ok := ctrl.LocalAddr().(*net.TCPAddr); ok && la.IP != nil {
		if v4 := la.IP.To4(); v4 != nil {
			bindIP = v4.String()
		}
	}
	udpConn, err := net.ListenPacket("udp4", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	ua := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := ua.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1)
	}
	var rep [10]byte
	rep[0], rep[1], rep[2], rep[3] = 0x05, 0x00, 0x00, 0x01
	copy(rep[4:8], ip4)
	binary.BigEndian.PutUint16(rep[8:10], uint16(ua.Port))
	if _, err := ctrl.Write(rep[:]); err != nil {
		return
	}
	_ = ctrl.SetDeadline(time.Time{})

	var assoc gft.UDPAssociation
	var directPC4 net.PacketConn
	var directPC6 net.PacketConn
	var assocMu sync.Mutex
	done := make(chan struct{})
	defer func() {
		close(done)
		assocMu.Lock()
		if assoc != nil {
			_ = assoc.Close()
		}
		if directPC4 != nil {
			_ = directPC4.Close()
		}
		if directPC6 != nil {
			_ = directPC6.Close()
		}
		assocMu.Unlock()
	}()

	var clientAddrMu sync.RWMutex
	var clientAddr net.Addr

	// Watch TCP control connection: closing it terminates the UDP association per RFC 1928.
	go func() {
		var sink [32]byte
		for {
			if _, err := ctrl.Read(sink[:]); err != nil {
				_ = udpConn.Close()
				return
			}
		}
	}()

	sendBackToClient := func(srcTarget string, payload []byte) {
		clientAddrMu.RLock()
		ca := clientAddr
		clientAddrMu.RUnlock()
		if ca == nil {
			return
		}
		ab, err := gft.EncodeAddr(srcTarget)
		if err != nil {
			return
		}
		pkt := make([]byte, 3+len(ab)+len(payload))
		// RSV(2)=0, FRAG(1)=0, ATYP|ADDR|PORT, DATA
		copy(pkt[3:], ab)
		copy(pkt[3+len(ab):], payload)
		_, _ = udpConn.WriteTo(pkt, ca)
	}

	ensureProxyAssoc := func() (gft.UDPAssociation, error) {
		assocMu.Lock()
		defer assocMu.Unlock()
		if assoc != nil {
			select {
			case <-assoc.Done():
				assoc = nil
			default:
				return assoc, nil
			}
		}
		a, err := s.engine.OpenUDPAssociation()
		if err != nil {
			return nil, err
		}
		assoc = a
		go func(u gft.UDPAssociation) {
			for {
				select {
				case <-done:
					return
				case <-u.Done():
					assocMu.Lock()
					if assoc == u {
						assoc = nil
					}
					assocMu.Unlock()
					return
				case pkt, ok := <-u.Recv():
					if !ok {
						assocMu.Lock()
						if assoc == u {
							assoc = nil
						}
						assocMu.Unlock()
						return
					}
					sendBackToClient(pkt.Target, pkt.Data)
				}
			}
		}(a)
		return a, nil
	}

	ensureDirectUDP := func(isIPv6 bool) (net.PacketConn, error) {
		assocMu.Lock()
		defer assocMu.Unlock()
		if isIPv6 {
			if directPC6 != nil {
				return directPC6, nil
			}
			lc := net.ListenConfig{Control: netbind.Control}
			pc, err := lc.ListenPacket(context.Background(), "udp6", "[::]:0")
			if err != nil {
				return nil, err
			}
			directPC6 = pc
			go func() {
				dbuf := make([]byte, 64*1024)
				for {
					dn, da, derr := pc.ReadFrom(dbuf)
					if derr != nil {
						return
					}
					sendBackToClient(da.String(), dbuf[:dn])
				}
			}()
			return pc, nil
		}
		if directPC4 != nil {
			return directPC4, nil
		}
		lc := net.ListenConfig{Control: netbind.Control}
		pc, err := lc.ListenPacket(context.Background(), "udp4", ":0")
		if err != nil {
			return nil, err
		}
		directPC4 = pc
		go func() {
			dbuf := make([]byte, 64*1024)
			for {
				dn, da, derr := pc.ReadFrom(dbuf)
				if derr != nil {
					return
				}
				sendBackToClient(da.String(), dbuf[:dn])
			}
		}()
		return pc, nil
	}

	buf := make([]byte, 64*1024)
	for {
		n, fromAddr, err := udpConn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 10 || buf[2] != 0x00 { // drop fragmented SOCKS5 UDP packets
			continue
		}
		clientAddrMu.Lock()
		clientAddr = fromAddr
		clientAddrMu.Unlock()

		target, payload, err := gft.DecodeAddr(buf[3:n])
		if err != nil {
			continue
		}
		act, resolvedTarget, _ := s.engine.DecideSmartRoute(target, target)
		if act == ActionReject {
			continue
		}
		if act == ActionDirect {
			allowV6 := s.engine.IPv6Enabled() || netbind.IsPureIPv6Physical()
			var uaDst *net.UDPAddr
			var err error
			if !allowV6 {
				uaDst, err = net.ResolveUDPAddr("udp4", resolvedTarget)
			} else {
				uaDst, err = netbind.ResolveUDPTarget(context.Background(), resolvedTarget)
			}
			if err != nil || uaDst == nil {
				continue
			}
			isV6 := uaDst.IP != nil && uaDst.IP.To4() == nil
			if isV6 && !allowV6 {
				continue
			}
			pc, err := ensureDirectUDP(isV6)
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(payload, uaDst)
		} else {
			a, err := ensureProxyAssoc()
			if err != nil {
				continue
			}
			_ = a.SendTo(target, payload)
		}
	}
}

var errNoActiveSession = errors.New("no active GFT session")
