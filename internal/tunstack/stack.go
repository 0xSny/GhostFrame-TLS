package tunstack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunNICID       tcpip.NICID = 1
	afINET                     = 2 // POSIX AF_INET (matches iOS NEPacketTunnelFlow protocol family)
	udpIdleTimeout             = 45 * time.Second
)

// PacketWriter receives outbound raw IP packets from the userspace TCP/IP stack
// and injects them back into the OS TUN interface (e.g. iOS NEPacketTunnelFlow).
type PacketWriter interface {
	WritePacket(pkt []byte, family int)
}

// Stats reports live TUN L3/L4 counters for telemetry & diagnostics.
type Stats struct {
	Active       bool   `json:"active"`
	MTU          int    `json:"mtu"`
	TCPConns     uint64 `json:"tcp_conns"`
	UDPConns     uint64 `json:"udp_conns"`
	DNSQueries   uint64 `json:"dns_queries"`
	PacketsIn    uint64 `json:"packets_in"`
	PacketsOut   uint64 `json:"packets_out"`
	FakeIPEntry  int    `json:"fakeip_entries"`
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

// Stack wraps a memory-bounded gVisor netstack bridging raw TUN IPv4 packets
// into GhostFrame's client.Engine (RuleSet + Fake-IP DNS + SNI Sniff + GFT-RTC/TCP).
type Stack struct {
	engine *client.Engine
	writer PacketWriter
	mtu    int
	fakeIP *FakeIPPool

	ns     *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	tcpConns   atomic.Uint64
	udpConns   atomic.Uint64
	dnsQueries atomic.Uint64
	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64
}

// New creates and starts a userspace TUN TCP/IP stack bound to eng.
// When lowMem is true (iOS PacketTunnel 50MB cap), TCP windows and queue depths are tightly bounded.
func New(eng *client.Engine, writer PacketWriter, mtu int, lowMem bool) (*Stack, error) {
	if eng == nil {
		return nil, errors.New("tunstack: nil engine")
	}
	if writer == nil {
		return nil, errors.New("tunstack: nil packet writer")
	}
	if mtu < 576 || mtu > 9000 {
		mtu = 1400
	}

	queueSize := 512
	fakeCap := 8192
	tcpWnd := 128 * 1024
	tcpMaxInFlight := 512
	if lowMem {
		queueSize = 256
		fakeCap = 4096
		tcpWnd = 64 * 1024
		tcpMaxInFlight = 256
	}

	ep := channel.New(queueSize, uint32(mtu), "")
	ns := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
	})

	// Enable SACK & bound TCP send/receive buffer sizes for iOS memory safety.
	sackEnabled := tcpip.TCPSACKEnabled(true)
	_ = ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled)
	rcvRange := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4 << 10,
		Default: tcpWnd,
		Max:     tcpWnd * 3,
	}
	sndRange := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4 << 10,
		Default: tcpWnd,
		Max:     tcpWnd * 3,
	}
	_ = ns.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvRange)
	_ = ns.SetTransportProtocolOption(tcp.ProtocolNumber, &sndRange)

	if err := ns.CreateNIC(tunNICID, ep); err != nil {
		ns.Close()
		return nil, fmt.Errorf("tunstack: create NIC: %s", err)
	}
	// Promiscuous + Spoofing lets netstack accept & respond to arbitrary destination IPs (0.0.0.0/0).
	if err := ns.SetPromiscuousMode(tunNICID, true); err != nil {
		ns.Close()
		return nil, fmt.Errorf("tunstack: promiscuous mode: %s", err)
	}
	if err := ns.SetSpoofing(tunNICID, true); err != nil {
		ns.Close()
		return nil, fmt.Errorf("tunstack: spoofing mode: %s", err)
	}
	ns.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         tunNICID,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		engine: eng,
		writer: writer,
		mtu:    mtu,
		fakeIP: NewFakeIPPool(fakeCap),
		ns:     ns,
		ep:     ep,
		ctx:    ctx,
		cancel: cancel,
	}

	tcpFwd := tcp.NewForwarder(ns, tcpWnd, tcpMaxInFlight, s.handleTCP)
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(ns, s.handleUDP)
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go s.outboundPump()
	return s, nil
}

// PushPacket injects a raw IPv4 packet read from the OS TUN interface into gVisor netstack.
func (s *Stack) PushPacket(pkt []byte) {
	if s.closed.Load() || len(pkt) < header.IPv4MinimumSize {
		return
	}
	// Only IPv4 packets are handled in IPv4 TUN mode.
	if pkt[0]>>4 != 4 {
		return
	}
	s.packetsIn.Add(1)
	// Copy into gVisor owned buffer so caller slice can be reused immediately.
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(cp),
	})
	s.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

// Close shuts down the userspace TCP/IP stack and releases all resources.
func (s *Stack) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.cancel()
	s.ep.Close()
	s.ns.Close()
}

// Stats returns live TUN stack metrics.
func (s *Stack) Stats() Stats {
	return Stats{
		Active:      !s.closed.Load(),
		MTU:         s.mtu,
		TCPConns:    s.tcpConns.Load(),
		UDPConns:    s.udpConns.Load(),
		DNSQueries:  s.dnsQueries.Load(),
		PacketsIn:   s.packetsIn.Load(),
		PacketsOut:  s.packetsOut.Load(),
		FakeIPEntry: s.fakeIP.Size(),
	}
}

func (s *Stack) outboundPump() {
	outBuf := make([]byte, 0, s.mtu+64)
	for {
		pb := s.ep.ReadContext(s.ctx)
		if pb == nil {
			return
		}
		outBuf = outBuf[:0]
		for _, slice := range pb.AsSlices() {
			outBuf = append(outBuf, slice...)
		}
		pb.DecRef()
		if len(outBuf) == 0 {
			continue
		}
		s.packetsOut.Add(1)
		s.writer.WritePacket(outBuf, afINET)
	}
}

func (s *Stack) resolveDestination(dstAddr tcpip.Address, dstPort uint16) (dialTarget, routeTarget string, isFake bool) {
	ip := net.IP(dstAddr.AsSlice())
	portStr := strconv.Itoa(int(dstPort))
	if host, ok := s.fakeIP.Lookup(ip); ok && host != "" {
		hp := net.JoinHostPort(host, portStr)
		return hp, hp, true
	}
	hp := net.JoinHostPort(ip.String(), portStr)
	return hp, hp, false
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	if s.closed.Load() {
		r.Complete(true)
		return
	}
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	ep.SocketOptions().SetKeepAlive(true)
	conn := gonet.NewTCPConn(&wq, ep)
	s.tcpConns.Add(1)

	go s.relayTCP(conn, id.LocalAddress, id.LocalPort)
}

func (s *Stack) relayTCP(conn *gonet.TCPConn, dstAddr tcpip.Address, dstPort uint16) {
	defer conn.Close()

	dialTarget, routeTarget, isFake := s.resolveDestination(dstAddr, dstPort)
	var clientConn net.Conn = conn

	// For raw public IPs (non-FakeIP) on TLS ports, perform 30ms ClientHello SNI sniff
	// so RuleSet can classify by domain name even when an app bypassed DNS.
	if !isFake && s.engine.ShouldSniffSNI(dialTarget) {
		var sni string
		sni, clientConn = gft.SniffTLSSNI(conn, 30*time.Millisecond)
		if sni != "" {
			routeTarget = net.JoinHostPort(sni, strconv.Itoa(int(dstPort)))
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
		bufPtr := copyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(st, clientConn, *bufPtr)
		copyBufPool.Put(bufPtr)
		_ = st.CloseWrite()
	}()

	bufPtr := copyBufPool.Get().(*[]byte)
	_, _ = io.CopyBuffer(conn, st, *bufPtr)
	copyBufPool.Put(bufPtr)
	_ = conn.CloseWrite()
	wg.Wait()
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	if s.closed.Load() {
		return false
	}
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return false
	}
	conn := gonet.NewUDPConn(&wq, ep)

	// Intercept ALL UDP port 53 traffic (198.18.0.1:53 and any hardcoded external DNS)
	// with our zero-latency Fake-IP DNS responder.
	if id.LocalPort == 53 {
		s.dnsQueries.Add(1)
		go s.handleDNSConn(conn)
		return true
	}

	s.udpConns.Add(1)
	go s.relayUDP(conn, id.LocalAddress, id.LocalPort)
	return true
}

func (s *Stack) handleDNSConn(conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return
	}
	if resp, ok := s.fakeIP.HandleDNSQuery(buf[:n]); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(resp)
	}
}

func (s *Stack) relayUDP(conn *gonet.UDPConn, dstAddr tcpip.Address, dstPort uint16) {
	defer conn.Close()

	dialTarget, routeTarget, _ := s.resolveDestination(dstAddr, dstPort)
	act := s.engine.RouteDecision(routeTarget)
	if act == client.ActionReject {
		return
	}

	if act == client.ActionDirect {
		s.relayUDPDirect(conn, dialTarget)
		return
	}

	assoc, err := s.engine.OpenUDPAssociation()
	if err != nil {
		return
	}
	defer assoc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-assoc.Done():
				return
			case pkt, ok := <-assoc.Recv():
				if !ok {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
				if _, werr := conn.Write(pkt.Data); werr != nil {
					return
				}
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, rerr := conn.Read(buf)
		if rerr != nil {
			break
		}
		if werr := assoc.SendTo(dialTarget, buf[:n]); werr != nil {
			break
		}
	}
	_ = assoc.Close()
	<-done
}

func (s *Stack) relayUDPDirect(conn *gonet.UDPConn, dialTarget string) {
	d := s.engine.DirectDialer(5 * time.Second)
	remote, err := d.Dial("udp", dialTarget)
	if err != nil {
		return
	}
	defer remote.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, rerr := remote.Read(buf)
			if rerr != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, rerr := conn.Read(buf)
		if rerr != nil {
			break
		}
		_ = remote.SetWriteDeadline(time.Now().Add(udpIdleTimeout))
		if _, werr := remote.Write(buf[:n]); werr != nil {
			break
		}
	}
	_ = remote.Close()
	<-done
}
