package tunstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	maxOutBatch                = 32
)

// PacketWriter receives outbound raw IP packets from the userspace TCP/IP stack
// and injects them back into the OS TUN interface (e.g. iOS NEPacketTunnelFlow).
type PacketWriter interface {
	WritePacket(pkt []byte, family int)
}

// BatchPacketWriter is an optional extension implemented by mobile PacketWriter bridges
// to receive up to 32 concatenated outbound packets in a single FFI/autoreleasepool boundary.
type BatchPacketWriter interface {
	WritePacketBatch(concatPkts []byte, lengthsBE []byte, count int, family int)
}

// Stats reports live TUN L3/L4 counters for telemetry & diagnostics.
type Stats struct {
	Active      bool   `json:"active"`
	MTU         int    `json:"mtu"`
	TCPConns    uint64 `json:"tcp_conns"`
	UDPConns    uint64 `json:"udp_conns"`
	ActiveTCP   int32  `json:"active_tcp"`
	ActiveUDP   int32  `json:"active_udp"`
	DNSQueries  uint64 `json:"dns_queries"`
	PacketsIn   uint64 `json:"packets_in"`
	PacketsOut  uint64 `json:"packets_out"`
	FakeIPEntry int    `json:"fakeip_entries"`
}

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

var dnsBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

// Stack wraps a memory-bounded gVisor netstack bridging raw TUN IPv4 packets
// into GhostFrame's client.Engine (RuleSet + Fake-IP DNS + SNI Sniff + GFT-RTC/TCP).
type Stack struct {
	engine       *client.Engine
	writer       PacketWriter
	batchWriter  BatchPacketWriter
	mtu          int
	lowMem       bool
	maxActiveTCP int32
	maxActiveUDP int32
	udpIdle      time.Duration
	fakeIP       *FakeIPPool

	ns     *stack.Stack
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	activeTCP  atomic.Int32
	activeUDP  atomic.Int32
	tcpConns   atomic.Uint64
	udpConns   atomic.Uint64
	dnsQueries atomic.Uint64
	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64
}

// New creates and starts an in-memory userspace TUN TCP/IP stack bound to eng.
func New(eng *client.Engine, writer PacketWriter, mtu int, lowMem bool) (*Stack, error) {
	return NewWithOptions(eng, writer, mtu, lowMem, "")
}

// NewWithOptions creates and starts a userspace TUN TCP/IP stack with optional Fake-IP cache persistence.
func NewWithOptions(eng *client.Engine, writer PacketWriter, mtu int, lowMem bool, fakeCachePath string) (*Stack, error) {
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
	maxTCP := int32(1024)
	maxUDP := int32(512)
	udpIdle := 45 * time.Second
	if lowMem {
		queueSize = 256
		fakeCap = 4096
		tcpWnd = 64 * 1024
		tcpMaxInFlight = 256
		maxTCP = 256
		maxUDP = 128
		udpIdle = 20 * time.Second
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

	bw, _ := writer.(BatchPacketWriter)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		engine:       eng,
		writer:       writer,
		batchWriter:  bw,
		mtu:          mtu,
		lowMem:       lowMem,
		maxActiveTCP: maxTCP,
		maxActiveUDP: maxUDP,
		udpIdle:      udpIdle,
		fakeIP:       NewFakeIPPoolWithPersistence(fakeCap, fakeCachePath),
		ns:           ns,
		ep:           ep,
		ctx:          ctx,
		cancel:       cancel,
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
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(cp),
	})
	s.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
	pb.DecRef()
}

// PushPacketBatch unpacks concatenated raw IPv4 packets packed with big-endian uint16 lengths
// and injects them into gVisor netstack in a single FFI crossing.
func (s *Stack) PushPacketBatch(concatPkts []byte, lengthsBE []byte, count int) {
	if s.closed.Load() || count <= 0 || len(lengthsBE) < count*2 {
		return
	}
	off := 0
	for i := 0; i < count; i++ {
		n := int(binary.BigEndian.Uint16(lengthsBE[i*2 : i*2+2]))
		if n <= 0 || off+n > len(concatPkts) {
			break
		}
		s.PushPacket(concatPkts[off : off+n])
		off += n
	}
}

// Close shuts down the userspace TCP/IP stack and releases all resources.
func (s *Stack) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.cancel()
	s.ep.Close()
	s.ns.Close()
	if s.fakeIP != nil {
		s.fakeIP.Close()
	}
}

// Stats returns live TUN stack metrics.
func (s *Stack) Stats() Stats {
	return Stats{
		Active:      !s.closed.Load(),
		MTU:         s.mtu,
		TCPConns:    s.tcpConns.Load(),
		UDPConns:    s.udpConns.Load(),
		ActiveTCP:   s.activeTCP.Load(),
		ActiveUDP:   s.activeUDP.Load(),
		DNSQueries:  s.dnsQueries.Load(),
		PacketsIn:   s.packetsIn.Load(),
		PacketsOut:  s.packetsOut.Load(),
		FakeIPEntry: s.fakeIP.Size(),
	}
}

func (s *Stack) outboundPump() {
	if s.batchWriter == nil {
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

	batchBuf := make([]byte, 0, (s.mtu+64)*maxOutBatch)
	var lenBuf [maxOutBatch * 2]byte
	for {
		pb := s.ep.ReadContext(s.ctx)
		if pb == nil {
			return
		}
		batchBuf = batchBuf[:0]
		count := 0

		appendPB := func(pkt *stack.PacketBuffer) {
			start := len(batchBuf)
			for _, slice := range pkt.AsSlices() {
				batchBuf = append(batchBuf, slice...)
			}
			pkt.DecRef()
			pktLen := len(batchBuf) - start
			if pktLen > 0 && pktLen <= 0xFFFF {
				binary.BigEndian.PutUint16(lenBuf[count*2:count*2+2], uint16(pktLen))
				count++
			} else if pktLen > 0xFFFF {
				batchBuf = batchBuf[:start]
			}
		}

		appendPB(pb)
		for count < maxOutBatch {
			nextPB := s.ep.Read()
			if nextPB == nil {
				break
			}
			appendPB(nextPB)
		}
		if count == 0 {
			continue
		}
		s.packetsOut.Add(uint64(count))
		s.batchWriter.WritePacketBatch(batchBuf, lenBuf[:count*2], count, afINET)
	}
}

func (s *Stack) resolveDestination(dstAddr tcpip.Address, dstPort uint16) (dialTarget, routeTarget string, isFake, hitFakeRange bool) {
	ip := net.IP(dstAddr.AsSlice())
	portStr := strconv.Itoa(int(dstPort))
	hitFakeRange = IsFakeIP(ip)
	if host, ok := s.fakeIP.Lookup(ip); ok && host != "" {
		hp := net.JoinHostPort(host, portStr)
		return hp, hp, true, true
	}
	hp := net.JoinHostPort(ip.String(), portStr)
	return hp, hp, false, hitFakeRange
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	if s.closed.Load() {
		r.Complete(true)
		return
	}
	if cur := s.activeTCP.Add(1); cur > s.maxActiveTCP {
		s.activeTCP.Add(-1)
		r.Complete(true)
		return
	}

	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		s.activeTCP.Add(-1)
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
	defer s.activeTCP.Add(-1)
	defer conn.Close()

	dialTarget, routeTarget, isFake, hitFakeRange := s.resolveDestination(dstAddr, dstPort)
	var clientConn net.Conn = conn

	// For raw public IPs (non-FakeIP) OR orphaned 198.18.x.x Fake-IPs missing after restart,
	// perform 30ms ClientHello SNI sniff to recover the true hostname.
	if (!isFake && s.engine.ShouldSniffSNI(dialTarget)) || (hitFakeRange && !isFake) {
		var sni string
		sni, clientConn = gft.SniffTLSSNI(conn, 30*time.Millisecond)
		if sni != "" {
			hp := net.JoinHostPort(sni, strconv.Itoa(int(dstPort)))
			routeTarget = hp
			if hitFakeRange && !isFake {
				dialTarget = hp
			}
		} else if hitFakeRange && !isFake {
			// Drop orphaned unmapped 198.18.x.x immediately (TCP RST/close) so the app re-queries DNS at 0ms.
			return
		}
	}

	st, _, err := s.engine.OpenTargetStreamWithRoute(dialTarget, routeTarget, nil)
	if err != nil {
		return
	}
	defer st.Close()

	gft.Relay(st, clientConn, 2*time.Minute)
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	if s.closed.Load() {
		return false
	}
	id := r.ID()
	// Intercept ALL UDP port 53 traffic (198.18.0.1:53 and any hardcoded external DNS)
	// with our zero-latency Fake-IP DNS responder.
	if id.LocalPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		conn := gonet.NewUDPConn(&wq, ep)
		s.dnsQueries.Add(1)
		go s.handleDNSConn(conn)
		return true
	}

	if cur := s.activeUDP.Add(1); cur > s.maxActiveUDP {
		s.activeUDP.Add(-1)
		return false
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		s.activeUDP.Add(-1)
		return false
	}
	conn := gonet.NewUDPConn(&wq, ep)
	s.udpConns.Add(1)
	go s.relayUDP(conn, id.LocalAddress, id.LocalPort)
	return true
}

func (s *Stack) handleDNSConn(conn *gonet.UDPConn) {
	defer conn.Close()
	bufPtr := dnsBufPool.Get().(*[]byte)
	defer dnsBufPool.Put(bufPtr)
	buf := *bufPtr

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
	defer s.activeUDP.Add(-1)
	defer conn.Close()

	dialTarget, routeTarget, isFake, hitFakeRange := s.resolveDestination(dstAddr, dstPort)
	if hitFakeRange && !isFake {
		// Unmapped 198.18.x.x UDP cannot be routed externally; drop immediately so app re-resolves DNS.
		return
	}
	act, resolvedDial, _ := s.engine.DecideSmartRoute(dialTarget, routeTarget)
	if act == client.ActionReject {
		return
	}

	if act == client.ActionDirect {
		s.relayUDPDirect(conn, resolvedDial)
		return
	}

	assoc, err := s.engine.OpenUDPAssociation()
	if err != nil {
		return
	}
	defer assoc.Close()

	idle := s.udpIdle
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
				_ = conn.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := conn.Write(pkt.Data); werr != nil {
					return
				}
			}
		}
	}()

	bufPtr := dnsBufPool.Get().(*[]byte)
	buf := *bufPtr
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, rerr := conn.Read(buf)
		if rerr != nil {
			break
		}
		if werr := assoc.SendTo(dialTarget, buf[:n]); werr != nil {
			break
		}
	}
	dnsBufPool.Put(bufPtr)
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

	idle := s.udpIdle
	done := make(chan struct{})
	go func() {
		defer close(done)
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			_ = remote.SetReadDeadline(time.Now().Add(idle))
			n, rerr := remote.Read(buf)
			if rerr != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
	}()

	bufPtr := dnsBufPool.Get().(*[]byte)
	buf := *bufPtr
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		n, rerr := conn.Read(buf)
		if rerr != nil {
			break
		}
		_ = remote.SetWriteDeadline(time.Now().Add(idle))
		if _, werr := remote.Write(buf[:n]); werr != nil {
			break
		}
	}
	dnsBufPool.Put(bufPtr)
	_ = remote.Close()
	<-done
}
