package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/netbind"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func buildDNSQuery(id uint16, domain string, qtype uint16) []byte {
	var msg []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	msg = append(msg, hdr...)

	for _, label := range splitLabels(domain) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	msg = append(msg, tail[:]...)
	return msg
}

func splitLabels(d string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(d); i++ {
		if i == len(d) || d[i] == '.' {
			if i > start {
				out = append(out, d[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func TestFakeIPPoolAndDNSResponder(t *testing.T) {
	pool := NewFakeIPPool(4)

	qA := buildDNSQuery(0x1234, "api.telegram.org", 1)
	resp, ok := pool.HandleDNSQuery(qA)
	if !ok {
		t.Fatalf("expected valid DNS A response")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatalf("mismatched DNS txid")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("expected ANCOUNT=1, got %d", binary.BigEndian.Uint16(resp[6:8]))
	}
	fakeIP := net.IPv4(resp[len(resp)-4], resp[len(resp)-3], resp[len(resp)-2], resp[len(resp)-1])
	if !IsFakeIP(fakeIP) {
		t.Fatalf("expected 198.18.x.x fake IP, got %s", fakeIP)
	}
	host, found := pool.Lookup(fakeIP)
	if !found || host != "api.telegram.org" {
		t.Fatalf("reverse lookup mismatch: found=%v host=%q", found, host)
	}

	// Verify A record TTL == 2s.
	ttl := binary.BigEndian.Uint32(resp[len(resp)-10 : len(resp)-6])
	if ttl != fakeIPDNSTTL {
		t.Fatalf("expected FakeIP A TTL=%d, got %d", fakeIPDNSTTL, ttl)
	}

	// AAAA query should return NOERROR (RCODE=0) with 0 answers (forces IPv4 Fake-IP fast path).
	qAAAA := buildDNSQuery(0x5678, "api.telegram.org", 28)
	respAAAA, ok := pool.HandleDNSQuery(qAAAA)
	if !ok {
		t.Fatalf("expected valid DNS AAAA response")
	}
	if rcode := binary.BigEndian.Uint16(respAAAA[2:4]) & 0x0F; rcode != 0 {
		t.Fatalf("expected AAAA RCODE=0 (NOERROR), got %d", rcode)
	}
	if binary.BigEndian.Uint16(respAAAA[6:8]) != 0 {
		t.Fatalf("expected ANCOUNT=0 for AAAA, got %d", binary.BigEndian.Uint16(respAAAA[6:8]))
	}

	// Ring eviction check (capacity=4).
	pool.Allocate("a.example.com")
	pool.Allocate("b.example.com")
	pool.Allocate("c.example.com")
	pool.Allocate("d.example.com")
	if pool.Size() != 4 {
		t.Fatalf("expected bounded size 4, got %d", pool.Size())
	}
	if _, stillThere := pool.Lookup(fakeIP); stillThere {
		t.Fatalf("expected oldest entry to be evicted after capacity overflow")
	}
}

type captureWriter struct {
	mu      sync.Mutex
	packets [][]byte
	ch      chan []byte
}

func (w *captureWriter) WritePacket(pkt []byte, family int) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	w.mu.Lock()
	w.packets = append(w.packets, cp)
	w.mu.Unlock()
	select {
	case w.ch <- cp:
	default:
	}
}

func buildIPv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)
	pkt := make([]byte, totalLen)

	ipHdr := header.IPv4(pkt[:header.IPv4MinimumSize])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srcIP),
		DstAddr:     tcpip.AddrFrom4(dstIP),
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	udpHdr := header.UDP(pkt[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(pkt[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, tcpip.AddrFrom4(srcIP), tcpip.AddrFrom4(dstIP), uint16(header.UDPMinimumSize+len(payload)))
	xsum = checksum.Checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	return pkt
}

func TestStackEndToEndFakeIPDNS(t *testing.T) {
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()

	w := &captureWriter{ch: make(chan []byte, 16)}
	st, err := New(eng, w, 1400, true)
	if err != nil {
		t.Fatalf("tunstack.New failed: %v", err)
	}
	defer st.Close()

	dnsReq := buildDNSQuery(0xABCD, "t.me", 1)
	rawPkt := buildIPv4UDPPacket([4]byte{198, 18, 0, 2}, [4]byte{198, 18, 0, 1}, 54321, 53, dnsReq)
	st.PushPacket(rawPkt)

	select {
	case out := <-w.ch:
		if len(out) < header.IPv4MinimumSize+header.UDPMinimumSize+12 {
			t.Fatalf("outbound packet too short: %d", len(out))
		}
		dnsResp := out[header.IPv4MinimumSize+header.UDPMinimumSize:]
		if binary.BigEndian.Uint16(dnsResp[0:2]) != 0xABCD {
			t.Fatalf("unexpected DNS txid: 0x%x", binary.BigEndian.Uint16(dnsResp[0:2]))
		}
		if binary.BigEndian.Uint16(dnsResp[6:8]) != 1 {
			t.Fatalf("expected 1 DNS answer, got %d", binary.BigEndian.Uint16(dnsResp[6:8]))
		}
		ip := net.IPv4(dnsResp[len(dnsResp)-4], dnsResp[len(dnsResp)-3], dnsResp[len(dnsResp)-2], dnsResp[len(dnsResp)-1])
		if !IsFakeIP(ip) {
			t.Fatalf("expected Fake-IP answer, got %s", ip)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for Fake-IP DNS response from gVisor TUN stack")
	}

	stats := st.Stats()
	if stats.DNSQueries < 1 || stats.PacketsIn < 1 || stats.PacketsOut < 1 {
		t.Fatalf("unexpected TUN stats: %+v", stats)
	}
}

func TestFakeIPPersistenceAndBatchIO(t *testing.T) {
	cachePath := t.TempDir() + "/fakeip_cache.bin"
	p1 := NewFakeIPPoolWithPersistence(16, cachePath)
	b4 := p1.Allocate("web.telegram.org")
	ip := net.IPv4(b4[0], b4[1], b4[2], b4[3])
	p1.Close()

	// Reopen simulates PacketTunnel extension wakeup / OnDemand restart.
	p2 := NewFakeIPPoolWithPersistence(16, cachePath)
	defer p2.Close()
	host, ok := p2.Lookup(ip)
	if !ok || host != "web.telegram.org" {
		t.Fatalf("expected persisted FakeIP %s -> web.telegram.org, got ok=%v host=%q", ip, ok, host)
	}
	b4Again := p2.Allocate("web.telegram.org")
	if b4Again != b4 {
		t.Fatalf("expected stable re-allocation after reload: got %v want %v", b4Again, b4)
	}

	// Verify batch packet injection & batch writer path.
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()

	bw := &batchCaptureWriter{ch: make(chan []byte, 8)}
	st, err := NewWithOptions(eng, bw, 1400, true, cachePath)
	if err != nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	defer st.Close()

	q := buildDNSQuery(0x2222, "www.google.com", 1)
	rawPkt := buildIPv4UDPPacket([4]byte{198, 18, 0, 2}, [4]byte{198, 18, 0, 1}, 55555, 53, q)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(rawPkt)))
	st.PushPacketBatch(rawPkt, lenBuf[:], 1)

	select {
	case out := <-bw.ch:
		if len(out) < header.IPv4MinimumSize+header.UDPMinimumSize+12 {
			t.Fatalf("batch output packet too short: %d", len(out))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for batch outbound response")
	}
}

type batchCaptureWriter struct {
	captureWriter
}

func (b *batchCaptureWriter) WritePacketBatch(concatPkts []byte, lengthsBE []byte, count int, family int) {
	off := 0
	for i := 0; i < count; i++ {
		n := int(binary.BigEndian.Uint16(lengthsBE[i*2 : i*2+2]))
		if n <= 0 || off+n > len(concatPkts) {
			break
		}
		b.WritePacket(concatPkts[off:off+n], family)
		off += n
	}
}

func buildIPv6UDPPacket(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := header.UDPMinimumSize + len(payload)
	pkt := make([]byte, header.IPv6MinimumSize+udpLen)
	srcAddr := tcpip.AddrFrom16(srcIP)
	dstAddr := tcpip.AddrFrom16(dstIP)
	ip := header.IPv6(pkt[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})

	udpHdr := header.UDP(pkt[header.IPv6MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(pkt[header.IPv6MinimumSize+header.UDPMinimumSize:], payload)

	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))
	return pkt
}

func TestFakeIPv6AndStackIPv6Toggle(t *testing.T) {
	// 1. FakeIPPool AAAA behavior toggles cleanly with SetIPv6Enabled.
	pool := NewFakeIPPool(8)
	qAAAA := buildDNSQuery(0x7777, "dualstack.example.org", 28)

	respOff, ok := pool.HandleDNSQuery(qAAAA)
	if !ok || binary.BigEndian.Uint16(respOff[6:8]) != 0 {
		t.Fatalf("expected AAAA NODATA when IPv6 disabled, ok=%v", ok)
	}

	pool.SetIPv6Enabled(true)
	respOn, ok := pool.HandleDNSQuery(qAAAA)
	if !ok || binary.BigEndian.Uint16(respOn[6:8]) != 1 {
		t.Fatalf("expected AAAA Fake-IPv6 answer when IPv6 enabled, ok=%v", ok)
	}
	fake6 := net.IP(respOn[len(respOn)-16:])
	if !IsFakeIP(fake6) {
		t.Fatalf("expected Fake-IPv6 in fd18:c612::/64, got %s", fake6)
	}
	host, found := pool.Lookup(fake6)
	if !found || host != "dualstack.example.org" {
		t.Fatalf("expected reverse lookup for Fake-IPv6, found=%v host=%q", found, host)
	}

	// 2. Stack drops raw IPv6 packets when engine IPv6 is disabled, and routes DNSv6 when enabled.
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	w := &captureWriter{ch: make(chan []byte, 4)}
	st, err := NewWithOptions(eng, w, 1400, true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var src6, dst6 [16]byte
	copy(src6[:], net.ParseIP("fd18:c612::2").To16())
	copy(dst6[:], net.ParseIP("fd18:c612::1").To16())
	pkt6 := buildIPv6UDPPacket(src6, dst6, 44444, 53, buildDNSQuery(0x8888, "ipv6test.example.org", 28))

	// With IPv6 disabled by default, PushPacket injects IPv6 packets for fast-reject (DNS AAAA NODATA / TCP RST).
	st.PushPacket(pkt6)
	if st.Stats().PacketsIn == 0 {
		t.Fatalf("expected IPv6 packet injected for fast-reject when engine IPv6 disabled, PacketsIn=%d", st.Stats().PacketsIn)
	}
	select {
	case out := <-w.ch:
		ans := out[header.IPv6MinimumSize+header.UDPMinimumSize:]
		if binary.BigEndian.Uint16(ans[6:8]) != 0 {
			t.Fatalf("expected 0 AAAA answers when IPv6 disabled, got %d", binary.BigEndian.Uint16(ans[6:8]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for AAAA NODATA response when IPv6 disabled")
	}

	// Enable IPv6: PushPacket injects IPv6 packet and DNS responder returns Fake-IPv6 AAAA packet over IPv6!
	if err := eng.SetEnableIPv6(true); err != nil {
		t.Fatal(err)
	}
	st.PushPacket(pkt6)
	select {
	case out := <-w.ch:
		if len(out) < header.IPv6MinimumSize+header.UDPMinimumSize+12 || (out[0]>>4) != 6 {
			t.Fatalf("expected valid IPv6 DNS response packet, got len=%d ver=%d", len(out), out[0]>>4)
		}
		ans := out[header.IPv6MinimumSize+header.UDPMinimumSize:]
		if binary.BigEndian.Uint16(ans[6:8]) != 1 {
			t.Fatalf("expected 1 AAAA answer record in TUN IPv6 DNS response, got %d", binary.BigEndian.Uint16(ans[6:8]))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for TUN IPv6 AAAA DNS response")
	}
}

func TestStackRegistersFakeIPLookupAndBlocksFakeIPDirectUDP(t *testing.T) {
	if !IsFakeIP(net.ParseIP("198.19.12.34")) {
		t.Fatal("expected tunstack.IsFakeIP to match 198.18.0.0/15")
	}

	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	w := &captureWriter{ch: make(chan []byte, 4)}
	st, err := NewWithOptions(eng, w, 1400, true, "")
	if err != nil {
		t.Fatal(err)
	}

	// Allocate a Fake-IP -> verify Engine.RecoverFakeIPTarget resolves it via registered callback.
	fakeIPArr := st.fakeIP.Allocate("direct.example.cn")
	fakeIP := net.IP(fakeIPArr[:])
	rec, err := eng.RecoverFakeIPTarget(net.JoinHostPort(fakeIP.String(), "443"))
	if err != nil || rec != "direct.example.cn:443" {
		t.Fatalf("expected Engine.RecoverFakeIPTarget to recover hostname, got rec=%q err=%v", rec, err)
	}
	// Unmapped Fake-IP must return ErrFakeIPBlocked.
	if _, err := eng.RecoverFakeIPTarget("198.19.88.88:53"); err != netbind.ErrFakeIPBlocked {
		t.Fatalf("expected ErrFakeIPBlocked for unmapped Fake-IP, got %v", err)
	}

	// DirectDialer + relayUDPDirect must drop unmapped Fake-IP without hitting external sockets.
	_, _, errResolver := netbind.ResolveDirectUDPAddr(context.Background(), "198.18.99.99:5353", true)
	if errResolver != netbind.ErrFakeIPBlocked {
		t.Fatalf("expected ResolveDirectUDPAddr to reject Fake-IP, got %v", errResolver)
	}

	// Closing Stack must clear FakeIPLookupFunc from Engine.
	st.Close()
	if _, err := eng.RecoverFakeIPTarget(net.JoinHostPort(fakeIP.String(), "443")); err != netbind.ErrFakeIPBlocked {
		t.Fatalf("expected ErrFakeIPBlocked after Stack.Close cleared FakeIPLookupFunc, got %v", err)
	}
}

func buildIPv6TCPSYNPacket(srcIP, dstIP [16]byte, srcPort, dstPort uint16) []byte {
	const tcpLen = header.TCPMinimumSize
	pkt := make([]byte, header.IPv6MinimumSize+tcpLen)

	ip := header.IPv6(pkt[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     tcpLen,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16(srcIP),
		DstAddr:           tcpip.AddrFrom16(dstIP),
	})

	tcpHdr := header.TCP(pkt[header.IPv6MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     0x11223344,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		tcpip.AddrFrom16(srcIP),
		tcpip.AddrFrom16(dstIP),
		uint16(tcpLen),
	)
	xsum = checksum.Checksum(tcpHdr, xsum)
	tcpHdr.SetChecksum(^xsum)
	return pkt
}

func TestStackIPv6DisabledTCPFastRSTAndLargeUDPRelay(t *testing.T) {
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	if err := eng.SetRouteMode(client.RouteRule); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetCustomRules([]string{"DOMAIN-SUFFIX,largeudp.test,DIRECT"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.SetEnableIPv6(false); err != nil {
		t.Fatal(err)
	}

	w := &captureWriter{ch: make(chan []byte, 16)}
	st, err := NewWithOptions(eng, w, 8000, true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// 1. Inject IPv6 TCP SYN while IPv6 disabled -> must get immediate TCP RST packet (not silent timeout).
	var src6, dst6 [16]byte
	copy(src6[:], net.ParseIP("fd18:c612::2").To16())
	copy(dst6[:], net.ParseIP("2606:4700:4700::1111").To16())
	syn6 := buildIPv6TCPSYNPacket(src6, dst6, 51234, 443)
	st.PushPacket(syn6)

	select {
	case out := <-w.ch:
		if len(out) < header.IPv6MinimumSize+header.TCPMinimumSize || (out[0]>>4) != 6 {
			t.Fatalf("expected valid IPv6 TCP RST packet, got len=%d ver=%d", len(out), out[0]>>4)
		}
		if out[6] != uint8(header.TCPProtocolNumber) {
			t.Fatalf("expected NextHeader=TCP(6), got %d", out[6])
		}
		flags := header.TCP(out[header.IPv6MinimumSize:]).Flags()
		if !flags.Contains(header.TCPFlagRst) {
			t.Fatalf("expected TCP RST flag set, got flags=%v", flags)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for immediate IPv6 TCP RST when IPv6 disabled")
	}

	// 2. Verify >4KB UDP datagrams pass losslessly through relayUDPDirect (udpBufPool 16KB, not 2KB dnsBufPool).
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	readyCh := make(chan struct{})
	go func() {
		close(readyCh)
		buf := make([]byte, 16384)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	<-readyCh
	echoPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	fakeIP := st.fakeIP.Allocate("echo.largeudp.test")
	restoreNAT64 := netbind.SetNAT64TestHooks(nil, nil, func(_ context.Context, host string) ([]net.IP, error) {
		if host == "echo.largeudp.test" {
			return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
		}
		return nil, nil
	})
	defer restoreNAT64()

	bigPayload := bytes.Repeat([]byte("KESTREL-UDP-4KB-"), 282) // 16 * 282 = 4512 bytes (>4KB)
	udpPkt := buildIPv4UDPPacket([4]byte{198, 18, 0, 2}, fakeIP, 55555, echoPort, bigPayload)

	var out []byte
	for attempt := 0; attempt < 5; attempt++ {
		st.PushPacket(udpPkt)
		select {
		case out = <-w.ch:
		case <-time.After(300 * time.Millisecond):
		}
		if out != nil {
			break
		}
	}
	if out == nil {
		t.Fatal("timed out waiting for >4KB UDP echo through TUN stack")
	}
	if len(out) < header.IPv4MinimumSize+header.UDPMinimumSize+len(bigPayload) {
		t.Fatalf("expected full >4KB UDP echo packet without 2KB truncation, got total len=%d", len(out))
	}
	ihl := int(out[0]&0x0F) * 4
	gotPayload := out[ihl+header.UDPMinimumSize:]
	if !bytes.Equal(gotPayload, bigPayload) {
		t.Fatalf("echoed >4KB UDP payload mismatch: got %d bytes want %d bytes", len(gotPayload), len(bigPayload))
	}
}
