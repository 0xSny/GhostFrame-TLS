package tunstack

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"ghostframe/internal/client"

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

	// AAAA query should return NOERROR with 0 answers (forces IPv4 Fake-IP fast path).
	qAAAA := buildDNSQuery(0x5678, "api.telegram.org", 28)
	respAAAA, ok := pool.HandleDNSQuery(qAAAA)
	if !ok {
		t.Fatalf("expected valid DNS AAAA response")
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
